"""Tests for floorvault storage adapters (vaultkit)."""

import sqlite3

import pytest

from floorvault.core import DecryptionVerificationError, FloorVault
from floorvault.vaultkit import (
    SessionCrypto,
    VaultStore,
    normalize_otp_secret,
    scrub_secret_from_text,
    totp_now,
)
from floorvault.vaultkit.vault import VaultError


def test_vault_store_lifecycle(tmp_path):
    crypto = FloorVault(b"\x11" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault_store", crypto=crypto)

    with store._connect() as conn:
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1

    # 1. Add login item
    meta = store.add_item(
        kind="login",
        label="GitHub Enterprise",
        secret={
            "identifier_type": "username",
            "identifier": "scott",
            "password": "super-secure-github-password",
        },
        origin="https://github.com",
    )

    assert meta.id.startswith("vault_")
    assert meta.label == "GitHub Enterprise"
    assert meta.identifier == "scott"
    assert meta.origin == "https://github.com"

    with store._db_path.open("rb") as db_file:
        raw_db = db_file.read()
    assert b"GitHub Enterprise" not in raw_db
    assert b"https://github.com" not in raw_db
    assert b"scott" not in raw_db

    # 2. Retrieve secret
    secret = store.get_secret(meta.id)
    assert secret["password"] == "super-secure-github-password"

    # 3. List all items
    all_items = store.list_items()
    assert len(all_items) == 1

    # 5. Delete item
    deleted = store.delete_item(meta.id)
    assert deleted is True
    assert len(store.list_items()) == 0


def test_connect_closes_the_connection_on_normal_exit(tmp_path):
    crypto = FloorVault(b"\x29" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)
    with store._connect() as conn:
        captured = conn
    with pytest.raises(sqlite3.ProgrammingError):
        captured.execute("SELECT 1")


def test_connect_closes_the_connection_on_error(tmp_path):
    crypto = FloorVault(b"\x2a" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)
    with pytest.raises(sqlite3.IntegrityError), store._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO vault_items (id) VALUES (NULL)")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_vault_migrates_legacy_plaintext_metadata(tmp_path):
    db_dir = tmp_path / "legacy"
    db_dir.mkdir()
    db_path = db_dir / "vault.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE vault_items (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL,
                origin TEXT, identifier_type TEXT,
                identifier TEXT, has_otp INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                payload_cipher BLOB NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO vault_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "vault_legacy",
                "login",
                "Legacy",
                "https://example.com",
                "email",
                "u",
                0,
                "now",
                b"cipher",
            ),
        )
    conn.close()

    with pytest.raises(VaultError, match="plaintext metadata"):
        VaultStore(db_dir, crypto=FloorVault(b"\x25" * 32, memory_mode="disabled"))

    store = VaultStore(
        db_dir,
        crypto=FloorVault(b"\x25" * 32, memory_mode="disabled"),
        migrate_legacy_metadata=True,
    )
    assert store.list_items()[0].label == "Legacy"
    with db_path.open("rb") as db_file:
        raw_db = db_file.read()
    assert b"Legacy" not in raw_db
    assert b"https://example.com" not in raw_db

    # Migration is one-shot: ordinary reopen works once metadata is sealed.
    reopened = VaultStore(db_dir, crypto=FloorVault(b"\x25" * 32, memory_mode="disabled"))
    assert reopened.list_items()[0].label == "Legacy"


def test_vault_rejects_plaintext_metadata_after_version_reset(tmp_path):
    """A database writer must not re-enable plaintext acceptance by resetting
    the attacker-editable user_version marker (a prior audit finding)."""
    crypto = FloorVault(b"\x27" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)
    item = store.add_item(
        kind="login",
        label="Trusted",
        origin="https://example.com",
        secret={"identifier_type": "username", "identifier": "u", "password": "p"},
    )

    db_path = tmp_path / "vault" / "vault.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA user_version = 0")
        conn.execute(
            "UPDATE vault_items SET label=?, origin=?, identifier_type=?, identifier=?, created_at=? WHERE id=?",
            (
                "forged",
                "https://evil.example",
                "username",
                "mallory",
                "2000-01-01T00:00:00+00:00",
                item.id,
            ),
        )

    with pytest.raises(VaultError, match="plaintext metadata"):
        VaultStore(tmp_path / "vault", crypto=FloorVault(b"\x27" * 32, memory_mode="disabled"))

    # Rejected without resealing: stored metadata is still the planted
    # plaintext, and the sealed payload still decrypts under the real key.
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT label, payload_cipher FROM vault_items WHERE id = ?", (item.id,)
        ).fetchone()
    assert row[0] == "forged"
    plaintext = crypto.decrypt(row[1], table="vault_items", record_id=item.id, column="payload")
    assert "p" in plaintext


def test_vault_removes_legacy_origin_index_column(tmp_path):
    db_dir = tmp_path / "legacy-index"
    db_dir.mkdir()
    db_path = db_dir / "vault.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE vault_items (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL,
                origin TEXT, origin_idx BLOB NOT NULL, identifier_type TEXT,
                identifier TEXT, has_otp INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                payload_cipher BLOB NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO vault_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("legacy", "generic", b"label", None, b"old-index", None, None, 0, b"date", b"payload"),
        )
    conn.close()

    VaultStore(db_dir, crypto=FloorVault(b"\x28" * 32, memory_mode="disabled"))
    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_items)")}
    conn.close()
    assert "origin_idx" not in columns


def test_vault_rejects_plaintext_metadata_after_migration(tmp_path):
    crypto = FloorVault(b"\x26" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)
    item = store.add_item(
        kind="login",
        label="Trusted",
        origin="https://example.com",
        secret={"identifier_type": "username", "identifier": "u", "password": "p"},
    )

    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        conn.execute("UPDATE vault_items SET label = ? WHERE id = ?", ("forged", item.id))
    conn.close()

    with pytest.raises(VaultError, match="plaintext metadata"):
        VaultStore(tmp_path / "vault", crypto=FloorVault(b"\x26" * 32, memory_mode="disabled"))


def test_session_crypto_hybrid_split(tmp_path):
    crypto = FloorVault(b"\x22" * 32, memory_mode="disabled")
    session_crypto = SessionCrypto(crypto, allow_plaintext_fts=True)

    raw_content = (
        "Please use this key: sk-1234567890123456789012345 to authenticate."  # gitleaks:allow
    )
    cipher, fts_text = session_crypto.encrypt_message(
        session_id="sess-001",
        message_id="msg-001",
        content=raw_content,
    )

    # 1. Ciphertext is encrypted bytes
    assert isinstance(cipher, bytes)
    assert cipher != raw_content.encode("utf-8")

    # 2. FTS text has sensitive API key redacted
    assert "sk-1234567890123456789012345" not in fts_text
    assert "[REDACTED_SECRET]" in fts_text

    # 3. Decryption recovers exact original plaintext
    decrypted = session_crypto.decrypt_message(
        session_id="sess-001",
        message_id="msg-001",
        payload_cipher=cipher,
    )
    assert decrypted == raw_content


def test_session_crypto_has_no_search_projection_by_default():
    crypto = FloorVault(b"\x23" * 32, memory_mode="disabled")
    session_crypto = SessionCrypto(crypto)

    _, fts_text = session_crypto.encrypt_message(
        session_id="sess-001",
        message_id="msg-001",
        content="private conversation and sk-1234567890123456789012345",
    )

    assert fts_text == ""


def test_session_crypto_plaintext_fts_requires_explicit_opt_in():
    crypto = FloorVault(b"\x27" * 32, memory_mode="disabled")
    session_crypto = SessionCrypto(crypto, allow_plaintext_fts=True)

    _, search_text = session_crypto.encrypt_message(
        session_id="sess-001", message_id="msg-001", content="private launch"
    )

    assert "private" in search_text


def test_session_crypto_binds_session_id():
    crypto = FloorVault(b"\x24" * 32, memory_mode="disabled")
    session_crypto = SessionCrypto(crypto)
    cipher, _ = session_crypto.encrypt_message(
        session_id="sess-a", message_id="same-id", content="secret"
    )

    with pytest.raises(DecryptionVerificationError):
        session_crypto.decrypt_message(
            session_id="sess-b", message_id="same-id", payload_cipher=cipher
        )


def test_vault_native_api_compatibility(tmp_path):
    crypto = FloorVault(b"\x30" * 32, memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)

    assert not store.has_items()

    item = store.add_item(
        kind="login",
        label="Test Site",
        origin="https://example.com",
        secret={"identifier_type": "username", "identifier": "user1", "password": "pass123"},
    )

    assert store.has_items()

    meta = store.get_meta(item.id)
    assert meta is not None
    assert meta.id == item.id
    assert meta.label == "Test Site"
    assert meta.identifier == "user1"

    # Both resolve_secret and get_secret alias work
    secret_res = store.resolve_secret(item.id)
    assert secret_res["password"] == "pass123"
    assert store.get_secret(item.id)["password"] == "pass123"

    # Both remove_item and delete_item alias work
    assert store.remove_item(item.id)
    assert not store.has_items()
    assert store.get_meta(item.id) is None


def test_vault_otp_and_totp_utilities():
    # 1. Standard OTP URI defaults
    seed_std = normalize_otp_secret("otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP")
    assert seed_std == "JBSWY3DPEHPK3PXP"
    code_std = totp_now(seed_std, at=1000000000)
    assert len(code_std) == 6

    # 2. Non-standard parameters (digits=8, period=60, algo=SHA256) preserved
    seed_custom = normalize_otp_secret(
        "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256"
    )
    assert seed_custom == "JBSWY3DPEHPK3PXP|8|60|SHA256"
    code_custom = totp_now(seed_custom, at=1000000000)
    assert len(code_custom) == 8

    # 3. Secret scrubbing helper
    secret = {"password": "SuperSecretPassword123"}
    scrubbed = scrub_secret_from_text(
        "Error: failed with SuperSecretPassword123 or password: 'foo'", secret
    )
    assert "SuperSecretPassword123" not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_session_crypto_unicode_and_legacy_ciphertext_is_rejected():
    crypto = FloorVault(b"\x31" * 32, memory_mode="disabled")
    session_crypto = SessionCrypto(crypto)

    # 1. Search projections are disabled unless plaintext FTS is explicitly opted in.
    _, fts_text = session_crypto.encrypt_message(
        session_id="s1",
        message_id="m1",
        content="Deploying to 生产环境 with secret token",
    )
    assert fts_text == ""

    # Legacy un-namespaced ciphertext must not bypass session binding.
    legacy_cipher = crypto.encrypt(
        "historical un-namespaced message content",
        table="messages",
        record_id="legacy-msg-99",
        column="content",
    )
    with pytest.raises(DecryptionVerificationError):
        session_crypto.decrypt_message(
            session_id="any-session-id",
            message_id="legacy-msg-99",
            payload_cipher=legacy_cipher,
        )

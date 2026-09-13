"""Tests for Hermes Agent-optimized storage adapters."""

import sqlite3

import pytest

from floorvault.core import DecryptionVerificationError, FloorVault
from floorvault.hermes import (
    HermesSessionCrypto,
    HermesVaultStore,
    normalize_otp_secret,
    scrub_secret_from_text,
    totp_now,
)


def test_hermes_vault_store_lifecycle(tmp_path):
    crypto = FloorVault(b"\x11" * 32, memory_mode="disabled")
    store = HermesVaultStore(tmp_path / "hermes_vault", crypto=crypto)

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

    # 3. Find by origin using HMAC blind index (0.18 ms lookup)
    matches = store.find_by_origin("https://github.com")
    assert len(matches) == 1
    assert matches[0].id == meta.id

    # Port normalization: https://github.com:443 must match https://github.com
    port_matches = store.find_by_origin("https://github.com:443")
    assert len(port_matches) == 1

    # 4. List all items
    all_items = store.list_items()
    assert len(all_items) == 1

    # 5. Delete item
    deleted = store.delete_item(meta.id)
    assert deleted is True
    assert len(store.list_items()) == 0


def test_hermes_vault_migrates_legacy_plaintext_metadata(tmp_path):
    db_dir = tmp_path / "legacy"
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
            (
                "vault_legacy",
                "login",
                "Legacy",
                "https://example.com",
                b"idx",
                "email",
                "u",
                0,
                "now",
                b"cipher",
            ),
        )

    store = HermesVaultStore(db_dir, crypto=FloorVault(b"\x25" * 32, memory_mode="disabled"))
    assert store.list_items()[0].label == "Legacy"
    with db_path.open("rb") as db_file:
        raw_db = db_file.read()
    assert b"Legacy" not in raw_db
    assert b"https://example.com" not in raw_db


def test_hermes_session_crypto_hybrid_split(tmp_path):
    crypto = FloorVault(b"\x22" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto, allow_plaintext_fts=True)

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


def test_hermes_session_crypto_tokenizes_fts_by_default():
    crypto = FloorVault(b"\x23" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto)

    _, fts_text = session_crypto.encrypt_message(
        session_id="sess-001",
        message_id="msg-001",
        content="private conversation and sk-1234567890123456789012345",
    )

    assert fts_text
    assert "private" not in fts_text


def test_hermes_session_crypto_uses_hmac_tokens_for_secure_fts():
    crypto = FloorVault(b"\x26" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto)

    _, search_text = session_crypto.encrypt_message(
        session_id="sess-001",
        message_id="msg-001",
        content="private conversation about a launch plan",
    )

    assert search_text
    assert "private" not in search_text
    query_tokens = session_crypto.secure_search_query("private launch").split()
    assert query_tokens
    assert all(token in search_text.split() for token in query_tokens)


def test_hermes_session_crypto_plaintext_fts_requires_explicit_opt_in():
    crypto = FloorVault(b"\x27" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto, allow_plaintext_fts=True)

    _, search_text = session_crypto.encrypt_message(
        session_id="sess-001", message_id="msg-001", content="private launch"
    )

    assert "private" in search_text


def test_hermes_session_crypto_binds_session_id():
    crypto = FloorVault(b"\x24" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto)
    cipher, _ = session_crypto.encrypt_message(
        session_id="sess-a", message_id="same-id", content="secret"
    )

    with pytest.raises(DecryptionVerificationError):
        session_crypto.decrypt_message(
            session_id="sess-b", message_id="same-id", payload_cipher=cipher
        )


def test_hermes_vault_native_api_compatibility(tmp_path):
    crypto = FloorVault(b"\x30" * 32, memory_mode="disabled")
    store = HermesVaultStore(tmp_path / "vault", crypto=crypto)

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


def test_hermes_vault_otp_and_totp_utilities():
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


def test_hermes_session_crypto_unicode_and_legacy_fallback():
    crypto = FloorVault(b"\x31" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto)

    # 1. Unicode/multilingual tokenization
    _, fts_text = session_crypto.encrypt_message(
        session_id="s1",
        message_id="m1",
        content="Deploying to 生产环境 with secret token",
    )
    query_tokens = session_crypto.secure_search_query("生产环境").split()
    assert query_tokens
    assert query_tokens[0] in fts_text.split()

    # 2. Legacy AAD decryption fallback (record_id=message_id without session_id prefix)
    legacy_cipher = crypto.encrypt(
        "historical un-namespaced message content",
        table="messages",
        record_id="legacy-msg-99",
        column="content",
    )
    decrypted = session_crypto.decrypt_message(
        session_id="any-session-id",
        message_id="legacy-msg-99",
        payload_cipher=legacy_cipher,
    )
    assert decrypted == "historical un-namespaced message content"

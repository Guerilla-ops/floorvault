"""Tests for Hermes Agent-optimized storage adapters."""

from floorvault.core import FloorVault
from floorvault.hermes import (
    HermesSessionCrypto,
    HermesVaultStore,
)


def test_hermes_vault_store_lifecycle(tmp_path):
    crypto = FloorVault(b"\x11" * 32, memory_mode="disabled")
    store = HermesVaultStore(tmp_path / "hermes_vault", crypto=crypto)

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


def test_hermes_session_crypto_hybrid_split(tmp_path):
    crypto = FloorVault(b"\x22" * 32, memory_mode="disabled")
    session_crypto = HermesSessionCrypto(crypto)

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

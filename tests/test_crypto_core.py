"""Tests for core AppStateCrypto engine, contextual AAD, and tamper resistance."""

import pytest

from appstate_crypto.core import (
    AppStateCrypto,
    DecryptionVerificationError,
)
from appstate_crypto.memory import HardenedMemoryKey


def test_appstate_crypto_round_trip():
    master_key = b"\x01" * 32
    crypto = AppStateCrypto(master_key, app_instance_id="inst-test-1", memory_mode="disabled")

    plaintext = "super-secret-api-token-12345"
    ciphertext = crypto.encrypt(
        plaintext,
        table="credentials",
        record_id="rec-001",
        column="token",
    )

    assert isinstance(ciphertext, bytes)
    assert ciphertext != plaintext.encode("utf-8")

    decrypted = crypto.decrypt(
        ciphertext,
        table="credentials",
        record_id="rec-001",
        column="token",
    )
    assert decrypted == plaintext


def test_contextual_splicing_attack_detection():
    """Verify that moving ciphertext across rows or columns fails decryption."""
    crypto = AppStateCrypto(b"\x02" * 32, app_instance_id="inst-test-1", memory_mode="disabled")

    secret_admin = "admin-confidential-password"
    cipher_admin = crypto.encrypt(
        secret_admin,
        table="credentials",
        record_id="admin-user",
        column="password",
    )

    # 1. Splicing across rows (trying to decrypt under normal-user)
    with pytest.raises(
        DecryptionVerificationError, match="Data was tampered with, spliced, or corrupted"
    ):
        crypto.decrypt(
            cipher_admin,
            table="credentials",
            record_id="normal-user",
            column="password",
        )

    # 2. Splicing across columns (trying to decrypt under token instead of password)
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(
            cipher_admin,
            table="credentials",
            record_id="admin-user",
            column="token",
        )

    # 3. Splicing across tables
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(
            cipher_admin,
            table="audit_logs",
            record_id="admin-user",
            column="password",
        )


def test_ephemeral_master_key_destruction():
    """Verify master key is wiped in memory within initialization."""
    master = HardenedMemoryKey(b"\x03" * 32, mode="disabled")
    crypto = AppStateCrypto(master, app_instance_id="inst-test-2", memory_mode="disabled")

    # Master key container must be wiped
    assert master.is_wiped is True
    with pytest.raises(RuntimeError, match="wiped"):
        master.get_bytes()

    # Derived engine is fully operational
    encrypted = crypto.encrypt("hello", table="t", record_id="r", column="c")
    assert crypto.decrypt(encrypted, table="t", record_id="r", column="c") == "hello"


def test_bounded_nonce_tracking():
    """Verify sliding window bounds memory without leak."""
    crypto = AppStateCrypto(b"\x04" * 32, maximum_tracked_nonces=20, memory_mode="disabled")

    # Generate 50 encrypted records
    for i in range(50):
        crypto.encrypt(f"msg-{i}", table="t", record_id=f"r-{i}", column="c")

    # Set and queue size must not exceed 20
    assert len(crypto._nonce_queue) == 20
    assert len(crypto._nonce_set) == 20


def test_engine_wipe_lifecycle():
    crypto = AppStateCrypto(b"\x05" * 32, memory_mode="disabled")
    ciphertext = crypto.encrypt("data", table="t", record_id="r", column="c")

    crypto.wipe()
    assert crypto._closed is True

    with pytest.raises(RuntimeError, match="wiped"):
        crypto.encrypt("data", table="t", record_id="r", column="c")

    with pytest.raises(RuntimeError, match="wiped"):
        crypto.decrypt(ciphertext, table="t", record_id="r", column="c")

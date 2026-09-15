"""Tests for core FloorVault engine, contextual AAD, and tamper resistance."""

import pytest

from floorvault.core import (
    DecryptionVerificationError,
    FloorVault,
)
from floorvault.memory import HardenedMemoryKey


def test_floorvault_round_trip():
    master_key = b"\x01" * 32
    crypto = FloorVault(master_key, app_instance_id="inst-test-1", memory_mode="disabled")

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
    crypto = FloorVault(b"\x02" * 32, app_instance_id="inst-test-1", memory_mode="disabled")

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
    crypto = FloorVault(master, app_instance_id="inst-test-2", memory_mode="disabled")

    # Master key container must be wiped
    assert master.is_wiped is True
    with pytest.raises(RuntimeError, match="wiped"):
        master.get_bytes()

    # Derived engine is fully operational
    encrypted = crypto.encrypt("hello", table="t", record_id="r", column="c")
    assert crypto.decrypt(encrypted, table="t", record_id="r", column="c") == "hello"


def test_bounded_nonce_tracking():
    """Verify sliding window bounds memory without leak."""
    crypto = FloorVault(b"\x04" * 32, maximum_tracked_nonces=20, memory_mode="disabled")

    # Generate 50 encrypted records
    for i in range(50):
        crypto.encrypt(f"msg-{i}", table="t", record_id=f"r-{i}", column="c")

    # Set and queue size must not exceed 20
    assert len(crypto._nonce_queue) == 20
    assert len(crypto._nonce_set) == 20


def test_binary_payload_round_trip():
    """encrypt() accepts bytes; decrypt_bytes() must return them unchanged."""
    crypto = FloorVault(b"\x08" * 32, memory_mode="disabled")
    payload = b"\xff\xfe\x00\x01binary\x80"
    ct = crypto.encrypt(payload, table="t", record_id="r", column="c")

    assert crypto.decrypt_bytes(ct, table="t", record_id="r", column="c") == payload

    # str path still works, and non-UTF-8 through the str API fails cleanly
    crypto.encrypt("plain text", table="t", record_id="r2", column="c")
    with pytest.raises(DecryptionVerificationError, match="not valid UTF-8"):
        crypto.decrypt(ct, table="t", record_id="r", column="c")


def test_engine_wipe_lifecycle():
    crypto = FloorVault(b"\x05" * 32, memory_mode="disabled")
    ciphertext = crypto.encrypt("data", table="t", record_id="r", column="c")

    crypto.wipe()
    assert crypto._closed is True

    with pytest.raises(RuntimeError, match="wiped"):
        crypto.encrypt("data", table="t", record_id="r", column="c")

    with pytest.raises(RuntimeError, match="wiped"):
        crypto.decrypt(ciphertext, table="t", record_id="r", column="c")


def test_failed_init_leaves_no_partial_instance():
    """A failed __init__ must not leave a half-built object whose __del__ raises.

    Regression: core.wipe() cleared _nonce_set before setting _closed, so
    garbage collecting a FloorVault that failed key validation raised
    AttributeError from __del__ and left the engine unclosed.
    """
    import gc

    for bad in (b"\x00" * 16, b"\x00" * 64, "not-bytes"):
        with pytest.raises((ValueError, TypeError)):
            FloorVault(bad, memory_mode="disabled")  # type: ignore[arg-type]
    gc.collect()


def test_maximum_tracked_nonces_must_be_positive():
    """max_nonces=0 used to raise IndexError on first encrypt (empty deque)."""
    with pytest.raises(ValueError, match="positive integer"):
        FloorVault(b"\x06" * 32, maximum_tracked_nonces=0, memory_mode="disabled")

    crypto = FloorVault(b"\x07" * 32, maximum_tracked_nonces=5, memory_mode="disabled")
    for i in range(20):
        crypto.encrypt(f"m{i}", table="t", record_id=f"r{i}", column="c")
    assert len(crypto._nonce_queue) == 5


def test_reencryption_is_not_deterministic():
    """SIV is deterministic *given its inputs*, so the nonce must be one of them.

    Raised during independent review as a plaintext-equality leak: if the AD
    vector were static, re-encrypting the same value at the same coordinates
    would produce identical ciphertext and an observer could tell when a stored
    value was rewritten. The engine generates a fresh 128-bit nonce per
    encryption and passes it as the final AD component, so this must hold.
    """
    crypto = FloorVault(b"\x08" * 32, app_instance_id="inst-nonrep", memory_mode="disabled")

    ciphertexts = [
        crypto.encrypt("identical-value", table="users", record_id="u-1", column="email")
        for _ in range(5)
    ]

    assert len(set(ciphertexts)) == 5, "identical plaintext re-encrypted to identical ciphertext"
    assert len({c[5:21] for c in ciphertexts}) == 5, "the envelope nonce repeats"
    for ciphertext in ciphertexts:
        assert (
            crypto.decrypt(ciphertext, table="users", record_id="u-1", column="email")
            == "identical-value"
        )

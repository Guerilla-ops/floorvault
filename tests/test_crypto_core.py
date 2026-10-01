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
    """Verify the source key is preserved unless wiping is explicitly requested."""
    master = HardenedMemoryKey(b"\x03" * 32, mode="disabled")
    crypto = FloorVault(
        master,
        app_instance_id="inst-test-2",
        memory_mode="disabled",
        wipe_source_key=True,
    )

    # Caller-owned key containers are preserved by default; this test opts in.
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


def test_concurrent_encryption_thread_safety():
    """FloorVault encrypt and decrypt must be thread-safe across concurrent threads."""
    import concurrent.futures

    crypto = FloorVault(b"\x09" * 32, memory_mode="disabled", maximum_tracked_nonces=500)
    num_threads = 16
    items_per_thread = 50

    def worker(thread_idx: int):
        results = []
        for i in range(items_per_thread):
            plaintext = f"thread-{thread_idx}-payload-{i}"
            ct = crypto.encrypt(
                plaintext,
                table="concurrent_test",
                record_id=f"rec-{thread_idx}-{i}",
                column="val",
            )
            recovered = crypto.decrypt(
                ct,
                table="concurrent_test",
                record_id=f"rec-{thread_idx}-{i}",
                column="val",
            )
            assert recovered == plaintext
            results.append(ct)
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        all_results = [f.result() for f in futures]

    total_encryptions = num_threads * items_per_thread
    all_ciphertexts = [ct for sublist in all_results for ct in sublist]
    assert len(all_ciphertexts) == total_encryptions
    # Verify nonces in queue match expected window size
    assert len(crypto._nonce_queue) == min(total_encryptions, 500)
    assert len(crypto._nonce_set) == min(total_encryptions, 500)


def test_wipe_after_nonce_tracking_does_not_tear_encrypt(monkeypatch):
    """A wipe() racing an in-flight encrypt() must not crash with AttributeError.

    Deterministic reproduction of the wipe/encrypt race: wipe() is invoked from
    inside _track_nonce, which runs *after* encrypt() has taken its engine
    reference. The pre-fix code dereferenced ``self._aead_siv`` at the engine
    call and crashed with ``AttributeError: 'NoneType' object has no attribute
    'encrypt'``; the fix snapshots the engine first, so the call completes.
    """
    crypto = FloorVault(b"\x0b" * 32, memory_mode="disabled")
    original_track = crypto._track_nonce

    def track_then_wipe(nonce):
        original_track(nonce)
        crypto.wipe()

    monkeypatch.setattr(crypto, "_track_nonce", track_then_wipe)
    ciphertext = crypto.encrypt("payload", table="t", record_id="r", column="c")
    # Completed without AttributeError: the engine snapshot kept the call alive.
    assert isinstance(ciphertext, bytes)
    # The wipe did land: a subsequent operation is correctly refused.
    with pytest.raises(RuntimeError, match="wiped"):
        crypto.encrypt("again", table="t", record_id="r2", column="c")


def test_concurrent_wipe_never_raises_attribute_error():
    """Stress the wipe/encrypt race: only RuntimeError('wiped') is acceptable."""
    import concurrent.futures
    import threading

    for _ in range(25):
        crypto = FloorVault(b"\x0c" * 32, memory_mode="disabled")
        barrier = threading.Barrier(2)

        def encrypt_worker():
            barrier.wait()
            for i in range(300):
                try:
                    ct = crypto.encrypt("payload", table="t", record_id=f"r{i}", column="c")
                    crypto.decrypt(ct, table="t", record_id=f"r{i}", column="c")
                except RuntimeError as exc:
                    assert "wiped" in str(exc)
                    return
                except AttributeError as exc:  # the defect under test
                    raise AssertionError(f"wipe() tore an in-flight operation: {exc}") from exc

        def wipe_worker():
            barrier.wait()
            crypto.wipe()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(encrypt_worker), executor.submit(wipe_worker)]
            for future in futures:
                future.result()

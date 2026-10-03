"""Tests for offline master-key recovery bundles."""

from __future__ import annotations

import pytest

from floorvault import (
    DecryptionVerificationError,
    HardenedMemoryKey,
    recover_master_key,
    wrap_master_key,
)

MASTER = bytes.fromhex("12" * 32)
RECOVERY = bytes.fromhex("34" * 32)


def test_recovery_bundle_round_trips_to_a_hardened_key():
    bundle = wrap_master_key(MASTER, RECOVERY)

    recovered = recover_master_key(bundle, RECOVERY, memory_mode="disabled")

    assert isinstance(recovered, HardenedMemoryKey)
    assert recovered.get_bytes() == MASTER
    recovered.wipe()


def test_recovery_bundle_rejects_the_wrong_recovery_key():
    bundle = wrap_master_key(MASTER, RECOVERY)

    with pytest.raises(DecryptionVerificationError):
        recover_master_key(bundle, bytes.fromhex("56" * 32), memory_mode="disabled")


def test_recovery_bundle_rejects_tampering_and_bad_key_lengths():
    bundle = wrap_master_key(MASTER, RECOVERY)
    tampered = bundle[:-1] + bytes([bundle[-1] ^ 1])

    with pytest.raises(DecryptionVerificationError):
        recover_master_key(tampered, RECOVERY, memory_mode="disabled")
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        wrap_master_key(b"short", RECOVERY)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        wrap_master_key(MASTER, b"short")


def test_wrap_refuses_to_wrap_a_key_with_itself():
    """A self-wrapped bundle is security theatre and must be refused.

    ``wrap_master_key`` documents that the recovery key "must be stored through an
    independently protected recovery process", but nothing enforced it: passing
    ``recovery_key == master_key`` produced a bundle that round-trips, so an
    attacker who recovered it holds the data key too. Recovery then appears to
    have been configured while providing no actual second factor.

    Compared with a constant-time comparison so the check cannot become a timing
    oracle on the key bytes.
    """
    from floorvault.key_recovery import wrap_master_key

    with pytest.raises(ValueError, match="recovery key must differ"):
        wrap_master_key(MASTER, MASTER)


def test_wrap_accepts_distinct_keys_that_happen_to_share_a_prefix():
    """The self-wrap guard must compare the whole key, not a prefix."""
    from floorvault.key_recovery import wrap_master_key

    recovery = b"\x12" * 31 + b"\x13"  # differs only in the final byte
    bundle = wrap_master_key(MASTER, recovery)
    assert bundle.startswith(b"FVRB1")

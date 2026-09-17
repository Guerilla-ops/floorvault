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

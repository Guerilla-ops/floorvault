"""Regression tests for the world-class blind-index BEACON redesign (Slice 2).

The original design returned the full 32-byte deterministic HMAC, which leaks
exact equality and frequency of every indexed value to anyone holding the DB —
the exact weakness the product docs claim to eliminate ("zero query privacy
leakage"). The fix adds a truncated HMAC beacon (AWS-beacon-style, configurable
bits) so the stored index is a bounded bucket assignment (equality/frequency
not exact), plus a verify path that re-derives on candidate rows to confirm.
"""

from __future__ import annotations

import pytest

from floorvault.blind_index import (
    BlindIndexer,
    beacon_bucket_bytes,
    beacon_matches,
    compute_beacon,
    suggest_beacon_bits,
)


def test_beacon_default_bits_is_bounded():
    key = b"\x10" * 32
    b1 = compute_beacon("scott@example.com", scope="users.email", key=key)
    b2 = compute_beacon("scott@example.com", scope="users.email", key=key)
    assert isinstance(b1, bytes)
    # Default 4 bits -> 1 byte (bucket byte), bounded, deterministic.
    assert len(b1) == beacon_bucket_bytes(bits=4) == 1
    assert b1 == b2  # deterministic for the same value


def test_bucket_bytes_bound():
    assert beacon_bucket_bytes(bits=4) == 1
    assert beacon_bucket_bytes(bits=8) == 1
    assert beacon_bucket_bytes(bits=16) == 2
    assert beacon_bucket_bytes(bits=32) == 4
    with pytest.raises(ValueError):
        beacon_bucket_bytes(bits=0)
    with pytest.raises(ValueError):
        beacon_bucket_bytes(bits=65)


def test_beacon_truncation_causes_collisions_so_frequency_is_not_exact():
    """A small beacon MUST produce collisions across a large enough sample, so
    an attacker with the DB cannot recover exact equality/frequency from the
    index alone (the original 32-byte leak). 4 bits round up to 1 bucket byte
    (8 bits of entropy, 256 buckets), so 500 distinct values MUST collide."""
    key = b"\x11" * 32
    values = [f"user-{i}@example.com" for i in range(500)]
    beacons = {compute_beacon(v, scope="users.email", key=key, bits=4) for v in values}
    # 500 values into at most 256 buckets => collisions are guaranteed, and the
    # index is definitely not a bijection (not injective) as full-width was.
    assert 0 < len(beacons) < len(values)


def test_full_bit_beacon_is_binding_for_low_volume():
    """At 32 bits the beacon is still truncated (4 bytes) but for a modest
    sample it is effectively collision-free — used for uniqueness when the
    caller can tolerate low false-positive rate within a bucket."""
    key = b"\x12" * 32
    values = [f"user-{i}@example.com" for i in range(100)]
    beacons = {compute_beacon(v, scope="users.email", key=key, bits=32) for v in values}
    assert len(beacons) == len(values)  # injective for this sample


def test_beacon_scope_domain_separation():
    key = b"\x10" * 32
    a = compute_beacon("x", scope="users.email", key=key, bits=32)
    b = compute_beacon("x", scope="contacts.email", key=key, bits=32)
    assert a != b


def test_beacon_matches_reconfirms_candidate():
    """beacon_matches(value, ...) is True iff value's beacon equals the stored
    beacon, letting a caller filter candidate rows then decrypt to confirm."""
    key = b"\x10" * 32
    value, scope = "alice@example.com", "users.email"
    beacon = compute_beacon(value, scope=scope, key=key, bits=8)
    assert beacon_matches(value, scope=scope, key=key, beacon=beacon, bits=8) is True
    assert beacon_matches("bob@example.com", scope=scope, key=key, beacon=beacon, bits=8) is False


def test_blind_indexer_beacon_round_trip():
    indexer = BlindIndexer(key=b"\x10" * 32)
    b = indexer.beacon("alice@example.com", scope="users.email", bits=8)
    assert len(b) == beacon_bucket_bytes(bits=8)
    assert indexer.verify_beacon("alice@example.com", scope="users.email", beacon=b, bits=8) is True
    assert indexer.verify_beacon("bob@example.com", scope="users.email", beacon=b, bits=8) is False


def test_suggest_beacon_bits_sizes_buckets_to_the_dataset():
    """The width recommendation answers "which bits for THIS dataset?".

    Buckets are byte-aligned, so the average occupancy of a width ``bits``
    over ``N`` rows is ``N / 256**ceil(bits/8)``. The recommendation is the
    smallest byte-aligned width whose average occupancy is at or below the
    requested target bucket size.
    """
    assert suggest_beacon_bits(1) == 8
    assert suggest_beacon_bits(100, target_bucket_size=8) == 8
    assert suggest_beacon_bits(100_000) == 16
    assert suggest_beacon_bits(100_000, target_bucket_size=16) == 16
    assert suggest_beacon_bits(10**12) == 40
    assert suggest_beacon_bits(10**30) == 64  # clamped to the supported maximum


def test_suggest_beacon_bits_is_byte_aligned_and_minimal():
    for rows, target in [
        (100, 8),
        (10_000, 8),
        (100_000, 8),
        (10**6, 16),
        (12345, 4),
        (500_000, 8),
    ]:
        bits = suggest_beacon_bits(rows, target_bucket_size=target)
        assert bits % 8 == 0, "recommendation must be byte-aligned"
        assert 8 <= bits <= 64
        bucket_bytes = bits // 8
        occupancy = rows / (256**bucket_bytes)
        assert occupancy <= target or bits == 64, "target occupancy not met"
        if bucket_bytes > 1:
            assert rows / (256 ** (bucket_bytes - 1)) > target, "width is not minimal"


def test_suggest_beacon_bits_rejects_invalid_input():
    for bad in (0, -1, 1.5, "100"):
        with pytest.raises((TypeError, ValueError)):
            suggest_beacon_bits(bad)
    for bad in (0, -8, 2.5):
        with pytest.raises((TypeError, ValueError)):
            suggest_beacon_bits(100, target_bucket_size=bad)


def test_suggest_beacon_bits_is_exported_from_the_package():
    import floorvault

    assert floorvault.suggest_beacon_bits is suggest_beacon_bits

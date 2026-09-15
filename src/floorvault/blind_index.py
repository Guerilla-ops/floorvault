"""Deterministic HMAC-SHA256 blind indexing for searchable database encryption.

Enables fast O(log N) exact-match equality lookups in standard SQLite B-Trees
without exposing plaintext search terms in memory, query caches, or logs.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Union

from .memory import HardenedMemoryKey


def _hmac(
    value: str,
    *,
    scope: str,
    key: Union[bytes, HardenedMemoryKey],
) -> bytes:
    """Domain-separated HMAC-SHA256 of ``value`` under ``scope`` (full 32B)."""
    if not isinstance(value, str):
        raise TypeError(f"Blind index value must be string, got {type(value).__name__}")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("Scope must be a non-empty string for domain separation")

    key_bytes = key.get_bytes() if isinstance(key, HardenedMemoryKey) else key
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) < 32:
        raise ValueError("Blind indexing key must be at least 32 bytes")

    # Domain separation: scope || 0x00 || value
    canonical_payload = f"{scope}\x00{value}".encode()
    return hmac.new(key_bytes, canonical_payload, hashlib.sha256).digest()


def compute_blind_index(
    value: str,
    *,
    scope: str,
    key: Union[bytes, HardenedMemoryKey],
    truncate_bytes: int = 32,
) -> bytes:
    """Compute a deterministic HMAC-SHA256 blind index for a string value.

    Args:
        value: Plaintext value to index (e.g. 'scott@example.com').
        scope: Domain separation string (e.g. 'users.email', 'vault.origin').
        key: Dedicated blind indexing key (32 bytes).
        truncate_bytes: Number of output bytes to retain (default: 32).

    Returns:
        Deterministic HMAC digest bytes suitable for storing in a UNIQUE or INDEX column.
    """
    full = _hmac(value, scope=scope, key=key)
    return full[:truncate_bytes]


# ---------------------------------------------------------------------------
# Truncated HMAC BEACON (AWS-DB-Encryption-SDK-style search index)
#
# The full-width blind index leaks exact equality + frequency of every indexed
# value to anyone holding the database. A "beacon" keeps only a bounded amount
# of the HMAC (default: one bucket byte = 256 buckets), so:
#   * an attacker cannot recover exact equality / frequency from the index, and
#   * the app still finds CANDIDATE rows in O(log N) via the bucket, then
#     decrypts the shortlisted candidates to confirm the exact match.
# This is the industry-standard design (AWS beacons, CipherSweet bloom filters)
# and it is what makes the "zero query privacy leakage" claim true.
# ---------------------------------------------------------------------------

_MIN_BEACON_BITS = 4
_MAX_BEACON_BITS = 64


def beacon_bucket_bytes(bits: int) -> int:
    """Bytes needed to hold ``bits`` of beacon entropy (1..8 bytes for 4..64)."""
    if not isinstance(bits, int) or not _MIN_BEACON_BITS <= bits <= _MAX_BEACON_BITS:
        raise ValueError(f"beacon bits must be in [{_MIN_BEACON_BITS}, {_MAX_BEACON_BITS}]")
    return (bits + 7) // 8


def compute_beacon(
    value: str,
    *,
    scope: str,
    key: Union[bytes, HardenedMemoryKey],
    bits: int = 4,
) -> bytes:
    """Return a truncated, bounded-behavior search beacon for ``value``.

    The beacon is a deterministic prefix of the value's keyed HMAC (domain
    separated by ``scope``), truncated to ``bits`` of requested width. Storage
    is byte-aligned (``ceil(bits / 8)`` bytes are kept), so two DISTINCT
    values collide within a bucket with a probability that reflects the
    effective width; the stored index reveals only a coarse bin, never the
    exact value or its true frequency. After a bucket lookup, use
    ``beacon_matches`` to discard candidates whose bucket disagrees, then
    confirm EXACT equality by decrypting the candidate and comparing its
    plaintext — a bucket hit is not by itself proof of equality.
    """
    bucket_size = beacon_bucket_bytes(bits)
    full = _hmac(value, scope=scope, key=key)
    return full[:bucket_size]


def beacon_matches(
    value: str,
    *,
    scope: str,
    key: Union[bytes, HardenedMemoryKey],
    beacon: bytes,
    bits: int = 4,
) -> bool:
    """True iff ``value``'s beacon (at ``bits``) equals the stored ``beacon``.

    Used to disambiguate the candidate set returned by a truncated-beacon
    bucket query: assert ``beacon_matches(value)`` for each row before
    attempting decryption, to avoid decrypting unrelated collisions. A True
    result means both values share the same bucket — collisions are by design —
    not that the values are equal; confirm equality by decrypting the
    candidate.
    """
    candidate = compute_beacon(value, scope=scope, key=key, bits=bits)
    return hmac.compare_digest(candidate, bytes(beacon))


def suggest_beacon_bits(expected_rows: int, target_bucket_size: int = 8) -> int:
    """Recommend a beacon width (``bits``) sized to a dataset.

    There is no universally safe width: the index must be coarse enough that
    an observer cannot recover exact equality or frequency, and fine enough
    that a search does not have to decrypt most of the table. Given
    ``expected_rows`` indexed values and a target average bucket occupancy of
    ``target_bucket_size``, returns the smallest byte-aligned width whose
    average occupancy is at or below the target.

    Buckets are byte-aligned (:func:`beacon_bucket_bytes`), so a width of
    ``bits`` stores ``ceil(bits / 8)`` bytes and the index holds
    ``256 ** ceil(bits / 8)`` buckets; the result is a multiple of 8 in
    [8, 64] (``bits=8`` is equivalent to every value in 4..8). At very large
    ``expected_rows`` the result clamps to 64 and the requested occupancy may
    not be reachable.
    """
    if isinstance(expected_rows, bool) or not isinstance(expected_rows, int):
        raise TypeError("expected_rows must be a positive integer")
    if expected_rows < 1:
        raise ValueError("expected_rows must be a positive integer")
    if isinstance(target_bucket_size, bool) or not isinstance(target_bucket_size, int):
        raise TypeError("target_bucket_size must be a positive integer")
    if target_bucket_size < 1:
        raise ValueError("target_bucket_size must be a positive integer")

    buckets_needed = -(-expected_rows // target_bucket_size)  # ceiling division
    bucket_bytes = 1
    capacity = 256
    while capacity < buckets_needed and bucket_bytes < _MAX_BEACON_BITS // 8:
        bucket_bytes += 1
        capacity *= 256
    return bucket_bytes * 8


class BlindIndexer:
    """Helper class bound to a persistent blind indexing subkey."""

    def __init__(self, key: Union[bytes, HardenedMemoryKey]) -> None:
        self._key = key

    def index(self, value: str, *, scope: str, truncate_bytes: int = 32) -> bytes:
        """Compute blind index using the bound subkey."""
        return compute_blind_index(
            value,
            scope=scope,
            key=self._key,
            truncate_bytes=truncate_bytes,
        )

    def beacon(self, value: str, *, scope: str, bits: int = 4) -> bytes:
        """Compute a truncated search beacon (bounded bucket assignment)."""
        return compute_beacon(value, scope=scope, key=self._key, bits=bits)

    def verify_beacon(self, value: str, *, scope: str, beacon: bytes, bits: int = 4) -> bool:
        """True iff ``value``'s beacon equals the stored ``beacon``."""
        return beacon_matches(value, scope=scope, key=self._key, beacon=beacon, bits=bits)

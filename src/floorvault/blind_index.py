"""Deterministic HMAC-SHA256 blind indexing for searchable database encryption.

Enables fast O(log N) exact-match equality lookups in standard SQLite B-Trees
without exposing plaintext search terms in memory, query caches, or logs.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Union

from .memory import HardenedMemoryKey


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
    if not isinstance(value, str):
        raise TypeError(f"Blind index value must be string, got {type(value).__name__}")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("Scope must be a non-empty string for domain separation")

    key_bytes = key.get_bytes() if isinstance(key, HardenedMemoryKey) else key
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) < 32:
        raise ValueError("Blind indexing key must be at least 32 bytes")

    # Domain separation: scope || 0x00 || value
    canonical_payload = f"{scope}\x00{value}".encode()
    digest = hmac.new(key_bytes, canonical_payload, hashlib.sha256).digest()

    return digest[:truncate_bytes]


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

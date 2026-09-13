"""Tests for universal hardware memory custody and page locking."""

import sys

import pytest

from floorvault.memory import HardenedMemoryKey


def test_hardened_memory_key_lifecycle():
    key_bytes = b"\x42" * 32
    locked = HardenedMemoryKey(key_bytes, mode="opportunistic")

    # Buffer holds the exact key material
    assert locked.get_bytes() == key_bytes
    assert bytes(locked.get_buffer()) == key_bytes

    if sys.platform in ("darwin", "linux"):
        # On developer macOS / Linux, mlock should succeed
        assert locked.is_locked is True

    # Wipe memory
    locked.wipe()
    assert locked.is_locked is False
    assert locked.is_wiped is True

    # Accessing after wipe must raise RuntimeError
    with pytest.raises(RuntimeError, match="wiped"):
        locked.get_bytes()

    with pytest.raises(RuntimeError, match="wiped"):
        locked.get_buffer()


def test_hardened_memory_key_context_manager():
    key_bytes = b"\x99" * 32
    with HardenedMemoryKey(key_bytes, mode="disabled") as key:
        assert key.get_bytes() == key_bytes
    assert key.is_wiped is True


def test_hardened_memory_key_validation():
    # Must be 32 or 64 bytes
    with pytest.raises(ValueError, match="exactly 32 or 64 bytes"):
        HardenedMemoryKey(b"too_short", mode="disabled")

    with pytest.raises(TypeError, match="must be bytes"):
        HardenedMemoryKey("not_bytes", mode="disabled")  # type: ignore


def test_hardened_memory_key_from_hex():
    hex_str = "a1b2c3d4" * 8
    key = HardenedMemoryKey.from_hex(hex_str, mode="disabled")
    assert len(key.get_bytes()) == 32
    assert key.get_bytes() == bytes.fromhex(hex_str)
    key.wipe()

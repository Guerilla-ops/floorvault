"""Tests for universal hardware memory custody and page locking."""

import gc
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


def test_key_buffer_is_page_aligned():
    """Linux madvise(2) requires a page-aligned address; an unaligned buffer
    can never receive MADV_DONTDUMP/MADV_DONTFORK."""
    import ctypes

    from floorvault.memory import PAGE_SIZE

    key = HardenedMemoryKey(b"\x77" * 32, mode="disabled")
    try:
        addr = ctypes.addressof(key._buffer)
        assert addr % PAGE_SIZE == 0, f"buffer not page-aligned: {addr % PAGE_SIZE}"
        assert key.get_bytes() == b"\x77" * 32
        assert bytes(key.get_buffer()) == b"\x77" * 32
        assert key.get_bytes() == bytes(key.get_buffer())
    finally:
        key.wipe()


def test_required_mode_uses_only_platform_available_advice():
    """required mode must not demand madvise advice the platform lacks.

    Darwin implements neither MADV_DONTDUMP nor MADV_DONTFORK, so required
    mode there means mlock + RLIMIT_CORE=0, not unavailable advice.
    """
    from floorvault.memory import MADV_DONTDUMP, MADV_DONTFORK

    if sys.platform == "darwin":
        assert MADV_DONTDUMP is None and MADV_DONTFORK is None
    key = HardenedMemoryKey(b"\x78" * 32, mode="required")
    try:
        assert key.is_locked is True
    finally:
        key.wipe()


def test_wipe_releases_mapping_and_is_repeatable():
    key = HardenedMemoryKey(b"\x79" * 32, mode="opportunistic")
    key.wipe()
    assert key.is_wiped is True
    assert key._buffer is None
    assert key._mmap_base is None
    # repeat wipe and GC must not raise
    key.wipe()
    del key
    gc.collect()

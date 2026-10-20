"""Tests for universal hardware memory custody and page locking."""

import gc
import sys
from types import SimpleNamespace

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


def test_retained_buffer_view_reads_zeroed_pages_after_wipe():
    """Regression: a retained get_buffer() view must not outlive the mapping.

    The view was previously taken over the non-owning ctypes ``from_address``
    alias, so wipe() closed the mmap underneath it and reading the retained
    view dereferenced released pages (SIGSEGV in a subprocess). The view is now
    taken over the owning mmap itself, so a stale view keeps the allocation
    alive and observes the zeroed pages wipe() wrote.
    """
    key = HardenedMemoryKey(b"\x43" * 32, mode="disabled")
    view = key.get_buffer()
    assert bytes(view) == b"\x43" * 32

    key.wipe()
    assert key.is_wiped is True

    # Safe to touch: the view kept the mapping alive, and wipe zeroed it.
    assert bytes(view) == b"\x00" * 32
    view.release()
    del key
    gc.collect()


def test_required_mode_fails_closed_without_a_lock_backend(monkeypatch):
    """mode='required' must not silently run on an unsupported platform."""
    import floorvault.memory as mem

    monkeypatch.setattr(mem, "is_macos", lambda: False)
    monkeypatch.setattr(mem, "is_linux", lambda: False)
    monkeypatch.setattr(mem, "is_windows", lambda: False)

    with pytest.raises(mem.SecurityHardeningError, match="locking backend"):
        mem.HardenedMemoryKey(b"\x80" * 32, mode="required")

    # Opportunistic still constructs on the same platform - it never promised.
    key = mem.HardenedMemoryKey(b"\x80" * 32, mode="opportunistic")
    assert key.is_locked is False
    key.wipe()


def test_required_mode_refuses_a_plain_heap_fallback(monkeypatch):
    """mode='required' must not silently accept the non-mmap heap fallback.

    Forcing ``mmap.mmap`` to fail used to drop the key onto a plain ctypes
    heap buffer; on Darwin - which implements neither MADV_DONTDUMP nor
    MADV_DONTFORK - the only remaining required-mode check is mlock, which
    succeeds even on an unaligned heap allocation. The object then reported
    ``is_locked=True`` with no dump or fork exclusion behind it. Required
    mode means the page-aligned protected allocation exists; when it cannot
    be established, construction must refuse.
    """
    import floorvault.memory as mem

    def no_mmap(*_args, **_kwargs):
        raise OSError("mmap unavailable")

    monkeypatch.setattr(mem.mmap, "mmap", no_mmap)

    with pytest.raises(mem.SecurityHardeningError, match="protected allocation"):
        mem.HardenedMemoryKey(b"\x82" * 32, mode="required")

    # Opportunistic keeps the documented heap fallback.
    key = mem.HardenedMemoryKey(b"\x82" * 32, mode="opportunistic")
    try:
        assert key._mmap_base is None
        assert key.get_bytes() == b"\x82" * 32
    finally:
        key.wipe()


def test_constructor_consumes_mutable_input():
    """A caller-supplied bytearray is zeroed once the key is copied in.

    The constructor's bytes() coercion used to leave the caller's mutable
    buffer holding the key material after the object was built - an unwiped
    ghost the object's own wipe() can never reach.
    """
    source = bytearray(b"\xab" * 32)
    key = HardenedMemoryKey(source, mode="disabled")
    try:
        assert bytes(source) == b"\x00" * 32
        assert key.get_bytes() == b"\xab" * 32
    finally:
        key.wipe()


def test_wipe_runs_after_module_globals_are_torn_down(monkeypatch):
    """wipe() must still zero the buffer when module globals are gone.

    At interpreter teardown, ``__del__`` ran ``wipe()`` against module
    globals already cleared to None, so ``ctypes.memset`` raised
    AttributeError and the buffer survived unwiped. The teardown path binds
    everything it needs at construction.
    """
    import floorvault.memory as mem

    key = HardenedMemoryKey(b"\x83" * 32, mode="disabled")
    view = key.get_buffer()
    monkeypatch.setattr(mem, "ctypes", None)
    monkeypatch.setattr(mem, "is_macos", None)
    monkeypatch.setattr(mem, "is_linux", None)
    monkeypatch.setattr(mem, "is_windows", None)

    key.wipe()
    assert key.is_wiped is True
    assert bytes(view) == b"\x00" * 32
    view.release()


def test_required_mode_fails_when_core_dumps_cannot_be_disabled(monkeypatch):
    """A failed setrlimit must not masquerade as protection under 'required'.

    Simulate the POSIX resource API so this failure path is exercised on every
    platform, including Windows where Python does not provide ``resource``.
    """
    import floorvault.memory as mem

    monkeypatch.setattr(mem, "is_macos", lambda: True)
    monkeypatch.setattr(mem, "is_linux", lambda: False)
    monkeypatch.setattr(mem, "is_windows", lambda: False)

    def fail_setrlimit(*_args):
        raise OSError("denied")

    monkeypatch.setattr(
        mem,
        "resource",
        SimpleNamespace(RLIMIT_CORE=0, setrlimit=fail_setrlimit),
    )

    with pytest.raises(mem.SecurityHardeningError, match="RLIMIT_CORE"):
        mem.HardenedMemoryKey(b"\x81" * 32, mode="required")

    # Opportunistic reports the failure instead of refusing to run.
    key = mem.HardenedMemoryKey(b"\x81" * 32, mode="opportunistic")
    assert key._core_dumps_disabled is False
    key.wipe()

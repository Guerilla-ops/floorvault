"""Tests for universal hardware memory custody and page locking."""

import ctypes
import gc
import os
import sys
from types import SimpleNamespace

import pytest

from floorvault.memory import HardenedMemoryKey
from floorvault.platform_support import is_linux


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


# ---------------------------------------------------------------------------
# fork()
#
# The buffer was a shared anonymous mapping, so it was the same page in every
# forked child. A child that merely exited ran __del__ -> wipe() and zeroed the
# parent's key under a handle that still reported it live; where the page was
# excluded from children instead, the same wipe() touched an unmapped address
# and the child died with SIGSEGV at exit.
# ---------------------------------------------------------------------------

_needs_fork = pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork() on this platform")


def _in_child(action) -> tuple[int, bytes]:
    """Run ``action`` in a forked child; return (wait status, what it wrote).

    The child leaves with ``os._exit`` so it does not run this test session's
    own teardown; a test that means "the child exits" calls the finalizer the
    interpreter would run.
    """
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            os.write(write_end, action())
        except BaseException as exc:  # noqa: BLE001 - reported to the parent
            os.write(write_end, f"raised {type(exc).__name__}".encode())
        os.close(write_end)
        os._exit(0)
    os.close(write_end)
    with os.fdopen(read_end, "rb") as pipe:
        output = pipe.read()
    return os.waitpid(pid, 0)[1], output


@_needs_fork
@pytest.mark.parametrize("mode", ["disabled", "opportunistic"])
def test_a_forked_child_that_exits_leaves_the_parents_key_alone(mode):
    key = HardenedMemoryKey(b"\x11" * 32, mode=mode)

    def exit_like_the_interpreter():
        key.__del__()  # what a normal exit runs on every live handle
        return b"done"

    status, output = _in_child(exit_like_the_interpreter)
    assert output == b"done"
    assert status == 0, f"the child did not exit cleanly (wait status {status})"
    assert not key.is_wiped
    assert bytes(key.get_buffer()) == b"\x11" * 32


@_needs_fork
@pytest.mark.parametrize("mode", ["disabled", "opportunistic"])
def test_a_wipe_in_a_forked_child_does_not_reach_the_parent(mode):
    key = HardenedMemoryKey(b"\x22" * 32, mode=mode)

    def wipe_there():
        key.wipe()
        return b"wiped" if key.is_wiped else b"still live"

    status, output = _in_child(wipe_there)
    assert (status, output) == (0, b"wiped")
    assert not key.is_wiped
    assert bytes(key.get_buffer()) == b"\x22" * 32


@_needs_fork
def test_a_child_the_page_is_excluded_from_is_refused_not_killed():
    key = HardenedMemoryKey(b"\x33" * 32)
    if not key._fork_excluded:
        pytest.skip("MADV_DONTFORK is not available here; the child inherits a copy")
    status, output = _in_child(lambda: bytes(key.get_buffer()))
    assert status == 0, f"reading in the child killed it (wait status {status})"
    assert output == b"raised RuntimeError"
    status, output = _in_child(key.get_bytes)
    assert (status, output) == (0, b"raised RuntimeError")


@pytest.mark.skipif(not is_linux(), reason="MADV_DONTDUMP/DONTFORK are Linux advice")
def test_dump_and_fork_exclusion_do_not_depend_on_the_page_lock(monkeypatch):
    """RLIMIT_MEMLOCK can refuse the lock; the page must still be excluded."""
    real = ctypes.CDLL

    class NoLock:
        def __init__(self, name):
            self._libc = real(name)

        def mlock(self, *args):
            return -1

        def __getattr__(self, name):
            return getattr(self._libc, name)

    monkeypatch.setattr(ctypes, "CDLL", NoLock)
    key = HardenedMemoryKey(b"\x44" * 32)
    assert not key.is_locked
    assert key._dump_excluded and key._fork_excluded


def test_a_handle_whose_page_is_absent_refuses_reads_and_wipes_without_touching_it():
    """The fork-excluded child, on any platform: the page must never be dereferenced."""
    key = HardenedMemoryKey(b"\x55" * 32, mode="disabled")
    touched = []
    real_memset = key._teardown_memset
    key._teardown_memset = lambda *args: touched.append(args) or real_memset(*args)
    # What a forked child of a fork-excluding platform sees: same handle, another pid.
    key._fork_excluded = True
    key._teardown_getpid = lambda: key._owner_pid + 1
    with pytest.raises(RuntimeError, match="excluded from child processes"):
        key.get_buffer()
    with pytest.raises(RuntimeError, match="excluded from child processes"):
        key.get_bytes()
    mapping = key._mapping
    key.wipe()
    assert key.is_wiped and touched == []
    # The owner's page was left as it was (this test is both processes).
    if mapping is not None:
        assert bytes(mapping[:32]) == b"\x55" * 32
        mapping.close()

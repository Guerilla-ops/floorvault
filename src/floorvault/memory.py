"""Universal hardware memory custody and page locking primitives.

Supports macOS (Darwin), Linux (glibc/musl), and Windows (Win32), with
proactive container capability probing and deterministic zeroization.
"""

from __future__ import annotations

import ctypes
import mmap
from typing import Any

from .platform_support import is_linux, is_macos, is_windows

try:
    import resource
except ImportError:
    resource = None

# POSIX madvise constants. Values are from Linux
# include/uapi/asm-generic/mman-common.h; MADV_KEEPONFORK is 19 and is NOT
# MADV_DONTFORK. Darwin does not implement either advice, so both stay None
# there and the capability is reported as unavailable rather than attempted.
MADV_DONTDUMP = 16 if is_linux() else None
MADV_DONTFORK = 10 if is_linux() else None

# Page size used to align the key allocation. Linux madvise(2) requires the
# address to be page-aligned and returns EINVAL otherwise, so an unaligned
# buffer can never receive either protection.
PAGE_SIZE = 4096


class SecurityHardeningError(RuntimeError):
    """Raised when critical memory protections fail under strict enforcement."""

    code = "memory_hardening_failed"


def disable_core_dumps() -> bool:
    """Globally prevent the OS kernel from flushing process RAM to disk on crash.

    PROCESS-WIDE AND PERMANENT: this sets ``RLIMIT_CORE`` to ``(0, 0)`` for the
    whole process and is never restored. ``HardenedMemoryKey.__init__`` calls it,
    so merely constructing a key handle (or a ``FloorVault``) silently disables
    the host application's own core dumps from that point on. Deliberate - a core
    dump of a process holding a master key writes that key to disk - but it is a
    side effect of using the library, not something the caller opts into
    per object. See SECURITY.md section 6.

    Returns ``True`` only when the limit was actually applied, so callers that
    require it (``mode="required"``, the status probe) distinguish "the platform
    does not have RLIMIT_CORE" from "setting it failed" instead of inferring
    success from the platform name.
    """
    if resource is None or not (is_macos() or is_linux()):
        return False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        return False
    return True


class HardenedMemoryKey:
    """Holds sensitive cryptographic key material in physical RAM with
    anti-swapping, anti-dumping, and deterministic zeroization *of the buffer
    this object manages*.

    Scope, stated plainly: ``wipe()`` zeroes and releases the mapped buffer.
    It cannot reach copies made by third-party crypto libraries from the
    material (e.g. the key inside an AEAD engine object) or heap-resident
    ``bytes`` intermediates produced by ``get_bytes()``. A caller-supplied
    ``bytearray`` is *consumed* - zeroed in place once the key material is
    copied into the managed buffer - so passing mutable input does not leave
    a live ghost the caller must wipe by hand. Callers needing the strongest
    hygiene should consume via :meth:`get_buffer` where the consumer accepts
    buffer objects.

    ``mode="required"`` fails closed: if the page-aligned protected
    allocation (or any control it demands) cannot be established, the
    constructor raises :class:`SecurityHardeningError` rather than silently
    holding the key on a plain heap buffer.
    """

    def __init__(
        self,
        key_bytes: bytes,
        *,
        mode: str = "opportunistic",
    ) -> None:
        self._closed = True
        self._locked = False
        self._dump_excluded = False
        self._fork_excluded = False
        self._buffer: Any = None
        self._size = 0
        self._mode = mode
        self._core_dumps_disabled = False
        # Bound at construction: wipe() must still work when __del__ runs after
        # interpreter teardown has cleared this module's globals to None.
        self._teardown_memset = ctypes.memset
        self._teardown_cdll = ctypes.CDLL
        self._teardown_windll = getattr(ctypes, "windll", None)
        self._teardown_c_size_t = ctypes.c_size_t
        self._teardown_is_macos = is_macos()
        self._teardown_is_linux = is_linux()
        self._teardown_is_windows = is_windows()

        if mode not in {"disabled", "opportunistic", "required"}:
            raise ValueError("mode must be one of 'disabled', 'opportunistic', or 'required'")

        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("Key material must be bytes or bytearray")
        if len(key_bytes) not in (32, 64):
            raise ValueError(f"Key must be exactly 32 or 64 bytes (got {len(key_bytes)})")

        self._core_dumps_disabled = disable_core_dumps()
        if mode == "required" and (is_macos() or is_linux()) and not self._core_dumps_disabled:
            raise SecurityHardeningError(
                "RLIMIT_CORE could not be set to 0; refusing to hold a master key "
                "in a process whose crash would write it to a core dump"
            )

        self._size = len(key_bytes)
        # Allocate a page-aligned unmanaged buffer outside Python's interning
        # allocator. Linux madvise(2) requires a page-aligned address and fails
        # with EINVAL otherwise, so a malloc-aligned buffer (ctypes default,
        # 16-byte alignment) can never receive dump/fork protection.
        # mmap.mmap gives a page-aligned region, so mlock/madvise act on it.
        self._alloc_size = PAGE_SIZE
        self._mmap_base: Any = None
        self._mapping: Any = None
        # memmove accepts a bytes object or a raw address; a bytearray needs
        # its buffer address so the copy happens without a bytes() ghost.
        source_addr = (
            ctypes.addressof(ctypes.c_char.from_buffer(key_bytes))
            if isinstance(key_bytes, bytearray)
            else key_bytes
        )
        try:
            self._mapping = mmap.mmap(-1, self._alloc_size)
            self._mmap_base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
            self._buffer = (ctypes.c_char * self._alloc_size).from_address(self._mmap_base)
            ctypes.memmove(self._buffer, source_addr, self._size)
        except Exception as exc:
            self._mmap_base = None
            self._mapping = None
            if mode == "required":
                # The heap fallback offers no dump/fork exclusion and only a
                # best-effort unaligned lock - required mode promised more.
                raise SecurityHardeningError(
                    "required mode: the page-aligned protected allocation could "
                    "not be established; refusing to hold the key on a plain "
                    "heap buffer"
                ) from exc
            self._buffer = ctypes.create_string_buffer(self._size)
            ctypes.memmove(self._buffer, source_addr, self._size)
        # Mutable caller input is consumed: the caller's buffer would otherwise
        # keep a live copy of the key that wipe() can never reach.
        if isinstance(key_bytes, bytearray):
            key_bytes[:] = b"\x00" * len(key_bytes)
        self._alloc_size = self._size if self._mmap_base is None else PAGE_SIZE
        self._locked_size = self._size if self._mmap_base is None else PAGE_SIZE
        self._closed = False

        if mode != "disabled":
            self._lock_pages()

    def _lock_pages(self) -> None:
        # 1. POSIX: macOS and Linux
        if is_macos() or is_linux():
            try:
                libc = ctypes.CDLL(None)
                # int mlock(const void *addr, size_t len);
                # Lock the whole page-aligned region; mlock rounds addr down,
                # and locking only the mapped page keeps the range consistent.
                res = libc.mlock(self._buffer, ctypes.c_size_t(self._locked_size))
                if res == 0:
                    self._locked = True
                    # Shield from core dumps (Linux only; EINVAL on Darwin)
                    if MADV_DONTDUMP is not None:
                        try:
                            self._dump_excluded = (
                                libc.madvise(
                                    self._buffer,
                                    ctypes.c_size_t(self._locked_size),
                                    MADV_DONTDUMP,
                                )
                                == 0
                            )
                        except Exception:  # madvise hardening is best-effort  # nosec B110
                            pass
                    # Shield from child process fork copies
                    if MADV_DONTFORK is not None:
                        try:
                            self._fork_excluded = (
                                libc.madvise(
                                    self._buffer,
                                    ctypes.c_size_t(self._locked_size),
                                    MADV_DONTFORK,
                                )
                                == 0
                            )
                        except Exception:  # madvise hardening is best-effort  # nosec B110
                            pass
                elif self._mode == "required":
                    raise SecurityHardeningError(
                        "mlock() failed: insufficient privileges or RLIMIT_MEMLOCK exceeded. "
                        "Refusing to operate with unpinned master key in production."
                    )
                # Required mode only demands advice the platform actually
                # implements. Darwin has neither MADV_DONTDUMP nor MADV_DONTFORK
                # (src/floorvault/memory.py:19-20), so requiring them there
                # could never succeed; page locking plus RLIMIT_CORE=0 is the
                # real Darwin guarantee.
                if self._mode == "required" and is_linux():
                    if not (self._dump_excluded and self._fork_excluded):
                        raise SecurityHardeningError(
                            "Required Linux dump/fork memory protections are unavailable"
                        )
            except SecurityHardeningError:
                raise
            except Exception as exc:
                if self._mode == "required":
                    raise SecurityHardeningError(f"Kernel memory locking error: {exc}") from exc

        # 2. Windows 10 / 11 / Server
        elif is_windows():
            try:
                kernel32 = ctypes.windll.kernel32
                # BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
                res = kernel32.VirtualLock(self._buffer, ctypes.c_size_t(self._locked_size))
                if res != 0:
                    self._locked = True
                elif self._mode == "required":
                    raise SecurityHardeningError("VirtualLock() failed on Windows")
            except SecurityHardeningError:
                raise
            except Exception as exc:
                if self._mode == "required":
                    raise SecurityHardeningError(f"VirtualLock error: {exc}") from exc

        # 3. No supported locking backend on this platform
        elif self._mode == "required":
            raise SecurityHardeningError(
                "No supported memory-locking backend on this platform; refusing "
                "to operate with an unpinned master key in production"
            )

    @property
    def is_locked(self) -> bool:
        """Whether the memory buffer is actively pinned in physical RAM."""
        return self._locked

    @property
    def is_wiped(self) -> bool:
        """Whether the key buffer has been zeroed and closed."""
        return self._closed

    def get_buffer(self) -> memoryview:
        """Return a zero-copy memoryview directly to the unmanaged buffer.

        Avoids creating transient immutable Python bytes objects on the heap.

        The view is taken over the object that OWNS the memory - the mmap, or
        on the malloc fallback path the ctypes array itself - never over the
        non-owning ``from_address`` alias in ``self._buffer``. A caller that
        retains the view past ``wipe()`` therefore keeps the underlying
        allocation alive and observes zeroed pages, instead of dereferencing a
        released mapping (which crashed the interpreter). ``wipe()``'s close of
        a mapping with outstanding views raises BufferError and is skipped; the
        zeroed mapping is released only when the last view is.
        """
        if self._closed:
            raise RuntimeError("Attempted to access wiped HardenedMemoryKey")
        if self._mapping is not None:
            return memoryview(self._mapping)[: self._size]
        return memoryview(self._buffer)[: self._size]

    def get_bytes(self) -> bytes:
        """Return raw bytes view. Use sparingly to avoid heap ghost copies."""
        if self._closed:
            raise RuntimeError("Attempted to access wiped HardenedMemoryKey")
        return bytes(memoryview(self._buffer)[: self._size])

    def wipe(self) -> None:
        """Securely zero memory buffer, unlock physical RAM pages, release mapping."""
        if self._closed:
            return

        # Mark closed first so a partial failure cannot leave the key readable.
        self._closed = True

        # Everything below reaches only construction-bound attributes: module
        # globals (``ctypes``, the platform probes) may already be None when a
        # ``__del__`` runs during interpreter shutdown - and a memset that
        # raises leaves the key material in place.
        memset = self._teardown_memset
        c_size_t = self._teardown_c_size_t

        # 1. Overwrite the whole mapped region with zeroes
        memset(self._buffer, 0, self._alloc_size)

        # 2. Unlock memory pages
        if self._locked:
            if self._teardown_is_macos or self._teardown_is_linux:
                try:
                    libc = self._teardown_cdll(None)
                    libc.munlock(self._buffer, c_size_t(self._locked_size))
                except Exception:  # best-effort unlock  # nosec B110
                    pass
            elif self._teardown_is_windows:
                try:
                    kernel32 = self._teardown_windll.kernel32
                    kernel32.VirtualUnlock(self._buffer, c_size_t(self._locked_size))
                except Exception:  # best-effort unlock  # nosec B110
                    pass
            self._locked = False

        # 3. Release the page-aligned mapping (no key material remains in it)
        self._buffer = None
        if self._mapping is not None:
            try:
                self._mapping.close()
            except Exception:  # mapping holds no key material by this point  # nosec B110
                pass
            self._mapping = None
        self._mmap_base = None

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:  # interpreter teardown must never raise  # nosec B110
            pass

    def __enter__(self) -> HardenedMemoryKey:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()

    @classmethod
    def from_hex(cls, hex_str: str, *, mode: str = "opportunistic") -> HardenedMemoryKey:
        """Construct from hexadecimal string.

        Note: the caller's string object cannot be zeroed from here; drop the
        reference in the calling scope if the hex form is sensitive.
        """
        key_bytes = bytes.fromhex(hex_str.strip())
        return cls(key_bytes, mode=mode)

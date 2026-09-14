"""Universal hardware memory custody and page locking primitives.

Supports macOS (Darwin), Linux (glibc/musl), and Windows (Win32), with
proactive container capability probing and deterministic zeroization.
"""

from __future__ import annotations

import ctypes
import mmap
import sys
from typing import Any

try:
    import resource
except ImportError:
    resource = None

# POSIX madvise constants. Values are from Linux
# include/uapi/asm-generic/mman-common.h; MADV_KEEPONFORK is 19 and is NOT
# MADV_DONTFORK. Darwin does not implement either advice, so both stay None
# there and the capability is reported as unavailable rather than attempted.
MADV_DONTDUMP = 16 if sys.platform == "linux" else None
MADV_DONTFORK = 10 if sys.platform == "linux" else None

# Page size used to align the key allocation. Linux madvise(2) requires the
# address to be page-aligned and returns EINVAL otherwise, so an unaligned
# buffer can never receive either protection.
PAGE_SIZE = 4096


class SecurityHardeningError(RuntimeError):
    """Raised when critical memory protections fail under strict enforcement."""

    code = "memory_hardening_failed"


def disable_core_dumps() -> None:
    """Globally prevent the OS kernel from flushing process RAM to disk on crash."""
    if resource is not None and sys.platform in ("darwin", "linux"):
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass


class HardenedMemoryKey:
    """Holds sensitive cryptographic key material in physical RAM with
    anti-swapping, anti-dumping, and deterministic zeroization guarantees.
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

        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("Key material must be bytes or bytearray")
        if len(key_bytes) not in (32, 64):
            raise ValueError(f"Key must be exactly 32 or 64 bytes (got {len(key_bytes)})")

        disable_core_dumps()

        self._size = len(key_bytes)
        # Allocate a page-aligned unmanaged buffer outside Python's interning
        # allocator. Linux madvise(2) requires a page-aligned address and fails
        # with EINVAL otherwise, so a malloc-aligned buffer (ctypes default,
        # 16-byte alignment) can never receive dump/fork protection.
        # mmap.mmap gives a page-aligned region, so mlock/madvise act on it.
        self._alloc_size = PAGE_SIZE
        self._mmap_base: Any = None
        self._mapping: Any = None
        try:
            self._mapping = mmap.mmap(-1, self._alloc_size)
            self._mmap_base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
            self._buffer = (ctypes.c_char * self._alloc_size).from_address(self._mmap_base)
            ctypes.memmove(self._buffer, bytes(key_bytes), self._size)
        except Exception:
            self._mmap_base = None
            self._mapping = None
            self._buffer = ctypes.create_string_buffer(bytes(key_bytes), self._size)
        self._alloc_size = self._size if self._mmap_base is None else PAGE_SIZE
        self._locked_size = self._size if self._mmap_base is None else PAGE_SIZE
        self._closed = False

        if mode != "disabled":
            self._lock_pages()

    def _lock_pages(self) -> None:
        # 1. POSIX: macOS and Linux
        if sys.platform in ("darwin", "linux"):
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
                        except Exception:
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
                        except Exception:
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
                if self._mode == "required" and sys.platform == "linux":
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
        elif sys.platform == "win32":
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
        """
        if self._closed:
            raise RuntimeError("Attempted to access wiped HardenedMemoryKey")
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

        # 1. Overwrite the whole mapped region with zeroes
        ctypes.memset(self._buffer, 0, self._alloc_size)

        # 2. Unlock memory pages
        if self._locked:
            if sys.platform in ("darwin", "linux"):
                try:
                    libc = ctypes.CDLL(None)
                    libc.munlock(self._buffer, ctypes.c_size_t(self._locked_size))
                except Exception:
                    pass
            elif sys.platform == "win32":
                try:
                    kernel32 = ctypes.windll.kernel32
                    kernel32.VirtualUnlock(self._buffer, ctypes.c_size_t(self._locked_size))
                except Exception:
                    pass
            self._locked = False

        # 3. Release the page-aligned mapping (no key material remains in it)
        self._buffer = None
        if self._mapping is not None:
            try:
                self._mapping.close()
            except Exception:
                pass
            self._mapping = None
        self._mmap_base = None

    def __del__(self) -> None:
        self.wipe()

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

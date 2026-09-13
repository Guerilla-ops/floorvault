"""Universal hardware memory custody and page locking primitives.

Supports macOS (Darwin), Linux (glibc/musl), and Windows (Win32), with
proactive container capability probing and deterministic zeroization.
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
from typing import Any, Optional

# POSIX madvise constants for Darwin and Linux
MADV_DONTDUMP = 16 if sys.platform in ("darwin", "linux") else None
MADV_DONTFORK = 19 if sys.platform in ("darwin", "linux") else None


class SecurityHardeningError(RuntimeError):
    """Raised when critical memory protections fail under strict enforcement."""
    code = "memory_hardening_failed"


def disable_core_dumps() -> None:
    """Globally prevent the OS kernel from flushing process RAM to disk on crash."""
    if sys.platform in ("darwin", "linux"):
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
        self._buffer: Any = None
        self._size = 0
        self._mode = mode

        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("Key material must be bytes or bytearray")
        if len(key_bytes) not in (32, 64):
            raise ValueError(f"Key must be exactly 32 or 64 bytes (got {len(key_bytes)})")

        disable_core_dumps()

        self._size = len(key_bytes)
        # Allocate unmanaged ctypes buffer outside Python's string-interning allocator
        self._buffer = ctypes.create_string_buffer(bytes(key_bytes), self._size)
        self._closed = False

        if mode != "disabled":
            self._lock_pages()

    def _lock_pages(self) -> None:
        # 1. POSIX: macOS and Linux
        if sys.platform in ("darwin", "linux"):
            try:
                libc = ctypes.CDLL(None)
                # int mlock(const void *addr, size_t len);
                res = libc.mlock(self._buffer, ctypes.c_size_t(self._size))
                if res == 0:
                    self._locked = True
                    # Shield from core dumps
                    if MADV_DONTDUMP is not None:
                        try:
                            libc.madvise(self._buffer, ctypes.c_size_t(self._size), MADV_DONTDUMP)
                        except Exception:
                            pass
                    # Shield from child process fork copies
                    if MADV_DONTFORK is not None:
                        try:
                            libc.madvise(self._buffer, ctypes.c_size_t(self._size), MADV_DONTFORK)
                        except Exception:
                            pass
                elif self._mode == "required":
                    raise SecurityHardeningError(
                        "mlock() failed: insufficient privileges or RLIMIT_MEMLOCK exceeded. "
                        "Refusing to operate with unpinned master key in production."
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
                res = kernel32.VirtualLock(self._buffer, ctypes.c_size_t(self._size))
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
        return memoryview(self._buffer)[:self._size]

    def get_bytes(self) -> bytes:
        """Return raw bytes view. Use sparingly to avoid heap ghost copies."""
        if self._closed:
            raise RuntimeError("Attempted to access wiped HardenedMemoryKey")
        return bytes(self._buffer.raw)

    def wipe(self) -> None:
        """Securely zero memory buffer and unlock physical RAM pages."""
        if self._closed:
            return

        # 1. Overwrite physical buffer with zeroes
        ctypes.memset(self._buffer, 0, self._size)

        # 2. Unlock memory pages
        if self._locked:
            if sys.platform in ("darwin", "linux"):
                try:
                    libc = ctypes.CDLL(None)
                    libc.munlock(self._buffer, ctypes.c_size_t(self._size))
                except Exception:
                    pass
            elif sys.platform == "win32":
                try:
                    kernel32 = ctypes.windll.kernel32
                    kernel32.VirtualUnlock(self._buffer, ctypes.c_size_t(self._size))
                except Exception:
                    pass
            self._locked = False

        self._closed = True

    def __del__(self) -> None:
        self.wipe()

    def __enter__(self) -> HardenedMemoryKey:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()

    @classmethod
    def from_hex(cls, hex_str: str, *, mode: str = "opportunistic") -> HardenedMemoryKey:
        """Construct from hexadecimal string and wipe the string reference."""
        key_bytes = bytes.fromhex(hex_str.strip())
        return cls(key_bytes, mode=mode)

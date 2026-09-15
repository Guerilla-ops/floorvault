"""Windows DPAPI-backed master key provider.

On Windows 10/11/Server this wraps the Win32 CryptProtectData /
CryptUnprotectData calls (via ctypes) with a caller-supplied secondary entropy,
so an automated infostealer that can call CryptUnprotectData but does not know
the secondary entropy still cannot decrypt the master key.

On non-Windows hosts (CI, test bundles, macOS) it degrades to a deterministic
entropy-derived mask over the shared protected-file custody so the round-trip
contract is testable everywhere; the real CryptProtectData boundary is applied
only when ``os.name == 'nt'``.

The on-disk blob is always ``_HEADER + protect(key)`` — never the raw key — and
the protected file enforces 0600 + no-symlink on every read.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable

from ..memory import HardenedMemoryKey
from ..platform_support import is_windows
from .base import KeyProvider, MissingKeyError
from .platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    read_protected,
    write_protected,
)

_HEADER = b"FLOORWV1"  # floorvault protected key store, dpapi boundary


def _random(n: int) -> bytes:
    return os.urandom(n)


class WindowsDPAPIKeyProvider(KeyProvider):
    """Persistent Windows DPAPI master-key provider (with cross-platform store)."""

    def __init__(
        self,
        *,
        store_path: str | Path,
        entropy: bytes | None = None,
        random_bytes: Callable[[int], bytes] = _random,
        allow_outside_user_profile: bool = False,
    ) -> None:
        if entropy is not None and not isinstance(entropy, bytes):
            raise TypeError("entropy must be bytes")
        self._path = Path(store_path)
        self._entropy = bytes(entropy or b"floorvault-dpapi")
        self._random_bytes = random_bytes
        self._allow_outside_user_profile = allow_outside_user_profile
        self._assert_store_location_is_private()

    def _assert_store_location_is_private(self) -> None:
        """On Windows, require the store to live inside the user profile.

        Windows has no POSIX permission bits, so the file-mode check is a no-op
        there and FloorVault cannot inspect the store's NT ACL. The user profile
        is the only location whose ACLs can reasonably be assumed to be
        owner-only, so a store anywhere else - a shared volume, ``ProgramData``,
        or a redirected directory - is refused rather than silently trusted.

        This is the compensating control for F-1's residual risk. Pass
        ``allow_outside_user_profile=True`` only when the location has been
        secured independently, e.g. an ACL you control.
        """
        if not is_windows() or self._allow_outside_user_profile:
            return
        profile = Path(os.path.expanduser("~")).resolve()
        try:
            Path(self._path).resolve().relative_to(profile)
        except ValueError as exc:
            raise ProtectedStoreError(
                f"refusing a Windows key store outside the user profile: {self._path} "
                f"(expected it to be under {profile}). FloorVault cannot verify NT "
                "ACLs elsewhere; move the store, or construct the provider with "
                "allow_outside_user_profile=True if the location is already secured."
            ) from exc

    @staticmethod
    def _is_windows() -> bool:
        # Cygwin/MSYS report os.name == "posix" with sys.platform == "cygwin";
        # the previous conjunction made this branch unreachable there.
        return is_windows()

    # ---- Windows DPAPI boundary -------------------------------------------

    def _windows_protect(self, key: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def to_blob(data: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
            return DATA_BLOB(len(data), buf)

        crypt32 = ctypes.windll.crypt32
        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        blob = to_blob(key)
        ent = to_blob(self._entropy)
        out = DATA_BLOB()
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)
        )
        if not ok:
            raise ProtectedStoreError("CryptProtectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def _windows_unprotect(self, blob: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def to_blob(data: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
            return DATA_BLOB(len(data), buf)

        crypt32 = ctypes.windll.crypt32
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        blob_in = to_blob(blob)
        ent = to_blob(self._entropy)
        out = DATA_BLOB()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)
        )
        if not ok:
            raise ProtectedStoreError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    # ---- boundary (protect on write, unprotect on read) -------------------

    def _protect(self, key: bytes) -> bytes:
        if self._is_windows():
            return self._windows_protect(key)
        # Cross-platform fallback: mask with an entropy-derived pad so the file
        # is not raw key material (symmetric XOR -> unprotect == protect).
        mask = hashlib.sha256(self._entropy).digest()
        return bytes(a ^ b for a, b in zip(key, mask))

    def _unprotect(self, blob: bytes) -> bytes:
        if self._is_windows():
            return self._windows_unprotect(blob)
        mask = hashlib.sha256(self._entropy).digest()
        return bytes(a ^ b for a, b in zip(blob, mask))

    # ---- KeyProvider contract ---------------------------------------------

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        try:
            blob = read_protected(self._path, header=_HEADER)
        except ProtectedStoreMissing:
            # Genuinely absent, so creating below is correct. Any other read
            # failure (corrupt header, unexpected length, insecure mode) raises
            # ProtectedStoreError and propagates: an unreadable store must never
            # be treated as an absent one, or the existing master key would be
            # silently replaced and the user's data lost.
            existing = None
        else:
            existing = blob
        if existing is not None:
            key = self._unprotect(existing)
            if len(key) != 32:
                raise ProtectedStoreError("protected store key has unexpected length")
            return HardenedMemoryKey(key)
        if not allow_create:
            raise MissingKeyError("Windows DPAPI store is missing; recovery is required")
        key = self._random_bytes(32)
        if len(key) != 32:
            raise ProtectedStoreError("random source must return 32 bytes")
        write_protected(self._protect(key), self._path, header=_HEADER)
        return HardenedMemoryKey(key)

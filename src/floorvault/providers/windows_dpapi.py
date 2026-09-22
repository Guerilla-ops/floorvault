"""Windows DPAPI-backed master key provider.

On Windows 10/11/Server this wraps the Win32 CryptProtectData /
CryptUnprotectData calls (via ctypes) with a secondary entropy parameter.
When the caller supplies ``entropy``, an automated infostealer that can call
CryptUnprotectData but does not know the entropy still cannot decrypt the
master key. When it is omitted the provider uses a public constant
(``b"floorvault-dpapi"``): the blob is still bound to the Windows user account
by DPAPI, but the constant adds no secrecy - it is a label, not a key.

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
    LEGACY_STORE_NAME,
    ProtectedStoreError,
    ProtectedStoreMissing,
    read_scheme_store,
    store_path_for,
    write_protected,
)

_HEADER = b"FLOORWV1"  # floorvault protected key store, dpapi boundary


def _random(n: int) -> bytes:
    return os.urandom(n)


class WindowsDPAPIKeyProvider(KeyProvider):
    """Persistent Windows DPAPI master-key provider (with cross-platform store).

    **Store location policy.** Windows has no POSIX permission bits: the mode
    FloorVault reads back is synthesised, and an NT ACL cannot be inspected from
    pure Python without a Windows-only dependency. The user profile is therefore
    the only location whose protection can reasonably be assumed, and a store
    outside it is REFUSED by default
    (``allow_outside_user_profile=False``). This is deliberate: an accidental
    ``C:\\ProgramData``, shared-volume, or redirected-directory placement would
    otherwise be trusted on the strength of a permission check that cannot see
    it. Pass ``allow_outside_user_profile=True`` only when that location has been
    secured independently, e.g. by an ACL you control and have verified.
    """

    #: Names this scheme's on-disk store: ``master.key.dpapi``. Distinct from the
    #: tier-3 raw key file (``master.key``) and the Secret Service store
    #: (``master.key.ss``) - the three formats are mutually unreadable, and
    #: sharing one path locked whichever tier ran second out of the data.
    STORE_SCHEME = "dpapi"

    @classmethod
    def default_store_path(cls, base_dir: str | Path) -> Path:
        """Canonical store path for this scheme under ``base_dir``."""
        return store_path_for(base_dir, cls.STORE_SCHEME)

    def _legacy_store_path(self) -> Path:
        """Where this scheme's store lived before the schemes were separated."""
        return self._path.with_name(LEGACY_STORE_NAME)

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
        # NOTE: the default is a public constant - a label that keeps the blob
        # domain-separated, not a secret. Only caller-supplied entropy adds the
        # "infostealer cannot unprotect" property described in the docstring.
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
            # expected_length=None: on Windows the stored payload is a DPAPI blob
            # whose size is chosen by CryptProtectData, not a fixed 32 bytes. The
            # key length is verified after unprotection (below), which is where
            # the invariant that matters actually lives.
            blob = read_scheme_store(
                self._path,
                header=_HEADER,
                expected_length=None,
                legacy_path=self._legacy_store_path(),
            )
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
        write_protected(self._protect(key), self._path, header=_HEADER, expected_length=None)
        return HardenedMemoryKey(key)

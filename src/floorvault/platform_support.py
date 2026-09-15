"""Centralised platform predicates for FloorVault.

Before this module the codebase mixed two conventions - ``os.name`` in the
providers and ``sys.platform`` elsewhere - which disagree on Cygwin/MSYS
(``os.name`` is ``"posix"`` there while ``sys.platform`` is ``"cygwin"``). That
produced an unreachable branch in ``windows_dpapi`` and let the Linux
Secret-Service provider treat macOS as eligible.

The module-level booleans are read by the predicate functions at *call* time, so
a test can patch a single attribute (``platform_support.IS_WINDOWS``) and have
every call site observe it.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from pathlib import Path

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def is_windows() -> bool:
    """True only on a real Windows CPython (not Cygwin/MSYS)."""
    return IS_WINDOWS


def is_macos() -> bool:
    return IS_MACOS


def is_linux() -> bool:
    return IS_LINUX


def has_posix_group_or_other_access(mode: int) -> bool:
    """Whether POSIX permission bits grant group or other access.

    Windows does not implement POSIX permission bits: ``os.stat()`` reports a
    synthesised mode (typically ``0o666`` for a writable file) regardless of the
    file's ACL, so applying this test there would reject every key file -
    including one we have just written with ``0o600``.
    """
    if is_windows():
        return False
    return bool(mode & 0o077)


def binary_mode_flag() -> int:
    """``O_BINARY`` on Windows, ``0`` elsewhere.

    ``os.open`` without ``O_BINARY`` leaves the descriptor in TEXT mode on
    Windows, where the C runtime translates ``\\n`` to ``\\r\\n`` on write and
    stops at the ``0x1A`` (Ctrl-Z) byte on read. Key material is uniformly random
    bytes, so a 40-byte store will contain one of those bytes often enough that
    the store is silently mangled or truncated - the failure the ``windows-latest``
    CI leg reported as a key of "unexpected length" on read and "must be exactly
    32 bytes" on the subsequent write.

    ``O_BINARY`` does not exist on POSIX, hence the ``getattr``.
    """
    return getattr(os, "O_BINARY", 0)


# ---------------------------------------------------------------------------
# Key-store permission verification
#
# Both branches answer one question: is this store readable by anyone other than
# its owner? On POSIX that is the file mode. On Windows the mode is synthesised
# and meaningless, so the effective DACL is consulted instead - and if it cannot
# be consulted, the store is refused rather than trusted.
# ---------------------------------------------------------------------------

#: SIDs that are not "someone else" for the purpose of protecting a key store.
#: SYSTEM and Administrators can take ownership of anything on the machine, and
#: CREATOR OWNER / OWNER RIGHTS grant nothing to another principal.
WINDOWS_TRUSTED_SIDS = frozenset(
    {
        "S-1-5-18",  # NT AUTHORITY\SYSTEM
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-3-0",  # CREATOR OWNER
        "S-1-3-4",  # OWNER RIGHTS
    }
)


def acl_sids_granting_others_access(
    sids: Iterable[str],
    *,
    owner_sid: str | None,
    trusted_sids: frozenset[str] = WINDOWS_TRUSTED_SIDS,
) -> frozenset[str]:
    """SIDs in ``sids`` that are neither the owner nor otherwise trusted.

    Pure, so the policy is testable without a Windows host. A key store that
    grants access to anyone else has no confidentiality boundary to speak of:
    whoever can read the store can read the key.
    """
    offenders = set()
    for sid in sids:
        if not sid:
            continue
        if owner_sid is not None and sid == owner_sid:
            continue
        if sid in trusted_sids:
            continue
        offenders.add(sid)
    return frozenset(offenders)


def windows_dacl_sids(path: str | Path) -> tuple[frozenset[str], str | None]:
    """Return ``(sids granted access by the DACL, owner SID)`` for ``path``.

    Windows only. Raises ``OSError`` if the security descriptor cannot be read -
    the caller treats that as a refusal, not as "no ACL".
    """
    import ctypes
    from ctypes import wintypes

    if not is_windows():
        raise OSError("windows_dacl_sids is only available on Windows")

    se_file_object = 1
    owner_security_information = 0x00000001
    dacl_security_information = 0x00000004
    acl_size_information = 2
    access_allowed_ace_type = 0

    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    advapi32 = getattr(ctypes, "windll", None)
    if advapi32 is None:
        # Only reachable when a test simulates Windows on a POSIX host. Raising
        # OSError (rather than AttributeError) routes it into the documented
        # fail-closed path: an unverifiable ACL is a refusal, never a pass.
        raise OSError("ctypes.windll is unavailable; not a real Windows host")
    advapi32 = advapi32.advapi32
    kernel32 = ctypes.windll.kernel32

    owner_ptr = ctypes.c_void_p()
    dacl_ptr = ctypes.c_void_p()
    descriptor_ptr = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        ctypes.c_wchar_p(str(path)),
        se_file_object,
        owner_security_information | dacl_security_information,
        ctypes.byref(owner_ptr),
        None,
        ctypes.byref(dacl_ptr),
        None,
        ctypes.byref(descriptor_ptr),
    )
    if result != 0:
        raise OSError(result, f"GetNamedSecurityInfoW failed for {path}")

    def sid_to_string(sid_pointer: ctypes.c_void_p) -> str:
        as_string = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(as_string)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(as_string.value)
        finally:
            kernel32.LocalFree(as_string)

    try:
        owner_sid = sid_to_string(owner_ptr) if owner_ptr else None

        if not dacl_ptr:
            # No DACL at all means every principal is granted access.
            return frozenset({"<null-dacl>"}), owner_sid

        size_info = ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(
            dacl_ptr,
            ctypes.byref(size_info),
            ctypes.sizeof(size_info),
            acl_size_information,
        ):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")

        sids: set[str] = set()
        for index in range(size_info.AceCount):
            ace_ptr = ctypes.c_void_p()
            if not advapi32.GetAce(dacl_ptr, index, ctypes.byref(ace_ptr)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            header = ctypes.cast(ace_ptr, ctypes.POINTER(ACE_HEADER)).contents
            if header.AceType != access_allowed_ace_type:
                continue
            # ACCESS_ALLOWED_ACE: ACE_HEADER (4 bytes) + ACCESS_MASK (4 bytes),
            # then the SID. The address is computed rather than described with a
            # struct because the SID is variable length.
            sid_address = ctypes.cast(ace_ptr, ctypes.c_void_p).value
            if sid_address is None:
                raise OSError("GetAce returned a null pointer")
            sids.add(sid_to_string(ctypes.c_void_p(sid_address + 8)))
        return frozenset(sids), owner_sid
    finally:
        if descriptor_ptr:
            kernel32.LocalFree(descriptor_ptr)


def store_permission_problem(path: str | Path, mode: int | None) -> str | None:
    """Return why a key store is not owner-only, or ``None`` if it is.

    Fails closed: a store whose permissions cannot be established is reported as
    a problem. A caller must never treat "cannot tell" as "fine".
    """
    if is_windows():
        try:
            sids, owner_sid = windows_dacl_sids(path)
        except OSError as exc:
            return (
                f"key store permissions could not be determined for {path} "
                f"({type(exc).__name__}: {exc}); refusing to trust an unverified ACL"
            )
        offenders = acl_sids_granting_others_access(sids, owner_sid=owner_sid)
        if offenders:
            return (
                f"key store ACL grants access beyond its owner "
                f"({', '.join(sorted(offenders))}); expected access for the owner, "
                "SYSTEM and Administrators only"
            )
        return None

    if mode is None:
        return f"key store permissions could not be determined for {path} (no file mode)"
    if has_posix_group_or_other_access(mode):
        return "key store permissions grant group or other access (expected 0600)"
    return None

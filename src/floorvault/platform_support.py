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

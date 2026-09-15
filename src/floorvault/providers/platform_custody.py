"""Shared file-backed master-key custody for platform-native providers.

Pure-Python, cross-platform, fail-closed:
  * Writes the protected key with O_EXCL|O_NOFOLLOW to a temp then atomically
    renames it, so the file is never group/world-readable mid-write.
  * Refuses to overwrite an existing store. Losing the previous key silently is
    indistinguishable from destroying the user's data.
  * Reads refuse symlinks (O_NOFOLLOW), and distinguish *absent* from
    *unreadable*: ``ProtectedStoreMissing`` means "no store yet, safe to
    create", while any other ``ProtectedStoreError`` means the store exists but
    is corrupt or insecurely permissioned and MUST NOT be replaced.
  * On POSIX, reads require that the store grants no group or other access
    (0600, 0400, 0700 all qualify). Windows does not implement POSIX permission
    bits - os.stat() reports a synthesised mode (0o666 for a writable file)
    whatever the ACL - so that check is POSIX-only; on Windows the file's
    protection comes from the ACL of the directory holding it.
  * The stored blob header marks the protection scheme so an on-disk value can
    never be mistaken for a raw key.

Platform providers wrap this with their native boundary (Windows DPAPI
secondary entropy, Linux Secret Service) — but the file/hardening contract is
identical and testable on every OS.
"""

from __future__ import annotations

import os
from pathlib import Path

# Resolved at import; tests patch it to exercise both platforms' behaviour.
IS_WINDOWS = os.name == "nt"


def has_posix_group_or_other_access(mode: int) -> bool:
    """Whether POSIX permission bits grant group or other access.

    Windows does not implement POSIX permission bits: ``os.stat()`` reports a
    synthesised mode (typically ``0o666`` for a writable file) regardless of the
    file's ACL, so applying this test there would reject every key file -
    including one this module has just written with ``0o600``.
    """
    if IS_WINDOWS:
        return False
    return bool(mode & 0o077)


class ProtectedStoreError(Exception):
    """Raised when the protected store is missing, corrupt, or insecurely owned."""


class ProtectedStoreMissing(ProtectedStoreError):
    """Raised when the protected store does not exist yet.

    Distinct from the other failure modes on purpose: callers may create a key
    when the store is absent, but must never treat a corrupt or unreadable
    store as absent - doing so rotates the master key and loses the data.
    """


def write_protected(key: bytes, path: Path, *, header: bytes) -> None:
    """Atomically write ``header + key`` to ``path`` with 0600. Refuses symlinks.

    Refuses to overwrite an existing store: the only reason to write is that no
    key exists yet. A caller that has wrongly concluded "no store" therefore
    fails loudly instead of destroying the previous key.
    """
    if len(key) != 32:
        raise ProtectedStoreError("master key must be exactly 32 bytes")
    if path.exists():
        # Defence in depth. The real fix is that callers distinguish
        # ProtectedStoreMissing from ProtectedStoreError; this guard means a
        # future call site cannot silently clobber a store either.
        raise ProtectedStoreError(f"refusing to overwrite an existing protected store: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.urandom(6).hex()}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.write(descriptor, header + key)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_protected(path: Path, *, header: bytes) -> bytes:
    """Read and validate a protected store; return the raw 32-byte key.

    Raises:
        ProtectedStoreMissing: the store does not exist (safe to create one).
        ProtectedStoreError: the store exists but is corrupt, is not a regular
            file, or is group/other-accessible on POSIX. Callers must not
            treat this as "absent".
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ProtectedStoreMissing("protected store not present") from exc
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    if not raw.startswith(header):
        raise ProtectedStoreError("protected store has an unknown or missing header")
    key = raw[len(header) :]
    if len(key) != 32:
        raise ProtectedStoreError("protected store key has an unexpected length")
    if has_posix_group_or_other_access(os.stat(path).st_mode):
        raise ProtectedStoreError(
            "protected store permissions grant group or other access (expected 0600)"
        )
    return key

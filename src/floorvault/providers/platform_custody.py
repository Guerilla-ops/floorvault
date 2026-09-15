"""Shared file-backed master-key custody for platform-native providers.

Pure-Python, cross-platform, fail-closed:
  * Writes the protected key with O_EXCL|O_NOFOLLOW to a temp file beside the
    store, then publishes it with os.link, which fails if the destination
    exists: the key is never group/world-readable mid-write and a store is
    never silently replaced.
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

from ..platform_support import binary_mode_flag, has_posix_group_or_other_access

#: Upper bound for a protected store, i.e. the read buffer. A DPAPI blob is a few
#: hundred bytes; anything approaching this is not a store we wrote.
_MAX_STORE_BYTES = 4096


class ProtectedStoreError(Exception):
    """Raised when the protected store is missing, corrupt, or insecurely owned."""


class ProtectedStoreMissing(ProtectedStoreError):
    """Raised when the protected store does not exist yet.

    Distinct from the other failure modes on purpose: callers may create a key
    when the store is absent, but must never treat a corrupt or unreadable
    store as absent - doing so rotates the master key and loses the data.
    """


class ProtectedStoreInvalidLength(ProtectedStoreError):
    """The store exists but its key is not exactly 32 bytes.

    Distinct from the header and permission failures so a test can pin *which*
    check fired. A generic ``ProtectedStoreError`` from one check can satisfy an
    assertion aimed at another - mutation testing found exactly that masking
    (a mutated length check still passed because the permission check raised
    instead).
    """


class ProtectedStoreHeaderError(ProtectedStoreError):
    """The store exists but does not start with the expected magic header.

    Distinct for the same reason as the length error, plus one more: this check
    runs *first*, so if its raise were removed the length check would fail on the
    same blob and raise a different subclass. An assertion naming only the base
    class cannot tell those two paths apart, which is how a mutant that deleted
    this raise survived until the test asserted this type specifically.
    """


def _mkdir_owner_only(directory: Path) -> None:
    """Create ``directory`` and every missing ancestor with mode 0700.

    ``Path.mkdir(parents=True, mode=0o700)`` applies the mode **only to the final
    component**: its recursive call for ancestors uses the default 0o777 (masked
    by umask), so a path like ``~/.floor/vault/keys/store`` would leave
    ``.floor/vault/keys`` world-searchable. The custody chain should be
    owner-only throughout, so each component is created explicitly.
    """
    missing: list[Path] = []
    current = directory
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=True)


def write_protected(
    key: bytes, path: Path, *, header: bytes, expected_length: int | None = 32
) -> None:
    """Atomically write ``header + key`` to ``path`` with 0600. Refuses symlinks.

    ``expected_length`` pins the payload size (32 bytes of key material by
    default). Pass ``None`` only for an opaque, variable-length payload - the
    Windows DPAPI blob - where the size is chosen by the OS; the recovery check
    then happens after unprotection, and an empty payload is still refused.

    The store is **created, never replaced**. No-clobber is enforced by
    :func:`_link_no_clobber`, which uses ``os.link`` - the OS fails that call if
    the destination exists, so there is no check-then-use window. Two processes
    starting at once therefore cannot both conclude "no store yet" and silently
    rotate each other's key; exactly one wins and the loser fails loudly.
    """
    if expected_length is not None and len(key) != expected_length:
        raise ProtectedStoreInvalidLength(f"master key must be exactly {expected_length} bytes")
    if expected_length is None and not key:
        raise ProtectedStoreInvalidLength("refusing to write an empty protected payload")
    _mkdir_owner_only(path.parent)
    temporary = path.parent / f".{path.name}.{os.urandom(6).hex()}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | binary_mode_flag()
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.write(descriptor, header + key)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _link_no_clobber(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _link_no_clobber(temporary: Path, path: Path) -> None:
    """Publish ``temporary`` as ``path``, failing if ``path`` already exists.

    ``os.link`` is the atomic primitive here: it either creates the name or
    fails with ``FileExistsError``, with no window between checking and acting.
    (``renameat2(RENAME_NOREPLACE)`` would be the Linux-native equivalent but is
    not exposed by Python's ``os`` module, and ``os.replace`` always clobbers.)
    """
    try:
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ProtectedStoreError(
            f"refusing to overwrite an existing protected store: {path}"
        ) from exc
    except OSError:
        # Hard links are unavailable on some filesystems (e.g. certain network or
        # FAT volumes). Fall back to check-then-replace, which is NOT atomic: two
        # concurrent writers could both win. Documented limitation, not a claim.
        if path.exists():
            raise ProtectedStoreError(
                f"refusing to overwrite an existing protected store: {path}"
            ) from None
        os.replace(temporary, path)


def read_protected(path: Path, *, header: bytes, expected_length: int | None = 32) -> bytes:
    """Read and validate a protected store; return the stored payload.

    ``expected_length`` pins the payload size (32 bytes by default); ``None``
    accepts an opaque variable-length payload such as a Windows DPAPI blob.

    Raises:
        ProtectedStoreMissing: the store does not exist (safe to create one).
        ProtectedStoreError: the store exists but is corrupt, is not a regular
            file, or is group/other-accessible on POSIX. Callers must not
            treat this as "absent".
    """
    flags = (
        os.O_RDONLY
        | binary_mode_flag()
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ProtectedStoreMissing("protected store not present") from exc
    try:
        size = os.fstat(fd).st_size
        raw = os.read(fd, _MAX_STORE_BYTES)
    finally:
        os.close(fd)
    if size > len(raw):
        # Reading stopped at the buffer, so the tail was never inspected. With a
        # fixed expected length this was caught downstream; with an opaque
        # payload it would be a silent truncation, so refuse it outright.
        raise ProtectedStoreError(
            f"protected store is larger ({size} bytes) than the read buffer "
            f"({_MAX_STORE_BYTES} bytes); refusing to validate a partial read"
        )
    if not raw.startswith(header):
        raise ProtectedStoreHeaderError("protected store has an unknown or missing header")
    key = raw[len(header) :]
    if expected_length is not None and len(key) != expected_length:
        raise ProtectedStoreInvalidLength("protected store key has an unexpected length")
    if expected_length is None and not key:
        raise ProtectedStoreInvalidLength("protected store holds an empty payload")
    if has_posix_group_or_other_access(os.stat(path).st_mode):
        raise ProtectedStoreError(
            "protected store permissions grant group or other access (expected 0600)"
        )
    return key

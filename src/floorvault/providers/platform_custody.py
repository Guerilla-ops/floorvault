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
    (0600, 0400, 0700 all qualify). Extended POSIX ACLs (macOS `chmod +a`,
    Linux `setfacl`) are not queried; the check covers standard POSIX
    permission bits only. Windows does not implement POSIX permission
    bits - os.stat() reports a synthesised mode (0o666 for a writable file)
    whatever the ACL - so the mode check is POSIX-only; on Windows the store's
    effective DACL is verified instead (GetNamedSecurityInfoW, refusing a store
    that grants access to any principal other than its owner, SYSTEM and
    Administrators). A store whose protection cannot be established on either
    platform is refused rather than trusted: "cannot tell" is never "fine".
  * The stored blob header marks the protection scheme so an on-disk value can
    never be mistaken for a raw key.

Platform providers wrap this with their native boundary (Windows DPAPI
secondary entropy, Linux Secret Service) — but the file/hardening contract is
identical and testable on every OS.
"""

from __future__ import annotations

import os
import stat
import warnings
from pathlib import Path

from ..platform_support import binary_mode_flag, store_permission_problem

#: Upper bound for a protected store, i.e. the read buffer. A DPAPI blob is a few
#: hundred bytes; anything approaching this is not a store we wrote.
_MAX_STORE_BYTES = 4096

#: The bare key-file name used by ``AdaptiveKeyProvider`` tier 3 (a raw 32-byte
#: or 64-hex-character key with no header) and, historically, by *every* scheme.
#:
#: It is kept as the tier-3 name rather than renamed so an existing raw key file
#: is still found. The header-bearing schemes moved to suffixed names because
#: three incompatible formats could not share one path: each reader refused the
#: others' file, so the first tier to run locked the rest out of the user's data.
LEGACY_STORE_NAME = "master.key"


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


def store_path_for(base_dir: str | Path, scheme: str | None) -> Path:
    """Path of the protected store for ``scheme`` under ``base_dir``.

    ``scheme=None`` is the header-less tier-3 raw key file; every other scheme
    gets ``master.key.<scheme>`` so two formats can never share one path.
    """
    base = Path(base_dir)
    if not scheme:
        return base / LEGACY_STORE_NAME
    return base / f"{LEGACY_STORE_NAME}.{scheme}"


def read_scheme_store(
    path: Path,
    *,
    header: bytes,
    expected_length: int | None = 32,
    legacy_path: Path | None = None,
) -> bytes:
    """Read this scheme's store, adopting a pre-split store when that is what it is.

    ``legacy_path`` is where an earlier build wrote this scheme's store, before
    the schemes were separated onto their own paths. It is adopted only when it
    parses with *this* scheme's ``header``: a file belonging to another scheme is
    ignored, so a raw tier-3 key file no longer blocks the Secret Service tier,
    while a genuine pre-split store is still found. Minting a fresh key beside an
    existing store would leave the user's data undecryptable.

    Raises ``ProtectedStoreMissing`` when neither location holds this scheme's
    store, which is the only condition under which the caller may create one.
    """
    try:
        return read_protected(path, header=header, expected_length=expected_length)
    except ProtectedStoreMissing:
        pass
    if legacy_path is None or legacy_path == path:
        raise ProtectedStoreMissing("protected store not present")
    try:
        adopted = read_protected(legacy_path, header=header, expected_length=expected_length)
    except (ProtectedStoreMissing, ProtectedStoreHeaderError):
        # Absent, or another scheme's file: neither is this scheme's store.
        raise ProtectedStoreMissing("protected store not present") from None
    warnings.warn(
        f"adopting the pre-split key store at {legacy_path}; future writes use {path}",
        UserWarning,
        stacklevel=2,
    )
    return adopted


def _is_system_symlink(path: Path) -> bool:
    """True for a root-owned symlink pointing at a root-owned directory.

    macOS ships system firmlinks such as ``/tmp -> /private/tmp`` and
    ``/var -> /private/var``. A vault base beneath the system temp dir must keep
    working, but a symlink an attacker planted in a user-writable parent must not
    be followed. Only root can create a link inside a root-owned directory, so a
    root-owned link to a root-owned target is a system link, not an attack.
    """
    if not hasattr(os, "getuid"):
        return False
    try:
        link_stat = path.lstat()
        if not stat.S_ISLNK(link_stat.st_mode) or link_stat.st_uid != 0:
            return False
        return path.resolve().stat().st_uid == 0
    except OSError:
        return False


def _mkdir_owner_only(directory: Path) -> None:
    """Create or harden ``directory`` and every missing ancestor with mode 0700.

    Existing paths are inspected with ``lstat`` rather than ``exists`` so a
    symlink cannot be accepted as a vault-controlled directory. The requested
    final directory is hardened even when it already exists; a permissive
    existing base must not bypass the owner-only custody policy.
    """
    directory = Path(directory)
    try:
        if stat.S_ISLNK(directory.lstat().st_mode):
            raise ValueError(f"vault directory must not be a symlink: {directory}")
    except FileNotFoundError:
        pass

    # Reject a symlinked *ancestor* before resolving: ``resolve()`` below follows
    # every ancestor link, so without this an attacker-controlled parent symlink
    # would silently redirect the vault to a location of their choosing. Only
    # root-owned system firmlinks (macOS /tmp, /var) are exempt.
    for ancestor in directory.parents:
        try:
            ancestor_stat = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(ancestor_stat.st_mode) and not _is_system_symlink(ancestor):
            raise ValueError(f"vault ancestor must not be a symlink: {ancestor}")

    directory = directory.parent.resolve() / directory.name

    missing: list[Path] = []
    current = directory
    while current != current.parent:
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
            continue
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(f"vault directory must not be a symlink: {current}")
        if not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError(f"vault path is not a directory: {current}")
        break

    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=False)

    final_stat = directory.lstat()
    if stat.S_ISLNK(final_stat.st_mode) or not stat.S_ISDIR(final_stat.st_mode):
        raise ValueError(f"vault path is not an owner-controlled directory: {directory}")
    if hasattr(os, "getuid") and final_stat.st_uid != os.getuid():
        raise ValueError(f"vault directory is not owned by the current user: {directory}")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(directory, 0o700)


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
    rotate each other's key; exactly one wins and the loser fails loudly. A
    filesystem that cannot provide that atomicity fails closed rather than
    falling back to a racy check-then-replace.
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
        _write_all(descriptor, header + key)
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


def _write_all(descriptor: int, data: bytes) -> None:
    """Write all bytes, handling the short-write contract of ``os.write``."""
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("protected-store write made no progress")
        view = view[written:]


def _link_no_clobber(temporary: Path, path: Path) -> None:
    """Publish ``temporary`` as ``path``, failing if ``path`` already exists.

    ``os.link`` is the atomic primitive here: it either creates the name or
    fails with ``FileExistsError``, with no window between checking and acting.
    (``renameat2(RENAME_NOREPLACE)`` would be the Linux-native equivalent but is
    not exposed by Python's ``os`` module, and ``os.replace`` always clobbers.)

    There is deliberately no check-then-replace fallback. On a filesystem where
    hard links are unavailable (some network or FAT volumes) a check followed
    by ``os.replace`` is racy: two concurrent creators could each pass the
    existence check and replace each other's store - silently rotating the
    master key. A loud failure is the safe outcome, so other link failures are
    refused rather than degraded.
    """
    try:
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ProtectedStoreError(
            f"refusing to overwrite an existing protected store: {path}"
        ) from exc
    except OSError as exc:
        raise ProtectedStoreError(
            f"atomic no-clobber publication is unavailable on the filesystem "
            f"holding {path} ({exc}); the store must live on a filesystem that "
            "supports hard links - refusing a non-atomic replace that could "
            "silently overwrite a concurrent writer's key"
        ) from exc


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
    except OSError as exc:
        # Windows may refuse to open a directory as a file before we can reach
        # the descriptor-based regular-file check below. Classify that existing
        # non-regular path consistently instead of leaking PermissionError.
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            raise ProtectedStoreError("protected store could not be opened") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ProtectedStoreError("protected store is not a regular file") from exc
        raise ProtectedStoreError(f"could not open protected store: {exc}") from exc
    try:
        file_stat = os.fstat(fd)
        # ``O_NOFOLLOW`` does not exist on Windows, so the flag alone cannot be the
        # control there: the descriptor may be the *target* of a symlink planted at
        # the store path. Check the path itself with ``lstat`` - which reports a link
        # as a link - and require it to name the same object the descriptor holds.
        # On POSIX the flag already refuses a link at the open (ELOOP); this is the
        # platform-independent check behind it, and it also catches a path that was
        # repointed between the open and the check.
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError as exc:
            raise ProtectedStoreError("protected store vanished while it was being opened") from exc
        except OSError as exc:
            raise ProtectedStoreError(f"protected store path could not be examined: {exc}") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise ProtectedStoreError("protected store is not a regular file")
        if (path_stat.st_dev, path_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino):
            raise ProtectedStoreError(
                "protected store changed identity between the path check and the open"
            )
        # No separate regular-file check on the descriptor: the path is a regular
        # file and the two stats are the same object, so the descriptor holds that
        # regular file. A second check here would be unkillable by mutation - one of
        # the two would always mask the other on the same input.
        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
            raise ProtectedStoreError("protected store has an unexpected owner")
        size = file_stat.st_size
        raw = os.read(fd, _MAX_STORE_BYTES)
        if size > len(raw):
            # Reading stopped at the buffer, so the tail was never inspected.
            # With a fixed expected length this was caught downstream; with an
            # opaque payload it would be a silent truncation, so refuse it
            # outright.
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
        problem = store_permission_problem(path, file_stat.st_mode)
        if problem is not None:
            raise ProtectedStoreError(problem)
        return key
    finally:
        os.close(fd)

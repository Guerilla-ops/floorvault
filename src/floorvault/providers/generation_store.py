"""Governed immutable-generation store for wrapped master keys.

``write_protected`` deliberately creates and never replaces: losing a master
key silently is indistinguishable from destroying the user's data. Rewrapping
the master key under a new KEK generation (Vault Transit ``rewrap``, KMS key
rotation) needs a *different* object with *different* semantics - so the
update path is a separate, audited protocol rather than a loosened store:

  * Generation payloads live in immutable ``g-XXXXXXXX.gen`` files, published
    with the same create-never-replace discipline as ``write_protected``.
  * The authoritative pointer is a separate ``active`` file replaced
    atomically under a single-writer lock, carrying the generation number and
    the SHA-256 of the payload it points to.
  * Updates are compare-and-swap: the caller supplies the generation it
    believes is current, and the store refuses the publish when reality
    disagrees. A client acting on a stale read cannot resurrect a superseded
    generation.
  * Directory fsyncs after every publication keep the names durable across
    power loss, matching the protected-store contract.

The store is opaque to its caller: payloads are blobs (a Vault-wrapped master
key, a KMS ciphertext) and the generation number is the only ordering it
enforces. It resolves *which* blob is current, never what the blob means.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from contextlib import contextmanager
from pathlib import Path

from ..platform_support import binary_mode_flag
from .platform_custody import (
    _MAX_STORE_BYTES,
    ProtectedStoreError,
    ProtectedStoreInvalidLength,
    ProtectedStoreMissing,
    ProtectedStoreRaceError,
    _fsync_directory,
    _mkdir_owner_only,
    _write_all,
    read_protected,
)

#: Generation payload files: ``FVGW1`` + opaque payload. Immutable once
#: published - a generation's bytes are never rewritten in place.
GENERATION_HEADER = b"FVGW1"

#: Authoritative pointer: ``FVGW0`` + u64be generation + SHA-256(payload).
#: The hash binds the pointer to the generation's content, so a swapped or
#: truncated generation file fails verification even if an attacker can write
#: inside the directory but not keep the two consistent.
POINTER_HEADER = b"FVGW0"
_POINTER_SIZE = len(POINTER_HEADER) + 8 + 32

_LOCK_NAME = ".active.lock"

#: Largest payload a generation file can carry. ``read_protected`` caps a
#: whole file at ``_MAX_STORE_BYTES`` and the payload travels behind the
#: ``FVGW1`` header, so the ceiling belongs to the reader, not the writer.
#: Exceeding it would publish state nothing can ever read back.
MAX_PAYLOAD_BYTES = _MAX_STORE_BYTES - len(GENERATION_HEADER)

#: Pointer-read retries for the lstat/open identity race: a concurrent
#: ``_publish_pointer`` replaces ``active`` atomically, so a reader straddling
#: the replace sees a one-generation "identity change" that is *not*
#: corruption. A few fast retries observe either the old or the new pointer;
#: a pointer churning forever still fails closed.
_POINTER_READ_RETRIES = 4


class GenerationMismatchError(ProtectedStoreError):
    """The on-disk generation does not equal the caller's expectation.

    Distinct from the generic corruption error because it is a *concurrency*
    verdict, not a filesystem one: someone else published while this caller
    was deciding what to write.
    """


class StoreLockError(ProtectedStoreError):
    """The single-writer lock is held. Fail closed, never steal the lock.

    A crashed writer leaves the lockfile behind; that is deliberate. Automatic
    stale-lock breaking turns a slow writer into two writers. The operator
    confirms no writer is alive and deletes the lockfile to recover.
    """


class GenerationStore:
    """Immutable generation files plus a locked, CAS-updated pointer."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self._pointer_path = self.directory / "active"
        self._lock_path = self.directory / _LOCK_NAME

    def _generation_path(self, generation: int) -> Path:
        return self.directory / f"g-{generation:08x}.gen"

    # ------------------------------------------------------------------
    # Read path - lock-free. The pointer is replaced atomically, so readers
    # always observe a complete old or complete new value.
    # ------------------------------------------------------------------

    def read_active(self) -> tuple[int, bytes]:
        """Return ``(generation, payload)`` for the authoritative generation.

        Raises ``ProtectedStoreMissing`` when the store is uninitialized -
        the only state in which a caller may provision. Corruption anywhere
        (bad pointer, missing or hash-mismatched generation file) raises
        ``ProtectedStoreError`` and must not be treated as absent.
        """
        # The pointer is replaced atomically, so a reader can legitimately
        # straddle an update: lstat saw the old inode, open got the new one.
        # Retry the identity race; every other ProtectedStoreError surfaces
        # immediately, and a pointer that never settles still fails closed.
        for attempt in range(_POINTER_READ_RETRIES + 1):
            try:
                raw = read_protected(
                    self._pointer_path,
                    header=POINTER_HEADER,
                    expected_length=_POINTER_SIZE - len(POINTER_HEADER),
                )
                break
            except ProtectedStoreRaceError:
                if attempt == _POINTER_READ_RETRIES:
                    raise
                time.sleep(0.001 * (attempt + 1))
        generation = struct.unpack(">Q", raw[:8])[0]
        digest = raw[8:]

        # The pointer names a generation the reader must be able to resolve.
        # A missing or corrupt generation file is corruption, not absence.
        try:
            payload = read_protected(
                self._generation_path(generation),
                header=GENERATION_HEADER,
                expected_length=None,
            )
        except ProtectedStoreMissing as exc:
            raise ProtectedStoreError(
                f"pointer references generation {generation} but its file is missing"
            ) from exc
        if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):
            raise ProtectedStoreError(
                f"generation {generation} payload does not match the pointer's hash"
            )
        return generation, payload

    def active_generation(self) -> int | None:
        """Current generation number, or ``None`` when uninitialized."""
        try:
            return self.read_active()[0]
        except ProtectedStoreMissing:
            return None

    # ------------------------------------------------------------------
    # Write path - every mutation happens under the single-writer lock.
    # ------------------------------------------------------------------

    @contextmanager
    def writer_lock(self):
        """Acquire the single-writer lock; raise ``StoreLockError`` if held.

        The lockfile is created ``O_CREAT | O_EXCL`` so acquisition is atomic:
        exactly one contender wins, with no check-then-create window. Release
        unlinks and directory-syncs so a released lock survives power loss
        semantics (a resurrected stale lock is a denial, not a double write).
        """
        _mkdir_owner_only(self.directory)
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | binary_mode_flag()
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError as exc:
            raise StoreLockError(
                f"generation-store writer lock is held: {self._lock_path} - "
                "if no writer is running, remove the lockfile to recover"
            ) from exc
        try:
            _write_all(descriptor, f"pid={os.getpid()}\n".encode())
        except BaseException:
            # A failed metadata write (e.g. ENOSPC) must not strand the
            # lockfile we just created - stale locks block every writer until
            # an operator intervenes, which is only acceptable after a real
            # process crash.
            os.close(descriptor)
            try:
                os.unlink(self._lock_path)
            except FileNotFoundError:
                pass
            else:
                _fsync_directory(self.directory)
            raise
        os.close(descriptor)
        try:
            yield
        finally:
            try:
                os.unlink(self._lock_path)
            except FileNotFoundError:
                pass
            else:
                _fsync_directory(self.directory)

    def provision(self, payload: bytes) -> int:
        """Publish the first generation; return its number (always 1).

        Idempotent for a crashed attempt: if generation 1 exists but the
        pointer was never published, the same payload is adopted rather than
        rejected. Any other pre-existing state fails closed - the store does
        not guess which orphan is authoritative.
        """
        if not payload:
            raise ProtectedStoreInvalidLength("refusing to write an empty generation")
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ProtectedStoreInvalidLength(
                f"generation payload is {len(payload)} bytes; the reader caps "
                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "
                "publish state nothing can read back"
            )
        with self.writer_lock():
            try:
                current, _ = self.read_active()
            except ProtectedStoreMissing:
                current = None
            if current is not None:
                raise ProtectedStoreError(
                    f"generation store is already provisioned at generation {current}; "
                    "use update() with expected_generation"
                )
            orphan = self._adoptable_orphan(1)
            if orphan is None:
                self._write_generation(1, payload)
            elif orphan != payload:
                raise ProtectedStoreError(
                    "an unpublished generation 1 exists with different content; "
                    "resolve the partial provision manually"
                )
            self._publish_pointer(1, orphan if orphan is not None else payload)
            return 1

    def update(self, payload: bytes, *, expected_generation: int) -> int:
        """CAS the pointer to a new generation; return its number.

        Fails with ``GenerationMismatchError`` when the authoritative
        generation is not ``expected_generation`` - the caller's decision was
        made against state that no longer holds. An orphaned next-generation
        file left by a crashed attempt is adopted only when its content equals
        the caller's payload (idempotent retry), never silently overwritten.
        """
        if not payload:
            raise ProtectedStoreInvalidLength("refusing to write an empty generation")
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ProtectedStoreInvalidLength(
                f"generation payload is {len(payload)} bytes; the reader caps "
                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "
                "publish state nothing can read back"
            )
        if expected_generation < 1:
            raise ValueError("expected_generation must be a positive integer")
        with self.writer_lock():
            try:
                current, _current_payload = self.read_active()
            except ProtectedStoreMissing as exc:
                raise ProtectedStoreMissing(
                    "generation store is uninitialized; provision() it first"
                ) from exc
            if current != expected_generation:
                raise GenerationMismatchError(
                    f"expected generation {expected_generation} but the store is "
                    f"at {current}; refusing to update from stale state"
                )
            target = expected_generation + 1
            orphan = self._adoptable_orphan(target)
            if orphan is None:
                self._write_generation(target, payload)
            elif orphan != payload:
                raise ProtectedStoreError(
                    f"an unpublished generation {target} exists with different "
                    "content; resolve the partial update manually"
                )
            self._publish_pointer(target, orphan if orphan is not None else payload)
            return target

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _adoptable_orphan(self, generation: int) -> bytes | None:
        """Payload of an unpublished generation file, or ``None``.

        A generation file that no pointer references can only come from a
        writer that crashed between publishing the file and repointing
        ``active``. The file is complete by construction (fsync before link),
        so it is safe to adopt when - and only when - its content matches the
        payload the retrying caller intended to write.
        """
        try:
            return read_protected(
                self._generation_path(generation),
                header=GENERATION_HEADER,
                expected_length=None,
            )
        except ProtectedStoreMissing:
            return None
        except ProtectedStoreError as exc:
            raise ProtectedStoreError(
                f"unpublished generation {generation} is present but unreadable: {exc}"
            ) from exc

    def _write_generation(self, generation: int, payload: bytes) -> None:
        """Publish a generation file with create-never-replace semantics.

        Temp file + fsync + ``os.link`` no-clobber + directory fsync: the same
        discipline as ``write_protected``, kept as its own function because the
        two objects have different mutability contracts and sharing a name
        would invite replacing one with the other.
        """
        path = self._generation_path(generation)
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
            _write_all(descriptor, GENERATION_HEADER + payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise ProtectedStoreError(
                    f"generation {generation} already exists and is immutable: {path}"
                ) from exc
            _fsync_directory(path.parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            else:
                _fsync_directory(path.parent)

    def _publish_pointer(self, generation: int, payload: bytes) -> None:
        """Atomically repoint ``active`` at ``generation``.

        Temp file + fsync + ``os.replace`` + directory fsync. The pointer is
        the *only* object in the store that is replaced: readers take it
        whole or not at all on every platform with atomic rename.
        """
        body = POINTER_HEADER + struct.pack(">Q", generation) + hashlib.sha256(payload).digest()
        temporary = self.directory / f".active.{os.urandom(6).hex()}.tmp"
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
            _write_all(descriptor, body)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self._pointer_path)
            _fsync_directory(self.directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            else:
                _fsync_directory(self.directory)


__all__ = [
    "GENERATION_HEADER",
    "POINTER_HEADER",
    "MAX_PAYLOAD_BYTES",
    "GenerationMismatchError",
    "GenerationStore",
    "StoreLockError",
]

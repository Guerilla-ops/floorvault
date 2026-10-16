"""Opt-in rollback detection: a freshness anchor kept outside the database.

AES-SIV and the contextual AAD prove a ciphertext is authentic and sits at its
own coordinates. They cannot prove it is *current*: an attacker who can write
the database (``SECURITY.md`` §5, A3/A7) can restore an old backup, replay an
old row into its own coordinates, or delete and duplicate rows, and every
envelope still verifies.

A :class:`FreshnessAnchor` closes that gap for the tables it is told about. At
every commit it records a keyed digest of those tables - every row, and the
schema that governs them, triggers included - in an :class:`AnchorStore` that
lives *outside* the database. :meth:`~FreshnessAnchor.verify` recomputes the
digest and refuses a database that does not match: a whole-file rollback, a
single row replayed, removed or added, or a planted trigger or index.

The guarantee is exactly as strong as the anchor store's placement:

- It holds against anyone who can rewrite or restore the database but **not**
  the anchor (a store writer, a database-only backup restore, a stolen and
  re-planted file).
- It does **not** hold against an attacker who can roll back both together -
  for example a whole-disk snapshot that also contains a file anchor. Put the
  anchor where that attacker cannot reach: another volume or host, an OS
  key store, Vault, or a server. :class:`AnchorStore` is a two-method protocol
  (``load`` and an atomic ``compare_and_swap``) so any of those can be plugged in.

Writes go through :meth:`~FreshnessAnchor.transaction`, which takes SQLite's
write lock (``BEGIN IMMEDIATE``), verifies *inside* it, runs the caller's
writes, and commits - so no other writer can slip a change in between the
check and the commit. A write that bypasses the anchor is, correctly,
indistinguishable from tampering. Code that owns its own commits can use
:meth:`~FreshnessAnchor.accept_external_write`, which is weaker and says so.

Every transaction and every verify reads every anchored row, so this suits
stores of modest size.

Crash safety: the commit records the new digest as *pending* before the
database commit and promotes it afterwards. A database found in the pending
state is accepted and promoted. A database found in the *previous* state while
a commit is pending is refused: from outside, "the commit never landed" and
"it landed and the database was then rolled back" look identical, so only an
operator who knows which happened may clear it
(:meth:`~FreshnessAnchor.discard_interrupted_commit`). That is the one case a
crash produces a refusal; it fails closed.

Every anchor-record transition is a compare-and-swap against the exact record
it was computed from, so two processes cannot overwrite each other's newer
record with an older one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Protocol, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._filelock import exclusive_lock
from .beacons import _KEY_BYTES, _coerce_key_material, _snapshot_key
from .core import FloorVaultError
from .memory import HardenedMemoryKey
from .providers.platform_custody import _fsync_directory
from .sqlite_adapter import _fold_sqlite, _quoted_identifier, _safe_column

#: HKDF domain-separation label for the anchor MAC key (SPEC.md §3).
_FRESHNESS_KEY_INFO = b"floorvault-v1-freshness"

#: Version tag bound into every MAC so the encoding can evolve.
_FORMAT = b"FVFA1"

_NAME_MAX = 128

#: How often a verify re-reads the record when a concurrent writer moved it.
_CAS_RETRIES = 5


class RollbackDetectedError(FloorVaultError):
    """The database does not match the state the freshness anchor recorded.

    Raised when anchored rows or schema were rolled back, replayed, deleted,
    added or altered outside :meth:`FreshnessAnchor.transaction`, or when the
    anchor record itself fails authentication. Treat it as tampering: do not
    serve the data.
    """


class AnchorStore(Protocol):
    """Where a :class:`FreshnessAnchor` keeps its state.

    ``load`` returns the current record for ``name`` or ``None``.
    ``compare_and_swap`` atomically replaces the record with ``new`` only if it
    is still exactly ``expected`` (``None`` meaning absent), returning whether
    it did; the write must be durable before it returns. The store is trusted
    for *freshness only*: its contents are authenticated, so it need not be
    secret, but it must not be something the attacker can roll back.
    """

    def load(self, name: str) -> Optional[bytes]: ...

    def compare_and_swap(self, name: str, expected: Optional[bytes], new: bytes) -> bool: ...


class FileAnchorStore:
    """An :class:`AnchorStore` backed by one small file per anchor name.

    Only as trustworthy as the file's location: keep it off the volume, and
    out of the backup set, that holds the database. Compare-and-swap holds a
    cross-process lock (``<name>.fvanchor.lock``); the write goes through a
    temporary file, ``fsync``, ``os.replace`` and a directory ``fsync``, so a
    crash or power loss leaves the old or the new record, never a torn or
    silently reverted one.
    """

    def __init__(self, directory: Union[str, os.PathLike[str]]) -> None:
        self.directory = Path(directory)

    def _path(self, name: str) -> Path:
        return self.directory / f"{name}.fvanchor"

    def load(self, name: str) -> Optional[bytes]:
        try:
            return self._path(name).read_bytes()
        except FileNotFoundError:
            return None

    def _ensure_directory(self) -> None:
        if self.directory.is_dir():
            return
        missing = []
        cursor = self.directory
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Make each newly created directory entry durable, not just the file.
        for created in reversed(missing):
            _fsync_directory(created.parent)

    def compare_and_swap(self, name: str, expected: Optional[bytes], new: bytes) -> bool:
        self._ensure_directory()
        path = self._path(name)
        with exclusive_lock(path.with_name(path.name + ".lock")):
            if self.load(name) != expected:
                return False
            temporary = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                try:
                    view = memoryview(new)
                    while view:
                        view = view[os.write(descriptor, view) :]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(temporary, path)
                # Flush the rename itself: without it a power loss can revert
                # the directory entry to the previous anchor record, which a
                # database restored to that same earlier state would match.
                _fsync_directory(self.directory)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            return True


def _encode_value(value: Any) -> bytes:
    """Type-tagged, length-prefixed encoding of one SQLite value.

    The tag keeps ``1``, ``1.0``, ``'1'`` and ``x'31'`` distinct, so a type
    change is a content change.
    """
    if value is None:
        return b"n"
    if isinstance(value, bool):  # pragma: no cover - SQLite returns ints
        value = int(value)
    if isinstance(value, int):
        raw = str(value).encode("ascii")
        tag = b"i"
    elif isinstance(value, float):
        raw = struct.pack(">d", value)
        tag = b"f"
    elif isinstance(value, str):
        raw = value.encode("utf-8", "surrogatepass")
        tag = b"t"
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        tag = b"b"
    else:
        raise TypeError(f"unsupported SQLite value type {type(value).__name__}")
    return tag + struct.pack(">Q", len(raw)) + raw


def _frame(data: bytes) -> bytes:
    return struct.pack(">Q", len(data)) + data


class FreshnessAnchor:
    """Detect rollback, replay, deletion, insertion and schema tampering.

    ``tables`` maps each anchored table to a column that orders its rows
    uniquely (normally the primary key). Every column of every anchored table
    is covered, plus the schema objects that can change what those tables
    hold: the tables' own definitions and indexes, and every trigger in the
    database. Include the tables whose integrity matters and leave out
    high-churn ones the threat model does not need.

    Typical use::

        anchor = FreshnessAnchor(master_key, FileAnchorStore("/srv/anchors"),
                                 name="app-db", tables={"users": "id"})
        anchor.initialize(connection)        # once, on a database you trust
        ...
        anchor.verify(connection)            # on open; raises if rolled back
        with anchor.transaction(connection): # write lock + verify + commit
            table.store("u1", "token_cipher", new_token)
    """

    def __init__(
        self,
        master_key: Union[bytes, bytearray, HardenedMemoryKey],
        store: AnchorStore,
        *,
        name: str,
        tables: Mapping[str, str],
    ) -> None:
        if not isinstance(name, str) or not name or len(name) > _NAME_MAX:
            raise ValueError(f"name must be a non-empty string of at most {_NAME_MAX} characters")
        if not all(ch.isalnum() or ch in "-_." for ch in name) or name.startswith("."):
            raise ValueError("name may contain only letters, digits, '-', '_' and '.'")
        if not callable(getattr(store, "load", None)) or not callable(
            getattr(store, "compare_and_swap", None)
        ):
            raise TypeError(
                "store must provide load(name) and compare_and_swap(name, expected, new)"
            )
        if not tables:
            raise ValueError("tables must name at least one table to anchor")
        folded: dict[str, str] = {}
        for table, order_column in tables.items():
            physical = _fold_sqlite(_safe_column(table))
            if physical in folded:
                raise ValueError(f"table {table!r} is listed twice")
            folded[physical] = _fold_sqlite(_safe_column(order_column))
        self.name = name
        self.store = store
        self._tables = dict(sorted(folded.items()))
        self._key = self._derive_key(master_key)
        # The committed digest this instance last verified or wrote, and the
        # connection it was established on. Writes refuse to advance from any
        # other state or connection, and a failed verify clears both, so an
        # application cannot bless a rolled-back database as the new baseline.
        self._trusted: Optional[bytes] = None
        self._trusted_connection: Any = None

    @staticmethod
    def _derive_key(master_key: Union[bytes, bytearray, HardenedMemoryKey]) -> bytes:
        source = _snapshot_key(
            _coerce_key_material(master_key, what="master key"),
            owner=master_key if isinstance(master_key, HardenedMemoryKey) else None,
        )
        try:
            if len(source) != _KEY_BYTES:
                raise ValueError(f"master key must be exactly {_KEY_BYTES} bytes")
            return HKDF(
                algorithm=hashes.SHA256(),
                length=_KEY_BYTES,
                salt=None,
                info=_FRESHNESS_KEY_INFO,
            ).derive(source)
        finally:
            for index in range(len(source)):
                source[index] = 0

    # -- digest ---------------------------------------------------------------

    def digest(self, connection: Any) -> bytes:
        """Keyed digest of the anchored tables' rows and schema, as seen by ``connection``."""
        mac = hmac.new(self._key, digestmod=hashlib.sha256)
        mac.update(_FORMAT + b"digest" + _frame(self.name.encode("utf-8")))
        # Schema first. A trigger can rewrite an anchored table on the next
        # legitimate write (and a trigger on any table can target one), so
        # every trigger is covered; so are the anchored tables' own
        # definitions (constraints, defaults, generated columns) and indexes.
        schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'index', 'trigger') ORDER BY type, name"
        ).fetchall()
        for object_type, object_name, table_name, sql in schema:
            if object_type != "trigger" and _fold_sqlite(str(table_name)) not in self._tables:
                continue
            mac.update(
                b"S"
                + _frame(str(object_type).encode("utf-8"))
                + _frame(str(object_name).encode("utf-8", "surrogatepass"))
                + _frame(str(table_name).encode("utf-8", "surrogatepass"))
                + _encode_value(sql)
            )
        for table, order_column in self._tables.items():
            table_sql = _quoted_identifier(table)
            # table_xinfo, not table_info: generated and hidden columns count.
            columns = sorted(
                _fold_sqlite(row[1])
                for row in connection.execute(f"PRAGMA table_xinfo({table_sql})").fetchall()
            )
            if not columns:
                raise RollbackDetectedError(f"anchored table {table!r} does not exist")
            if order_column not in columns:
                raise ValueError(f"order column {order_column!r} is not a column of {table!r}")
            mac.update(b"T" + _frame(table.encode("utf-8")))
            for column in columns:
                mac.update(b"C" + _frame(column.encode("utf-8")))
            select_list = ", ".join(_quoted_identifier(column) for column in columns)
            cursor = connection.execute(
                f"SELECT {select_list} FROM {table_sql} "  # nosec B608 - identifiers allow-listed and bracket-quoted
                f"ORDER BY {_quoted_identifier(order_column)}"
            )
            count = 0
            for row in cursor.fetchall():
                mac.update(b"R" + b"".join(_encode_value(value) for value in row))
                count += 1
            mac.update(b"E" + struct.pack(">Q", count))
        return mac.digest()

    # -- anchor record --------------------------------------------------------

    def _record_mac(self, committed: bytes, pending: Optional[bytes]) -> bytes:
        body = (
            _FORMAT
            + b"record"
            + _frame(self.name.encode("utf-8"))
            + _frame(committed)
            + _frame(pending or b"")
        )
        return hmac.new(self._key, body, hashlib.sha256).digest()

    def _encode_record(self, committed: bytes, pending: Optional[bytes]) -> bytes:
        record = {
            "format": _FORMAT.decode("ascii"),
            "committed": committed.hex(),
            "pending": pending.hex() if pending is not None else None,
            "mac": self._record_mac(committed, pending).hex(),
        }
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")

    def _load(self) -> Optional[tuple[bytes, bytes, Optional[bytes]]]:
        """Return ``(raw_blob, committed, pending)`` or ``None`` when absent."""
        blob = self.store.load(self.name)
        if blob is None:
            return None
        try:
            record = json.loads(blob.decode("ascii"))
            if record.get("format") != _FORMAT.decode("ascii"):
                raise ValueError("format")
            committed = bytes.fromhex(record["committed"])
            pending = bytes.fromhex(record["pending"]) if record["pending"] is not None else None
            mac = bytes.fromhex(record["mac"])
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError):
            raise RollbackDetectedError("freshness anchor record is malformed") from None
        if not hmac.compare_digest(mac, self._record_mac(committed, pending)):
            raise RollbackDetectedError(
                "freshness anchor record failed authentication (wrong key, or it was altered)"
            )
        return blob, committed, pending

    def _trust(self, state: Optional[bytes], connection: Any) -> None:
        self._trusted = state
        self._trusted_connection = connection if state is not None else None

    def _require_trusted(self, connection: Any) -> tuple[bytes, bytes]:
        """Return ``(raw_blob, committed)``, refusing unless this instance vouched for it."""
        loaded = self._load()
        if loaded is None:
            raise RollbackDetectedError(
                f"freshness anchor {self.name!r} has no record; initialize() it first"
            )
        blob, committed, pending = loaded
        if (
            self._trusted is None
            or pending is not None
            or not hmac.compare_digest(self._trusted, committed)
        ):
            raise RollbackDetectedError(
                "call verify() on this anchor before writing: advancing from an unverified "
                "or since-changed state would accept a rolled-back database as current"
            )
        if connection is not self._trusted_connection:
            raise RollbackDetectedError(
                "this connection was not the one verified; verify() it before writing "
                "so a different (possibly rolled-back) database cannot become the baseline"
            )
        return blob, committed

    # -- public operations ----------------------------------------------------

    def initialize(self, connection: Any) -> None:
        """Record ``connection``'s current state as the trusted baseline.

        Trust on first use: call it once, on a database you know is current.
        Refuses if the anchor already holds a record - re-baselining over an
        existing anchor would accept whatever state the database is in now,
        which is the attack this class exists to stop. To deliberately
        re-baseline, delete the anchor record through the store first.
        """
        baseline = self.digest(connection)
        if not self.store.compare_and_swap(self.name, None, self._encode_record(baseline, None)):
            raise FloorVaultError(
                f"freshness anchor {self.name!r} is already initialized; refusing to re-baseline"
            )
        self._trust(baseline, connection)

    def verify(self, connection: Any) -> None:
        """Raise :class:`RollbackDetectedError` unless the database is current.

        Accepts the committed state, or the pending state left by a commit that
        crashed after the database write (and promotes it). Refuses the
        pre-commit state while a commit is pending (see the module docstring).
        A missing anchor record is refused, not treated as a fresh start:
        deleting the anchor must not be a way to disable the check. Any failure
        also revokes this instance's write authorization.
        """
        self._trust(None, None)
        for _attempt in range(_CAS_RETRIES):
            loaded = self._load()
            if loaded is None:
                raise RollbackDetectedError(
                    f"freshness anchor {self.name!r} has no record; refusing to trust the "
                    "database (initialize() it on a known-good copy)"
                )
            blob, committed, pending = loaded
            current = self.digest(connection)
            if pending is not None and hmac.compare_digest(current, pending):
                if not self.store.compare_and_swap(
                    self.name, blob, self._encode_record(pending, None)
                ):
                    continue  # another process moved the record; re-evaluate
                self._trust(pending, connection)
                return
            if hmac.compare_digest(current, committed):
                if pending is not None:
                    raise RollbackDetectedError(
                        "an interrupted commit left this anchor pending, and the database "
                        "is at the state before it: either that commit never reached the "
                        "database, or it did and the database was rolled back. Call "
                        "discard_interrupted_commit() only if you know it never landed"
                    )
                self._trust(committed, connection)
                return
            raise RollbackDetectedError(
                "database does not match its freshness anchor: anchored rows or schema were "
                "rolled back, replayed, deleted, added or altered outside "
                "FreshnessAnchor.transaction()"
            )
        raise FloorVaultError(
            f"freshness anchor {self.name!r} kept changing under verification; retry"
        )

    def _commit(self, connection: Any) -> None:
        """Two-phase commit: record pending, commit the database, promote."""
        blob, committed = self._require_trusted(connection)
        new_state = self.digest(connection)
        pending_blob = self._encode_record(committed, new_state)
        if not self.store.compare_and_swap(self.name, blob, pending_blob):
            raise RollbackDetectedError(
                "freshness anchor moved since verify(); refusing to commit over it"
            )
        connection.commit()
        if not self.store.compare_and_swap(
            self.name, pending_blob, self._encode_record(new_state, None)
        ):
            # The database commit has landed, so this is not a failed write:
            # another holder of the key moved the record on - normally a
            # verify that promoted our pending state, then its own commit.
            # Our promotion must not overwrite that newer record, and this
            # instance no longer knows the current state, so it must
            # re-verify before writing again.
            self._trust(None, None)
            return
        self._trust(new_state, connection)

    @contextmanager
    def transaction(self, connection: Any) -> Iterator[Any]:
        """Verify, write and commit under SQLite's write lock.

        ``BEGIN IMMEDIATE`` takes the database's reserved lock before the
        check, so no other writer can change the anchored rows or schema
        between the verification and the commit. On an exception the
        transaction is rolled back and the anchor is left untouched::

            with anchor.transaction(connection):
                table.store("u1", "token_cipher", new_token)
        """
        if getattr(connection, "in_transaction", False):
            raise FloorVaultError(
                "connection already has an open transaction; commit or roll it back "
                "before FreshnessAnchor.transaction()"
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            self.verify(connection)
            yield connection
            self._commit(connection)
        except BaseException:
            if getattr(connection, "in_transaction", True):
                connection.rollback()
            raise

    def accept_external_write(self, connection: Any) -> None:
        """Advance the anchor after a write the caller already committed.

        For code that owns its own commits (such as :class:`~floorvault.vaultkit.VaultStore`).
        **Weaker than** :meth:`transaction`: it records whatever the database
        holds now, so the caller must guarantee that nothing else wrote the
        database between its :meth:`verify` (same connection, same instance)
        and this call. Not crash-safe either: a crash between the caller's
        commit and this call leaves a database the anchor rejects, which fails
        closed and is recovered by re-initializing from a copy you trust.
        """
        blob, _committed = self._require_trusted(connection)
        new_state = self.digest(connection)
        if not self.store.compare_and_swap(self.name, blob, self._encode_record(new_state, None)):
            self._trust(None, None)
            raise RollbackDetectedError(
                "freshness anchor moved since verify(); refusing to overwrite it"
            )
        self._trust(new_state, connection)

    def discard_interrupted_commit(self, connection: Any) -> None:
        """Clear a pending commit that the operator knows never reached the database.

        Only for the state :meth:`verify` refuses as ambiguous: a pending commit
        with the database at the state before it. This is an assertion by the
        caller - if the commit *had* landed and the database was rolled back,
        calling this accepts the rollback.
        """
        loaded = self._load()
        if loaded is None or loaded[2] is None:
            raise FloorVaultError("no interrupted commit to discard")
        blob, committed, _pending = loaded
        if not hmac.compare_digest(self.digest(connection), committed):
            raise RollbackDetectedError(
                "database matches neither side of the interrupted commit; refusing to discard"
            )
        if not self.store.compare_and_swap(self.name, blob, self._encode_record(committed, None)):
            raise FloorVaultError("freshness anchor changed concurrently; retry")
        self._trust(committed, connection)


__all__ = [
    "AnchorStore",
    "FileAnchorStore",
    "FreshnessAnchor",
    "RollbackDetectedError",
]

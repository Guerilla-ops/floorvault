"""Opt-in rollback detection: a freshness anchor kept outside the database.

AES-SIV and the contextual AAD prove a ciphertext is authentic and sits at its
own coordinates. They cannot prove it is *current*: an attacker who can write
the database (``SECURITY.md`` §5, A3/A7) can restore an old backup, replay an
old row into its own coordinates, or delete and duplicate rows, and every
envelope still verifies.

A :class:`FreshnessAnchor` closes that gap for the tables it is told about. At
every commit it records a keyed digest of those tables' full contents in an
:class:`AnchorStore` that lives *outside* the database. :meth:`~FreshnessAnchor.verify`
recomputes the digest and refuses a database that does not match - whether
the whole file was rolled back or a single row was replayed, removed, or added.

The guarantee is exactly as strong as the anchor store's placement:

- It holds against anyone who can rewrite or restore the database but **not**
  the anchor (a store writer, a database-only backup restore, a stolen and
  re-planted file).
- It does **not** hold against an attacker who can roll back both together -
  for example a whole-disk snapshot that also contains a file anchor. Put the
  anchor where that attacker cannot reach: another volume or host, an OS
  key store, Vault, or a server. :class:`AnchorStore` is a two-method protocol
  so any of those can be plugged in.

Costs: every :meth:`~FreshnessAnchor.commit` and :meth:`~FreshnessAnchor.verify`
reads every row of the anchored tables, so this suits stores of modest size.
Writes must go through :meth:`~FreshnessAnchor.commit` (or be followed by
:meth:`~FreshnessAnchor.update` for code that commits itself); a write that
bypasses the anchor is - correctly - indistinguishable from tampering.

Crash safety: :meth:`~FreshnessAnchor.commit` records the new digest as
*pending* before the database commit and promotes it afterwards, so a crash
between the two never produces a false alarm. The pending state can only ever
be the newer one, so accepting it does not reopen a rollback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .beacons import _KEY_BYTES, _coerce_key_material, _snapshot_key
from .core import FloorVaultError
from .memory import HardenedMemoryKey
from .sqlite_adapter import _fold_sqlite, _quoted_identifier, _safe_column

#: HKDF domain-separation label for the anchor MAC key (SPEC.md §3).
_FRESHNESS_KEY_INFO = b"floorvault-v1-freshness"

#: Version tag bound into every MAC so the encoding can evolve.
_FORMAT = b"FVFA1"

_NAME_MAX = 128


class RollbackDetectedError(FloorVaultError):
    """The database does not match the state the freshness anchor recorded.

    Raised when anchored rows were rolled back, replayed, deleted or added
    outside :meth:`FreshnessAnchor.commit`, or when the anchor record itself
    fails authentication. Treat it as tampering: do not serve the data.
    """


class AnchorStore(Protocol):
    """Where a :class:`FreshnessAnchor` keeps its state.

    ``load`` returns the bytes last passed to ``save`` for ``name``, or ``None``
    if nothing was saved. ``save`` must be durable before it returns. The store
    is trusted for *freshness only*: its contents are authenticated, so it need
    not be secret, but it must not be something the attacker can roll back.
    """

    def load(self, name: str) -> Optional[bytes]: ...

    def save(self, name: str, blob: bytes) -> None: ...


class FileAnchorStore:
    """An :class:`AnchorStore` backed by one small file per anchor name.

    Only as trustworthy as the file's location: keep it off the volume, and
    out of the backup set, that holds the database. Writes go through a
    temporary file, ``fsync`` and ``os.replace``, so a crash leaves the old or
    the new record, never a torn one.
    """

    def __init__(self, directory: Union[str, os.PathLike[str]]) -> None:
        self.directory = Path(directory)
        self._lock = threading.Lock()

    def _path(self, name: str) -> Path:
        return self.directory / f"{name}.fvanchor"

    def load(self, name: str) -> Optional[bytes]:
        try:
            return self._path(name).read_bytes()
        except FileNotFoundError:
            return None

    def save(self, name: str, blob: bytes) -> None:
        with self._lock:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = self._path(name)
            temporary = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                try:
                    view = memoryview(blob)
                    while view:
                        view = view[os.write(descriptor, view) :]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(temporary, path)
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise


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
    """Detect rollback, replay, deletion and insertion in anchored tables.

    ``tables`` maps each anchored table to a column that orders its rows
    uniquely (normally the primary key). Every column of every anchored table
    is covered, so include the tables whose integrity matters and leave out
    high-churn ones the threat model does not need.

    Typical use::

        anchor = FreshnessAnchor(master_key, FileAnchorStore("/srv/anchors"),
                                 name="app-db", tables={"users": "id"})
        anchor.initialize(connection)        # once, on a database you trust
        ...
        anchor.verify(connection)            # on open; raises if rolled back
        table.store("u1", "token_cipher", new_token)
        anchor.commit(connection)            # instead of connection.commit()
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
        if not callable(getattr(store, "load", None)) or not callable(getattr(store, "save", None)):
            raise TypeError("store must provide load(name) and save(name, blob)")
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
        # The committed digest this instance last verified or wrote. commit()
        # and update() refuse to advance from any other state, so an
        # application that forgot verify() cannot bless a rolled-back database
        # as the new baseline.
        self._trusted: Optional[bytes] = None

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
        """Keyed digest of every row of every anchored table, as seen by ``connection``."""
        mac = hmac.new(self._key, digestmod=hashlib.sha256)
        mac.update(_FORMAT + b"digest" + _frame(self.name.encode("utf-8")))
        for table, order_column in self._tables.items():
            table_sql = _quoted_identifier(table)
            columns = sorted(
                _fold_sqlite(row[1])
                for row in connection.execute(f"PRAGMA table_info({table_sql})").fetchall()
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

    def _load_record(self) -> Optional[tuple[bytes, Optional[bytes]]]:
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
        return committed, pending

    # -- public operations ----------------------------------------------------

    def initialize(self, connection: Any) -> None:
        """Record ``connection``'s current state as the trusted baseline.

        Trust on first use: call it once, on a database you know is current.
        Refuses if the anchor already holds a record - re-baselining over an
        existing anchor would accept whatever state the database is in now,
        which is the attack this class exists to stop. To deliberately
        re-baseline, delete the anchor record through the store first.
        """
        if self._load_record() is not None:
            raise FloorVaultError(
                f"freshness anchor {self.name!r} is already initialized; refusing to re-baseline"
            )
        baseline = self.digest(connection)
        self.store.save(self.name, self._encode_record(baseline, None))
        self._trusted = baseline

    def _require_trusted(self) -> bytes:
        """Return the committed digest, refusing unless this instance vouched for it."""
        record = self._load_record()
        if record is None:
            raise RollbackDetectedError(
                f"freshness anchor {self.name!r} has no record; initialize() it first"
            )
        committed, _pending = record
        if self._trusted is None or not hmac.compare_digest(self._trusted, committed):
            raise RollbackDetectedError(
                "call verify() (or initialize()) on this anchor before writing: advancing "
                "from an unverified state would accept a rolled-back database as current"
            )
        return committed

    def verify(self, connection: Any) -> None:
        """Raise :class:`RollbackDetectedError` unless the database is current.

        Accepts the committed state, or the pending state left by a commit that
        crashed after the database write (and promotes it). A missing anchor
        record is refused, not treated as a fresh start: deleting the anchor
        must not be a way to disable the check.
        """
        record = self._load_record()
        if record is None:
            raise RollbackDetectedError(
                f"freshness anchor {self.name!r} has no record; refusing to trust the "
                "database (initialize() it on a known-good copy)"
            )
        committed, pending = record
        current = self.digest(connection)
        if hmac.compare_digest(current, committed):
            self._trusted = committed
            return
        if pending is not None and hmac.compare_digest(current, pending):
            self.store.save(self.name, self._encode_record(pending, None))
            self._trusted = pending
            return
        raise RollbackDetectedError(
            "database does not match its freshness anchor: anchored rows were rolled "
            "back, replayed, deleted or added outside FreshnessAnchor.commit()"
        )

    def commit(self, connection: Any) -> None:
        """Commit ``connection`` and advance the anchor to the new state.

        Requires that this instance has already :meth:`verify`-ed (or
        initialized) the database, and that the anchor has not moved since.
        """
        committed = self._require_trusted()
        new_state = self.digest(connection)
        self.store.save(self.name, self._encode_record(committed, new_state))
        connection.commit()
        self.store.save(self.name, self._encode_record(new_state, None))
        self._trusted = new_state

    def update(self, connection: Any) -> None:
        """Advance the anchor after a write the caller already committed.

        For code that owns its own commits (such as :class:`~floorvault.vaultkit.VaultStore`).
        Call :meth:`verify` before the write, as with :meth:`commit`. Not
        crash-safe the way :meth:`commit` is: a crash between the caller's
        commit and this call leaves a database the anchor rejects, which fails
        closed and is recovered by re-initializing from a copy you trust.
        """
        self._require_trusted()
        new_state = self.digest(connection)
        self.store.save(self.name, self._encode_record(new_state, None))
        self._trusted = new_state


__all__ = [
    "AnchorStore",
    "FileAnchorStore",
    "FreshnessAnchor",
    "RollbackDetectedError",
]

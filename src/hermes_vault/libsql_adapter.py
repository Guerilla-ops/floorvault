"""libSQL adapter: the SQLite adapter's contract over a libsql connection.

The libsql Python client (local files, embedded replicas, remote Turso)
deliberately mirrors the sqlite3 DBAPI surface - ``execute()`` returning a
cursor with ``fetchone()``/``rowcount``, ``commit()``, ``close()`` - so this
adapter shares :class:`EncryptedSQLiteTable`'s SQL and crypto paths
unchanged. The only difference is connection validation: a libsql
``Connection`` is structurally, not nominally, a ``sqlite3.Connection``, so
the parent's ``isinstance`` check would refuse it.

Boundaries (the package's usual doctrine, applied to a remote-capable
driver):

- The caller owns commits, exactly as with sqlite3.
- Remote servers own their storage internals: the local plaintext-residue
  story (``secure_delete`` + checkpoint + ``VACUUM``, see
  ``sqlite_migration.drop_plaintext_column``) cannot be observed through a
  remote connection, so this module offers store/load only.
- Affected-row counts come from the wire: a store whose cursor reports
  anything but one written row fails closed with ``LookupError`` rather
  than trusting an unverifiable write.
- Async clients are refused at construction: a coroutine returned where a
  cursor is expected would fail mid-operation instead of at the boundary.

File-layer encryption (opt-in, local files only):

:func:`connect_encrypted` opens a local libSQL file under the client's native
page encryption, keyed by :func:`derive_libsql_file_key` - an HKDF subkey of
the master key with its own domain label (SPEC.md §3), never the AEAD key.
The two layers are complementary: the file layer hides the schema, indexes,
WAL, and unprotected columns from anyone holding the file without the key;
the field layer still binds each protected value to its coordinates. The
native cipher (``aes256cbc`` in libsql 0.1.x) provides confidentiality only -
pages are not authenticated, so tampering with the file is not detected below
the field layer.

The factory, not the caller, owns the ``libsql.connect()`` call because the
client offers no way to confirm a connection is encrypted (``PRAGMA cipher``
reports a cipher on plaintext connections too) and fails open on an empty
key (``encryption_key=""`` writes a plaintext SQLite file). Remote URLs and
embedded-replica options are refused. Against a local ``sqld`` 0.24.30 a
remote connection accepted any key - including none and a wrong one - and
the server stored the rows in plaintext, so a key there is silently
meaningless; libsql 0.1.11 itself refuses a key on a synced (replica)
database. Server-side encryption is the server operator's concern. This is
the one function in the module that imports the client, and it does so
lazily.
"""

from __future__ import annotations

import inspect
import os
import re
from typing import Any, Protocol, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .beacons import _KEY_BYTES, _coerce_key_material, _snapshot_key
from .core import FloorVault
from .memory import HardenedMemoryKey
from .records import RecordBinding
from .sqlite_adapter import (
    EncryptedSQLiteTable,
    _fold_sqlite,
    _quoted_identifier,
    _safe_column,
    _safe_identifier,
)

#: HKDF domain-separation label for the libSQL file-layer key. Distinct from
#: the AEAD (``floorvault-v1-aes-siv``) and beacon labels: the page cipher and
#: the field AEAD must never share a key.
_FILE_KEY_INFO = b"floorvault-v1-libsql-file"

#: Header of an unencrypted SQLite database file.
_PLAINTEXT_SQLITE_HEADER = b"SQLite format 3\x00"

#: ``libsql.connect`` options a local encrypted connection may pass through.
#: Everything else is either owned here (``encryption_key``) or selects a
#: remote / replica mode whose key handling cannot be verified locally.
_PASSTHROUGH_OPTIONS = frozenset({"timeout", "isolation_level", "autocommit"})

_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(//)?")


class _LibSqlConnection(Protocol):
    """The slice of the libsql client's Connection surface the adapter uses."""

    def execute(self, sql: str, parameters: Any = ...) -> Any: ...

    def commit(self) -> None: ...


def _check_connection(connection: object) -> None:
    """Refuse objects that cannot satisfy the sync DBAPI-shaped contract."""
    execute = getattr(connection, "execute", None)
    if not callable(execute) or not callable(getattr(connection, "commit", None)):
        raise TypeError("connection must be a libsql Connection (sync execute()/commit() surface)")
    if inspect.iscoroutinefunction(execute):
        raise TypeError(
            "async libsql clients are not supported; pass a sync libsql.connect() connection"
        )


class EncryptedLibSqlTable(EncryptedSQLiteTable):
    """Store and load encrypted fields in an existing libSQL table.

    Identical contract to :class:`EncryptedSQLiteTable`; the connection is
    a libsql ``Connection`` (``libsql.connect()`` - local file, embedded
    replica, or remote URL). The caller must call ``connection.commit()``
    after store calls.
    """

    def __init__(
        self,
        connection: _LibSqlConnection,
        crypto: FloorVault,
        table_name: str,
        *,
        id_column: str = "id",
        schema_id: str = "hermes.vault.v1",
    ) -> None:
        _check_connection(connection)
        if not isinstance(crypto, FloorVault):
            raise TypeError("crypto must be a FloorVault")
        self.connection = connection
        self.crypto = crypto
        # libSQL shares SQLite's ASCII-case-insensitive identifier resolution:
        # fold to physical identity exactly as EncryptedSQLiteTable does.
        self.table_name = _fold_sqlite(_safe_identifier(table_name))
        self.id_column = _fold_sqlite(_safe_column(id_column))
        self.schema_id = schema_id
        self._table_sql = _quoted_identifier(self.table_name)
        self._id_sql = _quoted_identifier(self.id_column)
        self._binding = RecordBinding(crypto, self.table_name, schema_id=schema_id)


def derive_libsql_file_key(master_key: Union[bytes, bytearray, HardenedMemoryKey]) -> str:
    """Derive the libSQL file-layer key from a 32-byte master key.

    HKDF-SHA256 with the domain-separating label ``floorvault-v1-libsql-file``
    (SPEC.md §3), returned as 64 lowercase hex characters because the libsql
    client accepts the key only as ``str``. That string is immutable and cannot
    be wiped; it is the client's API, not a choice made here, so prefer
    :func:`connect_encrypted`, which keeps the only reference for the duration
    of the ``connect()`` call rather than handing it to the caller.
    """
    source = _snapshot_key(
        _coerce_key_material(master_key, what="master key"),
        owner=master_key if isinstance(master_key, HardenedMemoryKey) else None,
    )
    try:
        if len(source) != _KEY_BYTES:
            raise ValueError(f"master key must be exactly {_KEY_BYTES} bytes")
        return (
            HKDF(
                algorithm=hashes.SHA256(),
                length=_KEY_BYTES,
                salt=None,
                info=_FILE_KEY_INFO,
            )
            .derive(source)
            .hex()
        )
    finally:
        for index in range(len(source)):
            source[index] = 0


def _local_database_path(database: Union[str, os.PathLike[str]]) -> str:
    """Return ``database`` as a local file path, refusing anything else."""
    try:
        path = os.fspath(database)
    except TypeError:
        raise TypeError("database must be a local file path (str or os.PathLike)") from None
    if not isinstance(path, str):
        raise TypeError("database must be a str path, not bytes")
    if not path or path == ":memory:":
        raise ValueError("file-layer encryption needs a database file, not an in-memory database")
    # A Windows drive letter ("C:\\db" / "C:/db") is a path, not a scheme.
    if _URL_SCHEME.match(path) and not re.match(r"^[A-Za-z]:[\\/]", path):
        raise ValueError(
            "connect_encrypted opens local files only; a remote server ignores "
            "the encryption key, and URI forms are not accepted"
        )
    return path


def connect_encrypted(
    database: Union[str, os.PathLike[str]],
    master_key: Union[bytes, bytearray, HardenedMemoryKey],
    **options: Any,
) -> Any:
    """Open a local libSQL file encrypted at rest under a derived file key.

    The key is :func:`derive_libsql_file_key` of ``master_key``. A new file is
    created encrypted; an existing file must already be encrypted under the
    same key. The connection is probed before it is returned, so a wrong key
    fails here with ``ValueError`` rather than on the first query.

    Refused, fail-closed:

    - remote URLs, URIs and ``:memory:`` (``ValueError``);
    - an existing unencrypted SQLite file (``ValueError``) - libSQL cannot
      encrypt in place; migrate the rows into a fresh encrypted file instead;
    - any ``libsql.connect`` option other than ``timeout``,
      ``isolation_level`` and ``autocommit`` (``TypeError``) - in particular
      ``encryption_key`` (owned here) and the embedded-replica / remote
      options ``sync_url``, ``sync_interval``, ``offline`` and ``auth_token``.

    The returned connection is a plain libsql ``Connection``; pass it to
    :class:`EncryptedLibSqlTable` for field-level encryption on top.
    """
    unsupported = sorted(set(options) - _PASSTHROUGH_OPTIONS)
    if unsupported:
        raise TypeError(
            f"connect_encrypted does not accept {', '.join(unsupported)}; "
            f"only {', '.join(sorted(_PASSTHROUGH_OPTIONS))} pass through to libsql.connect"
        )
    path = _local_database_path(database)
    try:
        with open(path, "rb") as handle:
            header = handle.read(len(_PLAINTEXT_SQLITE_HEADER))
    except FileNotFoundError:
        header = b""
    if header == _PLAINTEXT_SQLITE_HEADER:
        raise ValueError(
            "database is an unencrypted SQLite file; libSQL cannot encrypt it in "
            "place - copy the data into a new file opened with connect_encrypted"
        )
    try:
        import libsql
    except ImportError as exc:
        raise ImportError(
            "connect_encrypted requires the libsql client (install floorvault[libsql])"
        ) from exc

    file_key = derive_libsql_file_key(master_key)
    try:
        connection = libsql.connect(path, encryption_key=file_key, **options)
    finally:
        del file_key
    try:
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except Exception as exc:
        connection.close()
        raise ValueError(
            "could not open the database under the derived file key "
            "(wrong master key, or not a FloorVault-encrypted libSQL file)"
        ) from exc
    return connection

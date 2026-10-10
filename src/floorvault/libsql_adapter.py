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
"""

from __future__ import annotations

import inspect
from typing import Any, Protocol

from .core import FloorVault
from .records import RecordBinding
from .sqlite_adapter import (
    EncryptedSQLiteTable,
    _fold_sqlite,
    _quoted_identifier,
    _safe_column,
    _safe_identifier,
)


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
        schema_id: str = "floor.vault.v1",
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

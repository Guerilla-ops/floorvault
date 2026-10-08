"""PEP 249 (DB-API 2.0) adapters: contextual encryption beyond SQLite.

These classes carry the exact contract of
:class:`floorvault.sqlite_adapter.EncryptedSQLiteTable` to PostgreSQL and
MySQL drivers: the caller owns schema creation and transaction commits,
ciphertext columns are binary (``BYTEA`` on PostgreSQL, ``VARBINARY`` or
``BLOB`` on MySQL), and storing to a missing record raises rather than
inserting a row accidentally. The AAD coordinates - table, record ID,
column, schema ID - are computed identically, so an envelope written by
``EncryptedSQLiteTable`` decrypts through these adapters against the same
coordinates (and vice versa): engine migrations need no re-encryption.

Two dialect differences matter, and both live at the SQL text boundary -
never in the cryptography:

* Identifier quoting. PostgreSQL's ``"name"`` and MySQL's `` `name` `` are
  each that engine's fail-closed quote: ``"name"`` is always an identifier
  on PostgreSQL, and a backticked name is always an identifier on MySQL in
  every ``sql_mode``. The reverse does not hold - on MySQL's default mode
  ``"name"`` silently degrades to a string literal, which is the fail-open
  behaviour the SQLite adapter already rejects by bracket-quoting.
* Parameter style. Every sync driver in scope - psycopg 2/3,
  mysql-connector-python, PyMySQL, pg8000 - uses the ``format``/``pyformat``
  ``%s`` placeholder, so the statement text differs only in quoting.

The connection itself is checked structurally (``runtime_checkable``), not
by driver class: psycopg, mysql-connector and PyMySQL expose the same
``cursor()`` seam, and a hard isinstance list would only fail closed for
drivers not yet imported - a maintenance trap, not a security boundary.

A MySQL ``UPDATE`` that changes nothing normally reports ``rowcount = 0``,
which would masquerade as a missing record here. It cannot trigger through
this adapter: FloorVault nonces are randomized, so every ``store`` writes
fresh ciphertext and the row always "changes". Callers who reuse the
connection for ordinary writes should still know the ``CLIENT_FOUND_ROWS``
flag exists, but this adapter's invariant does not depend on it.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Union, runtime_checkable

from .core import FloorVault
from .records import RecordBinding
from .sqlite_adapter import _safe_identifier

__all__ = [
    "EncryptedPostgresTable",
    "EncryptedMySQLTable",
]


@runtime_checkable
class DBAPIConnection(Protocol):
    """The slice of PEP 249 a table adapter needs: one cursor factory.

    ``runtime_checkable`` makes the constructor's guard honest: it verifies
    the object offers ``cursor()``, which is the only connection method the
    adapter calls. Statements, parameters and commits flow through that
    seam identically on psycopg, mysql-connector and PyMySQL.
    """

    def cursor(self) -> Any: ...


def _quote_all(name: str, mark: str) -> str:
    """Validate ``name`` and wrap each dotted part in the dialect's quote mark.

    The allow-list charset (``_safe_identifier``) cannot produce the closing
    mark - ``"``, `` ` `` and ``]`` are all rejected - so no escape step is
    needed, matching the reasoning behind the SQLite adapter's brackets.
    Dotted names quote per part (``"schema"."table"``), because the AAD
    coordinate keeps the unquoted logical name while the SQL names the real
    qualified relation.
    """
    return ".".join(f"{mark}{part}{mark}" for part in _safe_identifier(name).split("."))


class _EncryptedDBAPITable:
    """Shared implementation for the PEP 249 table adapters.

    Only ``_QUOTE`` differs between engines; every method below is written
    once so the exactly-one-record and NULL invariants cannot drift between
    dialects. Cryptographic coordinates go through :class:`RecordBinding`,
    the driver-free layer the adapters already share.
    """

    _QUOTE = ""

    def __init__(
        self,
        connection: DBAPIConnection,
        crypto: FloorVault,
        table_name: str,
        *,
        id_column: str = "id",
        schema_id: str = "floor.vault.v1",
    ) -> None:
        if not isinstance(connection, DBAPIConnection):
            raise TypeError("connection must be a DB-API 2.0 connection offering cursor()")
        if not isinstance(crypto, FloorVault):
            raise TypeError("crypto must be a FloorVault")
        self.connection = connection
        self.crypto = crypto
        self.table_name = _safe_identifier(table_name)
        self.id_column = _safe_identifier(id_column)
        self.schema_id = schema_id
        self._binding = RecordBinding(crypto, self.table_name, schema_id=schema_id)
        self._table_sql = _quote_all(table_name, self._QUOTE)
        self._id_sql = _quote_all(id_column, self._QUOTE)

    def store(
        self,
        record_id: str,
        encrypted_column: str,
        value: Union[str, bytes],
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> None:
        """Encrypt ``value`` and update exactly one existing record.

        The caller must call ``connection.commit()``. A missing record raises
        ``LookupError`` and does not insert a new row accidentally.
        """
        column = _safe_identifier(encrypted_column)
        column_sql = _quote_all(encrypted_column, self._QUOTE)
        ciphertext = self._binding.encrypt_field(
            record_id,
            column,
            value,
            schema_version=schema_version,
            revision=revision,
        )
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"UPDATE {self._table_sql} SET {column_sql} = %s WHERE {self._id_sql} = %s",  # identifiers allow-listed + quoted  # nosec B608
                (ciphertext, record_id),
            )
            if cursor.rowcount != 1:
                raise LookupError(f"record not found: {record_id!r}")
        finally:
            cursor.close()

    def load(
        self,
        record_id: str,
        encrypted_column: str,
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> str:
        """Load and decrypt one field from exactly one existing record.

        Returns text. A value stored from ``bytes`` that is not valid UTF-8
        cannot be returned here - use :meth:`load_bytes` for those, so the
        binary path is not one-way.
        """
        column, ciphertext = self._fetch_ciphertext(record_id, encrypted_column)
        return self._binding.decrypt_field(
            record_id,
            column,
            ciphertext,
            schema_version=schema_version,
            revision=revision,
        )

    def load_bytes(
        self,
        record_id: str,
        encrypted_column: str,
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> bytes:
        """Load and decrypt one field as raw bytes.

        The counterpart to storing ``bytes``: :meth:`load` can only return
        text, so without this a binary value could be written and never read
        back. Text values decrypt to their UTF-8 bytes here.
        """
        column, ciphertext = self._fetch_ciphertext(record_id, encrypted_column)
        return self._binding.decrypt_field_bytes(
            record_id,
            column,
            ciphertext,
            schema_version=schema_version,
            revision=revision,
        )

    def store_fields(
        self,
        record_id: str,
        fields: Mapping[str, Union[str, bytes]],
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> None:
        """Encrypt several columns and update one record in a single statement.

        Equivalent to calling :meth:`store` per field, but one ``UPDATE`` and
        one shared AAD build replace a statement and a full AAD construction
        per field. The caller must still call ``connection.commit()``.
        """
        columns = [_safe_identifier(name) for name in fields]
        if not columns:
            raise ValueError("fields must not be empty")
        envelopes = self._binding.encrypt_fields(
            record_id,
            fields,
            schema_version=schema_version,
            revision=revision,
        )
        assignments = ", ".join(f"{_quote_all(column, self._QUOTE)} = %s" for column in columns)
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"UPDATE {self._table_sql} SET {assignments} WHERE {self._id_sql} = %s",  # identifiers allow-listed + quoted  # nosec B608
                (*(envelopes[column] for column in columns), record_id),
            )
            if cursor.rowcount != 1:
                raise LookupError(f"record not found: {record_id!r}")
        finally:
            cursor.close()

    def load_fields(
        self,
        record_id: str,
        encrypted_columns: list[str] | tuple[str, ...],
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> dict[str, str]:
        """Load and decrypt several fields of one record with one SELECT.

        Same "exactly one existing record" and NULL invariants as
        :meth:`load`; values must decode as UTF-8 (use :meth:`load_fields_bytes`
        for columns stored from ``bytes``).
        """
        raw = self._fetch_and_decrypt_fields(
            record_id, encrypted_columns, schema_version=schema_version, revision=revision
        )
        decoded: dict[str, str] = {}
        for column, value in raw.items():
            try:
                decoded[column] = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"encrypted field {self.table_name}.{column} is not valid UTF-8; "
                    "use load_fields_bytes() for binary values"
                ) from exc
        return decoded

    def load_fields_bytes(
        self,
        record_id: str,
        encrypted_columns: list[str] | tuple[str, ...],
        *,
        schema_version: int = 1,
        revision: int | None = None,
    ) -> dict[str, bytes]:
        """Load and decrypt several fields of one record as raw bytes."""
        return self._fetch_and_decrypt_fields(
            record_id, encrypted_columns, schema_version=schema_version, revision=revision
        )

    def _fetch_and_decrypt_fields(
        self,
        record_id: str,
        encrypted_columns: list[str] | tuple[str, ...],
        *,
        schema_version: int,
        revision: int | None,
    ) -> dict[str, bytes]:
        columns = [_safe_identifier(name) for name in encrypted_columns]
        if not columns:
            return {}
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"SELECT {', '.join(_quote_all(c, self._QUOTE) for c in columns)} "
                f"FROM {self._table_sql} WHERE {self._id_sql} = %s",  # identifiers allow-listed + quoted  # nosec B608
                (record_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise LookupError(f"record not found: {record_id!r}")
        envelopes = dict(zip(columns, row))
        for column, value in envelopes.items():
            if value is None:
                raise ValueError(f"encrypted field is NULL: {self.table_name}.{column}")
        return self._binding.decrypt_fields(
            record_id,
            envelopes,
            schema_version=schema_version,
            revision=revision,
        )

    def _fetch_ciphertext(self, record_id: str, encrypted_column: str) -> tuple[str, bytes]:
        """Return ``(validated column name, ciphertext)`` for exactly one record.

        Shared by both accessors so the "exactly one existing record" and NULL
        invariants cannot drift apart between the text and bytes paths.
        """
        column = _safe_identifier(encrypted_column)
        column_sql = _quote_all(encrypted_column, self._QUOTE)
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                f"SELECT {column_sql} FROM {self._table_sql} WHERE {self._id_sql} = %s",  # identifiers allow-listed + quoted  # nosec B608
                (record_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise LookupError(f"record not found: {record_id!r}")
        if row[0] is None:
            raise ValueError(f"encrypted field is NULL: {self.table_name}.{column}")
        return column, row[0]


class EncryptedPostgresTable(_EncryptedDBAPITable):
    """Store and load encrypted fields in an existing PostgreSQL table.

    Works with any sync PostgreSQL driver speaking ``format``-style ``%s``
    placeholders (psycopg 2/3, pg8000). Ciphertext columns should be
    ``BYTEA``; the caller owns schema creation and ``connection.commit()``.
    ``table_name`` may be schema-qualified (``"app.users"``), which quotes
    as ``"app"."users"`` while the AAD coordinate stays the logical name.
    """

    _QUOTE = '"'


class EncryptedMySQLTable(_EncryptedDBAPITable):
    """Store and load encrypted fields in an existing MySQL table.

    Works with mysql-connector-python and PyMySQL. Ciphertext columns
    should be ``VARBINARY`` or ``BLOB``; the caller owns schema creation
    and ``connection.commit()``. ``table_name`` may be database-qualified
    (``"shop.users"``), quoting as `` `shop`.`users` ``.
    """

    _QUOTE = "`"

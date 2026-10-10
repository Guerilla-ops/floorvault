"""High-level SQLite adapter for contextual encryption."""

from __future__ import annotations

import re
import sqlite3
from typing import Mapping, Union

from .core import FloorVault
from .records import RecordBinding

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?$")


def _safe_identifier(name: str) -> str:
    """Validate an SQL identifier before it is inserted into query text."""
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("Identifier must be a non-empty string of at most 128 characters")
    if _IDENTIFIER_RE.fullmatch(name) is None:
        raise ValueError(f"{name!r} is not a valid SQL identifier")
    return name


def _safe_column(name: str) -> str:
    """Validate a bare column name - qualified names like ``users.id`` are
    refused so a qualified spelling cannot slip past the id-column guard to
    name the same physical column."""
    if "." in name:
        raise ValueError(f"{name!r} is not a bare column name")
    return _safe_identifier(name)


def _fold_sqlite(name: str) -> str:
    """Fold an identifier to SQLite's physical identity (ASCII case fold).

    SQLite resolves table and column names ASCII-case-insensitively, so
    ``users`` and ``Users`` are one physical object. Binding the literal
    spelling into AAD would give one physical object several cryptographic
    identities - two adapters spelling it differently would clobber each
    other's writes. ASCII-only on purpose: ``casefold``/``lower`` converge
    characters SQLite treats as distinct (e.g. 'Ä' vs 'ä'), which would merge
    objects the engine keeps separate.
    """
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in name)


def _bound_record_id(record_id: str) -> str:
    """Return the exact-``str`` form of a record identifier.

    sqlite3 honours ``__conform__`` on str subclasses, so a subclass instance
    could make the bound SQL parameter differ from the coordinate AAD signs -
    the write would land on a different row than its cryptographic identity.
    Normalizing to a plain str removes the hook before either side sees it.
    """
    return str(record_id) if isinstance(record_id, str) else record_id


def _quoted_identifier(name: str) -> str:
    """Validate ``name`` and return it bracket-quoted for SQL interpolation.

    Validation alone is not enough: allow-listed names such as ``TRUE`` or
    ``CURRENT_TIMESTAMP`` still resolve as expressions when interpolated
    unquoted. Brackets fail closed - an unmatched ``[name]`` is an error -
    while a double-quoted unknown name silently degrades to a string literal.
    The allow-list charset cannot produce ``]``, so no escape step is needed.
    """
    return ".".join(f"[{part}]" for part in _safe_identifier(name).split("."))


class EncryptedSQLiteTable:
    """Store and load encrypted fields in an existing SQLite table.

    The caller owns schema creation and transaction commits. Table, ID-column and
    encrypted-column names are validated before query construction; record IDs and
    plaintext values remain bound parameters or cryptographic inputs. The record
    ID is always included in FloorVault's associated data, so callers must use the
    same ID for ``store`` and ``load``.

    Cryptographic coordinates follow SQLite's physical identity, not the literal
    spelling: table and column names are ASCII-folded (``users`` and ``Users``
    name one table - and now one AAD coordinate), and record IDs are normalized
    to a plain ``str`` so a subclass's ``__conform__``/``encode`` hooks cannot
    make the SQL binding diverge from the signed coordinate.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        crypto: FloorVault,
        table_name: str,
        *,
        id_column: str = "id",
        schema_id: str = "floor.vault.v1",
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3.Connection")
        if not isinstance(crypto, FloorVault):
            raise TypeError("crypto must be a FloorVault")
        self.connection = connection
        self.crypto = crypto
        # Folded to physical identity: SQLite is ASCII-case-insensitive, so
        # every spelling of one table/column must share one AAD coordinate.
        self.table_name = _fold_sqlite(_safe_identifier(table_name))
        self.id_column = _fold_sqlite(_safe_column(id_column))
        self.schema_id = schema_id
        self._table_sql = _quoted_identifier(self.table_name)
        self._id_sql = _quoted_identifier(self.id_column)
        self._binding = RecordBinding(crypto, self.table_name, schema_id=schema_id)

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
        ``LookupError`` and does not insert a new row accidentally. A match
        that is not unique (a duplicate or case-collided id) raises
        ``ValueError`` and writes NOTHING - the match count is part of the
        UPDATE's own WHERE clause, so a multi-row write cannot be persisted
        by a later caller commit.
        """
        record_id = _bound_record_id(record_id)
        column = _fold_sqlite(_safe_column(encrypted_column))
        if column == self.id_column:
            raise ValueError(
                f"encrypted column {column!r} must not be the id column "
                f"{self.id_column!r}: writing it would destroy the record's own key"
            )
        column_sql = _quoted_identifier(column)
        ciphertext = self._binding.encrypt_field(
            record_id,
            column,
            value,
            schema_version=schema_version,
            revision=revision,
        )
        try:
            cursor = self.connection.execute(
                f"UPDATE {self._table_sql} SET {column_sql} = ? "
                f"WHERE {self._id_sql} = ? AND ("
                f"SELECT COUNT(*) FROM {self._table_sql} WHERE {self._id_sql} = ?) = 1",  # identifiers allow-listed + quoted  # nosec B608
                (ciphertext, record_id, record_id),
            )
        except Exception as exc:
            raise ValueError(f"store failed on {self.table_name}: {exc}") from exc
        if cursor.rowcount != 1:
            self._raise_for_refused_write(record_id)

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
        record_id = _bound_record_id(record_id)
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

        The counterpart to storing ``bytes``: :meth:`load` can only return text,
        so without this a binary value could be written and never read back.
        Text values decrypt to their UTF-8 bytes here.
        """
        record_id = _bound_record_id(record_id)
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
        record_id = _bound_record_id(record_id)
        columns = [_fold_sqlite(_safe_column(name)) for name in fields]
        if not columns:
            raise ValueError("fields must not be empty")
        if len(set(columns)) != len(columns):
            raise ValueError("fields contain two spellings of the same physical column")
        for column in columns:
            if column == self.id_column:
                raise ValueError(
                    f"encrypted column {column!r} must not be the id column "
                    f"{self.id_column!r}: writing it would destroy the record's own key"
                )
        folded_fields = dict(zip(columns, fields.values()))
        envelopes = self._binding.encrypt_fields(
            record_id,
            folded_fields,
            schema_version=schema_version,
            revision=revision,
        )
        assignments = ", ".join(f"{_quoted_identifier(column)} = ?" for column in columns)
        try:
            cursor = self.connection.execute(
                f"UPDATE {self._table_sql} SET {assignments} "
                f"WHERE {self._id_sql} = ? AND ("
                f"SELECT COUNT(*) FROM {self._table_sql} WHERE {self._id_sql} = ?) = 1",  # identifiers allow-listed + quoted  # nosec B608
                (*(envelopes[column] for column in columns), record_id, record_id),
            )
        except Exception as exc:
            raise ValueError(f"store failed on {self.table_name}: {exc}") from exc
        if cursor.rowcount != 1:
            self._raise_for_refused_write(record_id)

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
        record_id = _bound_record_id(record_id)
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
        record_id = _bound_record_id(record_id)
        columns = [_fold_sqlite(_safe_column(name)) for name in encrypted_columns]
        if not columns:
            return {}
        try:
            cursor = self.connection.execute(
                f"SELECT {', '.join(_quoted_identifier(c) for c in columns)} "
                f"FROM {self._table_sql} WHERE {self._id_sql} = ?",  # identifiers allow-listed + quoted  # nosec B608
                (record_id,),
            )
        except Exception as exc:
            raise ValueError(f"load failed on {self.table_name}: {exc}") from exc
        row = cursor.fetchone()
        second = None if row is None else cursor.fetchone()
        if row is None:
            raise LookupError(f"record not found in {self.table_name}")
        if second is not None:
            raise ValueError(
                f"the id column matched more than one row in "
                f"{self.table_name}; the id column must be unique"
            )
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
        record_id = _bound_record_id(record_id)
        column = _fold_sqlite(_safe_column(encrypted_column))
        column_sql = _quoted_identifier(column)
        try:
            cursor = self.connection.execute(
                f"SELECT {column_sql} FROM {self._table_sql} WHERE {self._id_sql} = ?",  # identifiers allow-listed + quoted  # nosec B608
                (record_id,),
            )
        except Exception as exc:
            raise ValueError(f"load failed on {self.table_name}: {exc}") from exc
        row = cursor.fetchone()
        second = None if row is None else cursor.fetchone()
        if row is None:
            raise LookupError(f"record not found in {self.table_name}")
        if second is not None:
            raise ValueError(
                f"the id column matched more than one row in "
                f"{self.table_name}; the id column must be unique"
            )
        if row[0] is None:
            raise ValueError(f"encrypted field is NULL: {self.table_name}.{column}")
        return column, row[0]

    def _raise_for_refused_write(self, record_id: str) -> None:
        """Raise the error matching why a guarded UPDATE wrote zero rows.

        The atomic ``COUNT(*) = 1`` clause means the UPDATE wrote nothing, so
        this lookup exists only to name the failure: no matching row is
        ``LookupError``; several is a schema violation, ``ValueError``, so a
        caller treating "not found" as retryable cannot mistake a corrupted
        schema for an absent record.
        """
        matches = self.connection.execute(
            f"SELECT COUNT(*) FROM {self._table_sql} WHERE {self._id_sql} = ?",  # identifiers allow-listed + quoted  # nosec B608
            (_bound_record_id(record_id),),
        ).fetchone()[0]
        if matches > 1:
            raise ValueError(
                f"the id column matched more than one row in "
                f"{self.table_name}; the id column must be unique"
            )
        raise LookupError(f"record not found in {self.table_name}")


class ContextualTable:
    """Helper binding an individual SQLite table to the contextual crypto engine."""

    def __init__(
        self,
        crypto: FloorVault,
        table_name: str,
        *,
        schema_id: str = "floor.vault.v1",
    ) -> None:
        self.crypto = crypto
        self.table_name = table_name
        self.schema_id = schema_id

    def encrypt(
        self,
        record_id: str,
        column: str,
        value: Union[str, bytes],
        *,
        schema_version: int = 1,
    ) -> bytes:
        """Encrypt field bound to this table and record_id."""
        return self.crypto.encrypt(
            value,
            table=self.table_name,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=schema_version,
        )

    def decrypt(
        self,
        record_id: str,
        column: str,
        ciphertext: bytes,
        *,
        schema_version: int = 1,
    ) -> str:
        """Decrypt field verifying contextual coordinates."""
        return self.crypto.decrypt(
            ciphertext,
            table=self.table_name,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=schema_version,
        )


class ContextualSQLite:
    """Contextual encryption wrapper around a standard SQLite connection."""

    def __init__(self, connection: sqlite3.Connection, crypto: FloorVault) -> None:
        self.connection = connection
        self.crypto = crypto

    def table(self, table_name: str, *, schema_id: str = "floor.vault.v1") -> ContextualTable:
        """Get table-bound cryptographic helper."""
        return ContextualTable(self.crypto, table_name, schema_id=schema_id)

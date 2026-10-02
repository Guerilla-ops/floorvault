"""High-level SQLite adapter for contextual encryption."""

from __future__ import annotations

import re
import sqlite3
from typing import Mapping, Union

from .core import FloorVault

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?$")


def _safe_identifier(name: str) -> str:
    """Validate an SQL identifier before it is inserted into query text."""
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("Identifier must be a non-empty string of at most 128 characters")
    if _IDENTIFIER_RE.fullmatch(name) is None:
        raise ValueError(f"{name!r} is not a valid SQL identifier")
    return name


class EncryptedSQLiteTable:
    """Store and load encrypted fields in an existing SQLite table.

    The caller owns schema creation and transaction commits. Table, ID-column and
    encrypted-column names are validated before query construction; record IDs and
    plaintext values remain bound parameters or cryptographic inputs. The record
    ID is always included in FloorVault's associated data, so callers must use the
    same ID for ``store`` and ``load``.
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
        self.table_name = _safe_identifier(table_name)
        self.id_column = _safe_identifier(id_column)
        self.schema_id = schema_id

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
        ciphertext = self.crypto.encrypt(
            value,
            table=self.table_name,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=schema_version,
            revision=revision,
        )
        cursor = self.connection.execute(
            f"UPDATE {self.table_name} SET {column} = ? WHERE {self.id_column} = ?",
            (ciphertext, record_id),
        )
        if cursor.rowcount != 1:
            raise LookupError(f"record not found: {record_id!r}")

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
        return self.crypto.decrypt(
            ciphertext,
            table=self.table_name,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
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
        column, ciphertext = self._fetch_ciphertext(record_id, encrypted_column)
        return self.crypto.decrypt_bytes(
            ciphertext,
            table=self.table_name,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
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
        envelopes = self.crypto.encrypt_fields(
            fields,
            table=self.table_name,
            record_id=record_id,
            schema_id=self.schema_id,
            schema_version=schema_version,
            revision=revision,
        )
        assignments = ", ".join(f"{column} = ?" for column in columns)
        cursor = self.connection.execute(
            f"UPDATE {self.table_name} SET {assignments} WHERE {self.id_column} = ?",
            (*(envelopes[column] for column in columns), record_id),
        )
        if cursor.rowcount != 1:
            raise LookupError(f"record not found: {record_id!r}")

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
        row = self.connection.execute(
            f"SELECT {', '.join(columns)} FROM {self.table_name} WHERE {self.id_column} = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise LookupError(f"record not found: {record_id!r}")
        envelopes = dict(zip(columns, row))
        for column, value in envelopes.items():
            if value is None:
                raise ValueError(f"encrypted field is NULL: {self.table_name}.{column}")
        return self.crypto.decrypt_fields(
            envelopes,
            table=self.table_name,
            record_id=record_id,
            schema_id=self.schema_id,
            schema_version=schema_version,
            revision=revision,
        )

    def _fetch_ciphertext(self, record_id: str, encrypted_column: str) -> tuple[str, bytes]:
        """Return ``(validated column name, ciphertext)`` for exactly one record.

        Shared by both accessors so the "exactly one existing record" and NULL
        invariants cannot drift apart between the text and bytes paths.
        """
        column = _safe_identifier(encrypted_column)
        row = self.connection.execute(
            f"SELECT {column} FROM {self.table_name} WHERE {self.id_column} = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise LookupError(f"record not found: {record_id!r}")
        if row[0] is None:
            raise ValueError(f"encrypted field is NULL: {self.table_name}.{column}")
        return column, row[0]


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

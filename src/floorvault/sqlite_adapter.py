"""High-level SQLite adapter for contextual encryption and blind indexing."""

from __future__ import annotations

import sqlite3
from typing import Union

from .core import FloorVault


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

    def blind_index(self, column: str, value: str) -> bytes:
        """Compute blind index scoped to table.column."""
        scope = f"{self.table_name}.{column}"
        return self.crypto.blind_index(value, scope=scope)


class ContextualSQLite:
    """Contextual encryption wrapper around a standard SQLite connection."""

    def __init__(self, connection: sqlite3.Connection, crypto: FloorVault) -> None:
        self.connection = connection
        self.crypto = crypto

    def table(self, table_name: str, *, schema_id: str = "floor.vault.v1") -> ContextualTable:
        """Get table-bound cryptographic helper."""
        return ContextualTable(self.crypto, table_name, schema_id=schema_id)

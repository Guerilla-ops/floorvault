"""Safe migration helpers for existing SQLite tables."""

from __future__ import annotations

import sqlite3
from typing import Any

from .core import FloorVault
from .sqlite_adapter import _quoted_identifier, _safe_identifier


def _validate_inputs(
    connection: sqlite3.Connection,
    crypto: FloorVault,
    table: str,
    id_column: str,
    source_column: str,
    destination_column: str,
) -> tuple[str, str, str, str]:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection")
    if not isinstance(crypto, FloorVault):
        raise TypeError("crypto must be a FloorVault")
    table_name = _safe_identifier(table)
    id_name = _safe_identifier(id_column)
    source_name = _safe_identifier(source_column)
    destination_name = _safe_identifier(destination_column)
    if source_name == destination_name:
        raise ValueError("source and destination columns must differ")
    return table_name, id_name, source_name, destination_name


def migrate_plaintext_column(
    connection: sqlite3.Connection,
    crypto: FloorVault,
    *,
    table: str,
    id_column: str,
    source_column: str,
    destination_column: str,
) -> dict[str, int]:
    """Encrypt a plaintext column into an existing destination BLOB column.

    The source column is never deleted or modified. The operation is atomic from
    SQLite's transaction perspective: an exception rolls back all destination
    writes. It refuses to overwrite any non-NULL destination value when a source
    value exists, preventing an ambiguous partial migration. The caller owns the
    connection and should not rely on implicit commit behavior outside this
    function.
    """
    table, id_column, source_column, destination_column = _validate_inputs(
        connection, crypto, table, id_column, source_column, destination_column
    )
    sql_table, sql_id, sql_source, sql_dest = (
        _quoted_identifier(n) for n in (table, id_column, source_column, destination_column)
    )
    with connection:
        conflict = connection.execute(  # identifiers allow-listed + quoted  # nosemgrep: floorvault-sql-interpolation
            f"SELECT 1 FROM {sql_table} WHERE {sql_source} IS NOT NULL "  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
            f"AND {sql_dest} IS NOT NULL LIMIT 1"
        ).fetchone()
        if conflict is not None:
            raise ValueError("destination column already contains data")

        rows = connection.execute(  # identifiers allow-listed + quoted  # nosemgrep: floorvault-sql-interpolation
            f"SELECT {sql_id}, {sql_source} FROM {sql_table} WHERE {sql_source} IS NOT NULL"  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
        ).fetchall()
        migrated = 0
        for record_id, plaintext in rows:
            if record_id is None:
                raise ValueError("record ID cannot be NULL")
            if not isinstance(plaintext, (str, bytes, bytearray)):
                raise TypeError("plaintext values must be str or bytes")
            ciphertext = crypto.encrypt(
                bytes(plaintext) if isinstance(plaintext, bytearray) else plaintext,
                table=table,
                record_id=str(record_id),
                column=destination_column,
            )
            cursor = connection.execute(  # identifiers allow-listed + quoted  # nosemgrep: floorvault-sql-interpolation
                f"UPDATE {sql_table} SET {sql_dest} = ? WHERE {sql_id} = ?",  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
                (ciphertext, record_id),
            )
            if cursor.rowcount != 1:
                raise LookupError(f"record not found during migration: {record_id!r}")
            migrated += 1

        skipped_null = connection.execute(  # identifiers allow-listed + quoted  # nosemgrep: floorvault-sql-interpolation
            f"SELECT COUNT(*) FROM {sql_table} WHERE {sql_source} IS NULL"  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
        ).fetchone()[0]
    return {"migrated": migrated, "skipped_null": int(skipped_null)}


def verify_encrypted_column(
    connection: sqlite3.Connection,
    crypto: FloorVault,
    *,
    table: str,
    id_column: str,
    source_column: str,
    destination_column: str,
) -> int:
    """Decrypt every migrated value and compare it with its source value."""
    table, id_column, source_column, destination_column = _validate_inputs(
        connection, crypto, table, id_column, source_column, destination_column
    )
    sql_table, sql_id, sql_source, sql_dest = (
        _quoted_identifier(n) for n in (table, id_column, source_column, destination_column)
    )
    rows = connection.execute(  # identifiers allow-listed + quoted  # nosemgrep: floorvault-sql-interpolation
        f"SELECT {sql_id}, {sql_source}, {sql_dest} FROM {sql_table} "  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
        f"WHERE {sql_source} IS NOT NULL"
    ).fetchall()
    verified = 0
    for record_id, plaintext, ciphertext in rows:
        if record_id is None or ciphertext is None:
            raise ValueError("migrated record has a missing ID or encrypted value")
        if isinstance(plaintext, (bytes, bytearray)):
            recovered: Any = crypto.decrypt_bytes(
                ciphertext,
                table=table,
                record_id=str(record_id),
                column=destination_column,
            )
        else:
            recovered = crypto.decrypt(
                ciphertext,
                table=table,
                record_id=str(record_id),
                column=destination_column,
            )
        if recovered != plaintext:
            raise ValueError(f"migration verification failed for record {record_id!r}")
        verified += 1
    return verified

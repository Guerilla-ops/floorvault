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

    Plaintext residue: the plaintext source remains fully readable until the
    caller removes it, and removal is NOT a plain ``ALTER TABLE ... DROP
    COLUMN`` — unless the dropping connection runs with
    ``PRAGMA secure_delete=ON`` *and* the WAL is truncated
    (``PRAGMA wal_checkpoint(TRUNCATE)``) or the database is ``VACUUM``ed, the
    plaintext survives inside freelist/old pages of the database file. Even
    then, filesystem-level block slack may retain copies; the only complete
    guarantee is destroying the file. Use :func:`drop_plaintext_column` for the
    drop.
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


def drop_plaintext_column(
    connection: sqlite3.Connection,
    *,
    table: str,
    column: str,
    vacuum: bool = False,
) -> dict[str, Any]:
    """Drop a migrated plaintext column with reduced on-file residue.

    A bare ``ALTER TABLE ... DROP COLUMN`` frees the plaintext cells into the
    freelist / leaves them in the WAL, where they remain readable from the
    database file. This helper:

    * enables ``PRAGMA secure_delete`` so content freed by the drop is
      zero-overwritten rather than abandoned on pages,
    * drops the column inside a transaction (SQLite >= 3.35),
    * checkpoints and truncates the WAL so earlier page images holding
      plaintext do not persist in ``*-wal``, and
    * optionally ``VACUUM``s, rewriting the whole file so zeroed freelist
      pages are dropped outright. (``VACUUM`` cannot run inside a transaction
      and rewrites the entire database, so it is opt-in.)

    ``PRAGMA secure_delete`` is left ON for this connection afterwards —
    deliberate: a safer default than restoring the caller's previous setting.

    Honest limit: this scrubs the *database file's* live and freed pages. It
    cannot erase filesystem-level residue — deallocated disk blocks of earlier
    file versions (including a deleted rollback journal) can retain plaintext.
    The only complete guarantee is destroying the file. Returned flags state
    exactly what was done so a caller cannot mistake a partial scrub for a
    full one.
    """
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection")
    if connection.in_transaction:
        # ``with connection:`` below would silently COMMIT the caller's
        # pending work; refuse instead of committing on their behalf.
        raise RuntimeError(
            "drop_plaintext_column must not run inside an open transaction; "
            "commit or roll back first"
        )
    table_name = _safe_identifier(table)
    column_name = _safe_identifier(column)
    # _safe_identifier's charset admits one schema qualifier, but
    # PRAGMA table_info() cannot express a bracket-qualified name
    # ([s].[t] is a syntax error there) and a column name is never
    # schema-qualified - so this helper stays unqualified-only.
    if "." in table_name:
        raise ValueError("drop_plaintext_column does not support schema-qualified table names")
    if "." in column_name:
        raise ValueError("drop_plaintext_column does not support schema-qualified column names")
    sqlite_version = tuple(int(part) for part in sqlite3.sqlite_version.split(".")[:3])
    if sqlite_version < (3, 35, 0):
        raise ValueError(
            f"DROP COLUMN requires SQLite >= 3.35 (this build has {sqlite3.sqlite_version})"
        )
    columns = {
        row[1].casefold()
        for row in connection.execute(
            f"PRAGMA table_info({_quoted_identifier(table_name)})"
        ).fetchall()
    }
    if column_name.casefold() not in columns:
        raise ValueError(f"column {column_name!r} not present in {table_name!r}")

    # secure_delete applies to content freed *after* it is set, so it must be
    # armed before the drop, on this connection.
    connection.execute("PRAGMA secure_delete = ON")
    with connection:
        connection.execute(
            f"ALTER TABLE {_quoted_identifier(table_name)} "
            f"DROP COLUMN {_quoted_identifier(column_name)}"
        )

    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
    wal_truncated = False
    if journal_mode == "wal":
        # wal_checkpoint(TRUNCATE) reports (busy, log, checkpointed): a live
        # reader holds the WAL open and the truncate does not happen, so the
        # flag reports what the checkpoint actually did rather than what was
        # requested.
        busy = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        wal_truncated = busy == 0
    if vacuum:
        connection.execute("VACUUM")
    return {
        "dropped": column_name,
        "journal_mode": journal_mode,
        "wal_truncated": wal_truncated,
        "vacuumed": vacuum,
        # Freed disk blocks (incl. deleted rollback journals) can still hold
        # earlier plaintext images; only destroying the file removes those.
        "filesystem_residue": True,
    }

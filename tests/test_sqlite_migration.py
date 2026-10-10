"""Tests for plaintext-to-encrypted-column migration."""

from __future__ import annotations

import sqlite3

import pytest

from floorvault import FloorVault
from floorvault.sqlite_migration import (
    drop_plaintext_column,
    migrate_plaintext_column,
    verify_encrypted_column,
)


@pytest.fixture
def database():
    connection = sqlite3.connect(":memory:")
    connection.execute(
        """
        CREATE TABLE credentials (
            id TEXT PRIMARY KEY,
            api_token TEXT,
            api_token_cipher BLOB
        )
        """
    )
    connection.executemany(
        "INSERT INTO credentials (id, api_token) VALUES (?, ?)",
        [("user-1", "token-1"), ("user-2", "token-2"), ("user-null", None)],
    )
    yield connection
    connection.close()


def test_migrate_preserves_source_and_encrypts_each_record(database):
    crypto = FloorVault(b"m" * 32, memory_mode="disabled")

    result = migrate_plaintext_column(
        database,
        crypto,
        table="credentials",
        id_column="id",
        source_column="api_token",
        destination_column="api_token_cipher",
    )

    assert result == {"migrated": 2, "skipped_null": 1}
    assert (
        verify_encrypted_column(
            database,
            crypto,
            table="credentials",
            id_column="id",
            source_column="api_token",
            destination_column="api_token_cipher",
        )
        == 2
    )
    rows = database.execute(
        "SELECT id, api_token, typeof(api_token_cipher) FROM credentials ORDER BY id"
    ).fetchall()
    assert rows == [
        ("user-1", "token-1", "blob"),
        ("user-2", "token-2", "blob"),
        ("user-null", None, "null"),
    ]


def test_migration_refuses_to_overwrite_existing_destination(database):
    database.execute(
        "UPDATE credentials SET api_token_cipher = ? WHERE id = ?",
        (b"already-present", "user-1"),
    )
    crypto = FloorVault(b"m" * 32, memory_mode="disabled")

    with pytest.raises(ValueError, match="destination column already contains data"):
        migrate_plaintext_column(
            database,
            crypto,
            table="credentials",
            id_column="id",
            source_column="api_token",
            destination_column="api_token_cipher",
        )


def test_migration_rejects_untrusted_identifiers(database):
    crypto = FloorVault(b"m" * 32, memory_mode="disabled")

    with pytest.raises(ValueError, match="valid SQL identifier"):
        migrate_plaintext_column(
            database,
            crypto,
            table="credentials; DROP TABLE credentials",
            id_column="id",
            source_column="api_token",
            destination_column="api_token_cipher",
        )


# ---------------------------------------------------------------------------
# drop_plaintext_column: the drop itself must reduce on-file residue
# ---------------------------------------------------------------------------
#
# A bare ALTER TABLE .. DROP COLUMN abandons plaintext on freed pages and in
# the WAL. The helper arms secure_delete first, truncates the WAL, and reports
# honestly that filesystem slack is outside its reach.


def _marker_db(tmp_path):
    """Database with a unique plaintext marker in the source column."""
    db_path = tmp_path / "migrate.db"
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("CREATE TABLE creds (id TEXT PRIMARY KEY, token TEXT, token_cipher BLOB)")
    connection.execute("INSERT INTO creds VALUES (?, ?, NULL)", ("u1", "UNIQUE_MARK3R_STRING_xyz"))
    connection.commit()
    return db_path, connection


def test_drop_plaintext_column_scrubs_pages(tmp_path):
    db_path, connection = _marker_db(tmp_path)
    crypto = FloorVault(b"m" * 32, memory_mode="disabled")
    migrate_plaintext_column(
        connection,
        crypto,
        table="creds",
        id_column="id",
        source_column="token",
        destination_column="token_cipher",
    )
    result = drop_plaintext_column(connection, table="creds", column="token", vacuum=True)
    assert result["dropped"] == "token"
    assert result["journal_mode"] == "wal"
    assert result["wal_truncated"] is True
    assert result["vacuumed"] is True
    assert result["filesystem_residue"] is True
    connection.close()
    # The plaintext marker must be gone from the live file's bytes.
    blob = db_path.read_bytes()
    assert b"UNIQUE_MARK3R_STRING_xyz" not in blob
    # The ciphertext survives and still decrypts.
    connection = sqlite3.connect(db_path)
    cipher = connection.execute("SELECT token_cipher FROM creds WHERE id = 'u1'").fetchone()[0]
    assert (
        crypto.decrypt(cipher, table="creds", record_id="u1", column="token_cipher")
        == "UNIQUE_MARK3R_STRING_xyz"
    )
    connection.close()


def test_drop_plaintext_column_validates_identifiers(tmp_path):
    _, connection = _marker_db(tmp_path)
    with pytest.raises(ValueError, match="valid SQL identifier"):
        drop_plaintext_column(connection, table="creds; DROP TABLE creds", column="token")
    with pytest.raises(ValueError, match="valid SQL identifier"):
        drop_plaintext_column(connection, table="creds", column="token --")
    connection.close()


def test_drop_plaintext_column_missing_column_errors(tmp_path):
    _, connection = _marker_db(tmp_path)
    with pytest.raises(ValueError, match="not present"):
        drop_plaintext_column(connection, table="creds", column="nope")
    connection.close()


def test_drop_plaintext_column_drops_keyword_named_column(tmp_path):
    """An allow-listed name that is also a SQL keyword (``CURRENT_TIMESTAMP``)
    must drop correctly: bracket quoting is what keeps it a column name."""
    _, connection = _marker_db(tmp_path)
    connection.execute("ALTER TABLE creds ADD COLUMN [CURRENT_TIMESTAMP] TEXT")
    connection.commit()
    result = drop_plaintext_column(connection, table="creds", column="CURRENT_TIMESTAMP")
    assert result["dropped"] == "CURRENT_TIMESTAMP"
    columns = {row[1] for row in connection.execute("PRAGMA table_info([creds])")}
    assert "CURRENT_TIMESTAMP" not in columns
    connection.close()


def test_drop_plaintext_column_rejects_schema_qualified_names(tmp_path):
    _, connection = _marker_db(tmp_path)
    with pytest.raises(ValueError, match="schema-qualified"):
        drop_plaintext_column(connection, table="main.creds", column="token")
    with pytest.raises(ValueError, match="schema-qualified"):
        drop_plaintext_column(connection, table="creds", column="main.token")
    connection.close()


def test_drop_plaintext_column_matches_column_case_insensitively(tmp_path):
    """SQLite identifiers are case-insensitive; the existence check must fold
    case so ``TOKEN`` finds the ``token`` column and drops it. The result
    reports the column's own (DDL) spelling, not the caller's."""
    _, connection = _marker_db(tmp_path)
    result = drop_plaintext_column(connection, table="creds", column="TOKEN")
    assert result["dropped"] == "token"
    columns = {row[1] for row in connection.execute("PRAGMA table_info([creds])")}
    assert "token" not in columns
    connection.close()


def test_drop_plaintext_column_refuses_open_transaction(tmp_path):
    """Running inside the caller's open transaction would silently COMMIT it;
    the helper must refuse and leave the pending work uncommitted."""
    _, connection = _marker_db(tmp_path)
    connection.execute("INSERT INTO creds VALUES ('pending', 'x', NULL)")
    assert connection.in_transaction
    with pytest.raises(RuntimeError, match="open transaction"):
        drop_plaintext_column(connection, table="creds", column="token")
    connection.rollback()
    row = connection.execute("SELECT COUNT(*) FROM creds WHERE id = 'pending'").fetchone()
    assert row[0] == 0
    connection.close()


def test_drop_plaintext_column_reports_busy_wal_checkpoint(tmp_path):
    """An open reader pins WAL frames, so TRUNCATE cannot complete - the
    report flag must say so rather than claim a truncation that did not run."""
    db_path, connection = _marker_db(tmp_path)
    reader = sqlite3.connect(db_path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM creds").fetchall()
    try:
        result = drop_plaintext_column(connection, table="creds", column="token")
        assert result["journal_mode"] == "wal"
        assert result["wal_truncated"] is False
    finally:
        reader.close()
        connection.close()

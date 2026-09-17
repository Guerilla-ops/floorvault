"""Tests for plaintext-to-encrypted-column migration."""

from __future__ import annotations

import sqlite3

import pytest

from floorvault import FloorVault
from floorvault.sqlite_migration import migrate_plaintext_column, verify_encrypted_column


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

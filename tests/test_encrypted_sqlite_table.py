"""Tests for the explicit existing-SQLite repository integration helper."""

from __future__ import annotations

import sqlite3

import pytest

from floorvault import DecryptionVerificationError, EncryptedSQLiteTable, FloorVault


@pytest.fixture
def encrypted_users():
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE users (id TEXT PRIMARY KEY, api_token_cipher BLOB NOT NULL DEFAULT X'')"
    )
    crypto = FloorVault(b"k" * 32, memory_mode="disabled")
    table = EncryptedSQLiteTable(
        connection,
        crypto,
        "users",
        id_column="id",
    )
    yield connection, table
    connection.close()


def test_store_and_load_existing_sqlite_field(encrypted_users):
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store("user-123", "api_token_cipher", "secret-token")
    connection.commit()

    assert table.load("user-123", "api_token_cipher") == "secret-token"


def test_load_rejects_ciphertext_moved_to_another_record(encrypted_users):
    connection, table = encrypted_users
    connection.executemany("INSERT INTO users (id) VALUES (?)", [("user-123",), ("user-456",)])

    table.store("user-123", "api_token_cipher", "secret-token")
    ciphertext = connection.execute(
        "SELECT api_token_cipher FROM users WHERE id = ?", ("user-123",)
    ).fetchone()[0]
    connection.execute(
        "UPDATE users SET api_token_cipher = ? WHERE id = ?",
        (ciphertext, "user-456"),
    )

    with pytest.raises(DecryptionVerificationError):
        table.load("user-456", "api_token_cipher")


def test_store_rejects_untrusted_sql_identifiers(encrypted_users):
    _connection, table = encrypted_users

    with pytest.raises(ValueError, match="valid SQL identifier"):
        table.store("user-123", "api_token_cipher; DROP TABLE users", "secret")


def test_store_requires_exactly_one_existing_record(encrypted_users):
    _connection, table = encrypted_users

    with pytest.raises(LookupError, match="record not found"):
        table.store("missing", "api_token_cipher", "secret")

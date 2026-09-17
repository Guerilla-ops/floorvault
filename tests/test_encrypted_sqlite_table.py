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


# --------------------------------------------------------------------------
# The binary path must be symmetric: store() accepts bytes, so load_bytes()
# has to be able to return them. Before this, bytes went in and came back as
# DecryptionVerificationError ("not valid UTF-8") with no supported way out -
# the adapter offered half a feature.
# --------------------------------------------------------------------------


def test_binary_field_round_trips_through_load_bytes(encrypted_users):
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))
    payload = bytes(range(256))  # deliberately not valid UTF-8

    table.store("user-123", "api_token_cipher", payload)
    connection.commit()

    assert table.load_bytes("user-123", "api_token_cipher") == payload


def test_load_bytes_rejects_ciphertext_moved_to_another_record(encrypted_users):
    connection, table = encrypted_users
    connection.executemany("INSERT INTO users (id) VALUES (?)", [("user-123",), ("user-456",)])
    table.store("user-123", "api_token_cipher", bytes(range(256)))
    ciphertext = connection.execute(
        "SELECT api_token_cipher FROM users WHERE id = ?", ("user-123",)
    ).fetchone()[0]
    connection.execute(
        "UPDATE users SET api_token_cipher = ? WHERE id = ?", (ciphertext, "user-456")
    )

    with pytest.raises(DecryptionVerificationError):
        table.load_bytes("user-456", "api_token_cipher")


def test_load_bytes_returns_text_values_as_bytes(encrypted_users):
    """A text value is still readable through the bytes accessor."""
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))
    table.store("user-123", "api_token_cipher", "secret-token")
    connection.commit()

    assert table.load_bytes("user-123", "api_token_cipher") == b"secret-token"


def test_load_bytes_requires_exactly_one_existing_record(encrypted_users):
    _connection, table = encrypted_users

    with pytest.raises(LookupError, match="record not found"):
        table.load_bytes("missing", "api_token_cipher")


def test_load_bytes_rejects_a_null_field():
    """A NULL encrypted field is an error, not an empty value.

    Uses its own table: the shared fixture declares the column
    ``NOT NULL DEFAULT X''``, which can never actually hold NULL.
    """
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, api_token_cipher BLOB NULL)")
    table = EncryptedSQLiteTable(connection, FloorVault(b"k" * 32, memory_mode="disabled"), "users")
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    with pytest.raises(ValueError, match="encrypted field is NULL"):
        table.load_bytes("user-123", "api_token_cipher")

    connection.close()

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


# --------------------------------------------------------------------------
# Write invariant (red-team #3+#4): a multi-row match must write NOTHING, and
# the id column must never be a ciphertext target. The post-hoc rowcount guard
# checked after UPDATE, so a duplicate or NOCASE-collided match rewrote every
# row and the caller's documented commit() persisted the corruption.
# --------------------------------------------------------------------------


@pytest.fixture
def dup_table():
    """Two physical rows sharing one id - no UNIQUE constraint."""
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE dup (id TEXT, ssn TEXT)")
    connection.executemany("INSERT INTO dup VALUES (?, NULL)", [("r1",), ("r1",), ("r2",)])
    table = EncryptedSQLiteTable(
        connection, FloorVault(b"k" * 32, memory_mode="disabled"), "dup", id_column="id"
    )
    yield connection, table
    connection.close()


def test_store_on_duplicate_id_writes_nothing(dup_table):
    connection, table = dup_table

    with pytest.raises(ValueError, match="more than one row"):
        table.store("r1", "ssn", "MASS-OVERWRITE")

    # The failure path callers actually take: report the error, then commit.
    connection.commit()
    rows = connection.execute("SELECT id, ssn FROM dup ORDER BY rowid").fetchall()
    assert rows == [("r1", None), ("r1", None), ("r2", None)], (
        "a refused write left ciphertext behind"
    )


def test_store_fields_on_duplicate_id_writes_nothing(dup_table):
    connection, table = dup_table

    with pytest.raises(ValueError, match="more than one row"):
        table.store_fields("r1", {"ssn": "x"})

    connection.commit()
    assert connection.execute("SELECT COUNT(*) FROM dup WHERE ssn IS NOT NULL").fetchone()[0] == 0


def test_nocase_collided_ids_write_nothing():
    """A NOCASE column makes 'r1' and 'R1' match one WHERE - same class of bug."""
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE accts (id TEXT COLLATE NOCASE, ssn TEXT)")
    connection.executemany("INSERT INTO accts VALUES (?, NULL)", [("r1",), ("R1",)])
    table = EncryptedSQLiteTable(
        connection, FloorVault(b"k" * 32, memory_mode="disabled"), "accts", id_column="id"
    )

    with pytest.raises(ValueError, match="more than one row"):
        table.store("r1", "ssn", "CROSS-RECORD-OVERWRITE")

    connection.commit()
    assert connection.execute("SELECT COUNT(*) FROM accts WHERE ssn IS NOT NULL").fetchone()[0] == 0
    connection.close()


def test_store_rejects_id_column_as_ciphertext_target(encrypted_users):
    """encrypted_column == id_column rewrites the row's own key (rowcount==1,
    so the old guard accepted it) - destroying the record without an error."""
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("r1",))

    with pytest.raises(ValueError, match="id column"):
        table.store("r1", "id", "IMPERSONATE")

    assert connection.execute("SELECT id FROM users").fetchall() == [("r1",)]


def test_store_rejects_id_column_case_variant(encrypted_users):
    """SQL folds case; 'ID' names the same column as id_column 'id'."""
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("r1",))

    with pytest.raises(ValueError, match="id column"):
        table.store("r1", "ID", "IMPERSONATE")

    assert connection.execute("SELECT id FROM users").fetchall() == [("r1",)]


def test_store_fields_rejects_id_column_among_fields(encrypted_users):
    connection, table = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("r2",))

    with pytest.raises(ValueError, match="id column"):
        table.store_fields("r2", {"api_token_cipher": "s", "id": "HIJACK"})

    row = connection.execute("SELECT id, api_token_cipher FROM users").fetchone()
    assert row[0] == "r2" and row[1] in (b"",)


def test_load_on_duplicate_id_raises(dup_table):
    """Reads claim exactly-one too; a duplicate match must refuse, not pick an
    arbitrary row."""
    _connection, table = dup_table

    with pytest.raises(ValueError, match="more than one row"):
        table.load("r1", "ssn")


def test_load_fields_on_duplicate_id_raises(dup_table):
    _connection, table = dup_table

    with pytest.raises(ValueError, match="more than one row"):
        table.load_fields("r1", ["ssn"])

"""libSQL adapter contract tests.

Two tiers, matching repo convention:

- Fake-seam tests run everywhere: a sqlite3-backed stub exposing the libsql
  client's sync surface exercises the full SQL/crypto contract without the
  native wheel (libsql 0.1.11 ships no cp314 build for macOS).
- The live embedded test runs where ``import libsql`` succeeds - every CI
  leg interpreter (3.10-3.13, all three OSes) has a wheel. Remote Turso is
  deliberately untested here: it needs a live server, and the server-side
  residue guarantees the local migration helpers rely on are not observable
  over the wire.
"""

from __future__ import annotations

import importlib.util
import sqlite3

import pytest

from floorvault import (
    DecryptionVerificationError,
    EncryptedLibSqlTable,
    EncryptedSQLiteTable,
    FloorVault,
)


class _FakeLibSqlConnection:
    """sqlite3-backed stub with the libsql client's sync surface.

    Deliberately *not* a sqlite3.Connection: the point is to prove the
    adapter's structural check accepts the libsql shape rather than the
    nominal type.
    """

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real
        self.force_rowcount: int | None = None

    def execute(self, sql, params=()):
        cursor = self._real.execute(sql, params)
        if self.force_rowcount is not None:
            cursor = _RowCountOverride(cursor, self.force_rowcount)
        return cursor

    def commit(self) -> None:
        self._real.commit()

    def close(self) -> None:
        self._real.close()


class _RowCountOverride:
    """Cursor shim lying about the affected-row count.

    Models a connection that cannot report how many rows a write touched:
    the adapter must fail closed rather than trust an unverifiable write.
    """

    def __init__(self, cursor, rowcount: int) -> None:
        self._cursor = cursor
        self.rowcount = rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class _AsyncClient:
    """libsql-client-style async surface: execute() returns a coroutine."""

    async def execute(self, sql, params=()):  # pragma: no cover - never awaited
        raise AssertionError("must never be called")

    async def commit(self):
        raise AssertionError("must never be called")


@pytest.fixture
def encrypted_users():
    real = sqlite3.connect(":memory:")
    real.execute(
        "CREATE TABLE users (id TEXT PRIMARY KEY, api_token_cipher BLOB NOT NULL DEFAULT X'')"
    )
    connection = _FakeLibSqlConnection(real)
    crypto = FloorVault(b"k" * 32, memory_mode="disabled")
    table = EncryptedLibSqlTable(connection, crypto, "users", id_column="id")
    yield connection, table, real
    connection.close()


def test_store_and_load_existing_libsql_field(encrypted_users):
    connection, table, _real = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store("user-123", "api_token_cipher", "secret-token")
    connection.commit()

    assert table.load("user-123", "api_token_cipher") == "secret-token"


def test_binary_field_round_trips_through_load_bytes(encrypted_users):
    connection, table, _real = encrypted_users
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store("user-123", "api_token_cipher", b"\x00binary\xff")
    connection.commit()

    assert table.load_bytes("user-123", "api_token_cipher") == b"\x00binary\xff"
    with pytest.raises(DecryptionVerificationError, match="not valid UTF-8"):
        table.load("user-123", "api_token_cipher")


def test_batch_fields_round_trip(encrypted_users):
    connection, table, real = encrypted_users
    real.execute("ALTER TABLE users ADD COLUMN secret_b BLOB")
    connection.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store_fields("user-123", {"api_token_cipher": "token", "secret_b": b"\x01\x02"})
    connection.commit()

    assert table.load_fields("user-123", ("api_token_cipher", "secret_b")) == {
        "api_token_cipher": "token",
        "secret_b": "\x01\x02",
    }
    assert table.load_fields_bytes("user-123", ("api_token_cipher", "secret_b")) == {
        "api_token_cipher": b"token",
        "secret_b": b"\x01\x02",
    }


def test_envelopes_are_byte_compatible_with_the_sqlite_adapter(encrypted_users):
    """Ciphertext written through the libsql surface reads back through the
    sqlite3 adapter on the same connection - RecordBinding is shared."""
    connection, table, real = encrypted_users
    real.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store("user-123", "api_token_cipher", "secret-token")
    connection.commit()

    sqlite_table = EncryptedSQLiteTable(real, table.crypto, "users", id_column="id")
    assert sqlite_table.load("user-123", "api_token_cipher") == "secret-token"


def test_load_rejects_ciphertext_moved_to_another_record(encrypted_users):
    connection, table, real = encrypted_users
    real.executemany("INSERT INTO users (id) VALUES (?)", [("user-123",), ("user-456",)])

    table.store("user-123", "api_token_cipher", "secret-token")
    ciphertext = real.execute(
        "SELECT api_token_cipher FROM users WHERE id = ?", ("user-123",)
    ).fetchone()[0]
    real.execute("UPDATE users SET api_token_cipher = ? WHERE id = ?", (ciphertext, "user-456"))

    with pytest.raises(DecryptionVerificationError):
        table.load("user-456", "api_token_cipher")


def test_revision_binding_is_honored(encrypted_users):
    connection, table, real = encrypted_users
    real.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))

    table.store("user-123", "api_token_cipher", "secret-token", revision=7)
    connection.commit()

    assert table.load("user-123", "api_token_cipher", revision=7) == "secret-token"
    with pytest.raises(DecryptionVerificationError):
        table.load("user-123", "api_token_cipher", revision=8)


def test_store_to_missing_record_fails(encrypted_users):
    _connection, table, _real = encrypted_users
    with pytest.raises(LookupError, match="record not found"):
        table.store("missing", "api_token_cipher", "secret-token")


def test_load_from_missing_record_fails(encrypted_users):
    _connection, table, _real = encrypted_users
    with pytest.raises(LookupError, match="record not found"):
        table.load("missing", "api_token_cipher")


def test_store_fails_closed_when_affected_rows_unreported(encrypted_users):
    """A connection reporting rowcount -1 (count unknown on the wire) must not
    be trusted: the write is unverifiable, so the adapter refuses rather than
    claim a missing record was stored."""
    connection, table, real = encrypted_users
    real.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))
    connection.force_rowcount = -1

    with pytest.raises(LookupError, match="record not found"):
        table.store("user-123", "api_token_cipher", "secret-token")


def test_null_encrypted_field_refused(encrypted_users):
    connection, table, real = encrypted_users
    real.execute("CREATE TABLE nullable_users (id TEXT PRIMARY KEY, api_token_cipher BLOB)")
    real.execute("INSERT INTO nullable_users (id) VALUES (?)", ("user-123",))
    nullable = EncryptedLibSqlTable(connection, table.crypto, "nullable_users")

    with pytest.raises(ValueError, match="encrypted field is NULL"):
        nullable.load("user-123", "api_token_cipher")


def test_store_rejects_untrusted_sql_identifiers(encrypted_users):
    _connection, table, _real = encrypted_users

    with pytest.raises(ValueError, match="valid SQL identifier"):
        table.store("user-123", "api_token_cipher; DROP TABLE users", "secret")
    with pytest.raises(ValueError, match="valid SQL identifier"):
        EncryptedLibSqlTable(
            _FakeLibSqlConnection(sqlite3.connect(":memory:")),
            FloorVault(b"k" * 32, memory_mode="disabled"),
            "bad;name",
        )


def test_connection_must_expose_the_sync_surface():
    crypto = FloorVault(b"k" * 32, memory_mode="disabled")

    with pytest.raises(TypeError, match="libsql Connection"):
        EncryptedLibSqlTable(object(), crypto, "users")
    with pytest.raises(TypeError, match="libsql Connection"):
        EncryptedLibSqlTable(None, crypto, "users")

    class _ExecuteOnly:
        def execute(self, sql, params=()):
            raise AssertionError("unused")

    with pytest.raises(TypeError, match="libsql Connection"):
        EncryptedLibSqlTable(_ExecuteOnly(), crypto, "users")


def test_async_clients_are_refused_at_construction():
    crypto = FloorVault(b"k" * 32, memory_mode="disabled")
    with pytest.raises(TypeError, match="async libsql clients"):
        EncryptedLibSqlTable(_AsyncClient(), crypto, "users")


def test_crypto_must_be_floorvault(encrypted_users):
    connection, _table, _real = encrypted_users
    with pytest.raises(TypeError, match="must be a FloorVault"):
        EncryptedLibSqlTable(connection, object(), "users")


def test_sqlite3_connection_also_satisfies_the_structural_check():
    """A nominal sqlite3.Connection happens to expose the same surface; the
    check is structural, so it is accepted - the strict-class sibling remains
    the one that enforces nominal typing."""
    real = sqlite3.connect(":memory:")
    crypto = FloorVault(b"k" * 32, memory_mode="disabled")
    table = EncryptedLibSqlTable(real, crypto, "users")
    assert table.connection is real


_HAS_LIBSQL = importlib.util.find_spec("libsql") is not None


@pytest.mark.skipif(
    not _HAS_LIBSQL,
    reason="libsql wheel unavailable for this interpreter/platform",
)
def test_live_embedded_round_trip(tmp_path):
    """Real libsql embedded-mode connection: local file, real client."""
    import libsql

    conn = libsql.connect(str(tmp_path / "t.db"))
    conn.execute(
        "CREATE TABLE users (id TEXT PRIMARY KEY, api_token_cipher BLOB NOT NULL DEFAULT X'')"
    )
    conn.execute("INSERT INTO users (id) VALUES (?)", ("user-123",))
    conn.commit()

    crypto = FloorVault(b"k" * 32, memory_mode="disabled")
    table = EncryptedLibSqlTable(conn, crypto, "users")
    table.store("user-123", "api_token_cipher", "secret-token")
    conn.commit()

    assert table.load("user-123", "api_token_cipher") == "secret-token"
    conn.close()

"""Tests for the PEP 249 (DB-API 2.0) table adapters.

No live PostgreSQL or MySQL is required: the adapters speak only
``cursor()`` / ``execute`` / ``fetchone`` / ``rowcount`` / ``close``, so a
fake connection exercises the full SQL boundary while the cryptography
underneath is real. Cross-engine portability is covered by decrypting a
PostgreSQL-adapter ciphertext through the MySQL adapter - the AAD
coordinates, not the driver, decide authenticity.
"""

from __future__ import annotations

import pytest

from floorvault import (
    DecryptionVerificationError,
    EncryptedMySQLTable,
    EncryptedPostgresTable,
    FloorVault,
)


class FakeCursor:
    """Minimal DB-API cursor: records statements, returns staged rows."""

    def __init__(self, rowcount=1, rows=()):
        self.executed = []
        self.rowcount = rowcount
        self._rows = list(rows)
        self.closed = False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        return self

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def close(self):
        self.closed = True


class FakeConnection:
    """Hands out FakeCursors; ``next_rowcount``/``next_rows`` stage results."""

    def __init__(self):
        self.cursors = []
        self.next_rowcount = 1
        self.next_rows = []

    def cursor(self):
        cursor = FakeCursor(rowcount=self.next_rowcount, rows=self.next_rows)
        self.cursors.append(cursor)
        return cursor


@pytest.fixture
def crypto():
    return FloorVault(b"k" * 32, memory_mode="disabled")


@pytest.fixture
def postgres(crypto):
    connection = FakeConnection()
    table = EncryptedPostgresTable(connection, crypto, "users", id_column="id")
    return connection, table


@pytest.fixture
def mysql(crypto):
    connection = FakeConnection()
    table = EncryptedMySQLTable(connection, crypto, "users", id_column="id")
    return connection, table


def _last(connection):
    return connection.cursors[-1]


class TestPostgresDialect:
    def test_store_emits_double_quoted_update(self, postgres):
        connection, table = postgres

        table.store("user-123", "api_token_cipher", "secret-token")

        sql, params = _last(connection).executed[0]
        assert sql == 'UPDATE "users" SET "api_token_cipher" = %s WHERE "id" = %s'
        assert isinstance(params[0], bytes) and params[0] != b"secret-token"
        assert params[1] == "user-123"

    def test_load_emits_double_quoted_select(self, postgres):
        connection, table = postgres
        connection.next_rows = [(b"ct",)]

        with pytest.raises(DecryptionVerificationError):
            table.load("user-123", "api_token_cipher")

        sql, params = _last(connection).executed[0]
        assert sql == 'SELECT "api_token_cipher" FROM "users" WHERE "id" = %s'
        assert params == ("user-123",)

    def test_schema_qualified_table_quotes_each_part(self, crypto):
        connection = FakeConnection()
        table = EncryptedPostgresTable(connection, crypto, "app.users", id_column="id")

        table.store("r1", "cipher", "v")

        sql, _ = _last(connection).executed[0]
        assert sql == 'UPDATE "app"."users" SET "cipher" = %s WHERE "id" = %s'


class TestMySQLDialect:
    def test_store_emits_backtick_quoted_update(self, mysql):
        connection, table = mysql

        table.store("user-123", "api_token_cipher", "secret-token")

        sql, _ = _last(connection).executed[0]
        assert sql == "UPDATE `users` SET `api_token_cipher` = %s WHERE `id` = %s"

    def test_database_qualified_table_quotes_each_part(self, crypto):
        connection = FakeConnection()
        table = EncryptedMySQLTable(connection, crypto, "shop.users", id_column="id")

        table.store("r1", "cipher", "v")

        sql, _ = _last(connection).executed[0]
        assert sql == "UPDATE `shop`.`users` SET `cipher` = %s WHERE `id` = %s"


class TestCryptoRoundTrip:
    def test_postgres_store_then_load(self, postgres):
        connection, table = postgres
        table.store("user-123", "api_token_cipher", "secret-token")
        ciphertext = _last(connection).executed[0][1][0]

        connection.next_rows = [(ciphertext,)]
        assert table.load("user-123", "api_token_cipher") == "secret-token"

    def test_mysql_binary_round_trip(self, mysql):
        connection, table = mysql
        payload = bytes(range(256))
        table.store("user-123", "api_token_cipher", payload)
        ciphertext = _last(connection).executed[0][1][0]

        connection.next_rows = [(ciphertext,)]
        assert table.load_bytes("user-123", "api_token_cipher") == payload

    def test_ciphertext_written_by_postgres_loads_through_mysql(self, postgres, mysql):
        """Envelopes are driver-agnostic: same coordinates decrypt anywhere."""
        pg_connection, pg_table = postgres
        _, my_table = mysql
        pg_table.store("user-123", "api_token_cipher", "portable")
        ciphertext = _last(pg_connection).executed[0][1][0]

        my_connection = my_table.connection
        my_connection.next_rows = [(ciphertext,)]
        assert my_table.load("user-123", "api_token_cipher") == "portable"

    def test_load_rejects_ciphertext_moved_to_another_record(self, postgres):
        connection, table = postgres
        table.store("user-123", "api_token_cipher", "secret-token")
        ciphertext = _last(connection).executed[0][1][0]

        connection.next_rows = [(ciphertext,)]
        with pytest.raises(DecryptionVerificationError):
            table.load("user-456", "api_token_cipher")

    def test_revision_binds_to_the_stored_value(self, postgres):
        connection, table = postgres
        table.store("user-123", "api_token_cipher", "secret-token", revision=7)
        ciphertext = _last(connection).executed[0][1][0]

        connection.next_rows = [(ciphertext,)]
        assert table.load("user-123", "api_token_cipher", revision=7) == "secret-token"

        connection.next_rows = [(ciphertext,)]
        with pytest.raises(DecryptionVerificationError):
            table.load("user-123", "api_token_cipher", revision=8)


class TestInvariants:
    def test_store_rejects_untrusted_sql_identifiers(self, postgres, mysql):
        for _, table in (postgres, mysql):
            with pytest.raises(ValueError, match="valid SQL identifier"):
                table.store("r1", "cipher; DROP TABLE users", "v")
            with pytest.raises(ValueError, match="valid SQL identifier"):
                table.store("r1", 'cipher"x', "v")
            with pytest.raises(ValueError, match="valid SQL identifier"):
                table.store("r1", "cipher`x", "v")

    def test_store_requires_exactly_one_existing_record(self, postgres):
        connection, table = postgres
        connection.next_rowcount = 0

        with pytest.raises(LookupError, match="record not found"):
            table.store("missing", "api_token_cipher", "secret")

    def test_load_requires_exactly_one_existing_record(self, postgres):
        connection, table = postgres
        connection.next_rows = []

        with pytest.raises(LookupError, match="record not found"):
            table.load("missing", "api_token_cipher")

    def test_load_rejects_a_null_field(self, postgres):
        connection, table = postgres
        connection.next_rows = [(None,)]

        with pytest.raises(ValueError, match="encrypted field is NULL"):
            table.load("user-123", "api_token_cipher")

    def test_constructor_rejects_a_non_dbapi_connection(self, crypto):
        with pytest.raises(TypeError, match="DB-API 2.0"):
            EncryptedPostgresTable(object(), crypto, "users")

    def test_store_fields_emits_one_multi_column_update(self, postgres):
        connection, table = postgres

        table.store_fields("user-123", {"a_cipher": "va", "b_cipher": b"\x00"})

        sql, params = _last(connection).executed[0]
        assert sql == 'UPDATE "users" SET "a_cipher" = %s, "b_cipher" = %s WHERE "id" = %s'
        assert len(params) == 3 and params[-1] == "user-123"

    def test_load_fields_round_trips_text_and_rejects_binary(self, postgres):
        connection, table = postgres
        table.store_fields("user-123", {"a_cipher": "va", "b_cipher": "vb"})
        _, params = _last(connection).executed[0]

        connection.next_rows = [(params[0], params[1])]
        assert table.load_fields("user-123", ["a_cipher", "b_cipher"]) == {
            "a_cipher": "va",
            "b_cipher": "vb",
        }

    def test_cursor_is_closed_after_use(self, postgres):
        connection, table = postgres

        table.store("user-123", "api_token_cipher", "v")

        assert _last(connection).closed is True

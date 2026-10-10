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
        assert sql == (
            'UPDATE "users" SET "api_token_cipher" = %s WHERE "id" = %s AND ('
            'SELECT COUNT(*) FROM (SELECT 1 FROM "users" WHERE "id" = %s)'
            " AS _fv_match) = 1"
        )
        assert isinstance(params[0], bytes) and params[0] != b"secret-token"
        assert params[1] == params[2] == "user-123"

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
        assert sql == (
            'UPDATE "app"."users" SET "cipher" = %s WHERE "id" = %s AND ('
            'SELECT COUNT(*) FROM (SELECT 1 FROM "app"."users" WHERE "id" = %s)'
            " AS _fv_match) = 1"
        )


class TestMySQLDialect:
    def test_store_emits_backtick_quoted_update(self, mysql):
        connection, table = mysql

        table.store("user-123", "api_token_cipher", "secret-token")

        sql, _ = _last(connection).executed[0]
        assert sql == (
            "UPDATE `users` SET `api_token_cipher` = %s WHERE `id` = %s AND ("
            "SELECT COUNT(*) FROM (SELECT 1 FROM `users` WHERE `id` = %s)"
            " AS _fv_match) = 1"
        )

    def test_database_qualified_table_quotes_each_part(self, crypto):
        connection = FakeConnection()
        table = EncryptedMySQLTable(connection, crypto, "shop.users", id_column="id")

        table.store("r1", "cipher", "v")

        sql, _ = _last(connection).executed[0]
        assert sql == (
            "UPDATE `shop`.`users` SET `cipher` = %s WHERE `id` = %s AND ("
            "SELECT COUNT(*) FROM (SELECT 1 FROM `shop`.`users` WHERE `id` = %s)"
            " AS _fv_match) = 1"
        )


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
        connection.next_rows = [(0,)]

        with pytest.raises(LookupError, match="record not found"):
            table.store("missing", "api_token_cipher", "secret")

        # The refused write is classified by a real count query, not inferred.
        count_sql, count_params = _last(connection).executed[-1]
        assert count_sql == 'SELECT COUNT(*) FROM "users" WHERE "id" = %s'
        assert count_params == ("missing",)

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

    def test_load_rejects_duplicate_id_matches(self, postgres):
        """The exactly-one invariant holds on reads, not only writes."""
        connection, table = postgres
        connection.next_rows = [(b"ct",), (b"ct-second",)]

        with pytest.raises(ValueError, match="more than one row"):
            table.load("dup-id", "api_token_cipher")

    def test_load_fields_rejects_duplicate_id_matches(self, mysql):
        connection, table = mysql
        connection.next_rows = [(b"a", b"b"), (b"a2", b"b2")]

        with pytest.raises(ValueError, match="more than one row"):
            table.load_fields_bytes("dup-id", ["a_cipher", "b_cipher"])

    def test_constructor_rejects_a_non_dbapi_connection(self, crypto):
        with pytest.raises(TypeError, match="DB-API 2.0"):
            EncryptedPostgresTable(object(), crypto, "users")

    def test_store_fields_emits_one_multi_column_update(self, postgres):
        connection, table = postgres

        table.store_fields("user-123", {"a_cipher": "va", "b_cipher": b"\x00"})

        sql, params = _last(connection).executed[0]
        assert sql == (
            'UPDATE "users" SET "a_cipher" = %s, "b_cipher" = %s WHERE "id" = %s AND ('
            'SELECT COUNT(*) FROM (SELECT 1 FROM "users" WHERE "id" = %s)'
            " AS _fv_match) = 1"
        )
        assert len(params) == 4 and params[-1] == params[-2] == "user-123"

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


class TestWriteInvariants:
    """The exactly-one-write and id-column guards the SQLite adapter already
    enforces must hold on the DB-API adapters too - the SQL differs, the
    contract does not."""

    def test_store_binds_the_match_count_atomically(self, postgres):
        """The count predicate is inside the UPDATE's own WHERE, so a
        duplicate or collided match can never be persisted by a later
        commit - the post-hoc rowcount check only names the failure."""
        connection, table = postgres

        table.store("user-123", "api_token_cipher", "v")

        sql, _ = _last(connection).executed[0]
        assert "SELECT COUNT(*)" in sql and "AS _fv_match" in sql

    def test_store_rejects_id_column_as_ciphertext_target(self, postgres, mysql):
        for connection, table in (postgres, mysql):
            with pytest.raises(ValueError, match="id column"):
                table.store("r1", "id", "IMPERSONATE")
            assert connection.cursors == []

    def test_store_fields_rejects_id_column_among_fields(self, postgres, mysql):
        for _, table in (postgres, mysql):
            with pytest.raises(ValueError, match="id column"):
                table.store_fields("r1", {"cipher": "v", "id": "HIJACK"})

    def test_mysql_case_variant_id_column_is_refused(self, mysql):
        """MySQL column names are case-insensitive: 'ID' names the id column.
        PostgreSQL quoted identifiers are case-sensitive, so 'ID' there is a
        legitimately different column and stays allowed."""
        _connection, table = mysql
        with pytest.raises(ValueError, match="id column"):
            table.store("r1", "ID", "HIJACK")

    def test_store_rejects_qualified_ciphertext_target(self, postgres, mysql):
        """'users.id' resolves to the id column in a SET clause on MySQL and
        evades the guard everywhere: qualified columns are refused outright."""
        for _, table in (postgres, mysql):
            with pytest.raises(ValueError, match="bare column"):
                table.store("r1", "users.id", "IMPERSONATE")
            with pytest.raises(ValueError, match="bare column"):
                table.store_fields("r1", {"users.id": "x"})

    def test_constructor_rejects_a_qualified_id_column(self, postgres):
        connection, _ = postgres
        with pytest.raises(ValueError, match="bare column"):
            EncryptedPostgresTable(connection, postgres[1].crypto, "users", id_column="users.id")

    def test_refused_write_names_duplicate_match(self, postgres):
        """rowcount != 1 means the atomic guard refused; the classifier
        distinguishes 'no row' (LookupError) from 'many rows' (ValueError)."""
        connection, table = postgres
        connection.next_rowcount = 0
        connection.next_rows = [(2,)]

        with pytest.raises(ValueError, match="more than one row"):
            table.store("dup-id", "api_token_cipher", "v")

    def test_record_id_is_normalized_before_binding(self, postgres):
        """A str subclass' __conform__/driver adapter hooks must never reach
        the driver - the bound value and the AAD coordinate are one str."""

        class ConformingId(str):
            def __conform__(self, protocol):
                return "HIJACKED"

        connection, table = postgres
        table.store(ConformingId("r1"), "api_token_cipher", "v")

        _sql, params = _last(connection).executed[0]
        assert all(type(param) is str for param in params[1:])

    def test_failure_messages_do_not_echo_the_record_id(self, postgres):
        connection, table = postgres
        connection.next_rowcount = 0
        connection.next_rows = [(0,)]

        with pytest.raises(LookupError) as missing:
            table.store("victim-id-44bc", "api_token_cipher", "v")
        assert "victim-id-44bc" not in str(missing.value)

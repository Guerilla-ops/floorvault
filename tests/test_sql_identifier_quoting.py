"""Regression tests: allow-listed identifiers are bracket-quoted at the SQL boundary.

The identifier allow-list admits names SQLite reads as expressions when
interpolated unquoted (``TRUE``, ``CURRENT_TIMESTAMP``, ``NULL``). Verified
SQLite behavior that pins the design:

* unquoted ``SELECT CURRENT_TIMESTAMP FROM t`` returns the current time -
  the column is never touched;
* double-quoted ``SELECT "nosuchcol"`` returns the *string literal*
  ``'nosuchcol'`` - fail-open, so ANSI quoting is not acceptable;
* bracket-quoted ``SELECT [nosuchcol]`` raises ``no such column`` -
  fail-closed, so ``[name]`` is the required quoting.

Every interpolation site must use ``_quoted_identifier``; the cryptographic
context keeps the validated *unquoted* logical name.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from floorvault import EncryptedSQLiteTable, FloorVault
from floorvault.sqlite_adapter import _quoted_identifier, _safe_identifier
from floorvault.sqlite_migration import migrate_plaintext_column, verify_encrypted_column

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def crypto():
    return FloorVault(b"k" * 32, memory_mode="disabled")


class TestQuotedIdentifierHelper:
    def test_simple_name(self):
        assert _quoted_identifier("users") == "[users]"

    def test_schema_qualified_name(self):
        assert _quoted_identifier("main.users") == "[main].[users]"

    def test_rejects_unsafe_name(self):
        with pytest.raises(ValueError, match="not a valid SQL identifier"):
            _quoted_identifier("users]; DROP TABLE users--")

    def test_rejects_non_string(self):
        with pytest.raises(ValueError):
            _quoted_identifier(None)


class TestEncryptedSQLiteTableQuoting:
    def _make_table(self, connection: sqlite3.Connection, crypto) -> EncryptedSQLiteTable:
        connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, [TRUE] BLOB, cipher BLOB)")
        connection.execute("INSERT INTO users (id) VALUES (?)", ("r1",))
        return EncryptedSQLiteTable(connection, crypto, "users", id_column="id")

    def test_keyword_column_round_trips_real_value(self, crypto):
        """A column literally named TRUE must store and return real ciphertext.

        This is the killer for the unquoted-passthrough mutant: unquoted,
        ``SET TRUE = ?`` is a syntax error and ``SELECT TRUE`` returns the
        string 'TRUE' instead of the stored ciphertext.
        """
        connection = sqlite3.connect(":memory:")
        table = self._make_table(connection, crypto)

        table.store("r1", "TRUE", "secret-value")
        assert table.load("r1", "TRUE") == "secret-value"

        raw = connection.execute("SELECT [TRUE] FROM users WHERE id = 'r1'").fetchone()[0]
        assert isinstance(raw, bytes) and raw.startswith(b"FLV")

    def test_missing_column_fails_closed(self, crypto):
        """A column the schema does not have is a caller error surfaced as a
        library error - the raw driver OperationalError must not escape."""
        connection = sqlite3.connect(":memory:")
        table = self._make_table(connection, crypto)
        connection.execute("INSERT INTO users (id) VALUES ('r2')")

        with pytest.raises(ValueError, match="no such column"):
            table.load("r2", "nosuchcol")

    def test_missing_column_fails_closed_on_store(self, crypto):
        connection = sqlite3.connect(":memory:")
        table = self._make_table(connection, crypto)

        with pytest.raises(ValueError, match="no such column"):
            table.store("r1", "nosuchcol", "x")

    def test_keyword_table_name(self, crypto):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE [order] (id TEXT PRIMARY KEY, cipher BLOB)")
        connection.execute("INSERT INTO [order] (id) VALUES ('r1')")
        table = EncryptedSQLiteTable(connection, crypto, "order", id_column="id")

        table.store("r1", "cipher", "v")
        assert table.load("r1", "cipher") == "v"

    def test_schema_qualified_table_name(self, crypto):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, cipher BLOB)")
        connection.execute("INSERT INTO users (id) VALUES ('r1')")
        table = EncryptedSQLiteTable(connection, crypto, "main.users", id_column="id")

        table.store("r1", "cipher", "v")
        assert table.load("r1", "cipher") == "v"

    def test_crypto_context_keeps_unquoted_name(self, crypto):
        """AAD binds the physical-identity name: the adapter folds to SQLite's
        case-insensitive resolution, so 'TRUE' binds 'true' - the folded name
        decrypts, the raw spelling and the quoted SQL form do not."""
        connection = sqlite3.connect(":memory:")
        table = self._make_table(connection, crypto)
        table.store("r1", "TRUE", "bound-value")

        row = connection.execute("SELECT [TRUE] FROM users WHERE id = 'r1'").fetchone()[0]
        assert crypto.decrypt(row, table="users", record_id="r1", column="true") == "bound-value"
        with pytest.raises(Exception):
            crypto.decrypt(row, table="users", record_id="r1", column="TRUE")
        with pytest.raises(Exception):
            crypto.decrypt(row, table="[users]", record_id="r1", column="true")


class TestMigrationQuoting:
    def test_keyword_columns_migrate(self, crypto):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, [TRUE] TEXT, cipher BLOB)")
        connection.execute("INSERT INTO users (id, [TRUE]) VALUES ('r1', 'plain')")

        result = migrate_plaintext_column(
            connection,
            crypto,
            table="users",
            id_column="id",
            source_column="TRUE",
            destination_column="cipher",
        )
        assert result == {"migrated": 1, "skipped_null": 0}
        assert (
            verify_encrypted_column(
                connection,
                crypto,
                table="users",
                id_column="id",
                source_column="TRUE",
                destination_column="cipher",
            )
            == 1
        )

    def test_missing_column_fails_closed(self, crypto):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, src TEXT, dst BLOB)")
        connection.execute("INSERT INTO users (id, src) VALUES ('r1', 'p')")

        with pytest.raises(sqlite3.OperationalError, match="no such column"):
            migrate_plaintext_column(
                connection,
                crypto,
                table="users",
                id_column="id",
                source_column="nosuchcol",
                destination_column="dst",
            )


class TestInspectorQuoting:
    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        import os

        env = {**os.environ, "FLOOR_VAULT_KEY": "a" * 64, "PYTHONPATH": str(REPO_ROOT / "src")}
        return subprocess.run(
            [sys.executable, "-m", "floorvault.inspector", *argv],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=env,
        )

    def test_expression_column_fails_closed(self, tmp_path):
        """CURRENT_TIMESTAMP must not be evaluated - it must be treated as a
        column name and fail closed when absent."""
        db = tmp_path / "v.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE vault_items (id TEXT, payload_cipher BLOB)")
        conn.execute("INSERT INTO vault_items VALUES ('r1', X'00')")
        conn.commit()
        conn.close()

        result = self._run(["inspect", str(db), "vault_items", "r1", "CURRENT_TIMESTAMP"])
        assert result.returncode == 1
        assert "no such column" in result.stderr
        # Before quoting, the CLI printed the timestamp as the record's plaintext.
        assert "Plaintext" not in result.stdout

    def test_missing_column_is_clean_error_not_traceback(self, tmp_path):
        db = tmp_path / "v.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE vault_items (id TEXT, payload_cipher BLOB)")
        conn.execute("INSERT INTO vault_items VALUES ('r1', X'00')")
        conn.commit()
        conn.close()

        result = self._run(["inspect", str(db), "vault_items", "r1", "nosuchcol"])
        assert result.returncode == 1
        assert "no such column" in result.stderr
        assert "Traceback" not in result.stderr

    def test_validators_share_one_implementation(self):
        from floorvault.inspector import safe_identifier

        for name in ("users", "main.users", "TRUE", "x" * 129, "1bad", "a.b.c"):
            try:
                expected = _safe_identifier(name)
            except ValueError:
                expected = None
            try:
                actual = safe_identifier(name)
            except ValueError:
                actual = None
            assert actual == expected

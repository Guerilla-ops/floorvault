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

import hashlib
import hmac
import importlib.util
import sqlite3
import sys

import pytest

from hermes_vault import (
    DecryptionVerificationError,
    EncryptedLibSqlTable,
    EncryptedSQLiteTable,
    FloorVault,
    HardenedMemoryKey,
    connect_encrypted,
    derive_libsql_file_key,
)
from floorvault.beacons import derive_beacon_key


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


def test_crypto_must_be_hermes_vault(encrypted_users):
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


# --------------------------------------------------------------------------
# File-layer encryption: derive_libsql_file_key / connect_encrypted
# --------------------------------------------------------------------------


def _hkdf_sha256_stdlib(ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 from hmac/hashlib, independent of `cryptography`."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


def test_file_key_is_hkdf_under_its_own_domain_label():
    master = bytes(range(32))
    key = derive_libsql_file_key(master)

    assert key == _hkdf_sha256_stdlib(master, b"floorvault-v1-libsql-file", 32).hex()
    assert len(key) == 64 and key == key.lower()
    # Never another subkey: the AEAD and beacon derivations use other labels.
    assert key != derive_beacon_key(master).hex()
    assert key != _hkdf_sha256_stdlib(master, b"floorvault-v1-aes-siv", 64)[:32].hex()


def test_file_key_accepts_a_hardened_handle():
    master = b"M" * 32
    assert derive_libsql_file_key(HardenedMemoryKey(master, mode="disabled")) == (
        derive_libsql_file_key(master)
    )


def test_file_key_refuses_wrong_length_and_type():
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        derive_libsql_file_key(b"k" * 31)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        derive_libsql_file_key(b"")
    with pytest.raises(TypeError, match="master key must be"):
        derive_libsql_file_key("k" * 32)


@pytest.mark.parametrize(
    "database",
    [
        "libsql://example.turso.io",
        "http://127.0.0.1:8080",
        "https://example.turso.io",
        "wss://example.turso.io",
        "file:local.db?mode=rwc",
    ],
)
def test_connect_encrypted_refuses_remote_and_uri_databases(database):
    with pytest.raises(ValueError, match="local files only"):
        connect_encrypted(database, b"k" * 32)


@pytest.mark.parametrize("database", ["", ":memory:"])
def test_connect_encrypted_refuses_in_memory_databases(database):
    with pytest.raises(ValueError, match="needs a database file"):
        connect_encrypted(database, b"k" * 32)


def test_connect_encrypted_refuses_non_str_paths():
    with pytest.raises(TypeError, match="not bytes"):
        connect_encrypted(b"local.db", b"k" * 32)
    with pytest.raises(TypeError, match="local file path"):
        connect_encrypted(None, b"k" * 32)


@pytest.mark.parametrize(
    "option",
    ["encryption_key", "sync_url", "sync_interval", "offline", "auth_token", "_uri"],
)
def test_connect_encrypted_refuses_unverifiable_options(tmp_path, option):
    with pytest.raises(TypeError, match=f"does not accept {option}"):
        connect_encrypted(tmp_path / "t.db", b"k" * 32, **{option: "x"})
    assert not (tmp_path / "t.db").exists()


def test_connect_encrypted_refuses_an_existing_plaintext_file(tmp_path):
    path = tmp_path / "plain.db"
    plain = sqlite3.connect(path)
    plain.execute("CREATE TABLE t (a)")
    plain.commit()
    plain.close()

    with pytest.raises(ValueError, match="unencrypted SQLite file"):
        connect_encrypted(path, b"k" * 32)


def test_connect_encrypted_reports_a_missing_client(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "libsql", None)
    with pytest.raises(ImportError, match=r"floorvault\[libsql\]"):
        connect_encrypted(tmp_path / "t.db", b"k" * 32)


class _FakeLibSqlModule:
    """Driver-free stand-in for the ``libsql`` module behind ``connect_encrypted``.

    Records each ``connect()`` call and hands back a connection whose probe
    either succeeds or raises, so the factory's key hand-off, probe, and
    close-on-failure are pinned on every leg - including interpreters with no
    libsql wheel, where the live wrong-key test is skipped.
    """

    def __init__(self, *, probe_error: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.connections: list[_FakeEncryptedConnection] = []
        self._probe_error = probe_error

    def connect(self, database, **kwargs):
        self.calls.append((database, kwargs))
        connection = _FakeEncryptedConnection(self._probe_error)
        self.connections.append(connection)
        return connection


class _FakeEncryptedConnection:
    def __init__(self, probe_error: Exception | None) -> None:
        self._probe_error = probe_error
        self.executed: list[str] = []
        self.closed = False

    def execute(self, sql, params=()):
        self.executed.append(sql)
        if self._probe_error is not None:
            raise self._probe_error
        return sqlite3.connect(":memory:").execute("SELECT 0")

    def close(self) -> None:
        self.closed = True


def test_connect_encrypted_hands_the_derived_key_to_the_client(tmp_path, monkeypatch):
    fake = _FakeLibSqlModule()
    monkeypatch.setitem(sys.modules, "libsql", fake)
    master = b"k" * 32

    connection = connect_encrypted(tmp_path / "t.db", master, timeout=1.5)

    assert connection is fake.connections[0]
    assert fake.calls == [
        (
            str(tmp_path / "t.db"),
            {"encryption_key": derive_libsql_file_key(master), "timeout": 1.5},
        )
    ]
    assert connection.executed == ["SELECT count(*) FROM sqlite_master"]
    assert not connection.closed


def test_connect_encrypted_closes_and_refuses_when_the_probe_fails(tmp_path, monkeypatch):
    """A connection that cannot read the schema (wrong key) is closed and never
    returned - the driver-free twin of the live wrong-key test."""
    fake = _FakeLibSqlModule(probe_error=ValueError("file is not a database"))
    monkeypatch.setitem(sys.modules, "libsql", fake)

    with pytest.raises(ValueError, match="derived file key"):
        connect_encrypted(tmp_path / "t.db", b"k" * 32)

    assert len(fake.connections) == 1
    assert fake.connections[0].executed == ["SELECT count(*) FROM sqlite_master"]
    assert fake.connections[0].closed


def test_connect_encrypted_refuses_a_bad_master_key_before_connecting(tmp_path, monkeypatch):
    fake = _FakeLibSqlModule()
    monkeypatch.setitem(sys.modules, "libsql", fake)

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        connect_encrypted(tmp_path / "t.db", b"k" * 31)
    assert fake.calls == []


def _populate(conn) -> None:
    conn.execute(
        "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, "
        "api_token_cipher BLOB NOT NULL DEFAULT X'')"
    )
    conn.execute("CREATE INDEX users_email ON users (email)")
    conn.execute(
        "INSERT INTO users (id, email) VALUES (?, ?), (?, ?)",
        ("user-123", "MARKER-ALICE@example.com", "user-456", "MARKER-BOB@example.com"),
    )
    conn.commit()


def _files_contain(tmp_path, marker: bytes) -> list[str]:
    return [p.name for p in tmp_path.iterdir() if p.is_file() and marker in p.read_bytes()]


@pytest.mark.skipif(
    not _HAS_LIBSQL, reason="libsql wheel unavailable for this interpreter/platform"
)
@pytest.mark.parametrize("journal_mode", ["delete", "wal"])
def test_live_encrypted_file_is_opaque(tmp_path, journal_mode):
    master = b"k" * 32
    conn = connect_encrypted(tmp_path / "t.db", master)
    assert conn.execute(f"PRAGMA journal_mode={journal_mode}").fetchone()[0] == journal_mode
    _populate(conn)

    # Main file, index pages, and the WAL/-shm sidecars while still open.
    assert not _files_contain(tmp_path, b"MARKER-")
    assert not (tmp_path / "t.db").read_bytes().startswith(b"SQLite format 3\x00")
    conn.close()
    assert not _files_contain(tmp_path, b"MARKER-")

    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(tmp_path / "t.db").execute("SELECT * FROM users").fetchall()


@pytest.mark.skipif(
    not _HAS_LIBSQL, reason="libsql wheel unavailable for this interpreter/platform"
)
def test_live_wrong_master_key_is_refused_at_connect(tmp_path):
    conn = connect_encrypted(tmp_path / "t.db", b"k" * 32)
    _populate(conn)
    conn.close()

    with pytest.raises(ValueError, match="derived file key"):
        connect_encrypted(tmp_path / "t.db", b"w" * 32)

    import libsql

    with pytest.raises(ValueError):
        libsql.connect(str(tmp_path / "t.db")).execute("SELECT * FROM users").fetchall()

    reopened = connect_encrypted(tmp_path / "t.db", b"k" * 32)
    assert reopened.execute("SELECT count(*) FROM users").fetchone()[0] == 2
    reopened.close()


@pytest.mark.skipif(
    not _HAS_LIBSQL, reason="libsql wheel unavailable for this interpreter/platform"
)
def test_live_raw_derived_key_opens_the_file(tmp_path):
    """The factory is a thin wrapper: the documented key alone opens the file."""
    import libsql

    master = b"k" * 32
    conn = connect_encrypted(tmp_path / "t.db", master)
    _populate(conn)
    conn.close()

    raw = libsql.connect(str(tmp_path / "t.db"), encryption_key=derive_libsql_file_key(master))
    assert raw.execute("SELECT count(*) FROM users").fetchone()[0] == 2
    raw.close()


@pytest.mark.skipif(
    not _HAS_LIBSQL, reason="libsql wheel unavailable for this interpreter/platform"
)
def test_live_empty_key_plaintext_file_is_refused(tmp_path):
    """libsql writes a plaintext file for encryption_key="" - the fail-open the
    factory exists to keep out. Such a file must not be adopted."""
    import libsql

    leaky = libsql.connect(str(tmp_path / "t.db"), encryption_key="")
    _populate(leaky)
    leaky.close()
    assert _files_contain(tmp_path, b"MARKER-")

    with pytest.raises(ValueError, match="unencrypted SQLite file"):
        connect_encrypted(tmp_path / "t.db", b"k" * 32)


@pytest.mark.skipif(
    not _HAS_LIBSQL, reason="libsql wheel unavailable for this interpreter/platform"
)
def test_live_field_layer_still_binds_coordinates_under_file_encryption(tmp_path):
    master = b"k" * 32
    conn = connect_encrypted(tmp_path / "t.db", master)
    _populate(conn)

    table = EncryptedLibSqlTable(conn, FloorVault(master, memory_mode="disabled"), "users")
    table.store("user-123", "api_token_cipher", "secret-token")
    conn.commit()
    assert table.load("user-123", "api_token_cipher") == "secret-token"

    ciphertext = conn.execute(
        "SELECT api_token_cipher FROM users WHERE id = ?", ("user-123",)
    ).fetchone()[0]
    conn.execute("UPDATE users SET api_token_cipher = ? WHERE id = ?", (ciphertext, "user-456"))
    conn.commit()
    with pytest.raises(DecryptionVerificationError):
        table.load("user-456", "api_token_cipher")
    conn.close()

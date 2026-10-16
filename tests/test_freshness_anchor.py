"""Freshness anchor: rollback, replay, deletion and insertion detection.

Regression for the SECURITY.md §5 limits "same-coordinate replay is not
detected by default" and attacker rows A3/A7 ("rows can be deleted, duplicated
or replayed"): with a FreshnessAnchor whose store the attacker cannot roll
back, every such change to an anchored table is refused.
"""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from floorvault import EncryptedSQLiteTable, FloorVault, FloorVaultError, HardenedMemoryKey
from floorvault.freshness import (
    FileAnchorStore,
    FreshnessAnchor,
    RollbackDetectedError,
)

KEY = b"\x07" * 32


class MemoryStore:
    def __init__(self):
        self.records: dict[str, bytes] = {}
        self.saves = 0

    def load(self, name):
        return self.records.get(name)

    def save(self, name, blob):
        self.saves += 1
        self.records[name] = blob


@pytest.fixture
def app(tmp_path):
    path = tmp_path / "app.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, token_cipher BLOB, note TEXT)")
    connection.executemany("INSERT INTO users (id) VALUES (?)", [("alice",), ("bob",)])
    connection.commit()
    store = FileAnchorStore(tmp_path / "anchors")
    anchor = FreshnessAnchor(KEY, store, name="app", tables={"users": "id"})
    anchor.initialize(connection)
    table = EncryptedSQLiteTable(connection, FloorVault(KEY, memory_mode="disabled"), "users")
    table.store("alice", "token_cipher", "v1")
    table.store("bob", "token_cipher", "bob")
    anchor.commit(connection)
    yield path, store, connection, anchor, table
    connection.close()


def _reopen(path, store):
    connection = sqlite3.connect(path)
    return connection, FreshnessAnchor(KEY, store, name="app", tables={"users": "id"})


def test_current_database_verifies(app):
    path, store, connection, _anchor, _table = app
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    fresh.close()


def test_whole_database_restore_is_refused(app, tmp_path):
    path, store, connection, anchor, table = app
    shutil.copy(path, tmp_path / "backup.db")
    table.store("alice", "token_cipher", "v2")
    anchor.commit(connection)
    connection.close()
    shutil.copy(tmp_path / "backup.db", path)

    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match="does not match"):
        anchor.verify(fresh)
    fresh.close()


def test_single_row_replay_into_its_own_coordinates_is_refused(app):
    """The case AES-SIV cannot catch: the old envelope authenticates in place."""
    path, store, connection, anchor, table = app
    old = connection.execute("SELECT token_cipher FROM users WHERE id='alice'").fetchone()[0]
    table.store("alice", "token_cipher", "v2")
    anchor.commit(connection)
    connection.execute("UPDATE users SET token_cipher=? WHERE id='alice'", (old,))
    connection.commit()
    # The replayed envelope is cryptographically valid on its own...
    assert table.load("alice", "token_cipher") == "v1"
    # ...which is exactly what the anchor exists to catch.
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError):
        anchor.verify(fresh)
    fresh.close()


@pytest.mark.parametrize(
    "tamper",
    [
        "DELETE FROM users WHERE id='bob'",
        "INSERT INTO users (id, token_cipher) SELECT 'carol', token_cipher FROM users WHERE id='bob'",
        "UPDATE users SET note='x' WHERE id='bob'",  # unprotected column
        "UPDATE users SET note=NULL WHERE id='bob'",  # NULL vs absent value
        "UPDATE users SET id='bob2' WHERE id='bob'",
        "ALTER TABLE users ADD COLUMN extra TEXT",
    ],
)
def test_out_of_band_changes_are_refused(app, tamper):
    path, store, connection, _anchor, _table = app
    if "NULL" in tamper:
        # Give the NULL case a non-NULL baseline to move away from.
        connection.execute("UPDATE users SET note='' WHERE id='bob'")
        _anchor.commit(connection)
    connection.execute(tamper)
    connection.commit()
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError):
        anchor.verify(fresh)
    fresh.close()


def test_values_of_different_types_are_distinct(tmp_path):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v)")
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="t", tables={"t": "id"})
    digests = set()
    for value in (1, 1.0, "1", b"1", None):
        connection.execute("DELETE FROM t")
        connection.execute("INSERT INTO t VALUES (1, ?)", (value,))
        digests.add(anchor.digest(connection))
    assert len(digests) == 5


def test_missing_anchor_record_is_refused_not_reinitialized(app):
    path, store, connection, _anchor, _table = app
    (store.directory / "app.fvanchor").unlink()
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match="no record"):
        anchor.verify(fresh)
    fresh.close()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.replace(b'"committed":"', b'"committed":"00'),
        lambda b: b.replace(b'"mac":"', b'"mac":"00'),
        lambda b: b"{not json",
        lambda b: b.replace(b'"FVFA1"', b'"FVFA9"'),
    ],
)
def test_tampered_anchor_record_is_refused(app, mutate):
    path, store, connection, _anchor, _table = app
    record = store.directory / "app.fvanchor"
    record.write_bytes(mutate(record.read_bytes()))
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError):
        anchor.verify(fresh)
    fresh.close()


def test_anchor_record_from_another_key_is_refused(app):
    path, store, _connection, _anchor, _table = app
    fresh = sqlite3.connect(path)
    other = FreshnessAnchor(b"\x08" * 32, store, name="app", tables={"users": "id"})
    with pytest.raises(RollbackDetectedError, match="authentication"):
        other.verify(fresh)
    fresh.close()


def test_anchor_name_is_bound(app):
    """A record copied to another anchor name does not authenticate there."""
    path, store, _connection, _anchor, _table = app
    store.save("other", store.load("app"))
    fresh = sqlite3.connect(path)
    other = FreshnessAnchor(KEY, store, name="other", tables={"users": "id"})
    with pytest.raises(RollbackDetectedError, match="authentication"):
        other.verify(fresh)
    fresh.close()


def test_commit_without_verify_is_refused(app):
    """An app that forgot verify() must not bless a rolled-back state."""
    path, store, _connection, _anchor, _table = app
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match="verify"):
        anchor.commit(fresh)
    with pytest.raises(RollbackDetectedError, match="verify"):
        anchor.update(fresh)
    fresh.close()


def test_commit_refuses_when_the_anchor_moved_since_verify(app):
    """Two writers: the second must re-verify instead of overwriting the first."""
    path, store, connection, _anchor, _table = app
    first, a1 = _reopen(path, store)
    second, a2 = _reopen(path, store)
    a1.verify(first)
    a2.verify(second)
    first.execute("UPDATE users SET note='a' WHERE id='alice'")
    a1.commit(first)
    second.execute("UPDATE users SET note='b' WHERE id='bob'")
    with pytest.raises(RollbackDetectedError, match="verify"):
        a2.commit(second)
    first.close()
    second.close()


def test_crash_after_database_commit_recovers_without_false_alarm(app, monkeypatch):
    """Pending state written, DB committed, crash before promotion."""
    path, store, connection, anchor, table = app
    real_save = store.save
    calls = []

    def save_then_crash(name, blob):
        calls.append(name)
        if len(calls) == 2:
            raise KeyboardInterrupt("simulated crash before the anchor is promoted")
        real_save(name, blob)

    monkeypatch.setattr(store, "save", save_then_crash)
    table.store("alice", "token_cipher", "v2")
    with pytest.raises(KeyboardInterrupt):
        anchor.commit(connection)
    monkeypatch.setattr(store, "save", real_save)

    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)  # accepts the committed-but-unpromoted pending state
    assert '"pending":null' in store.load("app").decode()
    fresh.close()


def test_pending_state_accepts_only_the_pending_digest(app, monkeypatch):
    """A crash leaves pending=new; any *other* state is still refused."""
    path, store, connection, anchor, table = app
    real_save = store.save
    calls = []

    def save_then_crash(name, blob):
        calls.append(name)
        if len(calls) == 2:
            raise KeyboardInterrupt
        real_save(name, blob)

    monkeypatch.setattr(store, "save", save_then_crash)
    table.store("alice", "token_cipher", "v2")
    with pytest.raises(KeyboardInterrupt):
        anchor.commit(connection)
    monkeypatch.setattr(store, "save", real_save)
    connection.execute("UPDATE users SET note='tampered' WHERE id='bob'")
    connection.commit()

    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError):
        anchor.verify(fresh)
    fresh.close()


def test_crash_before_database_commit_keeps_the_old_state_valid(app, monkeypatch):
    path, store, connection, anchor, table = app
    table.store("alice", "token_cipher", "v2")

    class _Crash(Exception):
        pass

    class _NoCommit:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, *args):
            return self._inner.execute(*args)

        def commit(self):
            raise _Crash

    with pytest.raises(_Crash):
        anchor.commit(_NoCommit(connection))
    connection.rollback()
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)  # the committed (old) state still matches
    fresh.close()


def test_update_after_self_committed_write(app):
    path, store, connection, anchor, table = app
    table.store("alice", "token_cipher", "v2")
    connection.commit()
    anchor.update(connection)
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    fresh.close()


def test_initialize_refuses_to_rebaseline(app):
    path, store, _connection, _anchor, _table = app
    fresh, anchor = _reopen(path, store)
    with pytest.raises(FloorVaultError, match="already initialized"):
        anchor.initialize(fresh)
    fresh.close()


def test_accepts_a_hardened_key_handle():
    store = MemoryStore()
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    plain = FreshnessAnchor(KEY, store, name="t", tables={"t": "id"})
    hardened = FreshnessAnchor(
        HardenedMemoryKey(KEY, mode="disabled"), store, name="t", tables={"t": "id"}
    )
    assert plain.digest(connection) == hardened.digest(connection)


def test_digest_is_keyed():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    a = FreshnessAnchor(KEY, MemoryStore(), name="t", tables={"t": "id"})
    b = FreshnessAnchor(b"\x08" * 32, MemoryStore(), name="t", tables={"t": "id"})
    assert a.digest(connection) != b.digest(connection)


def test_table_identifiers_fold_like_sqlite():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE Users (Id INTEGER PRIMARY KEY)")
    lower = FreshnessAnchor(KEY, MemoryStore(), name="t", tables={"users": "id"})
    upper = FreshnessAnchor(KEY, MemoryStore(), name="t", tables={"USERS": "ID"})
    assert lower.digest(connection) == upper.digest(connection)


@pytest.mark.parametrize(
    ("kwargs", "error", "match"),
    [
        ({"name": ""}, ValueError, "name"),
        ({"name": "../escape"}, ValueError, "name may contain"),
        ({"name": ".hidden"}, ValueError, "name may contain"),
        ({"tables": {}}, ValueError, "at least one"),
        ({"tables": {"users; DROP": "id"}}, ValueError, "valid SQL identifier"),
        ({"tables": {"main.users": "id"}}, ValueError, "bare column name"),
        ({"tables": {"users": "id", "USERS": "id"}}, ValueError, "listed twice"),
        ({"store": object()}, TypeError, "load"),
    ],
)
def test_constructor_validation(kwargs, error, match):
    params = {"name": "app", "tables": {"users": "id"}, "store": MemoryStore()}
    params.update(kwargs)
    with pytest.raises(error, match=match):
        FreshnessAnchor(KEY, params.pop("store"), **params)


def test_master_key_length_is_enforced():
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        FreshnessAnchor(b"k" * 31, MemoryStore(), name="t", tables={"t": "id"})


def test_missing_table_and_order_column(tmp_path):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    with pytest.raises(RollbackDetectedError, match="does not exist"):
        FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"gone": "id"}).digest(connection)
    with pytest.raises(ValueError, match="order column"):
        FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"t": "nope"}).digest(connection)


def test_file_store_round_trip_and_permissions(tmp_path):
    store = FileAnchorStore(tmp_path / "a")
    assert store.load("x") is None
    store.save("x", b"one")
    store.save("x", b"two")
    assert store.load("x") == b"two"
    assert sorted(p.name for p in (tmp_path / "a").iterdir()) == ["x.fvanchor"]
    if hasattr(__import__("os"), "geteuid"):
        assert ((tmp_path / "a" / "x.fvanchor").stat().st_mode & 0o077) == 0

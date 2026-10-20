"""Freshness anchor: rollback, replay, deletion, insertion and schema tampering.

Regression for the SECURITY.md §5 limits "same-coordinate replay is not
detected by default" and attacker rows A3/A7 ("rows can be deleted, duplicated
or replayed"): with a FreshnessAnchor whose store the attacker cannot roll
back, every such change to an anchored table is refused. Review findings on
PR #56 (interrupted-commit rollback, cross-connection blessing, concurrent
anchor overwrite, trigger tampering, unflushed rename) each have a test here.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import threading

import pytest

from hermes_vault import EncryptedSQLiteTable, FloorVault, FloorVaultError, HardenedMemoryKey
from hermes_vault import freshness as freshness_module
from hermes_vault.freshness import (
    FileAnchorStore,
    FreshnessAnchor,
    RollbackDetectedError,
)

KEY = b"\x07" * 32


class MemoryStore:
    def __init__(self):
        self.records: dict[str, bytes] = {}

    def load(self, name):
        return self.records.get(name)

    def compare_and_swap(self, name, expected, new):
        if self.records.get(name) != expected:
            return False
        self.records[name] = new
        return True


class CrashingStore(FileAnchorStore):
    """Raises KeyboardInterrupt on the Nth compare-and-swap call."""

    def __init__(self, directory):
        super().__init__(directory)
        self.calls = 0
        self.crash_on = None

    def compare_and_swap(self, name, expected, new):
        self.calls += 1
        if self.calls == self.crash_on:
            raise KeyboardInterrupt("simulated crash")
        return super().compare_and_swap(name, expected, new)


class _CommitCrashes:
    """Connection proxy whose COMMIT crashes before reaching SQLite."""

    def __init__(self, inner):
        self._inner = inner

    @property
    def in_transaction(self):
        return self._inner.in_transaction

    def execute(self, sql, *args):
        if sql.strip().upper() == "COMMIT":
            raise KeyboardInterrupt("crash before the database commit")
        return self._inner.execute(sql, *args)


def _table(connection):
    return EncryptedSQLiteTable(connection, FloorVault(KEY, memory_mode="disabled"), "users")


@pytest.fixture
def app(tmp_path):
    path = tmp_path / "app.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, token_cipher BLOB, note TEXT)")
    connection.executemany("INSERT INTO users (id) VALUES (?)", [("alice",), ("bob",)])
    connection.commit()
    store = CrashingStore(tmp_path / "anchors")
    anchor = FreshnessAnchor(KEY, store, name="app", tables={"users": "id"})
    anchor.initialize(connection)
    table = _table(connection)
    with anchor.transaction(connection):
        table.store("alice", "token_cipher", "v1")
        table.store("bob", "token_cipher", "bob")
    yield path, store, connection, anchor, table
    connection.close()


def _reopen(path, store):
    connection = sqlite3.connect(path)
    return connection, FreshnessAnchor(KEY, store, name="app", tables={"users": "id"})


def _assert_refused(path, store, match=None):
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match=match):
        anchor.verify(fresh)
    fresh.close()


def _write_crashing_on(store, nth_cas, anchor, connection, value):
    """Run a transaction whose ``nth_cas`` anchor write (1 = pending, 2 = promote) crashes."""
    store.crash_on = store.calls + nth_cas
    with pytest.raises(KeyboardInterrupt):
        with anchor.transaction(connection):
            _table(connection).store("alice", "token_cipher", value)
    store.crash_on = None


# -- detection ----------------------------------------------------------------


def test_current_database_verifies(app):
    path, store, _connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    assert _table(fresh).load("alice", "token_cipher") == "v1"
    fresh.close()


def test_whole_database_restore_is_refused(app, tmp_path):
    path, store, connection, anchor, table = app
    shutil.copy(path, tmp_path / "backup.db")
    with anchor.transaction(connection):
        table.store("alice", "token_cipher", "v2")
    connection.close()
    shutil.copy(tmp_path / "backup.db", path)
    _assert_refused(path, store, "does not match")


def test_single_row_replay_into_its_own_coordinates_is_refused(app):
    """The case AES-SIV cannot catch: the old envelope authenticates in place."""
    path, store, connection, anchor, table = app
    old = connection.execute("SELECT token_cipher FROM users WHERE id='alice'").fetchone()[0]
    with anchor.transaction(connection):
        table.store("alice", "token_cipher", "v2")
    connection.execute("UPDATE users SET token_cipher=? WHERE id='alice'", (old,))
    connection.commit()
    assert table.load("alice", "token_cipher") == "v1"  # cryptographically valid...
    _assert_refused(path, store)  # ...which is exactly what the anchor catches


@pytest.mark.parametrize(
    "tamper",
    [
        "DELETE FROM users WHERE id='bob'",
        "INSERT INTO users (id, token_cipher) SELECT 'carol', token_cipher FROM users WHERE id='bob'",
        "UPDATE users SET note='x' WHERE id='bob'",
        "UPDATE users SET id='bob2' WHERE id='bob'",
        "ALTER TABLE users ADD COLUMN extra TEXT",
        "CREATE INDEX users_note ON users (note)",
        "ALTER TABLE users ADD COLUMN gen TEXT GENERATED ALWAYS AS (note || 'x') VIRTUAL",
    ],
)
def test_out_of_band_changes_are_refused(app, tamper):
    path, store, connection, _anchor, _table_ = app
    connection.execute(tamper)
    connection.commit()
    _assert_refused(path, store)


def test_unanchored_tables_are_not_covered(app):
    path, store, connection, _anchor, _table_ = app
    connection.execute("CREATE TABLE other (x)")
    connection.execute("INSERT INTO other VALUES (1)")
    connection.commit()
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    fresh.close()


def test_planted_trigger_is_refused(app):
    """Review finding: a trigger that silently undoes later writes."""
    path, store, connection, _anchor, _table_ = app
    connection.execute(
        "CREATE TRIGGER keep_old AFTER UPDATE OF token_cipher ON users "
        "BEGIN UPDATE users SET token_cipher = OLD.token_cipher WHERE id = NEW.id; END"
    )
    connection.commit()
    _assert_refused(path, store)


def test_trigger_on_an_unanchored_table_is_refused_too(app):
    """A trigger on another table can still write the anchored one."""
    path, store, connection, _anchor, _table_ = app
    connection.execute("CREATE TABLE side (x)")
    connection.execute("CREATE TRIGGER via_side AFTER INSERT ON side BEGIN DELETE FROM users; END")
    connection.commit()
    _assert_refused(path, store)


def test_null_versus_empty_is_a_change(app):
    path, store, connection, anchor, _table_ = app
    with anchor.transaction(connection):
        connection.execute("UPDATE users SET note='' WHERE id='bob'")
    connection.execute("UPDATE users SET note=NULL WHERE id='bob'")
    connection.commit()
    _assert_refused(path, store)


def test_values_of_different_types_are_distinct():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v)")
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="t", tables={"t": "id"})
    digests = set()
    for value in (1, 1.0, "1", b"1", None):
        connection.execute("DELETE FROM t")
        connection.execute("INSERT INTO t VALUES (1, ?)", (value,))
        digests.add(anchor.digest(connection))
    assert len(digests) == 5


# -- anchor record integrity --------------------------------------------------


def test_missing_anchor_record_is_refused_not_reinitialized(app):
    path, store, _connection, _anchor, _table_ = app
    (store.directory / "app.fvanchor").unlink()
    _assert_refused(path, store, "no record")


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
    path, store, _connection, _anchor, _table_ = app
    record = store.directory / "app.fvanchor"
    record.write_bytes(mutate(record.read_bytes()))
    _assert_refused(path, store)


def test_anchor_record_from_another_key_is_refused(app):
    path, store, _connection, _anchor, _table_ = app
    fresh = sqlite3.connect(path)
    other = FreshnessAnchor(b"\x08" * 32, store, name="app", tables={"users": "id"})
    with pytest.raises(RollbackDetectedError, match="authentication"):
        other.verify(fresh)
    fresh.close()


def test_anchor_name_is_bound(app):
    path, store, _connection, _anchor, _table_ = app
    assert store.compare_and_swap("other", None, store.load("app"))
    fresh = sqlite3.connect(path)
    other = FreshnessAnchor(KEY, store, name="other", tables={"users": "id"})
    with pytest.raises(RollbackDetectedError, match="authentication"):
        other.verify(fresh)
    fresh.close()


def test_initialize_refuses_to_rebaseline(app):
    path, store, _connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    with pytest.raises(FloorVaultError, match="already initialized"):
        anchor.initialize(fresh)
    fresh.close()


# -- write authorization ------------------------------------------------------


def test_transaction_refuses_a_rolled_back_database(app, tmp_path):
    path, store, connection, anchor, table = app
    shutil.copy(path, tmp_path / "old.db")
    with anchor.transaction(connection):
        table.store("alice", "token_cipher", "v2")
    connection.close()
    shutil.copy(tmp_path / "old.db", path)
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError):
        with anchor.transaction(fresh):
            raise AssertionError("must not run")
    assert not fresh.in_transaction
    fresh.close()


def test_transaction_rolls_back_on_error_and_leaves_the_anchor(app):
    path, store, _connection, _anchor, _table_ = app
    before = store.load("app")
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RuntimeError):
        with anchor.transaction(fresh):
            fresh.execute("UPDATE users SET note='x' WHERE id='bob'")
            raise RuntimeError("boom")
    assert store.load("app") == before
    assert not fresh.in_transaction
    anchor.verify(fresh)
    fresh.close()


def test_transaction_holds_the_write_lock(app):
    """No other writer can slip a change in between verify and commit."""
    path, store, _connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    intruder = sqlite3.connect(path, timeout=0)
    with anchor.transaction(fresh):
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            intruder.execute("UPDATE users SET note='sneak' WHERE id='bob'")
    intruder.close()
    anchor.verify(fresh)
    fresh.close()


def test_transaction_refuses_an_already_open_transaction(app):
    path, store, _connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    fresh.execute("UPDATE users SET note='open' WHERE id='bob'")
    assert fresh.in_transaction
    with pytest.raises(FloorVaultError, match="open transaction"):
        with anchor.transaction(fresh):
            pass
    fresh.rollback()
    fresh.close()


def test_failed_verify_revokes_write_authorization(app):
    """Review finding: a failed verify must not leave earlier trust in place."""
    path, store, connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    connection.execute("UPDATE users SET note='replayed' WHERE id='bob'")
    connection.commit()
    with pytest.raises(RollbackDetectedError):
        anchor.verify(fresh)
    with pytest.raises(RollbackDetectedError, match="verify"):
        anchor.accept_external_write(fresh)
    fresh.close()


def test_external_write_from_a_different_connection_is_refused(app, tmp_path):
    """Review finding: verify one database, then record another (rolled back) one."""
    path, store, connection, anchor, table = app
    shutil.copy(path, tmp_path / "old.db")
    with anchor.transaction(connection):
        table.store("alice", "token_cipher", "v2")
    verified, anchor = _reopen(path, store)
    anchor.verify(verified)
    stale = sqlite3.connect(tmp_path / "old.db")
    with pytest.raises(RollbackDetectedError, match="not the one verified"):
        anchor.accept_external_write(stale)
    verified.close()
    stale.close()


def test_external_write_after_verify(app):
    path, store, connection, anchor, table = app
    anchor.verify(connection)
    table.store("alice", "token_cipher", "v2")
    connection.commit()
    anchor.accept_external_write(connection)
    fresh, verifier = _reopen(path, store)
    verifier.verify(fresh)
    fresh.close()


def test_external_write_refuses_when_the_anchor_moved(app):
    path, store, connection, anchor, _table_ = app
    other, other_anchor = _reopen(path, store)
    anchor.verify(connection)
    with other_anchor.transaction(other):
        other.execute("UPDATE users SET note='other' WHERE id='bob'")
    with pytest.raises(RollbackDetectedError):
        anchor.accept_external_write(connection)
    other.close()


# -- crash safety -------------------------------------------------------------


def test_crash_after_database_commit_recovers(app):
    """Pending written, DB committed, crash before promotion: accepted."""
    path, store, connection, anchor, _table_ = app
    _write_crashing_on(store, 2, anchor, connection, "v2")
    fresh, anchor = _reopen(path, store)
    anchor.verify(fresh)
    assert '"pending":null' in store.load("app").decode()
    assert _table(fresh).load("alice", "token_cipher") == "v2"
    fresh.close()


def test_rollback_during_an_interrupted_commit_is_refused(app, tmp_path):
    """Review finding: crash after the DB commit, then restore the old DB."""
    path, store, connection, anchor, _table_ = app
    shutil.copy(path, tmp_path / "before.db")
    _write_crashing_on(store, 2, anchor, connection, "v2-rotated")
    connection.close()
    shutil.copy(tmp_path / "before.db", path)
    _assert_refused(path, store, "interrupted commit")


def test_crash_before_database_commit_fails_closed_until_discarded(app):
    """Pending written, DB commit never happened: ambiguous, so refused, and
    recoverable only by the operator's explicit assertion."""
    path, store, connection, anchor, _table_ = app
    with pytest.raises(KeyboardInterrupt):
        with anchor.transaction(_CommitCrashes(connection)):
            _table(connection).store("alice", "token_cipher", "v2")
    assert not connection.in_transaction  # rolled back
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match="interrupted commit"):
        anchor.verify(fresh)
    anchor.discard_interrupted_commit(fresh)
    anchor.verify(fresh)
    assert _table(fresh).load("alice", "token_cipher") == "v1"
    fresh.close()


def test_pending_state_accepts_only_the_pending_digest(app):
    path, store, connection, anchor, _table_ = app
    _write_crashing_on(store, 2, anchor, connection, "v2")
    connection.execute("UPDATE users SET note='tampered' WHERE id='bob'")
    connection.commit()
    _assert_refused(path, store)


def test_discard_refuses_without_a_pending_commit(app):
    path, store, _connection, _anchor, _table_ = app
    fresh, anchor = _reopen(path, store)
    with pytest.raises(FloorVaultError, match="no interrupted commit"):
        anchor.discard_interrupted_commit(fresh)
    fresh.close()


def test_discard_refuses_a_database_matching_neither_state(app):
    path, store, connection, anchor, _table_ = app
    _write_crashing_on(store, 2, anchor, connection, "v2")
    connection.execute("UPDATE users SET note='other' WHERE id='bob'")
    connection.commit()
    fresh, anchor = _reopen(path, store)
    with pytest.raises(RollbackDetectedError, match="neither"):
        anchor.discard_interrupted_commit(fresh)
    fresh.close()


# -- concurrency --------------------------------------------------------------


def test_stale_promotion_cannot_overwrite_a_newer_record(app, monkeypatch):
    """Review finding: writer A pauses before promoting; B commits; A resumes.

    A's promotion is a compare-and-swap against its own pending record, so it
    cannot replace B's newer record, and the database stays verifiable.
    """
    path, store, connection, _anchor, _table_ = app
    connection.close()
    anchor_a = FreshnessAnchor(KEY, store, name="app", tables={"users": "id"})
    other, anchor_b = _reopen(path, store)

    paused = threading.Event()
    resume = threading.Event()
    real_cas = FileAnchorStore.compare_and_swap
    a_calls = []

    def pausing_cas(self, name, expected, new):
        if threading.current_thread().name == "writer-a":
            a_calls.append(name)
            if len(a_calls) == 2:  # A's promotion, after its DB commit
                paused.set()
                resume.wait(10)
        return real_cas(self, name, expected, new)

    monkeypatch.setattr(CrashingStore, "compare_and_swap", pausing_cas)
    errors = []

    def writer_a():
        a = sqlite3.connect(path, check_same_thread=False)
        try:
            with anchor_a.transaction(a):
                _table(a).store("alice", "token_cipher", "from-a")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            a.close()

    thread = threading.Thread(target=writer_a, name="writer-a")
    thread.start()
    assert paused.wait(10)
    with anchor_b.transaction(other):  # B verifies (promoting A's pending) and commits
        _table(other).store("bob", "token_cipher", "from-b")
    resume.set()
    thread.join(10)

    assert errors == []  # A finds its pending already promoted and accepts that
    final, verifier = _reopen(path, store)
    verifier.verify(final)  # B's newer state is the anchor, not A's older one
    assert _table(final).load("bob", "token_cipher") == "from-b"
    assert _table(final).load("alice", "token_cipher") == "from-a"
    final.close()
    other.close()


def test_file_store_cas_refuses_a_stale_expectation(tmp_path):
    store = FileAnchorStore(tmp_path / "a")
    assert store.compare_and_swap("x", None, b"one")
    assert not store.compare_and_swap("x", None, b"two")
    assert not store.compare_and_swap("x", b"wrong", b"two")
    assert store.compare_and_swap("x", b"one", b"two")
    assert store.load("x") == b"two"


def test_file_store_flushes_new_directories_and_the_rename(tmp_path, monkeypatch):
    """Review finding: the rename (and any new directory) must be durable."""
    flushed = []
    monkeypatch.setattr(freshness_module, "_fsync_directory", lambda d: flushed.append(d))
    store = FileAnchorStore(tmp_path / "a" / "b")
    store.compare_and_swap("x", None, b"one")
    assert flushed == [tmp_path, tmp_path / "a", tmp_path / "a" / "b"]


def test_file_store_round_trip_and_permissions(tmp_path):
    store = FileAnchorStore(tmp_path / "a")
    assert store.load("x") is None
    store.compare_and_swap("x", None, b"one")
    assert store.load("x") == b"one"
    assert sorted(p.name for p in (tmp_path / "a").iterdir()) == [
        "x.fvanchor",
        "x.fvanchor.lock",
    ]
    if os.name == "posix":
        assert ((tmp_path / "a" / "x.fvanchor").stat().st_mode & 0o077) == 0


# -- construction -------------------------------------------------------------


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
        ({"store": object()}, TypeError, "compare_and_swap"),
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


def test_missing_table_and_order_column():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    with pytest.raises(RollbackDetectedError, match="does not exist"):
        FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"gone": "id"}).digest(connection)
    with pytest.raises(ValueError, match="order column"):
        FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"t": "nope"}).digest(connection)


# -- connection modes (issue #58) ---------------------------------------------


def _modes():
    modes = [("default", {}), ("isolation_level=None", {"isolation_level": None})]
    if sys.version_info >= (3, 12):
        modes.append(("autocommit=True", {"autocommit": True}))
    return modes


@pytest.mark.parametrize(("label", "kwargs"), _modes(), ids=[m[0] for m in _modes()])
def test_transaction_commits_in_every_supported_connection_mode(tmp_path, label, kwargs):
    """autocommit=True made connection.commit() a no-op: the write was lost
    while the anchor advanced, bricking every later verify."""
    path = tmp_path / "m.db"
    connection = sqlite3.connect(path, **kwargs)
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    if connection.in_transaction:
        connection.execute("COMMIT")
    store = FileAnchorStore(tmp_path / "anchors")
    anchor = FreshnessAnchor(KEY, store, name="m", tables={"t": "id"})
    anchor.initialize(connection)
    with anchor.transaction(connection):
        connection.execute("INSERT INTO t VALUES (1, 'a')")
    assert not connection.in_transaction
    connection.close()

    fresh = sqlite3.connect(path, **kwargs)
    assert fresh.execute("SELECT * FROM t").fetchall() == [(1, "a")]
    FreshnessAnchor(KEY, store, name="m", tables={"t": "id"}).verify(fresh)
    fresh.close()


@pytest.mark.parametrize(("label", "kwargs"), _modes(), ids=[m[0] for m in _modes()])
def test_transaction_rolls_back_in_every_supported_connection_mode(tmp_path, label, kwargs):
    path = tmp_path / "m.db"
    connection = sqlite3.connect(path, **kwargs)
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    if connection.in_transaction:
        connection.execute("COMMIT")
    store = FileAnchorStore(tmp_path / "anchors")
    anchor = FreshnessAnchor(KEY, store, name="m", tables={"t": "id"})
    anchor.initialize(connection)
    before = store.load("m")
    with pytest.raises(RuntimeError):
        with anchor.transaction(connection):
            connection.execute("INSERT INTO t VALUES (1, 'a')")
            raise RuntimeError("boom")
    assert not connection.in_transaction
    assert connection.execute("SELECT * FROM t").fetchall() == []
    assert store.load("m") == before
    connection.close()


@pytest.mark.skipif(sys.version_info < (3, 12), reason="autocommit= is Python 3.12+")
def test_transaction_refuses_autocommit_false_accurately(tmp_path):
    connection = sqlite3.connect(tmp_path / "m.db", autocommit=False)
    connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    connection.commit()
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="m", tables={"t": "id"})
    anchor.initialize(connection)
    with pytest.raises(FloorVaultError, match="autocommit=False"):
        with anchor.transaction(connection):
            raise AssertionError("must not run")
    connection.close()


class _NoOpCommitConnection:
    """Models autocommit=True on every Python version: commit()/rollback()
    do nothing, so only explicit COMMIT/ROLLBACK statements take effect."""

    def __init__(self, inner):
        self._inner = inner

    @property
    def in_transaction(self):
        return self._inner.in_transaction

    def execute(self, *args):
        return self._inner.execute(*args)

    def commit(self):
        pass

    def rollback(self):
        pass


def test_transaction_does_not_rely_on_driver_commit(tmp_path):
    path = tmp_path / "m.db"
    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    store = FileAnchorStore(tmp_path / "anchors")
    connection = _NoOpCommitConnection(raw)
    anchor = FreshnessAnchor(KEY, store, name="m", tables={"t": "id"})
    anchor.initialize(connection)
    with anchor.transaction(connection):
        connection.execute("INSERT INTO t VALUES (1, 'a')")
    with pytest.raises(RuntimeError):
        with anchor.transaction(connection):
            connection.execute("INSERT INTO t VALUES (2, 'b')")
            raise RuntimeError("boom")
    assert not raw.in_transaction
    raw.close()
    fresh = sqlite3.connect(path)
    assert fresh.execute("SELECT * FROM t").fetchall() == [(1, "a")]
    FreshnessAnchor(KEY, store, name="m", tables={"t": "id"}).verify(fresh)
    fresh.close()


def test_transaction_refuses_an_autocommit_false_connection_object():
    class _AutocommitFalse:
        autocommit = False
        in_transaction = True

        def execute(self, *args):
            raise AssertionError("must not reach the database")

    anchor = FreshnessAnchor(KEY, MemoryStore(), name="m", tables={"t": "id"})
    with pytest.raises(FloorVaultError, match="autocommit=False"):
        with anchor.transaction(_AutocommitFalse()):
            raise AssertionError("must not run")


# -- order column uniqueness (issue #59) --------------------------------------


@pytest.mark.parametrize(
    "rows",
    [
        [("g", "1"), ("g", "2")],  # duplicate values
        [(None, "1"), (None, "2")],  # two NULLs tie as well
    ],
)
def test_non_unique_order_column_is_refused(rows):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (grp TEXT, v TEXT)")
    connection.executemany("INSERT INTO t VALUES (?, ?)", rows)
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"t": "grp"})
    with pytest.raises(ValueError, match="uniquely"):
        anchor.digest(connection)


def test_unique_order_column_with_one_null_is_accepted():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (k TEXT, v TEXT)")
    connection.executemany("INSERT INTO t VALUES (?, ?)", [(None, "1"), ("a", "2")])
    FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"t": "k"}).digest(connection)


def test_digest_does_not_depend_on_physical_row_order():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE t (id TEXT PRIMARY KEY, v TEXT)")
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="x", tables={"t": "id"})
    rows = [("a", "1"), ("b", "2"), ("c", "3")]
    connection.executemany("INSERT INTO t VALUES (?, ?)", rows)
    first = anchor.digest(connection)
    connection.execute("DELETE FROM t")
    connection.executemany("INSERT INTO t VALUES (?, ?)", list(reversed(rows)))
    connection.commit()
    connection.execute("VACUUM")
    assert anchor.digest(connection) == first


def test_duplicated_row_on_a_non_pk_order_column_is_refused(app):
    """An attacker duplicating a row on a unique-but-unconstrained order
    column hits the uniqueness check rather than slipping through."""
    path, store, connection, _anchor, _table_ = app
    connection.execute("CREATE TABLE loose (k TEXT, v TEXT)")
    connection.execute("INSERT INTO loose VALUES ('a', '1')")
    connection.commit()
    anchor = FreshnessAnchor(KEY, MemoryStore(), name="loose", tables={"loose": "k"})
    anchor.initialize(connection)
    connection.execute("INSERT INTO loose VALUES ('a', '1')")
    connection.commit()
    with pytest.raises(ValueError, match="uniquely"):
        anchor.verify(connection)


# -- store name validation (issue #60) ----------------------------------------


@pytest.mark.parametrize("name", ["../escaped", "a/b", "..", ".hidden", "", "a\\b"])
def test_file_store_refuses_unsafe_names(tmp_path, name):
    store = FileAnchorStore(tmp_path / "store")
    with pytest.raises(ValueError, match="name"):
        store.compare_and_swap(name, None, b"x")
    with pytest.raises(ValueError, match="name"):
        store.load(name)
    assert not any(p.name.startswith("escaped") for p in tmp_path.iterdir())

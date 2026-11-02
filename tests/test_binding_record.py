"""The binding record kept outside the store (RUN-9, #97), and its fingerprint."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from floorvault import FloorVault
from floorvault.binding_record import (
    MARKER_NAME,
    STATE_DIR_ENV,
    BindingRecord,
    BindingRecordError,
    BindingRecordLost,
    default_state_dir,
)
from floorvault.vaultkit import VaultError
from floorvault.vaultkit.vault import VaultStore

PROGRAM = os.path.abspath("/opt/tool/bin/server")


@pytest.fixture()
def vault(tmp_path):
    crypto = FloorVault(os.urandom(32), memory_mode="disabled")
    store = VaultStore(tmp_path / "vault", crypto=crypto)
    store.add_item("generic", "Token", {"value": "s3cret"}, item_id="tok")
    return store


def test_fingerprint_tracks_the_stored_binding(vault, tmp_path):
    assert vault.binding_fingerprint("tok") == "none"
    vault.set_allowed_commands("tok", [[PROGRAM]])
    first = vault.binding_fingerprint("tok")
    assert len(first) == 64 and first != "none"
    with contextlib.closing(sqlite3.connect(tmp_path / "vault" / "vault.db")) as db:
        sealed = db.execute("SELECT allowed_commands FROM vault_items").fetchone()[0]
    # Sealing the same lines again gives another ciphertext, so another fingerprint:
    # an older copy written back is told apart from the current one.
    vault.set_allowed_commands("tok", [[PROGRAM]])
    assert vault.binding_fingerprint("tok") not in ("none", first)
    with contextlib.closing(sqlite3.connect(tmp_path / "vault" / "vault.db")) as db:
        db.execute("UPDATE vault_items SET allowed_commands = ?", (sealed,))
        db.commit()
    assert vault.binding_fingerprint("tok") == first
    with pytest.raises(VaultError, match="not found"):
        vault.binding_fingerprint("missing")


def test_record_trusts_first_use_then_refuses_changes(tmp_path):
    record = BindingRecord(tmp_path / "vault", tmp_path / "state")
    assert record.check({"a": "none", "b": "1" * 64}) == []
    assert record.check({"a": "none", "b": "1" * 64}) == []
    assert record.check({"a": "2" * 64, "b": "1" * 64, "c": "none"}) == ["a"]
    # A refused item is not overwritten by the check that refused it.
    assert record.check({"a": "2" * 64}) == ["a"]
    record.record("a", "2" * 64)
    assert record.check({"a": "2" * 64, "c": "3" * 64}) == ["c"]
    record.forget("c")
    assert record.check({"c": "3" * 64}) == []


def test_record_is_per_store_and_outside_it(tmp_path):
    one = BindingRecord(tmp_path / "one", tmp_path / "state")
    two = BindingRecord(tmp_path / "two", tmp_path / "state")
    one.check({"a": "none"})
    assert two.check({"a": "1" * 64}) == []
    assert one.path != two.path
    assert one.path.parent == tmp_path / "state" / "bindings"
    for inside in (tmp_path / "one", tmp_path / "one" / "state"):
        with pytest.raises(BindingRecordError, match="inside the store"):
            BindingRecord(tmp_path / "one", inside)


def test_record_refuses_one_it_cannot_read_or_that_names_another_store(tmp_path):
    record = BindingRecord(tmp_path / "vault", tmp_path / "state")
    record.check({"a": "none"})
    data = json.loads(record.path.read_text(encoding="utf-8"))
    for broken in (
        b"{not json",
        json.dumps({**data, "format": "OTHER"}).encode(),
        json.dumps({**data, "vault": str(tmp_path / "elsewhere")}).encode(),
        json.dumps({**data, "items": {"a": 1}}).encode(),
    ):
        record.path.write_bytes(broken)
        with pytest.raises(BindingRecordError, match="unreadable"):
            record.check({"a": "none"})


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions")
def test_an_unwritable_state_directory_is_reported(tmp_path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o500)
    try:
        with pytest.raises(BindingRecordError, match=STATE_DIR_ENV):
            BindingRecord(tmp_path / "vault", state).check({"a": "none"})
    finally:
        state.chmod(0o700)


def test_default_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    home = Path.home()
    assert default_state_dir({STATE_DIR_ENV: str(tmp_path / "x")}) == tmp_path / "x"
    assert default_state_dir({}, "linux") == home / ".local" / "state" / "floorvault"
    assert default_state_dir({"XDG_STATE_HOME": "/srv/state"}, "linux") == Path(
        "/srv/state/floorvault"
    )
    # A relative XDG path is ignored, as the XDG spec requires.
    assert default_state_dir({"XDG_STATE_HOME": "rel"}, "linux") == (
        home / ".local" / "state" / "floorvault"
    )
    assert default_state_dir({}, "darwin") == (
        home / "Library" / "Application Support" / "floorvault"
    )
    assert default_state_dir({"LOCALAPPDATA": str(tmp_path / "L")}, "win32") == (
        tmp_path / "L" / "floorvault"
    )


def test_a_record_that_disappears_is_noticed_through_the_store_marker(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    record = BindingRecord(vault_dir, tmp_path / "state")
    marker = vault_dir / MARKER_NAME
    assert record.marker_path == marker
    # Nothing recorded yet: no marker, nothing lost, and an empty check adds neither.
    assert record.check({}) == []
    assert not marker.exists() and not record.lost_on_last_update
    assert record.check({"a": "none"}) == []
    assert marker.is_file() and not record.lost_on_last_update
    # The state directory is wiped (an ephemeral container): the marker stays.
    record.path.unlink()
    with pytest.raises(BindingRecordLost):
        record.check({"a": "none"}, refuse_lost=True)
    assert record.lost_on_last_update
    assert not record.path.exists()  # refusing starts no record
    # Without the requirement the check goes on, trusting items as they are, and
    # says that the record it updated had been lost.
    assert record.check({"a": "1" * 64}) == []
    assert record.lost_on_last_update and record.path.exists()
    assert record.check({"a": "1" * 64}, refuse_lost=True) == []
    assert not record.lost_on_last_update


def test_loss_is_judged_on_the_snapshot_the_update_is_made_against(tmp_path, monkeypatch):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    record = BindingRecord(vault_dir, tmp_path / "state")
    record.check({"a": "none"})
    # The record vanishes between any earlier look and the load the swap uses:
    # that load is the one that decides, so the loss cannot be recreated unnoticed.
    monkeypatch.setattr(record._anchors, "load", lambda name: None)
    with pytest.raises(BindingRecordLost):
        record.check({"a": "none"}, refuse_lost=True)


def test_the_marker_is_left_beside_a_record_that_already_exists(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    record = BindingRecord(vault_dir, tmp_path / "state")
    record.check({"a": "none"})
    (vault_dir / MARKER_NAME).unlink()
    record.path.unlink()
    assert record.check({"a": "none"}, refuse_lost=True) == []  # no marker: a first use
    assert not record.lost_on_last_update
    (vault_dir / MARKER_NAME).unlink()
    record.check({"a": "none"})  # nothing changed, but a record exists
    assert (vault_dir / MARKER_NAME).is_file()
    record.path.unlink()
    with pytest.raises(BindingRecordLost):
        record.check({"a": "none"}, refuse_lost=True)


def test_only_a_regular_marker_counts_and_a_missing_store_dir_is_not_an_error(tmp_path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    record = BindingRecord(vault_dir, tmp_path / "state")
    (vault_dir / MARKER_NAME).mkdir()
    record.check({"a": "none"})  # leaves the directory where it is
    assert (vault_dir / MARKER_NAME).is_dir()
    record.path.unlink()
    assert record.check({"a": "none"}, refuse_lost=True) == []
    assert not record.lost_on_last_update
    gone = BindingRecord(tmp_path / "nowhere", tmp_path / "state2")
    assert gone.check({"a": "none"}, refuse_lost=True) == []
    assert not gone.lost_on_last_update

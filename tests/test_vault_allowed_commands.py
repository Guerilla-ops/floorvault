"""VaultStore per-item command bindings (`floorvault secrets allow`, #80)."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from floorvault import DecryptionVerificationError, FloorVault, KeyRing
from floorvault.vault_rotation import rotate_vault_store
from floorvault.vaultkit.vault import VaultError, VaultStore

OLD = bytes.fromhex("31" * 32)
NEW = bytes.fromhex("42" * 32)
PROG = os.path.abspath("/opt/tool/bin/server")
OTHER = os.path.abspath("/opt/tool/bin/other")


def _crypto(key: bytes) -> FloorVault:
    return FloorVault(key, memory_mode="disabled")


def _store(tmp_path: Path, key: bytes = OLD) -> VaultStore:
    return VaultStore(tmp_path / "vault", crypto=_crypto(key))


def _raw(tmp_path: Path, item_id: str):
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        return conn.execute(
            "SELECT allowed_commands FROM vault_items WHERE id = ?", (item_id,)
        ).fetchone()[0]


def _set_raw(tmp_path: Path, item_id: str, value) -> None:
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        conn.execute("UPDATE vault_items SET allowed_commands = ? WHERE id = ?", (value, item_id))


def test_items_start_unbound_and_bindings_round_trip(tmp_path):
    store = _store(tmp_path)
    item = store.add_item("generic", "Token", {"value": "s"})
    assert store.get_allowed_commands(item.id) is None
    commands = [[PROG, "--stdio"], [OTHER]]
    assert store.set_allowed_commands(item.id, commands + [[PROG, "--stdio"]]) is True
    assert store.get_allowed_commands(item.id) == commands  # duplicates dropped, order kept
    assert store.set_allowed_commands(item.id, []) is True
    assert store.get_allowed_commands(item.id) is None
    store.set_allowed_commands(item.id, commands)
    assert store.set_allowed_commands(item.id, None) is True
    assert store.get_allowed_commands(item.id) is None


def test_missing_item(tmp_path):
    store = _store(tmp_path)
    assert store.set_allowed_commands("nope", [[PROG]]) is False
    with pytest.raises(VaultError):
        store.get_allowed_commands("nope")


@pytest.mark.parametrize(
    "commands",
    [[[]], [["relative/server"]], [[""]], [[PROG, 3]], [[PROG, "a\x00b"]], ["not-a-list"]],
)
def test_invalid_commands_are_refused_and_nothing_changes(tmp_path, commands):
    store = _store(tmp_path)
    item = store.add_item("generic", "Token", {"value": "s"})
    store.set_allowed_commands(item.id, [[PROG]])
    with pytest.raises(VaultError):
        store.set_allowed_commands(item.id, commands)
    assert store.get_allowed_commands(item.id) == [[PROG]]


def test_binding_is_sealed_and_bound_to_its_item(tmp_path):
    store = _store(tmp_path)
    first = store.add_item("generic", "First", {"value": "1"})
    second = store.add_item("generic", "Second", {"value": "2"})
    store.set_allowed_commands(first.id, [[PROG, "--stdio"]])
    sealed = _raw(tmp_path, first.id)
    assert isinstance(sealed, bytes)
    assert PROG.encode() not in sealed and b"--stdio" not in sealed
    # Moved onto another item, the envelope no longer authenticates.
    _set_raw(tmp_path, second.id, sealed)
    with pytest.raises(DecryptionVerificationError):
        store.get_allowed_commands(second.id)
    assert store.get_allowed_commands(first.id) == [[PROG, "--stdio"]]


def test_planted_or_malformed_bindings_fail_closed(tmp_path):
    store = _store(tmp_path)
    item = store.add_item("generic", "Token", {"value": "s"})
    _set_raw(tmp_path, item.id, '{"commands": [["/bin/sh"]]}')  # plaintext, not sealed
    with pytest.raises(VaultError):
        store.get_allowed_commands(item.id)
    for plaintext in ("not json", '{"commands": []}', '{"commands": [["relative"]]}', "[]"):
        _set_raw(tmp_path, item.id, store._encrypt_metadata(item.id, "allowed_commands", plaintext))
        with pytest.raises(VaultError):
            store.get_allowed_commands(item.id)


def test_field_updates_keep_the_binding(tmp_path):
    store = _store(tmp_path)
    item = store.add_item("generic", "Token", {"value": "s"})
    store.set_allowed_commands(item.id, [[PROG]])
    assert store.update_generic_field(item.id, "value", "t")
    assert store.get_allowed_commands(item.id) == [[PROG]]
    assert store.resolve_secret(item.id) == {"value": "t"}


@pytest.mark.skipif(
    sqlite3.sqlite_version_info < (3, 35, 0), reason="DROP COLUMN needs SQLite 3.35"
)
def test_existing_schema_3_store_gains_the_column_and_keeps_version_3(tmp_path):
    vault = tmp_path / "vault"
    old = _store(tmp_path)
    item = old.add_item("generic", "Token", {"value": "s"})
    del old
    with sqlite3.connect(vault / "vault.db") as conn:
        conn.execute("ALTER TABLE vault_items DROP COLUMN allowed_commands")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_items)")}
        assert "allowed_commands" not in columns
    store = _store(tmp_path)
    assert store.get_allowed_commands(item.id) is None
    assert store.resolve_secret(item.id) == {"value": "s"}
    with sqlite3.connect(vault / "vault.db") as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3


def test_rotation_reseals_the_binding(tmp_path):
    store = _store(tmp_path)
    bound = store.add_item("generic", "Bound", {"value": "1"})
    unbound = store.add_item("generic", "Unbound", {"value": "2"})
    store.set_allowed_commands(bound.id, [[PROG, "--stdio"]])
    result = rotate_vault_store(
        store, source_ring=KeyRing({0: _crypto(OLD)}), new_vault=_crypto(NEW), new_key_id=1
    )
    assert result["verified"] == 2
    rotated = _store(tmp_path, NEW)
    assert rotated.get_allowed_commands(bound.id) == [[PROG, "--stdio"]]
    assert rotated.get_allowed_commands(unbound.id) is None
    with pytest.raises(DecryptionVerificationError):
        _store(tmp_path, OLD).get_allowed_commands(bound.id)


def test_sealed_listing_mode_stores_bindings_too(tmp_path):
    store = VaultStore(tmp_path / "vault", crypto=_crypto(OLD), seal_listing_metadata=True)
    item = store.add_item("generic", "Token", {"value": "s"})
    store.set_allowed_commands(item.id, [[PROG]])
    assert store.get_allowed_commands(item.id) == [[PROG]]
    result = rotate_vault_store(
        store, source_ring=KeyRing({0: _crypto(OLD)}), new_vault=_crypto(NEW), new_key_id=1
    )
    assert result["verified"] == 1
    rotated = VaultStore(tmp_path / "vault", crypto=_crypto(NEW), seal_listing_metadata=True)
    assert rotated.get_allowed_commands(item.id) == [[PROG]]

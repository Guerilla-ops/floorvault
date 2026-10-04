"""Tests for complete VaultStore key rotation orchestration."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from floorvault import FloorVault, KeyRing
from floorvault.vault_rotation import rotate_vault_store
from floorvault.vaultkit.vault import VaultError, VaultStore

OLD = bytes.fromhex("31" * 32)
NEW = bytes.fromhex("42" * 32)
IMPOSTOR = bytes.fromhex("77" * 32)


def _crypto(key: bytes) -> FloorVault:
    return FloorVault(key, memory_mode="disabled")


def _store(tmp_path: Path) -> VaultStore:
    return VaultStore(tmp_path / "vault", crypto=_crypto(OLD))


def test_rotation_moves_all_items_and_verifies_with_new_key(tmp_path):
    store = _store(tmp_path)
    first = store.add_item("generic", "First", {"note": "one"})
    second = store.add_item("generic", "Second", {"note": "two"})

    result = rotate_vault_store(
        store,
        source_ring=KeyRing({0: _crypto(OLD)}),
        new_vault=_crypto(NEW),
        new_key_id=1,
    )

    assert result == {"migrated": 2, "verified": 2, "retirements": 0}
    assert store.rotation_journal() == {}

    rotated = VaultStore(tmp_path / "vault", crypto=_crypto(NEW))
    assert rotated.resolve_secret(first.id) == {"note": "one"}
    assert rotated.resolve_secret(second.id) == {"note": "two"}


def test_rotation_resumes_after_a_write_failure(tmp_path, monkeypatch):
    store = _store(tmp_path)
    first = store.add_item("generic", "First", {"note": "one"})
    second = store.add_item("generic", "Second", {"note": "two"})
    original = store.write_sealed_item
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "write_sealed_item", fail_once)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        rotate_vault_store(
            store,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )

    assert store.rotation_journal()
    monkeypatch.setattr(store, "write_sealed_item", original)
    result = rotate_vault_store(
        store,
        source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
        new_vault=_crypto(NEW),
        new_key_id=1,
    )

    assert result == {"migrated": 1, "verified": 2, "retirements": 0}
    assert store.rotation_journal() == {}
    rotated = VaultStore(tmp_path / "vault", crypto=_crypto(NEW))
    assert rotated.resolve_secret(first.id) == {"note": "one"}
    assert rotated.resolve_secret(second.id) == {"note": "two"}


def test_rotation_rejects_invalid_key_id(tmp_path):
    with pytest.raises(ValueError, match="key_id"):
        rotate_vault_store(
            _store(tmp_path),
            source_ring=KeyRing({0: _crypto(OLD)}),
            new_vault=_crypto(NEW),
            new_key_id=256,
        )


def test_rotation_resume_with_a_different_master_is_refused_before_any_write(tmp_path, monkeypatch):
    """Resume must bind to the committed target master, not the 1-byte key_id.

    A rotation that committed one item under NEW (key_id=1) and then stopped
    must refuse a resume presenting a DIFFERENT master under the same key_id,
    and it must refuse BEFORE any write: previously the remaining item was
    re-sealed under the impostor and the mismatch surfaced only at final
    verification, leaving the store split across two masters both labelled
    key_id=1.
    """
    store = _store(tmp_path)
    first = store.add_item("generic", "First", {"note": "one"})
    second = store.add_item("generic", "Second", {"note": "two"})
    # _item_ids walks ORDER BY id: the interrupted run commits whichever item
    # sorts first, which is not necessarily the first one added.
    notes = {first.id: "one", second.id: "two"}
    committed_id, remaining_id = sorted(notes)

    # Interrupt the rotation after the first committed item (key_id=1, NEW).
    original = store.write_sealed_item
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "write_sealed_item", fail_once)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        rotate_vault_store(
            store,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )
    monkeypatch.setattr(store, "write_sealed_item", original)

    # Resume under a different master carrying the same key_id.
    impostor = _crypto(IMPOSTOR)
    with pytest.raises(VaultError, match="different target master"):
        rotate_vault_store(
            store,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=impostor,
            new_key_id=1,
        )

    # Nothing may have been re-sealed or journaled past the committed item.
    journal = store.rotation_journal()
    assert journal and all(record_id == committed_id for _kind, record_id, _column in journal)
    remaining = store.read_sealed_item(remaining_id, KeyRing({0: _crypto(OLD)}))
    assert json.loads(remaining["payload"]) == {"note": notes[remaining_id]}
    with pytest.raises(Exception, match="key id|verification failed"):
        store.read_sealed_item(remaining_id, KeyRing({0: impostor}))

    # The committed master itself still resumes the rotation.
    result = rotate_vault_store(
        store,
        source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
        new_vault=_crypto(NEW),
        new_key_id=1,
    )
    assert result == {"migrated": 1, "verified": 2, "retirements": 0}
    assert store.rotation_journal() == {}


def test_rotation_resume_refuses_a_pre_commitment_in_flight_rotation(tmp_path):
    """A rotation begun by a build that recorded no commitment cannot be
    verified against any master key; it must fail closed, not adopt whichever
    vault the resumer happens to present."""
    store = _store(tmp_path)
    store.add_item("generic", "First", {"note": "one"})

    # Simulate the on-disk state an older build left mid-rotation: active with
    # a target_key_id but no target-key commitment.
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        conn.execute(
            "UPDATE vault_rotation_state SET active = 1, target_key_id = 1 WHERE singleton = 1"
        )

    with pytest.raises(VaultError, match="predates"):
        rotate_vault_store(
            store,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )

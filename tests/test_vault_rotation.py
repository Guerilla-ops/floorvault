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


def test_fresh_store_is_marked_schema_version_3_with_commitment_column(tmp_path):
    _store(tmp_path)
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        user_version = conn.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_rotation_state)")}
    assert user_version == 3
    assert "target_commitment" in columns


def test_a_store_from_a_newer_schema_version_is_refused_untouched(tmp_path):
    """A user_version this build does not understand must fail closed.

    The marker is writable by anyone holding the file, so it can never be an
    authorization to proceed: a future-version store is refused before DDL or
    migration, preserving the schema, data, and version marker.
    """
    store = _store(tmp_path)
    store.add_item("generic", "First", {"note": "one"})

    db = tmp_path / "vault" / "vault.db"
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA user_version = 4")
        columns_before = conn.execute("PRAGMA table_info(vault_items)").fetchall()
        items_before = conn.execute("SELECT * FROM vault_items").fetchall()
        state_before = conn.execute("SELECT * FROM vault_rotation_state").fetchall()

    with pytest.raises(VaultError, match="unsupported vault schema version"):
        VaultStore(tmp_path / "vault", crypto=_crypto(OLD))

    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        assert conn.execute("PRAGMA table_info(vault_items)").fetchall() == columns_before
        assert conn.execute("SELECT * FROM vault_items").fetchall() == items_before
        assert conn.execute("SELECT * FROM vault_rotation_state").fetchall() == state_before


@pytest.mark.parametrize("active", [0, 1])
def test_a_version2_store_upgrades_to_schema_3_on_open(tmp_path, active):
    """A pre-commitment store keeps working: the column arrives as a nullable
    add-on, rows and payloads are untouched, and only an ACTIVE legacy rotation
    is refused - never adopted - when resumed."""
    store = _store(tmp_path)
    item = store.add_item("generic", "First", {"note": "one"})
    plaintext = store.resolve_secret(item.id)

    db = tmp_path / "vault" / "vault.db"
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE vault_rotation_state DROP COLUMN target_commitment")
        conn.execute(
            "UPDATE vault_rotation_state SET active = ?, target_key_id = 1 WHERE singleton = 1",
            (active,),
        )
        conn.execute("PRAGMA user_version = 2")
        items_before = conn.execute("SELECT * FROM vault_items").fetchall()

    reopened = VaultStore(tmp_path / "vault", crypto=_crypto(OLD))
    assert reopened.resolve_secret(item.id) == plaintext

    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        info = conn.execute("PRAGMA table_info(vault_rotation_state)").fetchall()
        commitment = {row[1]: row for row in info}["target_commitment"]
        assert commitment[3] == 0
        assert conn.execute("SELECT * FROM vault_items").fetchall() == items_before

    if active:
        with pytest.raises(VaultError, match="predates"):
            rotate_vault_store(
                reopened,
                source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
                new_vault=_crypto(NEW),
                new_key_id=1,
            )
        with sqlite3.connect(db) as conn:
            assert (
                conn.execute(
                    "SELECT active FROM vault_rotation_state WHERE singleton = 1"
                ).fetchone()[0]
                == 1
            )
            assert conn.execute("SELECT * FROM vault_items").fetchall() == items_before
    else:
        result = rotate_vault_store(
            reopened,
            source_ring=KeyRing({0: _crypto(OLD)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )
        assert result == {"migrated": 1, "verified": 1, "retirements": 0}
        rotated = VaultStore(tmp_path / "vault", crypto=_crypto(NEW))
        assert rotated.resolve_secret(item.id) == plaintext


def test_an_id_only_rotation_under_the_same_master_stays_readable(tmp_path):
    """Rotating the key id without changing key material keeps records readable.

    The envelope's authenticated key id moves to the new generation, but the
    sealing master is unchanged, so the ORIGINAL store's convenience reads
    still authenticate - the unreadable-after-rotation case is master change,
    not id change.
    """
    store = _store(tmp_path)
    item = store.add_item("generic", "First", {"note": "one"})

    result = rotate_vault_store(
        store,
        source_ring=KeyRing({0: _crypto(OLD)}),
        new_vault=_crypto(OLD),
        new_key_id=1,
    )
    assert result == {"migrated": 1, "verified": 1, "retirements": 0}
    assert store.resolve_secret(item.id) == {"note": "one"}

    from floorvault.core import envelope_header

    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        (payload,) = conn.execute(
            "SELECT payload_cipher FROM vault_items WHERE id = ?", (item.id,)
        ).fetchone()
    assert envelope_header(bytes(payload))["key_id"] == 1


# ---------------------------------------------------------------------------
# Journal key-id validation and commitment store-binding (red-team P2)
# ---------------------------------------------------------------------------


def test_mark_rotation_done_rejects_an_unrepresentable_key_id(tmp_path):
    """Journal rows name a key generation the envelope header must be able to
    express: key_id is a u8 in [0, 255]. A caller-supplied id outside that
    range (or of the wrong type) must never reach the journal."""
    store = _store(tmp_path)
    rows = [("item", "i", "payload")]
    for bad in (-1, 256, 300):
        with pytest.raises(ValueError, match="key_id"):
            store.mark_rotation_done(rows, target_key_id=bad)
    for bad_type in (True, "1", 1.5):
        with pytest.raises(TypeError, match="key_id"):
            store.mark_rotation_done(rows, target_key_id=bad_type)
    # Nothing was journaled by the refused calls.
    assert store.rotation_journal() == {}


def test_begin_rotation_rejects_an_unrepresentable_key_id(tmp_path):
    store = _store(tmp_path)
    for bad in (-1, 256, 300):
        with pytest.raises(ValueError, match="key_id"):
            store.begin_rotation(bad, target_vault=_crypto(NEW))
    for bad_type in (True, "1", 1.5):
        with pytest.raises(TypeError, match="key_id"):
            store.begin_rotation(bad_type, target_vault=_crypto(NEW))


def _in_flight_state(store_db: Path) -> None:
    with sqlite3.connect(store_db) as conn:
        return conn.execute(
            "SELECT active, target_key_id, target_commitment "
            "FROM vault_rotation_state WHERE singleton = 1"
        ).fetchone()


def test_a_commitment_sealed_for_another_store_is_refused(tmp_path):
    """The resume commitment must authenticate THIS store, not merely the key.

    The canary plaintext and its AAD coordinates are public constants, so a
    commitment envelope sealed for store A under the shared target vault also
    verifies for store B - anyone who can write B's file can transplant A's
    in-flight state and have B's resume authenticate a rotation B never
    began. The commitment payload therefore binds the store's content
    fingerprint, and a transplanted envelope must fail verification.
    """
    store_a = VaultStore(tmp_path / "a", crypto=_crypto(OLD))
    store_a.add_item("generic", "A item", {"note": "a"})
    store_a.begin_rotation(1, target_vault=_crypto(NEW))
    active, key_id, stolen = _in_flight_state(tmp_path / "a" / "vault.db")
    assert active and key_id == 1 and stolen

    store_b = VaultStore(tmp_path / "b", crypto=_crypto(OLD))
    store_b.add_item("generic", "B item", {"note": "b"})
    with sqlite3.connect(tmp_path / "b" / "vault.db") as conn:
        conn.execute(
            "UPDATE vault_rotation_state SET active = 1, target_key_id = 1, "
            "target_commitment = ? WHERE singleton = 1",
            (stolen,),
        )

    with pytest.raises(VaultError, match="commitment"):
        rotate_vault_store(
            store_b,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )


def test_a_bare_canary_commitment_is_refused(tmp_path):
    """A commitment over the bare public canary - the pre-binding format, or a
    planted forgery - must fail the resume check. Sealing a constant proves
    key custody but binds nothing about which store the rotation belongs to."""
    store = _store(tmp_path)
    store.add_item("generic", "First", {"note": "one"})
    bare = _crypto(NEW).encrypt(
        b"floorvault-rotation-target-v1",
        key_id=1,
        table="vault_rotation_state",
        record_id="target",
        column="commitment",
    )
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        conn.execute(
            "UPDATE vault_rotation_state SET active = 1, target_key_id = 1, "
            "target_commitment = ? WHERE singleton = 1",
            (bare,),
        )

    with pytest.raises(VaultError, match="commitment"):
        rotate_vault_store(
            store,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )


def test_commitment_rejected_when_record_ids_match_across_stores(tmp_path):
    """Identical record ids across stores must not equalize commitments.

    Two vaults seeded from the same source legitimately share record ids, so
    the content fingerprint alone cannot distinguish them - only the minted
    per-store nonce does. A commitment transplanted between such stores must
    still fail the resume check.
    """
    store_a = VaultStore(tmp_path / "a", crypto=_crypto(OLD))
    store_a.add_item("generic", "item", {"note": "a"}, item_id="shared-id")
    store_a.begin_rotation(1, target_vault=_crypto(NEW))
    *_, stolen = _in_flight_state(tmp_path / "a" / "vault.db")

    store_b = VaultStore(tmp_path / "b", crypto=_crypto(OLD))
    store_b.add_item("generic", "item", {"note": "b"}, item_id="shared-id")
    with sqlite3.connect(tmp_path / "b" / "vault.db") as conn:
        conn.execute(
            "UPDATE vault_rotation_state SET active = 1, target_key_id = 1, "
            "target_commitment = ? WHERE singleton = 1",
            (stolen,),
        )

    with pytest.raises(VaultError, match="commitment"):
        rotate_vault_store(
            store_b,
            source_ring=KeyRing({0: _crypto(OLD), 1: _crypto(NEW)}),
            new_vault=_crypto(NEW),
            new_key_id=1,
        )

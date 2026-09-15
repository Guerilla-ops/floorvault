"""Master-key rotation: the store-side primitives.

Rotation re-seals everything the master key protects. That is more than the payloads:

* ``vault_items.payload_cipher`` — the secret;
* the sealed metadata columns ``label``, ``origin``, ``identifier_type``,
  ``identifier``, ``created_at`` (each under its own ``meta:<column>`` AAD);
* ``vault_items.origin_idx`` — an HMAC blind index whose key is derived from the
  master key, so it MUST be recomputed or ``find_by_origin()`` silently stops
  finding anything. This is the trap in the whole operation: everything still
  decrypts, and search just returns nothing;
* ``vault_legacy_retirements.tombstone_cipher`` — the F-1 retirement records, or a
  rotation would leave a store whose retirement records no longer authenticate.

These tests cover the primitives the orchestration is built from. The
crash-resume journal semantics are covered with the orchestration.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from floorvault.core import DecryptionVerificationError, FloorVault
from floorvault.keyring import KeyRing, UnknownKeyIdError
from floorvault.memory import HardenedMemoryKey
from floorvault.migration import LegacyRetiredError, MigratingVaultStore
from floorvault.vaultkit.vault import VaultError, VaultStore

KEY_OLD = bytes.fromhex("11" * 32)
KEY_NEW = bytes.fromhex("22" * 32)


def _vault(seed: bytes) -> FloorVault:
    return FloorVault(HardenedMemoryKey(seed))


def _store(tmp_path: Path, seed: bytes = KEY_OLD, name: str = "vault") -> VaultStore:
    return VaultStore(tmp_path / name, crypto=_vault(seed))


def _legacy_files(base: Path, items: dict[str, dict]) -> None:
    base.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    (base / "vault.json.enc").write_text(
        base64.urlsafe_b64encode(Fernet(key).encrypt(json.dumps(items).encode())).decode()
    )
    (base / "vault.key").write_text(key.decode())


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------


def test_journal_starts_empty(tmp_path):
    assert _store(tmp_path).rotation_journal() == {}


def test_journal_records_progress_and_is_idempotent(tmp_path):
    store = _store(tmp_path)
    rows = [("item", "vault_abc", "payload"), ("item", "vault_abc", "meta:label")]
    store.mark_rotation_done(rows, target_key_id=1)
    first = store.rotation_journal()
    assert set(first) == set(rows)
    assert all(state == "done" and target == 1 for target, state in first.values())

    store.mark_rotation_done(rows, target_key_id=1)  # re-run must not duplicate or fail
    assert store.rotation_journal() == first


def test_journal_can_be_cleared_when_a_rotation_completes(tmp_path):
    store = _store(tmp_path)
    store.mark_rotation_done([("item", "i", "payload")], target_key_id=1)
    store.clear_rotation_journal()
    assert store.rotation_journal() == {}


def test_journal_records_the_target_key_so_a_second_rotation_is_visible(tmp_path):
    store = _store(tmp_path)
    store.mark_rotation_done([("item", "i", "payload")], target_key_id=1)
    store.mark_rotation_done([("item", "i", "payload")], target_key_id=2)
    target, _state = store.rotation_journal()[("item", "i", "payload")]
    assert target == 2


# ---------------------------------------------------------------------------
# Reading one item's plaintext (through the ring, i.e. whatever key it is under)
# ---------------------------------------------------------------------------


def test_read_sealed_item_returns_the_plaintext_of_every_sealed_column(tmp_path):
    store = _store(tmp_path)
    item = store.add_item(
        "login",
        "My login",
        {"password": "pw-secret", "identifier": "me@example.com", "identifier_type": "email"},
        origin="https://example.com",
    )
    ring = KeyRing({0: _vault(KEY_OLD)})
    sealed = store.read_sealed_item(item.id, ring)

    assert sealed["payload"] == json.dumps({"password": "pw-secret"})
    assert sealed["meta"]["label"] == "My login"
    assert sealed["meta"]["origin"] == "https://example.com"
    assert sealed["meta"]["identifier"] == "me@example.com"
    assert sealed["meta"]["identifier_type"] == "email"
    assert sealed["meta"]["created_at"]


def test_read_sealed_item_reports_a_missing_item(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(VaultError):
        store.read_sealed_item("vault_missing", KeyRing({0: _vault(KEY_OLD)}))


# ---------------------------------------------------------------------------
# Re-sealing one item under a new generation
# ---------------------------------------------------------------------------


def test_write_sealed_item_moves_every_column_to_the_new_key(tmp_path):
    store = _store(tmp_path)
    item = store.add_item(
        "login",
        "My login",
        {"password": "pw-secret", "identifier": "me@example.com", "identifier_type": "email"},
        origin="https://example.com",
    )
    old_ring = KeyRing({0: _vault(KEY_OLD)})
    sealed = store.read_sealed_item(item.id, old_ring)

    store.write_sealed_item(item.id, sealed, new_vault=_vault(KEY_NEW), key_id=1)

    # The new generation reads it...
    new_ring = KeyRing({0: _vault(KEY_OLD), 1: _vault(KEY_NEW)})
    reread = store.read_sealed_item(item.id, new_ring)
    assert reread["payload"] == sealed["payload"]
    assert reread["meta"] == sealed["meta"]

    # ...a ring that does not hold the new generation refuses it BY NAME (an
    # operational condition: this holder needs the new key)...
    with pytest.raises(UnknownKeyIdError):
        store.read_sealed_item(item.id, old_ring)

    # ...and a ring that wrongly claims to hold it fails authentication, so the
    # old material cannot decrypt what was re-sealed (payload and metadata alike).
    wrong_ring = KeyRing({1: _vault(KEY_OLD)})
    with pytest.raises(DecryptionVerificationError):
        store.read_sealed_item(item.id, wrong_ring)


def test_write_sealed_item_recomputes_the_blind_index(tmp_path):
    """The trap: without this, everything decrypts and search returns nothing."""
    store = _store(tmp_path)
    item = store.add_item(
        "login",
        "My login",
        {"password": "pw", "identifier": "me@example.com", "identifier_type": "email"},
        origin="https://example.com",
    )
    before = sqlite3.connect(tmp_path / "vault" / "vault.db")
    old_index = before.execute(
        "SELECT origin_idx FROM vault_items WHERE id=?", (item.id,)
    ).fetchone()[0]
    before.close()

    sealed = store.read_sealed_item(item.id, KeyRing({0: _vault(KEY_OLD)}))
    store.write_sealed_item(item.id, sealed, new_vault=_vault(KEY_NEW), key_id=1)

    after = sqlite3.connect(tmp_path / "vault" / "vault.db")
    new_index = after.execute(
        "SELECT origin_idx FROM vault_items WHERE id=?", (item.id,)
    ).fetchone()[0]
    after.close()
    assert new_index != old_index, "the blind index was not recomputed for the new key"


def test_lookup_by_origin_still_works_after_a_re_seal(tmp_path):
    """The end the index exists for: find_by_origin must still find the item."""
    store = _store(tmp_path)
    item = store.add_item(
        "login",
        "My login",
        {"password": "pw", "identifier": "me@example.com", "identifier_type": "email"},
        origin="https://example.com",
    )
    sealed = store.read_sealed_item(item.id, KeyRing({0: _vault(KEY_OLD)}))
    store.write_sealed_item(item.id, sealed, new_vault=_vault(KEY_NEW), key_id=1)

    rotated = VaultStore(tmp_path / "vault", crypto=_vault(KEY_NEW))
    found = rotated.find_by_origin("https://example.com")
    assert [meta.id for meta in found] == [item.id]


def test_write_sealed_item_records_the_journal_row_in_the_same_transaction(tmp_path):
    store = _store(tmp_path)
    item = store.add_item("generic", "thing", {"password": "pw"}, origin=None)
    sealed = store.read_sealed_item(item.id, KeyRing({0: _vault(KEY_OLD)}))
    rows = [("item", item.id, "payload")]
    store.write_sealed_item(item.id, sealed, new_vault=_vault(KEY_NEW), key_id=1, journal_rows=rows)
    journal = store.rotation_journal()
    assert journal[("item", item.id, "payload")] == (1, "done")


def test_write_sealed_item_tolerates_a_null_metadata_column(tmp_path):
    store = _store(tmp_path)
    item = store.add_item("generic", "thing", {"password": "pw"})
    sealed = store.read_sealed_item(item.id, KeyRing({0: _vault(KEY_OLD)}))
    assert sealed["meta"]["origin"] is None
    store.write_sealed_item(item.id, sealed, new_vault=_vault(KEY_NEW), key_id=1)
    reread = store.read_sealed_item(item.id, KeyRing({1: _vault(KEY_NEW)}))
    assert reread["meta"]["origin"] is None


# ---------------------------------------------------------------------------
# Retirement tombstones (F-1 records) are sealed too
# ---------------------------------------------------------------------------


def test_retirement_tombstones_are_re_sealed_and_still_refuse_resurrection(tmp_path):
    base = tmp_path / "vault"
    store = _store(tmp_path)
    legacy_dir = base / "modern"
    _legacy_files(legacy_dir, {"legacy-1": {"password": "retired-value"}})
    facade = MigratingVaultStore(modern_store=store, legacy_base_dir=legacy_dir)
    facade.resolve_secret("legacy-1")  # migrates and retires

    ring = KeyRing({0: _vault(KEY_OLD)})
    modern_id = store.list_legacy_retirements()["legacy-1"]
    assert store.reseal_retirements(ring, new_vault=_vault(KEY_NEW), key_id=1) == 1

    # The store still holding only the old key can no longer read the tombstone -
    # an operational condition, and the reason a rotation needs a KeyRing rather
    # than a single vault.
    with pytest.raises(VaultError):
        store.list_legacy_retirements()

    # Rotate the migrated item too, so the whole store is on the new generation.
    # (These are the primitives A2b orchestrates; this test proves they compose.)
    sealed = store.read_sealed_item(modern_id, ring)
    store.write_sealed_item(modern_id, sealed, new_vault=_vault(KEY_NEW), key_id=1)

    rotated = VaultStore(base, crypto=_vault(KEY_NEW))
    assert rotated.retired_modern_id("legacy-1") == modern_id
    assert rotated.resolve_secret(modern_id)["password"] == "retired-value"

    # F-1 still holds after a rotation. While the modern record exists, serving it
    # is the normal path; the retirement matters when the record is gone, and then
    # the legacy source must be refused rather than resurrected.
    assert rotated.remove_item(modern_id) is True
    with pytest.raises(LegacyRetiredError):
        MigratingVaultStore(modern_store=rotated, legacy_base_dir=legacy_dir).resolve_secret(
            "legacy-1"
        )

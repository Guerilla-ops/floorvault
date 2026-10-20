"""Complete, resumable key rotation for a VaultStore."""

from __future__ import annotations

import json

from .core import FloorVault
from .keyring import KeyRing
from .vaultkit.vault import VaultError, VaultStore


def _item_ids(store: VaultStore) -> list[str]:
    """Read item IDs without decrypting metadata through the store's old key."""
    with store._connect() as connection:
        rows = connection.execute("SELECT id FROM vault_items ORDER BY id").fetchall()
    return [str(row[0]) for row in rows]


def _retirement_count(store: VaultStore) -> int:
    with store._connect() as connection:
        return int(
            connection.execute("SELECT COUNT(*) FROM vault_legacy_retirements").fetchone()[0]
        )


def _verify_retirements(store: VaultStore, ring: KeyRing) -> int:
    """Authenticate every retirement tombstone through the target key ring."""
    with store._connect() as connection:
        rows = connection.execute(
            "SELECT legacy_id, tombstone_cipher FROM vault_legacy_retirements"
        ).fetchall()
    for legacy_id, ciphertext in rows:
        try:
            payload = json.loads(
                ring.decrypt(
                    ciphertext,
                    table=store._TOMBSTONE_TABLE,
                    record_id=legacy_id,
                    column="tombstone",
                )
            )
        except Exception as exc:  # noqa: BLE001
            raise VaultError(f"retirement verification failed for {legacy_id!r}") from exc
        if not isinstance(payload, dict) or payload.get("legacy_id") != legacy_id:
            raise VaultError(f"retirement verification failed for {legacy_id!r}")
    return len(rows)


def rotate_vault_store(
    store: VaultStore,
    *,
    source_ring: KeyRing,
    new_vault: FloorVault,
    new_key_id: int,
) -> dict[str, int]:
    """Re-seal every store value under ``new_vault`` and verify the result.

    Rotation is resumable: each completed item is recorded by the existing
    transaction-coupled journal. If a process stops after some items, call this
    function again with a ring holding both old and new generations. A resume
    must present the same key generation the interrupted rotation committed to -
    the persisted commitment is authenticated before any write, so the same
    ``new_key_id`` under a different master key is refused rather than splitting
    the store. The function skips journaled target units, re-seals all
    retirement tombstones, verifies every item and tombstone through the new
    generation, and clears the journal only after verification succeeds.

    The caller must atomically switch future application reads to a
    ``KeyRing``/``VaultStore`` containing the new key after this returns.
    """
    if not isinstance(store, VaultStore):
        raise TypeError("store must be a VaultStore")
    if not isinstance(source_ring, KeyRing):
        raise TypeError("source_ring must be a KeyRing")
    if not isinstance(new_vault, FloorVault):
        raise TypeError("new_vault must be a FloorVault")
    if isinstance(new_key_id, bool) or not isinstance(new_key_id, int):
        raise TypeError("new_key_id must be an integer in [0, 255]")
    if not 0 <= new_key_id <= 255:
        raise ValueError("new_key_id must be an integer in [0, 255]")

    store.begin_rotation(new_key_id, target_vault=new_vault)
    journal = store.rotation_journal()
    migrated = 0
    unit_columns = ("payload", *tuple(f"meta:{column}" for column in store._SEALED_META_COLUMNS))
    for item_id in _item_ids(store):
        units = [("item", item_id, column) for column in unit_columns]
        if all(journal.get(unit) == (new_key_id, "done") for unit in units):
            continue
        sealed = store.read_sealed_item(item_id, source_ring)
        store.write_sealed_item(
            item_id,
            sealed,
            new_vault=new_vault,
            key_id=new_key_id,
            journal_rows=units,
        )
        migrated += 1

    retirements = store.reseal_retirements(
        source_ring,
        new_vault=new_vault,
        key_id=new_key_id,
    )

    target_ring = KeyRing({new_key_id: new_vault})
    verified = 0
    for item_id in _item_ids(store):
        store.read_sealed_item(item_id, target_ring)
        verified += 1
    if retirements != _retirement_count(store):
        raise VaultError("retirement count changed during rotation")
    _verify_retirements(store, target_ring)
    store.clear_rotation_journal()
    return {"migrated": migrated, "verified": verified, "retirements": retirements}

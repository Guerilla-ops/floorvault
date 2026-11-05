"""Re-seal a store under a new key, for ``floorvault secrets protect --rotate`` (#84, part 4).

``protect`` wraps a raw key file and keeps the key. A key held anywhere else (the OS key
store, a systemd-creds credential, an environment variable, a ``--key-file``) cannot be
moved under a passphrase without that key being read out and written again, so the store
is rotated instead: every sealed value is re-encrypted under a new random key, and the new
key is kept only wrapped under the passphrase. The old key then opens nothing in the store
(a copy or backup made earlier still opens with it).

This module is the mechanical part, on top of :func:`floorvault.rotate_vault_store`; the
sequence (stage the new key, rotate, re-record bindings, publish, remove the old custody)
and every message are in :mod:`floorvault.agent_cli`.
"""

from __future__ import annotations

from .core import FloorVault
from .keyring import KeyRing
from .memory import HardenedMemoryKey
from .vault_rotation import _item_ids, _verify_retirements, rotate_vault_store
from .vaultkit.vault import VaultError, VaultStore

MAX_GENERATION = 255


class CustodyRotationError(Exception):
    """The store cannot be rotated. The message is safe to print."""


def vault_for(key: bytes, app_context: str) -> FloorVault:
    """A ``FloorVault`` for ``key``, in the application context the CLI's stores use."""
    return FloorVault(HardenedMemoryKey(key), app_instance_id=app_context)


def generation(store: VaultStore) -> int:
    """The key generation ``store``'s records are sealed under (0 for a store never rotated)."""
    return int(store._write_key_id)


def check_retirements(store: VaultStore) -> None:
    """Raise unless ``store``'s key authenticates every retirement record in the store.

    Item metadata alone proves nothing for a store with no items, and a key that opens no
    retirement record is not the store's key. Records labelled with an earlier generation
    were sealed under the current key (see :func:`rotate_store`), so every label up to the
    current one is read through it.
    """
    current = generation(store)
    ring = KeyRing({g: store._crypto for g in range(current + 1)}, default_key_id=current)
    try:
        _verify_retirements(store, ring)
    except VaultError:
        raise CustodyRotationError(
            "this key does not open the retirement records in the store"
        ) from None


def unrotated_item_ids(store: VaultStore) -> list[str]:
    """Items still sealed under the old key: all of them before a rotation, the rest during one."""
    target = store.rotation_in_progress()
    ids = _item_ids(store)
    if target is None:
        return ids
    journal = store.rotation_journal()
    columns = ("payload", *(f"meta:{column}" for column in store._SEALED_META_COLUMNS))
    return [
        item_id
        for item_id in ids
        if not all(journal.get(("item", item_id, column)) == (target, "done") for column in columns)
    ]


def rotate_store(
    store: VaultStore, old_vault: FloorVault, new_key: bytes, *, app_context: str
) -> int:
    """Re-seal every value of ``store`` under ``new_key``; return the new key generation.

    ``store`` must be open under ``old_vault``. Starts a rotation to the next generation, or
    resumes one already in progress (``new_key`` must be the key it committed to: the library
    refuses a different key under the same generation before it writes anything). Verifies
    every item through the new key and clears the journal only when that succeeds.
    """
    target = store.rotation_in_progress()
    if target is None:
        old_generation = generation(store)
        new_id = old_generation + 1
        if new_id > MAX_GENERATION:
            raise CustodyRotationError(
                f"this store has been rotated {old_generation} times, the most a key generation "
                "number can count; it cannot be rotated again"
            )
        # Every label up to the current generation reads through the old key: releases through
        # 0.2.8 could write records labelled 0 after a rotation (SPEC 12.4), sealed under the
        # key then current, so a store can hold labels 0 and its completed generation at once.
        keys = {earlier: old_vault for earlier in range(old_generation + 1)}
        ring = KeyRing(keys, default_key_id=old_generation)
    else:
        # Part of the store is already under the new key: the ring needs both. Every earlier
        # generation was this one old key, since a rotation here only ever moves one step.
        new_id = target
        keys = {earlier: old_vault for earlier in range(new_id)}
        keys[new_id] = vault_for(new_key, app_context)
        ring = KeyRing(keys, default_key_id=new_id - 1)
    try:
        rotate_vault_store(
            store,
            source_ring=ring,
            new_vault=vault_for(new_key, app_context),
            new_key_id=new_id,
        )
    except Exception as exc:  # noqa: BLE001 - the library's own errors carry the detail
        raise CustodyRotationError(
            f"the rotation stopped ({type(exc).__name__}: {exc}); the store is part-way "
            "through it and nothing else was changed. Run the same command again to resume"
        ) from None
    return new_id

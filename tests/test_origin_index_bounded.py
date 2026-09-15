"""The vault's origin search index is a bounded bucket, not a full-width HMAC.

``vault_items.origin_idx`` used to store the full 32-byte HMAC of the normalized
origin. That is deterministic and collision-free, so anyone holding the database
file could recover **exact** equality (which rows share an origin) and the
frequency distribution of every origin — the classic deterministic-search leak.
It is also the one searchable index the store writes, so the library's own
"bounded beacon leakage" claim did not describe the store.

The index is now a truncated bucket (``ORIGIN_INDEX_BITS``). A bucket hit is
candidate evidence ONLY: ``find_by_origin`` confirms it by decrypting
``meta:origin`` and comparing the plaintext exactly, so two origins that collide
in a bucket are never confused for one another.
"""

from __future__ import annotations

import sqlite3

from floorvault.blind_index import beacon_bucket_bytes
from floorvault.core import FloorVault
from floorvault.memory import HardenedMemoryKey
from floorvault.vaultkit import normalize_origin
from floorvault.vaultkit.vault import (
    ORIGIN_INDEX_BITS,
    ORIGIN_INDEX_SCOPE,
    VaultStore,
)

KEY = bytes.fromhex("33" * 32)


def _vault(seed: bytes = KEY) -> FloorVault:
    return FloorVault(HardenedMemoryKey(seed))


def _store(tmp_path, seed: bytes = KEY) -> VaultStore:
    return VaultStore(tmp_path / "vault", crypto=_vault(seed))


def _db(tmp_path):
    return sqlite3.connect(tmp_path / "vault" / "vault.db")


def _add(store: VaultStore, origin: str):
    return store.add_item(
        "login",
        f"login for {origin}",
        {"password": "pw", "identifier": "me@example.com", "identifier_type": "email"},
        origin=origin,
    )


def _stored_index(tmp_path, item_id: str) -> bytes:
    conn = _db(tmp_path)
    try:
        return conn.execute("SELECT origin_idx FROM vault_items WHERE id=?", (item_id,)).fetchone()[
            0
        ]
    finally:
        conn.close()


def _colliding_origins(crypto: FloorVault) -> list[str]:
    """Return two distinct origins that land in the same (bounded) bucket."""
    seen: dict[bytes, str] = {}
    for i in range(20_000):
        candidate = f"https://host{i}.example"
        bucket = crypto.beacon(
            normalize_origin(candidate), scope=ORIGIN_INDEX_SCOPE, bits=ORIGIN_INDEX_BITS
        )
        previous = seen.setdefault(bucket, candidate)
        if previous != candidate:
            return [previous, candidate]
    raise AssertionError("no bucket collision found in 20000 origins")


def test_stored_origin_index_is_a_bounded_bucket(tmp_path):
    """RED before the fix: the stored index was the full 32-byte HMAC."""
    store = _store(tmp_path)
    item = _add(store, "https://example.com")

    index = _stored_index(tmp_path, item.id)

    # Pin the security property, not just the constant: the index must stay
    # coarse enough that exact equality is not recoverable from it.
    assert ORIGIN_INDEX_BITS <= 16, "index width must stay coarse (<= 2 bytes)"
    assert len(index) == beacon_bucket_bytes(ORIGIN_INDEX_BITS)
    assert len(index) <= 2
    assert len(index) < 32, "a full-width HMAC discloses exact equality and frequency"


def test_colliding_origins_share_a_bucket_and_are_never_confused(tmp_path):
    """The truncation buys privacy; the confirm-by-decrypt keeps the lookup correct."""
    store = _store(tmp_path)
    first, second = _colliding_origins(_vault())
    assert normalize_origin(first) == first
    assert normalize_origin(second) == second

    item = _add(store, first)

    # The stored index no longer tells the two origins apart. That is the point:
    # an observer can no longer read exact equality out of the index.
    assert _stored_index(tmp_path, item.id) == _vault().beacon(
        second, scope=ORIGIN_INDEX_SCOPE, bits=ORIGIN_INDEX_BITS
    )

    # ...and a bucket collision must NOT be reported as a match. Equality is
    # confirmed by decrypting meta:origin, not by agreeing on a bucket.
    assert store.find_by_origin(second) == []
    assert [meta.id for meta in store.find_by_origin(first)] == [item.id]


def test_exact_match_is_still_found_through_the_bucket(tmp_path):
    """Coarsening the index must not cost the lookup its actual job."""
    store = _store(tmp_path)
    item = _add(store, "https://github.com")

    assert [meta.id for meta in store.find_by_origin("https://github.com")] == [item.id]
    # Port normalization still applies before the beacon is derived.
    assert [meta.id for meta in store.find_by_origin("https://github.com:443")] == [item.id]


def test_opening_a_full_width_store_reseals_the_index(tmp_path):
    """A store written before the index was bounded migrates on open."""
    store = _store(tmp_path)
    item = _add(store, "https://example.com")

    legacy_index = _vault().blind_index("https://example.com", scope=ORIGIN_INDEX_SCOPE)
    assert len(legacy_index) == 32, "precondition: the legacy index is full width"

    conn = _db(tmp_path)
    conn.execute("UPDATE vault_items SET origin_idx=? WHERE id=?", (legacy_index, item.id))
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()

    reopened = _store(tmp_path)

    with reopened._connect() as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 2

    resealed = _stored_index(tmp_path, item.id)
    assert len(resealed) == beacon_bucket_bytes(ORIGIN_INDEX_BITS)
    assert resealed != legacy_index
    assert [meta.id for meta in reopened.find_by_origin("https://example.com")] == [item.id]


def test_the_index_migration_is_idempotent(tmp_path):
    """Re-opening an already-migrated store must not rewrite the index.

    Starts from a full-width store so the second open is a genuine re-visit of
    the migration, then asserts the value is left exactly as the first open
    sealed it (a re-run must be a no-op, not a re-derivation that drifts).
    """
    store = _store(tmp_path)
    item = _add(store, "https://example.com")

    legacy_index = _vault().blind_index("https://example.com", scope=ORIGIN_INDEX_SCOPE)
    conn = _db(tmp_path)
    conn.execute("UPDATE vault_items SET origin_idx=? WHERE id=?", (legacy_index, item.id))
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()

    _store(tmp_path)  # first open: migrates to the bounded width
    after_first_open = _stored_index(tmp_path, item.id)
    assert after_first_open != legacy_index

    _store(tmp_path)  # second open: already current, must not touch the row
    assert _stored_index(tmp_path, item.id) == after_first_open

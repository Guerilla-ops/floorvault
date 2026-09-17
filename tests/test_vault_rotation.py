"""Tests for complete VaultStore key rotation orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest

from floorvault import FloorVault, KeyRing
from floorvault.vault_rotation import rotate_vault_store
from floorvault.vaultkit.vault import VaultStore

OLD = bytes.fromhex("31" * 32)
NEW = bytes.fromhex("42" * 32)


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

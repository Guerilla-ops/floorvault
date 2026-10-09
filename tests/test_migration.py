"""TDD RED/GREEN tests for Slice 3: lazy non-destructive migration.

The MigratingVaultStore facade must:
- read from the MODERN (floorvault) store first;
- transparently fall back to a legacy Fernet vault (vault.json.enc + vault.key);
- upgrade a legacy item into the modern store LAZILY (only when touched);
- NEVER delete/overwrite the legacy file (non-destructive) — keep it until an
  explicit verify confirms every migrated item decrypts;
- provide migrate_all() that backups then converts everything, and verify() that
  proves the migration is sound before the legacy source may be removed.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from floorvault.core import FloorVault
from floorvault.memory import HardenedMemoryKey
from floorvault.migration import LegacyVaultError, MigratingVaultStore
from floorvault.vaultkit.vault import VaultError, VaultStore


def _make_crypto() -> FloorVault:
    return FloorVault(HardenedMemoryKey(bytes.fromhex("cd" * 32)))


def _write_legacy_fernet(base_dir: Path, items: dict[str, dict]) -> tuple[bytes, Path, Path]:
    """Write a legacy Fernet vault the way the legacy reference store did:
    vault.json.enc = Fernet-encrypted JSON {item_id: secret-dict},
    vault.key = the fernet key."""
    base_dir.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fernet = Fernet(key)
    payload = base64.urlsafe_b64encode(fernet.encrypt(json.dumps(items).encode())).decode()
    vault_path = base_dir / "vault.json.enc"
    key_path = base_dir / "vault.key"
    vault_path.write_text(payload)
    key_path.write_text(key.decode())
    os.chmod(key_path, 0o600)
    return key, vault_path, key_path


def test_modern_item_read_first_without_touching_legacy(tmp_path):
    """An item already in the modern store must be served from modern, and the
    legacy fetch must not run / must not mutate anything."""
    crypto = _make_crypto()
    modern = VaultStore(tmp_path / "modern", crypto=crypto)
    _write_legacy_fernet(tmp_path / "modern", {"legacy-1": {"password": "p1"}})

    meta = modern.add_item(
        "login",
        "modern-entry",
        {"password": "pw", "identifier": "u@x", "identifier_type": "email"},
        origin="https://modern.example",
    )
    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=tmp_path / "modern")
    got = facade.resolve_secret(meta.id)
    assert got["password"] == "pw"


def test_legacy_item_read_and_lazily_upgraded(tmp_path):
    """Reading a legacy-only item must: serve it, write it into the modern store,
    and leave the legacy file intact (non-destructive)."""
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _, legacy_vault_path, _ = _write_legacy_fernet(
        base / "modern",
        {
            "legacy-1": {
                "password": "legacy-secret",
                "identifier": "old@x",
                "identifier_type": "email",
            }
        },
    )
    orig_legacy = legacy_vault_path.read_text()

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    secret = facade.resolve_secret("legacy-1")
    assert secret["password"] == "legacy-secret"

    assert modern.has_items() is True
    assert legacy_vault_path.read_text() == orig_legacy


def test_legacy_meta_and_has_items(tmp_path):
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw", "label": "Legacy item"}})

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    assert facade.has_items() is True
    meta = facade.get_meta("legacy-1")
    assert meta is not None
    assert meta.label


def test_migrate_all_backs_up_and_verify(tmp_path):
    """migrate_all() must convert every legacy item into modern, create a .bak of
    the legacy vault, and verify() must confirm all items decrypt. The legacy
    source stays until verify passes."""
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    legacy_items = {
        "a": {"password": "pw-a"},
        "b": {"password": "pw-b", "identifier": "b@x", "identifier_type": "email"},
    }
    _, legacy_vault_path, legacy_key_path = _write_legacy_fernet(base / "modern", legacy_items)

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    result = facade.migrate_all()

    assert result["migrated"] == 2
    assert legacy_vault_path.exists() and legacy_key_path.exists()
    assert legacy_vault_path.with_name("vault.json.enc.pre-migration.bak").exists()
    assert facade.verify() is True


def test_migrate_all_raises_and_keeps_legacy_if_invalid(tmp_path):
    """If the legacy store is corrupt, migrate_all() must raise and NOT delete
    the legacy source."""
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _write_legacy_fernet(base / "modern", {"x": {"password": "pw-x"}})
    legacy_vault_path = base / "modern" / "vault.json.enc"

    legacy_vault_path.write_text("garbage-not-valid")

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    with pytest.raises(VaultError):
        facade.migrate_all()
    assert legacy_vault_path.exists()


def test_migrate_all_is_idempotent(tmp_path):
    """A repeated batch migration must not duplicate modern credentials."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")

    first = facade.migrate_all()
    second = facade.migrate_all()

    assert first["migrated"] == 1
    assert second["migrated"] == 0
    assert len(modern.list_items()) == 1
    assert set(modern.list_legacy_retirements()) == {"legacy-1"}


def test_migrate_all_recovers_after_modern_write_before_retirement(tmp_path, monkeypatch):
    """A retry must finish an interrupted migration without duplicating it."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})
    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")

    monkeypatch.setattr(
        modern,
        "retire_legacy_id",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("simulated crash")),
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        facade.migrate_all()

    monkeypatch.undo()
    retry = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    retry.migrate_all()

    assert len(modern.list_items()) == 1
    assert set(modern.list_legacy_retirements()) == {"legacy-1"}


# ---- legacy vault.key must go through read_protected (red-team P0 #7) ------


def test_legacy_key_reached_through_symlink_is_refused(tmp_path):
    """A ``vault.key`` that is a symlink must be refused, not followed.

    Every other key store reads its master key through ``read_protected``,
    which refuses symlinks, non-regular files, foreign owners and
    group/other-accessible modes. The legacy Fernet path used a bare
    ``Path.read_bytes()`` and skipped all of it, so a planted link could hand
    the migration an attacker-chosen key silently.
    """
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _, _, key_path = _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})

    planted = tmp_path / "planted.key"
    planted.write_bytes(key_path.read_bytes())
    os.chmod(planted, 0o600)
    key_path.unlink()
    key_path.symlink_to(planted)

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    with pytest.raises(LegacyVaultError, match="key"):
        facade.list_item_ids()


def test_legacy_key_group_or_other_readable_is_refused(tmp_path):
    """A world-readable ``vault.key`` must be refused, not adopted.

    read_protected refuses any mode granting group/other access; a 0666 key
    file is exactly the exposure the rest of the library rejects.
    """
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _, _, key_path = _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})
    os.chmod(key_path, 0o666)

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    with pytest.raises(LegacyVaultError, match="key"):
        facade.list_item_ids()


def test_legacy_key_replaced_by_fifo_is_refused(tmp_path):
    """A FIFO at the key path must not hang or be read as a key."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is POSIX-only")
    base = tmp_path / "vault"
    crypto = _make_crypto()
    modern = VaultStore(base / "modern", crypto=crypto)
    _, _, key_path = _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})
    key_path.unlink()
    os.mkfifo(key_path)

    facade = MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")
    with pytest.raises(LegacyVaultError, match="key"):
        facade.list_item_ids()

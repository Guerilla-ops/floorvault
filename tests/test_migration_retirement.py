"""Retirement tombstones: a migrated legacy id must never be served from the
pre-migration source again, even if the modern record disappears.

Why this file exists
--------------------
``MigratingVaultStore`` serves the modern store first and falls through to the
retained legacy Fernet source on *any* ``VaultError``. Nothing distinguished
"never migrated" from "was migrated, modern row has since gone", so deleting a
modern row made the facade answer from the pre-migration file — silently
resurrecting the value from BEFORE the credential was rotated. Every
cryptographic check passed, because the legacy value was authentic; it was
simply retired.

These tests pin the intended behaviour: once an id has been migrated, the
legacy source is permanently forbidden for that id.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from floorvault.core import FloorVault
from floorvault.memory import HardenedMemoryKey
from floorvault.migration import LegacyRetiredError, MigratingVaultStore
from floorvault.vaultkit.vault import VaultError, VaultStore


def _make_crypto() -> FloorVault:
    return FloorVault(HardenedMemoryKey(bytes.fromhex("ab" * 32)))


def _write_legacy_fernet(base_dir: Path, items: dict[str, dict]) -> None:
    """Write a legacy Fernet vault the way the legacy reference store did."""
    base_dir.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    payload = base64.urlsafe_b64encode(Fernet(key).encrypt(json.dumps(items).encode())).decode()
    (base_dir / "vault.json.enc").write_text(payload)
    (base_dir / "vault.key").write_text(key.decode())


def _facade(modern: VaultStore, base: Path) -> MigratingVaultStore:
    return MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")


def test_deleted_modern_record_does_not_resurrect_the_legacy_value(tmp_path):
    """Deleting the migrated modern row must NOT serve the pre-migration value."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "old-revoked"}})

    facade = _facade(modern, base)
    assert facade.resolve_secret("legacy-1")["password"] == "old-revoked"

    migrated = modern.list_items()
    assert len(migrated) == 1
    assert modern.remove_item(migrated[0].id) is True

    # The pre-migration file still holds the revoked value; it must not be served.
    # The precise error type is asserted: a bare VaultError could be satisfied by
    # an unrelated failure ("item not found"), which would mask a regression.
    with pytest.raises(LegacyRetiredError):
        facade.resolve_secret("legacy-1")


def test_retirement_survives_a_new_facade_instance(tmp_path):
    """Retirement is persisted in the modern store, not inferred from the
    in-memory id map, so a fresh process refuses the fallback too."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "old-revoked"}})

    first = _facade(modern, base)
    first.resolve_secret("legacy-1")
    assert modern.remove_item(modern.list_items()[0].id) is True

    fresh = _facade(modern, base)
    assert fresh._legacy_to_modern == {}  # nothing carried over in memory
    with pytest.raises(LegacyRetiredError):
        fresh.resolve_secret("legacy-1")


def test_get_meta_refuses_retired_legacy_fallback(tmp_path):
    """The downgrade channel is not specific to resolve_secret()."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw", "label": "Old"}})

    facade = _facade(modern, base)
    assert facade.get_meta("legacy-1") is not None
    assert modern.remove_item(modern.list_items()[0].id) is True

    with pytest.raises(LegacyRetiredError):
        facade.get_meta("legacy-1")


def test_never_migrated_legacy_item_is_still_served(tmp_path):
    """Guard against over-blocking: an item never migrated still reads legacy."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(
        base / "modern",
        {"untouched": {"password": "still-legacy"}, "moved": {"password": "moved"}},
    )

    assert _facade(modern, base).resolve_secret("moved")["password"] == "moved"

    fresh = _facade(modern, base)
    assert fresh.resolve_secret("untouched")["password"] == "still-legacy"


def test_migrate_all_records_a_retirement_for_every_item(tmp_path):
    """Batch migration retires every migrated id, readable after the fact."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"a": {"password": "pw-a"}, "b": {"password": "pw-b"}})

    facade = _facade(modern, base)
    facade.migrate_all()

    retired = modern.list_legacy_retirements()
    assert set(retired) == {"a", "b"}
    assert all(retired[legacy_id] for legacy_id in retired)
    assert facade.verify() is True


def test_tampered_retirement_record_is_refused(tmp_path):
    """The retirement record is authenticated: a flipped byte must raise rather
    than read as 'not retired'."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "pw"}})

    facade = _facade(modern, base)
    facade.resolve_secret("legacy-1")
    assert modern.list_legacy_retirements() == {"legacy-1": modern.list_items()[0].id}

    with sqlite3.connect(base / "modern" / "vault.db") as conn:
        row = conn.execute(
            "SELECT legacy_id, tombstone_cipher FROM vault_legacy_retirements"
        ).fetchone()
        assert row is not None
        legacy_id, blob = row
        conn.execute(
            "UPDATE vault_legacy_retirements SET tombstone_cipher = ? WHERE legacy_id = ?",
            (bytes([blob[0] ^ 0x01]) + blob[1:], legacy_id),
        )
        conn.commit()

    with pytest.raises(VaultError):
        modern.list_legacy_retirements()


def test_verify_reports_false_when_a_retired_item_is_missing(tmp_path):
    """verify() must not report a sound migration once a retired item's modern
    record has disappeared: the tombstone says it was migrated, but there is
    nothing left to serve, and the fallback is refused."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_make_crypto())
    _write_legacy_fernet(base / "modern", {"a": {"password": "pw-a"}, "b": {"password": "pw-b"}})

    facade = _facade(modern, base)
    facade.migrate_all()
    assert facade.verify() is True

    assert modern.remove_item(modern.list_items()[0].id) is True
    assert facade.verify() is False

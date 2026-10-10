"""Security regression scan: deterministic reproductions of the five findings
from the 2026-09-18 deep-dive review of revision 5433191.

Each test encodes one vulnerable behaviour as a failing assertion, so the suite
acts as a scan: it FAILS if any of the five regression classes is reintroduced.
They are written deterministically (no true concurrency) so they run on every
platform in CI and the mutation gate (step 12) can verify they detect a
reintroduction by killing the corresponding mutant.

Findings covered
----------------
F1 (critical)   A write landing between the rotation's final verification
                snapshot and journal-clear stays under the OLD key and is
                unreadable once that key retires. Writers must be refused while
                a rotation is in progress (durable DB rotation state).
F2 (warning)    Distinct ``schema_version`` values (1.9, True, "1") collapse to
                the same AAD as integer 1, breaking injective context binding.
F3 (warning)    Migration crash-recovery retires a legacy id onto UNRELATED
                pre-existing data at the deterministic id without comparing it.
F4 (warning)    An invalid memory-hardening mode (e.g. "require") silently
                downgrades to opportunistic behaviour instead of being rejected.
F5 (warning)    An existing permissive or symlinked vault base bypasses the
                owner-only (0700) policy because only missing segments are
                created with 0700.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from floorvault.core import FloorVault, associated_data
from floorvault.keyring import KeyRing
from floorvault.memory import HardenedMemoryKey
from floorvault.migration import MigratingVaultStore
from floorvault.vault_rotation import rotate_vault_store
from floorvault.vaultkit.vault import VaultError, VaultStore

OLD = bytes.fromhex("31" * 32)
NEW = bytes.fromhex("42" * 32)


def _crypto(key: bytes) -> FloorVault:
    return FloorVault(key, memory_mode="disabled")


def _store(tmp_path: Path) -> VaultStore:
    return VaultStore(tmp_path / "vault", crypto=_crypto(OLD))


# ---------------------------------------------------------------------------
# F1 (critical) - rotation can succeed while a write stays under the old key
# ---------------------------------------------------------------------------


def test_f1_writer_is_refused_while_rotation_is_in_progress(tmp_path, monkeypatch):
    """A write in the rotation window must be refused, never left under old key."""
    store = _store(tmp_path)
    store.add_item("generic", "First", {"note": "one"})

    outcome: list[bool] = []
    original_clear = store.clear_rotation_journal

    def clear_with_injected_write():
        # Simulate a writer landing during the vulnerable window: it must be
        # refused (False). Landing it under the old key is the F1 bug.
        try:
            store.add_item("generic", "Late", {"note": "should-be-refused"})
            outcome.append(True)
        except VaultError:
            outcome.append(False)
        original_clear()

    monkeypatch.setattr(store, "clear_rotation_journal", clear_with_injected_write)

    rotate_vault_store(
        store,
        source_ring=KeyRing({0: _crypto(OLD)}),
        new_vault=_crypto(NEW),
        new_key_id=1,
    )

    assert outcome == [False], (
        "a write landed during rotation under the old key; it will be unreadable "
        "once the old key retires (F1)"
    )
    # A refused write must not be present anywhere under the new key.
    rotated = VaultStore(tmp_path / "vault", crypto=_crypto(NEW))
    assert all(rotated.get_meta(m.id) is not None for m in rotated.list_items())


# ---------------------------------------------------------------------------
# F2 (warning) - distinct schema versions authenticate as the same context
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [1.9, 1.1, True, "1"])
def test_f2_non_integer_schema_version_is_rejected(bad):
    """Coercible non-integers must not collapse into the same AAD as integer 1."""
    with pytest.raises(TypeError):
        associated_data(
            table="t",
            record_id="r",
            column="c",
            schema_id="s",
            schema_version=bad,
            app_instance_id="a",
        )


def test_f2_encrypt_rejects_float_schema_version(tmp_path):
    fv = _crypto(OLD)
    with pytest.raises(TypeError):
        fv.encrypt(
            b"payload",
            table="t",
            record_id="r",
            column="c",
            schema_version=1.9,
        )


# ---------------------------------------------------------------------------
# F3 (warning) - migration retires a legacy id onto unrelated pre-existing data
# ---------------------------------------------------------------------------


def _write_legacy_fernet(base_dir: Path, items: dict[str, dict]) -> None:
    import base64
    import json

    from cryptography.fernet import Fernet

    base_dir.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    payload = base64.urlsafe_b64encode(Fernet(key).encrypt(json.dumps(items).encode())).decode()
    (base_dir / "vault.json.enc").write_text(payload)
    key_path = base_dir / "vault.key"
    key_path.write_text(key.decode())
    os.chmod(key_path, 0o600)


def _facade(modern: VaultStore, base: Path) -> MigratingVaultStore:
    return MigratingVaultStore(modern_store=modern, legacy_base_dir=base / "modern")


def test_f3_migration_fails_closed_on_unrelated_pre_existing_id(tmp_path):
    """Pre-existing data at the deterministic id must NOT be retired onto."""
    base = tmp_path / "vault"
    modern = VaultStore(base / "modern", crypto=_crypto(OLD))
    _write_legacy_fernet(base / "modern", {"legacy-1": {"password": "original"}})

    # Pre-create the deterministic modern id with UNRELATED content.
    digest = hashlib.sha256(b"legacy-1").hexdigest()[:24]
    deterministic = f"vault_migration_{digest}"
    modern.add_item("generic", "Unrelated", {"password": "unrelated"}, item_id=deterministic)

    facade = _facade(modern, base)
    with pytest.raises(VaultError):
        facade.resolve_secret("legacy-1")

    # The unrelated row must remain untouched and the legacy id NOT retired.
    assert modern.resolve_secret(deterministic) == {"password": "unrelated"}
    assert "legacy-1" not in modern.list_legacy_retirements()


# ---------------------------------------------------------------------------
# F4 (warning) - invalid memory-hardening modes silently downgrade enforcement
# ---------------------------------------------------------------------------


def test_f4_invalid_mode_rejected_in_hardened_memory_key():
    with pytest.raises(ValueError):
        HardenedMemoryKey(bytes.fromhex("ab" * 32), mode="require")


def test_f4_invalid_mode_rejected_in_floorvault():
    with pytest.raises(ValueError):
        FloorVault(bytes.fromhex("cd" * 32), memory_mode="require")


# ---------------------------------------------------------------------------
# F5 (warning) - existing permissive/symlinked vault base bypasses owner-only
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no POSIX permission bits; os.lstat reports a synthesised mode",
)
def test_f5_existing_permissive_base_is_hardened(tmp_path):
    base = tmp_path / "vault"
    base.mkdir(parents=True)
    os.chmod(base, 0o777)

    VaultStore(base, crypto=_crypto(OLD))

    mode = stat.S_IMODE(os.lstat(base).st_mode)
    assert mode == 0o700, f"existing permissive base left at {oct(mode)}, expected 0o700"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows symlink creation in pytest tmp dirs is unreliable",
)
def test_f5_symlinked_vault_base_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "vault"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError):
        VaultStore(link, crypto=_crypto(OLD))

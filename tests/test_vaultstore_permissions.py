"""F-6: a nested vault base directory must be owner-only on every segment.

VaultStore used Path.mkdir(mode=0o700, parents=True), which applies the mode only
to the final component; ancestors are created with the default 0o777 masked by
umask, leaving e.g. ~/.floor/vault world-searchable. Creation now goes through
the same owner-only helper the custody chain uses.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from floorvault.core import FloorVault
from floorvault.memory import HardenedMemoryKey
from floorvault.vaultkit.vault import VaultStore

MASTER = bytes.fromhex("5a" * 32)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no POSIX permission bits; os.lstat reports a synthesised mode",
)
def test_vault_store_hardens_every_path_segment(tmp_path):
    base = tmp_path / "a" / "b" / "vault"
    VaultStore(base, crypto=FloorVault(HardenedMemoryKey(MASTER)))

    for segment in (tmp_path / "a", tmp_path / "a" / "b", base):
        mode = stat.S_IMODE(os.lstat(segment).st_mode)
        assert mode == 0o700, f"{segment} has mode {oct(mode)}, expected 0o700"


_POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no POSIX permission bits; os.lstat reports a synthesised mode",
)


def _mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@_POSIX_ONLY
def test_new_vault_db_is_owner_only_even_under_a_permissive_umask(tmp_path):
    """The database file is as private as its directory (it was 0644 under umask 022)."""
    old = os.umask(0o022)
    try:
        base = tmp_path / "vault"
        store = VaultStore(base, crypto=FloorVault(HardenedMemoryKey(MASTER)))
        store.add_item("generic", "x", {"value": "p"})
    finally:
        os.umask(old)
    assert _mode(base / "vault.db") == 0o600
    # Nothing SQLite leaves beside it may be looser than the database.
    for leftover in base.iterdir():
        assert _mode(leftover) & 0o077 == 0, leftover.name


@_POSIX_ONLY
def test_an_existing_loose_vault_db_is_tightened_and_still_opens(tmp_path):
    base = tmp_path / "vault"
    crypto = FloorVault(HardenedMemoryKey(MASTER))
    store = VaultStore(base, crypto=crypto)
    item = store.add_item("generic", "keep", {"value": "p"})
    os.chmod(base / "vault.db", 0o644)
    reopened = VaultStore(base, crypto=FloorVault(HardenedMemoryKey(MASTER)))
    assert _mode(base / "vault.db") == 0o600
    assert reopened.get_meta(item.id) is not None


@_POSIX_ONLY
def test_a_symlinked_vault_db_is_not_chmodded_through_the_link(tmp_path):
    """chmod follows links: tightening must not touch whatever the link points at."""
    base = tmp_path / "vault"
    base.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.db"
    target.write_bytes(b"")
    os.chmod(target, 0o644)
    os.symlink(target, base / "vault.db")
    try:
        VaultStore(base, crypto=FloorVault(HardenedMemoryKey(MASTER)))
    except Exception:
        pass  # refusing a symlinked database is acceptable; changing its target is not
    assert _mode(target) == 0o644

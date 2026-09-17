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

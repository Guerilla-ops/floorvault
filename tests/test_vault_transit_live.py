"""Live-Vault integration test — runs only when CI or an operator points it
at a reachable Vault.

Enabled by setting ``FLOORVAULT_LIVE_VAULT=1`` plus ``VAULT_ADDR``
(https://...), ``VAULT_TOKEN`` and ``VAULT_CACERT`` (PEM bundle for the dev
server's generated CA). CI's ``vault-live`` job provisions all four; without
them every test here skips, so the default suite stays hermetic.
"""

from __future__ import annotations

import hashlib
import os
import struct

import pytest

from floorvault.providers.base import CustodyDowngradeError
from floorvault.providers.vault_transit import VaultTransitProvider

LIVE = os.environ.get("FLOORVAULT_LIVE_VAULT") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="live Vault leg: set FLOORVAULT_LIVE_VAULT=1")


def _provider(tmp_path):
    return VaultTransitProvider(
        vault_addr=os.environ["VAULT_ADDR"],
        key_name="floorvault-ci",
        store_dir=tmp_path / "keystore",
        app_instance_id="floorvault-ci",
        cafile=os.environ.get("VAULT_CACERT"),
        cache_ttl=0,  # every resolve exercises the wire in the live leg
    )


def test_live_provision_resolve_rewrap(tmp_path):
    provider = _provider(tmp_path)
    key1 = provider.resolve_key()
    assert len(key1.get_bytes()) == 32

    # Second provider instance: same store, same context, same plaintext.
    provider2 = _provider(tmp_path)
    assert provider2.resolve_key().get_bytes() == key1.get_bytes()

    # Rewrap publishes generation 2 and keeps the plaintext master stable.
    assert provider.rewrap() == 2
    assert provider.resolve_key().get_bytes() == key1.get_bytes()

    # A different store directory mints a different store.id, so its binding
    # context differs: grafting our generation-2 blob into that store must
    # fail at Transit decrypt. This simulates splicing a blob across stores.
    foreign_dir = tmp_path / "foreign"
    foreign = VaultTransitProvider(
        vault_addr=os.environ["VAULT_ADDR"],
        key_name="floorvault-ci",
        store_dir=foreign_dir,
        app_instance_id="floorvault-ci",
        cafile=os.environ.get("VAULT_CACERT"),
        cache_ttl=0,
    )
    foreign.resolve_key()  # provisions generation 1 under foreign's store.id

    swapped = (tmp_path / "keystore" / "g-00000002.gen").read_bytes()[len(b"FVGW1") :]
    (foreign_dir / "g-00000001.gen").write_bytes(b"FVGW1" + swapped)
    (foreign_dir / "active").write_bytes(
        b"FVGW0" + struct.pack(">Q", 1) + hashlib.sha256(swapped).digest()
    )
    with pytest.raises(CustodyDowngradeError):
        foreign.resolve_key()

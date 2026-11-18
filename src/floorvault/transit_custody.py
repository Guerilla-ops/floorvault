"""Vault Transit custody for a store the CLI opens (``secrets init --custody vault-transit``).

The master key is kept only wrapped by HashiCorp Vault's Transit engine, in a
generation store at ``<store>/vault-transit/`` (``VaultTransitProvider``; formats
in SPEC.md §10.6-10.7, operator guide in docs/VAULT-TRANSIT.md). Nothing in that
directory is secret: it holds ciphertext and the store's identity. Opening the
store needs Vault, the Transit key and a token allowed to use it.

Where to reach Vault, and with what, comes from the environment, never from a
file beside the store:

- ``VAULT_ADDR`` (required, ``https://``) and ``VAULT_TOKEN`` (required), the names
  Vault's own tools read;
- ``VAULT_CACERT``, a CA bundle for a Vault on private PKI (TLS is always verified);
- ``FLOOR_VAULT_TRANSIT_KEY`` (default ``floorvault-master``) and
  ``FLOOR_VAULT_TRANSIT_MOUNT`` (default ``transit``).

A file beside the store would let whoever can write that directory point the next
open at a server of their choosing, which would then receive the token.

The hermesvault plugin keeps its wrapped key in the same place under the same
application context, so a store set up by either can be opened by both.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Optional

__all__ = [
    "ADDR_ENV",
    "CACERT_ENV",
    "DEFAULT_KEY_NAME",
    "DEFAULT_MOUNT",
    "KEY_ENV",
    "MOUNT_ENV",
    "STORE_DIRNAME",
    "TOKEN_ENV",
    "TransitCustodyError",
    "create",
    "present",
    "read_key",
    "store_dir",
]

#: The directory beside ``vault.db`` that holds the wrapped key. Its presence (as
#: anything, even a broken link) means the store's key is kept by Vault.
STORE_DIRNAME = "vault-transit"
ADDR_ENV = "VAULT_ADDR"
TOKEN_ENV = "VAULT_TOKEN"  # nosec B105 - a variable's name, not a secret
CACERT_ENV = "VAULT_CACERT"
KEY_ENV = "FLOOR_VAULT_TRANSIT_KEY"
MOUNT_ENV = "FLOOR_VAULT_TRANSIT_MOUNT"
DEFAULT_KEY_NAME = "floorvault-master"
DEFAULT_MOUNT = "transit"


class TransitCustodyError(Exception):
    """The Vault-wrapped key cannot be created or read. The message is safe to print."""


def store_dir(vault_dir: Path) -> Path:
    return Path(vault_dir) / STORE_DIRNAME


def present(vault_dir: Path) -> bool:
    """Whether this store's key is kept by Vault Transit.

    ``lexists``: a link or a half-created directory counts, so a damaged custody is
    reported as damaged instead of letting another key source stand in for it.
    """
    return os.path.lexists(store_dir(vault_dir))


def _provider(vault_dir: Path, environ: Mapping[str, str], app_instance_id: str):
    from .providers.vault_transit import VaultTransitProvider

    addr = (environ.get(ADDR_ENV) or "").strip()
    token = (environ.get(TOKEN_ENV) or "").strip()
    if not addr or not token:
        missing = " and ".join(
            name for name, value in ((ADDR_ENV, addr), (TOKEN_ENV, token)) if not value
        )
        raise TransitCustodyError(
            f"the key of the vault at {vault_dir} is wrapped by Vault Transit; set {missing} "
            f"(the token needs only transit datakey, decrypt and rewrap on the key)"
        )
    try:
        return VaultTransitProvider(
            vault_addr=addr,
            key_name=(environ.get(KEY_ENV) or "").strip() or DEFAULT_KEY_NAME,
            store_dir=store_dir(vault_dir),
            token=token,
            app_instance_id=app_instance_id,
            transit_mount=(environ.get(MOUNT_ENV) or "").strip() or DEFAULT_MOUNT,
            cafile=(environ.get(CACERT_ENV) or "").strip() or None,
            # Every open asks Vault, so revoking the token takes effect at the next one.
            cache_ttl=0,
        )
    except ValueError as exc:  # a malformed address: the message names no secret
        raise TransitCustodyError(f"{ADDR_ENV}: {exc}") from None


def _key_bytes(provider, *, allow_create: bool) -> bytes:
    from .providers.base import KeyProviderError

    try:
        key = provider.resolve_key(allow_create=allow_create)
    except KeyProviderError as exc:
        # The provider never puts the token in a message (docs/VAULT-TRANSIT.md).
        raise TransitCustodyError(f"Vault Transit: {exc}") from None
    try:
        return key.get_bytes()
    finally:
        key.wipe()
        provider.wipe()


def read_key(
    vault_dir: Path, environ: Mapping[str, str], *, app_instance_id: str
) -> Optional[bytes]:
    """The store's master key, unwrapped by Vault; None when the store has no such custody.

    Never creates anything: a store whose wrapped key is missing or damaged is an
    error, not a reason to mint a new key over its data.
    """
    if not present(vault_dir):
        return None
    return _key_bytes(_provider(vault_dir, environ, app_instance_id), allow_create=False)


def create(vault_dir: Path, environ: Mapping[str, str], *, app_instance_id: str) -> Path:
    """Mint a new master key with Vault and keep it only wrapped; return the directory.

    Refuses when the store already has this custody, so a second key can never be
    created beside the first.
    """
    if present(vault_dir):
        raise TransitCustodyError(
            f"{store_dir(vault_dir)} already exists; it is never replaced. Nothing was created"
        )
    provider = _provider(vault_dir, environ, app_instance_id)
    _key_bytes(provider, allow_create=True)
    return store_dir(vault_dir)

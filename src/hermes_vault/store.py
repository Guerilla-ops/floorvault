"""Hermes Vault Store: First-class vault persistence for Hermes Agent."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .vaultkit.vault import (
    GENERIC_FIELDS,
    LOGIN_IDENTIFIER_TYPES,
    PAYMENT_FIELDS,
    REQUIRED_FIELDS,
    VAULT_KINDS,
    HermesVaultStore,
    VaultError,
    VaultItemMeta,
    VaultStore,
    normalize_origin,
    normalize_otp_secret,
    scrub_secret_from_text,
)


def get_vault_store(base_dir: Optional[Path | str] = None, *, auto_migrate: bool = True):
    """Return a Hermes vault store, with transparent legacy migration if present."""
    if base_dir is None:
        hermes_home = os.environ.get("HERMES_HOME")
        if hermes_home:
            base_dir = Path(hermes_home) / "vault"
        else:
            base_dir = Path.home() / ".hermes" / "vault"
    base = Path(base_dir)
    modern = VaultStore(base)
    if auto_migrate and (base / "vault.json.enc").is_file() and (base / "vault.key").is_file():
        from .migration import MigratingVaultStore

        return MigratingVaultStore(modern_store=modern, legacy_base_dir=base)
    return modern


__all__ = [
    "HermesVaultStore",
    "VaultStore",
    "VaultItemMeta",
    "VaultError",
    "get_vault_store",
    "normalize_origin",
    "normalize_otp_secret",
    "scrub_secret_from_text",
    "VAULT_KINDS",
    "LOGIN_IDENTIFIER_TYPES",
    "PAYMENT_FIELDS",
    "REQUIRED_FIELDS",
    "GENERIC_FIELDS",
]

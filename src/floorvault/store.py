"""FloorVault credential store and migration-aware factory."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .vaultkit.vault import (
    GENERIC_FIELDS,
    LOGIN_IDENTIFIER_TYPES,
    PAYMENT_FIELDS,
    REQUIRED_FIELDS,
    VAULT_KINDS,
    VaultError,
    VaultItemMeta,
    VaultStore,
    normalize_origin,
    normalize_otp_secret,
    scrub_secret_from_text,
)
from .vaultkit.vault import (
    get_vault_store as _get_vault_store,
)


def get_vault_store(base_dir: Optional[Path | str] = None, *, auto_migrate: bool = True):
    """Open the existing FloorVault location; optionally expose legacy migration."""
    modern = _get_vault_store(base_dir)
    base = modern._base
    if auto_migrate and (base / "vault.json.enc").is_file() and (base / "vault.key").is_file():
        from .migration import MigratingVaultStore

        return MigratingVaultStore(modern_store=modern, legacy_base_dir=base)
    return modern


__all__ = [
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

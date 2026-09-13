"""Hermes Agent-optimized storage adapters."""

from __future__ import annotations

from .session_crypto import HermesSessionCrypto, scrub_secrets_for_fts
from .vault import (
    HermesVaultStore,
    VaultError,
    VaultItemMeta,
    normalize_origin,
    normalize_otp_secret,
)

__all__ = [
    "HermesSessionCrypto",
    "HermesVaultStore",
    "VaultError",
    "VaultItemMeta",
    "normalize_origin",
    "normalize_otp_secret",
    "scrub_secrets_for_fts",
]

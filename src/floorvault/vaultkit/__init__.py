"""Agent-optimized storage adapters."""

from __future__ import annotations

from .session_crypto import SessionCrypto, scrub_secrets_for_fts
from .vault import (
    VaultError,
    VaultItemMeta,
    VaultStore,
    get_vault_store,
    normalize_origin,
    normalize_otp_secret,
    scrub_secret_from_text,
    totp_now,
)

__all__ = [
    "SessionCrypto",
    "VaultError",
    "VaultItemMeta",
    "VaultStore",
    "get_vault_store",
    "normalize_origin",
    "normalize_otp_secret",
    "scrub_secret_from_text",
    "scrub_secrets_for_fts",
    "totp_now",
]

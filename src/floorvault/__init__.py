"""floorvault: Contextual, misuse-resistant database encryption for SQLite."""

from __future__ import annotations

from .core import (
    AppStateCrypto,
    AppStateCryptoError,
    DecryptionVerificationError,
    FloorVault,
    FloorVaultError,
    NonceReuseError,
    associated_data,
)
from .keyring import KeyRing, UnknownKeyIdError
from .memory import (
    HardenedMemoryKey,
    SecurityHardeningError,
    disable_core_dumps,
)
from .migration import LegacyVaultError, MigratingVaultStore
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProvider, KeyProviderError, MissingKeyError
from .sqlite_adapter import ContextualSQLite, ContextualTable, EncryptedSQLiteTable
from .sqlite_migration import migrate_plaintext_column, verify_encrypted_column

__version__ = "0.1.0"

__all__ = [
    # Core Cryptography
    "FloorVault",
    "FloorVaultError",
    "AppStateCrypto",
    "AppStateCryptoError",
    "DecryptionVerificationError",
    "NonceReuseError",
    "associated_data",
    # Hardware Memory Custody
    "HardenedMemoryKey",
    "SecurityHardeningError",
    "disable_core_dumps",
    # SQLite Helpers
    "ContextualSQLite",
    "ContextualTable",
    "EncryptedSQLiteTable",
    "migrate_plaintext_column",
    "verify_encrypted_column",
    # Key Providers
    "KeyProvider",
    "KeyProviderError",
    "MissingKeyError",
    "AdaptiveKeyProvider",
    # Lazy Migration
    "MigratingVaultStore",
    "LegacyVaultError",
    # Multi-generation reads (rotation)
    "KeyRing",
    "UnknownKeyIdError",
]

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
from .key_recovery import recover_master_key, wrap_master_key
from .keyring import KeyRing, UnknownKeyIdError
from .memory import (
    HardenedMemoryKey,
    SecurityHardeningError,
    disable_core_dumps,
)
from .migration import LegacyRetiredError, LegacyVaultError, MigratingVaultStore
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProvider, KeyProviderError, MissingKeyError
from .records import EncryptedWriteError, RecordBinding, UnsupportedWriteError
from .sqlite_adapter import ContextualSQLite, ContextualTable, EncryptedSQLiteTable
from .sqlite_migration import (
    drop_plaintext_column,
    migrate_plaintext_column,
    verify_encrypted_column,
)
from .vault_rotation import rotate_vault_store

__version__ = "0.1.0"

# SQLAlchemy is an optional extra; the adapter classes that import it resolve
# lazily so that `import floorvault` never hard-requires SQLAlchemy. The error
# types live in the driver-free records layer and are eager exports.
_LAZY = {
    "SqlAlchemyEncryption",
    "EncryptedField",
}


def __getattr__(name: str):
    if name in _LAZY:
        from . import sqlalchemy_adapter

        return getattr(sqlalchemy_adapter, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    "drop_plaintext_column",
    "rotate_vault_store",
    # Key Providers
    "KeyProvider",
    "KeyProviderError",
    "MissingKeyError",
    "AdaptiveKeyProvider",
    # Lazy Migration
    "MigratingVaultStore",
    "LegacyVaultError",
    # Raised when a migrated legacy id is asked for and its modern record is
    # gone. Named in SECURITY.md as the read-failure type callers should handle,
    # so it belongs in the public surface rather than only in floorvault.migration.
    "LegacyRetiredError",
    # Multi-generation reads (rotation)
    "KeyRing",
    "UnknownKeyIdError",
    "wrap_master_key",
    "recover_master_key",
    # Shared record layer + adapter error types
    "RecordBinding",
    "EncryptedWriteError",
    "UnsupportedWriteError",
    # SQLAlchemy adapter (lazy; requires the 'sqlalchemy' extra)
    "SqlAlchemyEncryption",
    "EncryptedField",
]

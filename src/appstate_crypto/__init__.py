"""appstate-crypto: Contextual, misuse-resistant, searchable database encryption for SQLite."""

from __future__ import annotations

from .blind_index import BlindIndexer, compute_blind_index
from .core import (
    AppStateCrypto,
    AppStateCryptoError,
    DecryptionVerificationError,
    NonceReuseError,
    associated_data,
)
from .memory import (
    HardenedMemoryKey,
    SecurityHardeningError,
    disable_core_dumps,
)
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProvider, KeyProviderError, MissingKeyError
from .sqlite_adapter import ContextualSQLite, ContextualTable

__version__ = "0.1.0"

__all__ = [
    # Core Cryptography
    "AppStateCrypto",
    "AppStateCryptoError",
    "DecryptionVerificationError",
    "NonceReuseError",
    "associated_data",
    # Hardware Memory Custody
    "HardenedMemoryKey",
    "SecurityHardeningError",
    "disable_core_dumps",
    # Blind Indexing
    "BlindIndexer",
    "compute_blind_index",
    # SQLite Helpers
    "ContextualSQLite",
    "ContextualTable",
    # Key Providers
    "KeyProvider",
    "KeyProviderError",
    "MissingKeyError",
    "AdaptiveKeyProvider",
]

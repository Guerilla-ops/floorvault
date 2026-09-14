"""Master key provider interfaces and implementations."""

from __future__ import annotations

from .adaptive import AdaptiveKeyProvider
from .base import KeyProvider, KeyProviderError, MissingKeyError
from .linux_keyring import LinuxSecretServiceKeyProvider
from .windows_dpapi import WindowsDPAPIKeyProvider

__all__ = [
    "AdaptiveKeyProvider",
    "KeyProvider",
    "KeyProviderError",
    "MissingKeyError",
    "WindowsDPAPIKeyProvider",
    "LinuxSecretServiceKeyProvider",
]

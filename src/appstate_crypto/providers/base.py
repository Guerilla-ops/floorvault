"""Abstract base class for master key providers."""

from __future__ import annotations

import abc
from typing import Optional, Tuple, Union

from ..memory import HardenedMemoryKey


class KeyProviderError(Exception):
    """Base exception for key resolution failures."""


class MissingKeyError(KeyProviderError):
    """Raised when an existing key cannot be found and creation is disallowed."""


class KeyProvider(abc.ABC):
    """Abstract interface for securely resolving or deriving a master key."""

    @abc.abstractmethod
    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        """Resolve the 32-byte master encryption key wrapped in HardenedMemoryKey.
        
        Args:
            allow_create: If True, generate a new key if none exists.
            
        Returns:
            HardenedMemoryKey containing exactly 32 bytes.
        """
        raise NotImplementedError

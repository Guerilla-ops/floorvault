"""Abstract base class for master key providers."""

from __future__ import annotations

import abc

from ..memory import HardenedMemoryKey


class KeyProviderError(Exception):
    """Base exception for key resolution failures."""


class MissingKeyError(KeyProviderError):
    """Raised when an existing key cannot be found and creation is disallowed."""


class CustodyDowngradeError(KeyProviderError):
    """Raised when a stronger custody tier is present but unusable.

    Deliberately distinct from :class:`MissingKeyError` and from a tier simply
    not being available. A failure means a security-relevant condition (a locked
    or broken keychain, a denied prompt) is being handled, and continuing would
    silently resolve the key from a weaker store - for example a plaintext key
    file. Failing closed keeps the operator aware that custody was degraded.
    """


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

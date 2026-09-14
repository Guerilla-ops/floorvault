"""Linux Secret Service / keyring-backed master key provider.

Primary: the freedesktop Secret Service (GNOME Keyring / KWallet via the
`secretstorage` package) when it is reachable and a desktop session is present.
Fallback (headless / no D-Bus / library absent): a fail-closed, entropy-masked
protected file exactly like the DPAPI provider, so the round-trip contract is
testable on any platform.

Fail-closed: if Secret Service is expected (interactive desktop) but cannot be
reached, and no key file exists yet, a MissingKeyError is raised rather than
silently writing an unprotected key.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable

from ..memory import HardenedMemoryKey
from .base import KeyProvider, MissingKeyError
from .platform_custody import ProtectedStoreError, read_protected, write_protected

_HEADER = b"FLOORLV1"  # floorvault protected key store, linux/secret-service boundary


def _random(n: int) -> bytes:
    return os.urandom(n)


def _looks_interactive_desktop() -> bool:
    return bool(
        os.environ.get("DISPLAY")
        or os.environ.get("WAYLAND_DISPLAY")
        or os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    )


class LinuxSecretServiceKeyProvider(KeyProvider):
    """Linux Secret Service master-key provider (with fail-closed fallback)."""

    def __init__(
        self,
        *,
        store_path: str | Path,
        service: str = "floorvault",
        attribute: str = "master-key",
        random_bytes: Callable[[int], bytes] = _random,
    ) -> None:
        if not service or not isinstance(service, str):
            raise ValueError("service must be a non-empty string")
        self._path = Path(store_path)
        self._service = service
        self._attribute = attribute
        self._random_bytes = random_bytes

    # ---- Secret Service primary (Linux, interactive) ----------------------

    def _secret_service_available(self) -> bool:
        if os.name != "posix" or not _looks_interactive_desktop():
            return False
        try:
            import secretstorage  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    def _resolve_via_secret_service(self, *, allow_create: bool) -> HardenedMemoryKey | None:
        try:
            import secretstorage
            from secretstorage.exceptions import SecretServiceNotAvailable
        except ImportError:
            return None
        try:
            bus = secretstorage.DBusAddressConnection(secretstorage.get_default_bus())
            collection = secretstorage.get_default_collection(bus)
            if collection.is_locked():
                collection.unlock()
            item = next(
                (
                    i
                    for i in collection.search_items({"application": self._service})
                    if i.get_attribute("floorvault") == self._attribute
                ),
                None,
            )
            if item is not None:
                secret = item.get_secret()
                if secret is None or len(secret) != 32:
                    raise ProtectedStoreError("Secret Service entry has an invalid key length")
                return HardenedMemoryKey(secret)
            if not allow_create:
                raise MissingKeyError("Secret Service master key not found; recovery is required")
            key = self._random_bytes(32)
            collection.create_item(
                f"{self._service}:{self._attribute}",
                {"application": self._service, "floorvault": self._attribute},
                key,
                replace=False,
            )
            return HardenedMemoryKey(key)
        except SecretServiceNotAvailable:
            return None
        except Exception:  # noqa: BLE001
            return None

    # ---- fallback custody (masked protected file) -------------------------

    def _mask(self, plaintext: bytes) -> bytes:
        pad = hashlib.sha256(self._service.encode()).digest()
        return bytes(a ^ b for a, b in zip(plaintext, pad))

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        # Try the primary boundary first.
        if self._secret_service_available():
            via_ss = self._resolve_via_secret_service(allow_create=allow_create)
            if via_ss is not None:
                return via_ss
        # Fallback: masked protected file.
        try:
            blob = read_protected(self._path, header=_HEADER)
        except ProtectedStoreError:
            blob = None
        if blob is not None:
            key = self._mask(blob)
            if len(key) != 32:
                raise ProtectedStoreError("protected store key has unexpected length")
            return HardenedMemoryKey(key)
        if not allow_create:
            raise MissingKeyError("Linux Secret Service store is missing; recovery is required")
        # On an interactive desktop where Secret Service is expected but absent,
        # fail closed rather than silently writing a key file.
        if _looks_interactive_desktop() and os.name == "posix":
            raise MissingKeyError(
                "Secret Service is unavailable but a desktop session is present; "
                "refusing to fall back to a key file. Set a key explicitly."
            )
        key = self._random_bytes(32)
        if len(key) != 32:
            raise ProtectedStoreError("random source must return 32 bytes")
        write_protected(self._mask(key), self._path, header=_HEADER)
        return HardenedMemoryKey(key)

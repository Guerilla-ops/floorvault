"""3-Tier Adaptive Key Provider.

Scales from interactive desktop storage to headless cloud/Docker environments:
  Tier 1: Explicit Environment Variable (APPSTATE_KEY, FLOOR_VAULT_KEY)
  Tier 2: macOS Keychain when available
  Tier 3: Explicitly Opt-In Local 0600 File Key (Headless Docker / Remote SSH)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

from ..memory import HardenedMemoryKey
from ..platform_support import (
    binary_mode_flag,
    has_posix_group_or_other_access,
    is_macos,
    is_windows,
)
from .base import CustodyDowngradeError, KeyProvider, KeyProviderError


class AdaptiveKeyProvider(KeyProvider):
    """Adaptive key provider with fail-closed protected-storage defaults."""

    def __init__(
        self,
        service_name: str = "floorvault",
        account_name: str = "default-v1",
        *,
        fallback_dir: Optional[Path] = None,
        strict: bool = False,
        allow_disk_fallback: bool = False,
    ) -> None:
        self.service_name = service_name
        self.account_name = account_name
        self.fallback_dir = fallback_dir or (Path.home() / ".floorvault")
        self.strict = strict
        self.allow_disk_fallback = allow_disk_fallback and not strict
        self.keychain_unavailable_reason: Optional[str] = None

    def _is_interactive_desktop(self) -> bool:
        """Heuristic detecting whether a GUI keyring environment is present."""
        if is_macos():
            # On macOS, window server is active if not in a raw detached ssh without gui
            return os.environ.get("SSH_CONNECTION") is None or bool(os.environ.get("DISPLAY"))
        if is_windows():
            return True
        # Linux: check for X11 / Wayland / DBus session
        return bool(
            os.environ.get("DISPLAY")
            or os.environ.get("WAYLAND_DISPLAY")
            or os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        )

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        """Resolve the master key across the three autonomous tiers."""
        # --- Tier 1: Explicit Environment Variable (CI / Cloud / Kubernetes) ---
        for var_name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
            val = os.environ.get(var_name)
            if val:
                raw_bytes: bytes
                clean_val = val.strip()
                if len(clean_val) != 64:
                    raise KeyProviderError(
                        "Environment key must be 64 hexadecimal characters (32 bytes hex-encoded)"
                    )
                try:
                    raw_bytes = bytes.fromhex(clean_val)
                except ValueError as exc:
                    raise KeyProviderError("Environment key must be valid hexadecimal") from exc
                return HardenedMemoryKey(raw_bytes)

        # --- Tier 2: System Keyring (Desktop Workstation) ---
        if self._is_interactive_desktop():
            try:
                key = self._resolve_from_system_keyring(allow_create=allow_create)
                if key is not None:
                    return key
            except KeyProviderError:
                raise
            except Exception:
                # If desktop keyring is unavailable, locked, or prompts are denied, fall through
                pass
        # --- Tier 3: Zero-Config Machine-Bound Local File Key (Docker / SSH) ---
        return self._resolve_machine_bound_file_key(allow_create=allow_create)

    def _resolve_from_system_keyring(self, *, allow_create: bool) -> Optional[HardenedMemoryKey]:
        """Attempt to read from macOS Keychain or generic system keyring."""
        if is_macos():
            try:
                import Security  # type: ignore[import-not-found]
            except ImportError:
                # pyobjc-framework-Security not installed: Tier 2 cannot run.
                # Install the "macos" extra to enable Keychain custody.
                self.keychain_unavailable_reason = (
                    "pyobjc-framework-Security is not installed; "
                    "install floorvault[macos] to enable the macOS Keychain tier"
                )
                return None
            try:
                query = {
                    Security.kSecClass: Security.kSecClassGenericPassword,
                    Security.kSecAttrService: self.service_name,
                    Security.kSecAttrAccount: self.account_name,
                    Security.kSecReturnData: True,
                    Security.kSecMatchLimit: Security.kSecMatchLimitOne,
                }
                status, data = Security.SecItemCopyMatching(query, None)
                if status == 0 and data:
                    key_bytes = bytes(data)
                    return HardenedMemoryKey(key_bytes)
                if status == -25300 and allow_create:  # errSecItemNotFound
                    new_key = os.urandom(32)
                    add_query = {
                        Security.kSecClass: Security.kSecClassGenericPassword,
                        Security.kSecAttrService: self.service_name,
                        Security.kSecAttrAccount: self.account_name,
                        Security.kSecValueData: new_key,
                        Security.kSecAttrAccessible: Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    }
                    add_status, _ = Security.SecItemAdd(add_query, None)
                    if add_status == 0:
                        return HardenedMemoryKey(new_key)
                    if add_status != -25299:  # errSecDuplicateItem: resolve the winner
                        raise KeyProviderError(f"Keychain insert failed with status {add_status}")
                    status, data = Security.SecItemCopyMatching(query, None)
                    if status != 0 or not data:
                        raise KeyProviderError(f"Keychain duplicate could not be read: {status}")
                    return HardenedMemoryKey(bytes(data))
            except KeyProviderError:
                # Our own deliberate failures (lines above) must not be mistaken
                # for "tier unavailable" - swallowing them silently downgrades
                # custody. This clause is why they are no longer dead code.
                raise
            except Exception as exc:
                # The Keychain is present and reachable but failed unexpectedly
                # (locked, denied prompt, missing entitlement). Falling through
                # to a weaker tier would hide that from the operator.
                raise CustodyDowngradeError(
                    "macOS Keychain is present but unusable "
                    f"({type(exc).__name__}: {exc}); refusing to fall back to a "
                    "weaker custody tier"
                ) from exc
        return None

    def _resolve_machine_bound_file_key(self, *, allow_create: bool) -> HardenedMemoryKey:
        """Resolve an explicitly enabled 0600 local file key without GUI prompts."""
        if self.strict or not self.allow_disk_fallback:
            raise KeyProviderError(
                "Refusing headless fallback to plaintext disk key in strict mode. "
                "Set APPSTATE_KEY or FLOOR_VAULT_KEY environment variable."
            )

        self.fallback_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_file = self.fallback_dir / "master.key"

        if key_file.exists():
            file_stat = key_file.lstat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise KeyProviderError("Refusing non-regular key file")
            if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
                raise KeyProviderError("Refusing key file with unexpected owner")
            if has_posix_group_or_other_access(file_stat.st_mode):
                raise KeyProviderError("Refusing key file with insecure permissions")
            key_bytes = key_file.read_bytes()
            if len(key_bytes) == 32:
                return HardenedMemoryKey(key_bytes)
            if len(key_bytes) == 64:
                return HardenedMemoryKey(bytes.fromhex(key_bytes.decode("ascii").strip()))

        if not allow_create:
            raise KeyProviderError(f"Master key file not found: {key_file}")

        # Generate new 32-byte key and write with strict 0600 permissions
        new_key = os.urandom(32)
        fd = os.open(
            str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_mode_flag(), 0o600
        )
        try:
            os.write(fd, new_key)
        finally:
            os.close(fd)

        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

        return HardenedMemoryKey(new_key)

"""3-Tier Adaptive Key Provider.

Seamlessly scales from interactive desktop keyrings to headless cloud/Docker
environments without hanging, crashing, or requiring manual configuration:
  Tier 1: OS Keyring (macOS Keychain, Windows DPAPI, Linux Secret Service)
  Tier 2: Explicit Environment Variable (APPSTATE_KEY, HERMES_VAULT_KEY)
  Tier 3: Machine-Bound Local 0600 File Key (Headless Docker / Remote SSH)
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

from ..memory import HardenedMemoryKey
from .base import KeyProvider, KeyProviderError


class AdaptiveKeyProvider(KeyProvider):
    """Zero-configuration key provider with autonomous headless fallback."""

    def __init__(
        self,
        service_name: str = "appstate-crypto",
        account_name: str = "default-v1",
        *,
        fallback_dir: Optional[Path] = None,
    ) -> None:
        self.service_name = service_name
        self.account_name = account_name
        self.fallback_dir = fallback_dir or (Path.home() / ".appstate-crypto")

    def _is_interactive_desktop(self) -> bool:
        """Heuristic detecting whether a GUI keyring environment is present."""
        if sys.platform == "darwin":
            # On macOS, window server is active if not in a raw detached ssh without gui
            return os.environ.get("SSH_CONNECTION") is None or bool(os.environ.get("DISPLAY"))
        if sys.platform == "win32":
            return True
        # Linux: check for X11 / Wayland / DBus session
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DBUS_SESSION_BUS_ADDRESS"))

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        """Resolve the master key across the three autonomous tiers."""
        # --- Tier 1: Explicit Environment Variable (CI / Cloud / Kubernetes) ---
        for var_name in ("APPSTATE_KEY", "HERMES_VAULT_KEY", "VAULT_MASTER_KEY"):
            val = os.environ.get(var_name)
            if val:
                raw_bytes: bytes
                clean_val = val.strip()
                if len(clean_val) == 64:
                    raw_bytes = bytes.fromhex(clean_val)
                else:
                    raw_bytes = clean_val.encode("utf-8")
                    if len(raw_bytes) != 32:
                        raw_bytes = hashlib.sha256(raw_bytes).digest()
                return HardenedMemoryKey(raw_bytes)

        # --- Tier 2: System Keyring (Desktop Workstation) ---
        if self._is_interactive_desktop():
            try:
                key = self._resolve_from_system_keyring(allow_create=allow_create)
                if key is not None:
                    return key
            except Exception:
                # If desktop keyring is unavailable, locked, or prompts are denied, fall through
                pass

        # --- Tier 3: Zero-Config Machine-Bound Local File Key (Docker / SSH) ---
        return self._resolve_machine_bound_file_key(allow_create=allow_create)

    def _resolve_from_system_keyring(self, *, allow_create: bool) -> Optional[HardenedMemoryKey]:
        """Attempt to read from macOS Keychain or generic system keyring."""
        if sys.platform == "darwin":
            try:
                import Security  # type: ignore[import-not-found]
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
                    Security.SecItemAdd(add_query, None)
                    return HardenedMemoryKey(new_key)
            except Exception:
                return None
        return None

    def _resolve_machine_bound_file_key(self, *, allow_create: bool) -> HardenedMemoryKey:
        """Resolve a machine-bound 0600 local file key without GUI prompts."""
        self.fallback_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_file = self.fallback_dir / "master.key"

        if key_file.exists():
            key_bytes = key_file.read_bytes()
            if len(key_bytes) == 32:
                return HardenedMemoryKey(key_bytes)
            if len(key_bytes) == 64:
                return HardenedMemoryKey(bytes.fromhex(key_bytes.decode("ascii").strip()))

        if not allow_create:
            raise KeyProviderError(f"Master key file not found: {key_file}")

        # Generate new 32-byte key and write with strict 0600 permissions
        new_key = os.urandom(32)
        fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, new_key)
        finally:
            os.close(fd)

        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass

        return HardenedMemoryKey(new_key)

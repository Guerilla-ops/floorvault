"""3-Tier Adaptive Key Provider.

Scales from interactive desktop storage to headless cloud/Docker environments:
  Tier 1: Explicit Environment Variable (APPSTATE_KEY, FLOOR_VAULT_KEY)
  Tier 2: macOS Keychain when available
  Tier 3: Explicitly Opt-In Local 0600 File Key (Headless Docker / Remote SSH),
          optionally wrapped under a caller-held passphrase (``passphrase=``)
"""

from __future__ import annotations

import os
import stat
import warnings
from pathlib import Path
from typing import Optional, Union

from .._filelock import exclusive_lock
from ..memory import HardenedMemoryKey
from ..platform_support import (
    is_linux,
    is_macos,
    is_windows,
)
from . import passphrase_store
from .base import CustodyDowngradeError, KeyProvider, KeyProviderError
from .linux_keyring import LinuxSecretServiceKeyProvider
from .platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    _mkdir_owner_only,
    read_protected,
    write_protected,
)
from .windows_dpapi import WindowsDPAPIKeyProvider


class AdaptiveKeyProvider(KeyProvider):
    """Adaptive key provider with fail-closed protected-storage defaults."""

    def __init__(
        self,
        service_name: str = "hermes-vault",
        account_name: str = "default-v1",
        *,
        fallback_dir: Optional[Path | str] = None,
        strict: bool = False,
        allow_disk_fallback: bool = False,
        dpapi_entropy: Optional[bytes] = None,
        allow_legacy_env_vars: bool = False,
        allow_legacy_adoption: bool = False,
        passphrase: Optional[Union[str, bytes]] = None,
    ) -> None:
        self.service_name = service_name
        self.account_name = account_name
        if fallback_dir is not None:
            self.fallback_dir = Path(fallback_dir)
        else:
            hermes_home = os.environ.get("HERMES_HOME")
            if hermes_home:
                self.fallback_dir = Path(hermes_home) / "vault"
            else:
                self.fallback_dir = Path.home() / ".hermes" / "vault"
        self.strict = strict
        self.allow_disk_fallback = allow_disk_fallback and not strict
        # Optional secondary entropy for the Windows DPAPI tier. When omitted
        # the provider uses a public constant - still user-bound through DPAPI,
        # but without the extra secret an infostealer cannot guess.
        self.dpapi_entropy = dpapi_entropy
        # APPSTATE_KEY shares a process-wide namespace with other tools, so it
        # is read only when this is set; the namespaced variables always are.
        self.allow_legacy_env_vars = allow_legacy_env_vars
        # Opt-in for adopting a pre-split ``master.key`` store whose payload
        # parses under a custody scheme. Default False: a planted legacy file
        # is refused rather than silently adopted as the master key.
        self.allow_legacy_adoption = allow_legacy_adoption
        self.keychain_unavailable_reason: Optional[str] = None
        # Tier-3 only: wrap the local key file under this passphrase (FVPW1,
        # SPEC.md §10.8) so a copy of the file alone does not yield the key.
        # Validated now so an empty passphrase fails at construction, not at
        # the first resolve after a key was already generated.
        if passphrase is not None:
            passphrase_store._normalize_passphrase(passphrase)
        self._passphrase = passphrase

    def _is_interactive_desktop(self) -> bool:
        """Deprecated compatibility hook; capability probing is unconditional."""
        return True

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        """Resolve the master key across the three autonomous tiers."""
        # --- Tier 1: Explicit Environment Variable (CI / Cloud / Kubernetes) ---
        # strict=True is a pledge of OS-backed custody. A plaintext environment
        # variable is the weakest custody there is - readable through
        # /proc/<pid>/environ, `ps e`, and CI logs - so adopting one under
        # strict silently downgrades below the pledge.
        if self.strict:
            # Only names this provider would actually consider for custody: a
            # foreign APPSTATE_KEY (not opted into) is ignored, not a breach.
            strict_env = ["HERMES_VAULT_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"]
            if self.allow_legacy_env_vars:
                strict_env.append("APPSTATE_KEY")
            for var_name in strict_env:
                if os.environ.get(var_name):
                    raise CustodyDowngradeError(
                        f"strict=True refuses environment-variable key custody, "
                        f"but {var_name} is set. Unset it, construct the provider "
                        "without strict, or rely on OS-backed custody."
                    )
        else:
            # Namespaced variables first; the legacy shared-namespace name is
            # read only on explicit opt-in - a value another tool placed there
            # must not be adopted as the vault master key.
            env_names = ["HERMES_VAULT_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"]
            if self.allow_legacy_env_vars:
                env_names.append("APPSTATE_KEY")
            for var_name in env_names:
                val = os.environ.get(var_name)
                if val:
                    if var_name == "APPSTATE_KEY":
                        warnings.warn(
                            "APPSTATE_KEY is a legacy, non-namespaced variable name; "
                            "prefer FLOOR_VAULT_KEY or VAULT_MASTER_KEY so a value "
                            "set for another tool cannot be silently adopted as the "
                            "vault master key",
                            UserWarning,
                            stacklevel=2,
                        )
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
            # Warn about the ignored legacy name only once the namespaced
            # variables had their chance: under warnings-as-errors a stray
            # APPSTATE_KEY must not veto a valid FLOOR_VAULT_KEY.
            if not self.allow_legacy_env_vars and os.environ.get("APPSTATE_KEY"):
                warnings.warn(
                    "APPSTATE_KEY is set but ignored: it shares a namespace "
                    "with other tools, so FloorVault honours it only when the "
                    "provider is constructed with allow_legacy_env_vars=True. "
                    "Prefer FLOOR_VAULT_KEY or VAULT_MASTER_KEY.",
                    UserWarning,
                    stacklevel=2,
                )

        # --- Tier 2: Direct system-keyring capability probe ---
        # Do not infer keyring availability from SSH_CONNECTION, DISPLAY, or
        # other session environment variables. The provider itself is the
        # capability probe; an installed but unusable Keychain fails closed.
        key = self._resolve_from_system_keyring(allow_create=allow_create)
        if key is not None:
            return key

        # --- Tier 3: Zero-Config Machine-Bound Local File Key (Docker / SSH) ---
        return self._resolve_machine_bound_file_key(allow_create=allow_create)

    def _resolve_from_system_keyring(self, *, allow_create: bool) -> Optional[HardenedMemoryKey]:
        """Resolve from the native provider for the current platform."""
        if is_windows():
            return WindowsDPAPIKeyProvider(
                store_path=WindowsDPAPIKeyProvider.default_store_path(self.fallback_dir),
                entropy=self.dpapi_entropy,
                allow_legacy_adoption=self.allow_legacy_adoption,
            ).resolve_key(allow_create=allow_create)

        if is_linux():
            provider = LinuxSecretServiceKeyProvider(
                store_path=LinuxSecretServiceKeyProvider.default_store_path(self.fallback_dir),
                service=self.service_name,
                attribute=self.account_name,
                # The provider's masked-file tier is disk custody too, so it is
                # gated on the same opt-in as Tier 3: strict mode, or a caller
                # that never enabled disk fallback, must not read master.key.ss.
                # With a passphrase the caller asked for wrapped disk custody;
                # the masked master.key.ss is unwrapped and must not be used.
                allow_file_fallback=self.allow_disk_fallback and self._passphrase is None,
                allow_legacy_adoption=self.allow_legacy_adoption,
            )
            # A headless Linux session has no Secret Service capability. Preserve
            # AdaptiveKeyProvider's explicit local-file policy in that case.
            if provider._secret_service_available():
                return provider.resolve_key(allow_create=allow_create)
            return None

        if is_macos():
            try:
                import Security  # type: ignore[import-not-found]
            except ImportError:
                # pyobjc-framework-Security not installed: Tier 2 cannot run.
                # Install the "macos" extra to enable Keychain custody.
                self.keychain_unavailable_reason = (
                    "pyobjc-framework-Security is not installed; "
                    "install hermes_vault[macos] to enable the macOS Keychain tier"
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
                if status == -25300:  # errSecItemNotFound, creation disallowed
                    return None
                raise CustodyDowngradeError(
                    "macOS Keychain returned an unusable status "
                    f"({status}); refusing to fall back to a weaker custody tier"
                )
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

    def _disk_fallback_refusal(self) -> str:
        """Explain precisely why Tier 3 is refusing, and what would enable it.

        The message names the *actual* gate. A previous version blamed "strict
        mode" even when ``strict`` was False and the real cause was
        ``allow_disk_fallback`` not being enabled, which sent an operator
        looking for a flag that was not the problem.
        """
        cause = (
            "strict=True forbids it"
            if self.strict
            else "allow_disk_fallback was not explicitly enabled"
        )
        missing_tier = (
            f" The OS-native tier reported: {self.keychain_unavailable_reason}"
            if self.keychain_unavailable_reason
            else ""
        )
        return (
            f"Refusing headless fallback to plaintext disk key ({cause}).{missing_tier} "
            "Provide the key explicitly (FLOOR_VAULT_KEY or VAULT_MASTER_KEY as 64 "
            "hexadecimal characters; APPSTATE_KEY requires allow_legacy_env_vars=True "
            "and neither is honoured while strict=True), install the OS-native "
            "custody extra for this platform, or opt in to a 0600 local key file with "
            "AdaptiveKeyProvider(allow_disk_fallback=True)."
        )

    def _resolve_machine_bound_file_key(self, *, allow_create: bool) -> HardenedMemoryKey:
        """Resolve an explicitly enabled 0600 local file key without GUI prompts.

        WARNING: ``~/.hermes/vault/master.key`` is Tier 3 custody only. It does
        not establish a hardware-backed or OS confidentiality boundary; anyone
        able to copy the file can recover the master key.

        The file is read and written through the shared protected-store helpers
        rather than a second implementation of the same job: a temporary file
        beside the target published with ``os.link`` (no-clobber, no partially
        written store ever visible at the live path), a full-write loop, an
        ``fsync``, and a read through a descriptor opened ``O_NOFOLLOW`` that
        re-checks regular-file-ness, ownership and permissions on the descriptor
        it actually holds.
        """
        if self.strict or not self.allow_disk_fallback:
            raise KeyProviderError(self._disk_fallback_refusal())

        key_file = self.fallback_dir / "master.key"
        wrapped_file = self.fallback_dir / WRAPPED_KEY_FILENAME
        if self._passphrase is not None:
            return self._resolve_passphrase_file_key(key_file, wrapped_file, allow_create)
        # Fail closed: once the key is passphrase-wrapped, resolving without the
        # passphrase must never fall through to creating a fresh raw key beside
        # it - that would silently fork the master key.
        if self._read_wrapped_key_file(wrapped_file) is not None:
            raise KeyProviderError(
                f"{wrapped_file} is passphrase-protected; construct the provider "
                "with passphrase= to unlock it"
            )

        warnings.warn(
            "FloorVault is using Tier-3 file-based key custody "
            "(~/.hermes/vault/master.key); this is not a hardware or OS "
            "confidentiality boundary.",
            UserWarning,
            stacklevel=2,
        )

        stored = self._read_raw_key_file(key_file)
        if stored is not None:
            if len(stored) == 32:
                return HardenedMemoryKey(stored)
            if len(stored) == 64:
                try:
                    return HardenedMemoryKey(bytes.fromhex(stored.decode("ascii").strip()))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise KeyProviderError("Refusing malformed hexadecimal key file") from exc
            raise KeyProviderError(
                f"Refusing key file with unexpected length ({len(stored)} bytes)"
            )

        if not allow_create:
            raise KeyProviderError(f"Master key file not found: {key_file}")

        # Generate new 32-byte key and publish it with the hardened writer.
        new_key = os.urandom(32)
        with self._tier3_creation_lock():
            # Re-check the *other* store under the lock: a concurrent resolver
            # with a passphrase may have just created the wrapped one, and
            # no-clobber cannot catch that because the file names differ.
            if self._read_wrapped_key_file(wrapped_file) is not None:
                raise KeyProviderError(
                    f"{wrapped_file} is passphrase-protected; construct the provider "
                    "with passphrase= to unlock it"
                )
            try:
                write_protected(new_key, key_file, header=b"", expected_length=32)
            except ProtectedStoreError as exc:
                # The writer creates and never replaces, so an existing store is a
                # hard error rather than a silent rotation of the master key.
                raise KeyProviderError(f"Refusing to overwrite the key file: {exc}") from exc

        return HardenedMemoryKey(new_key)

    def _tier3_creation_lock(self):
        """Serialize Tier-3 store creation across processes and both file names."""
        _mkdir_owner_only(self.fallback_dir)
        return exclusive_lock(self.fallback_dir / TIER3_LOCK_FILENAME)

    def _resolve_passphrase_file_key(
        self, key_file: Path, wrapped_file: Path, allow_create: bool
    ) -> HardenedMemoryKey:
        """Resolve the passphrase-wrapped Tier-3 key (``FVPW1``).

        A raw ``master.key`` beside the wrapped store is refused, not ignored:
        while it exists a copy of the directory still yields the key without
        the passphrase, which is exactly what wrapping exists to prevent. A raw
        store with no wrapped one is refused too - converting it is an explicit
        step (:func:`protect_key_file`), never a side effect of resolving.
        """
        passphrase = self._passphrase
        if passphrase is None:  # pragma: no cover - guarded by the caller
            raise KeyProviderError("passphrase custody requested without a passphrase")
        payload = self._read_wrapped_key_file(wrapped_file)
        raw_present = self._read_raw_key_file(key_file) is not None
        if raw_present:
            raise KeyProviderError(
                f"an unwrapped key file exists at {key_file}; convert it with "
                "floorvault.providers.adaptive.protect_key_file() (which removes "
                "the raw copy) before using passphrase custody"
            )
        if payload is not None:
            try:
                key = passphrase_store.unwrap(payload, passphrase)
            except passphrase_store.PassphraseStoreError as exc:
                raise KeyProviderError(str(exc)) from exc
            try:
                return HardenedMemoryKey(bytes(key))
            finally:
                key[:] = bytes(len(key))
        if not allow_create:
            raise KeyProviderError(f"Master key file not found: {wrapped_file}")
        new_key = bytearray(os.urandom(32))
        try:
            payload = passphrase_store.wrap(new_key, passphrase)
            with self._tier3_creation_lock():
                if self._read_raw_key_file(key_file) is not None:
                    raise KeyProviderError(
                        f"an unwrapped key file exists at {key_file}; convert it with "
                        "floorvault.providers.adaptive.protect_key_file() (which removes "
                        "the raw copy) before using passphrase custody"
                    )
                try:
                    write_protected(
                        payload,
                        wrapped_file,
                        header=passphrase_store.MAGIC,
                        expected_length=passphrase_store.PAYLOAD_BYTES,
                    )
                except ProtectedStoreError as exc:
                    raise KeyProviderError(f"Refusing to overwrite the key file: {exc}") from exc
            return HardenedMemoryKey(bytes(new_key))
        finally:
            new_key[:] = bytes(len(new_key))

    def _read_wrapped_key_file(self, wrapped_file: Path) -> Optional[bytes]:
        """Return the ``FVPW1`` payload, or ``None`` when the store is absent."""
        try:
            return read_protected(
                wrapped_file,
                header=passphrase_store.MAGIC,
                expected_length=passphrase_store.PAYLOAD_BYTES,
            )
        except ProtectedStoreMissing:
            return None
        except ProtectedStoreError as exc:
            raise KeyProviderError(f"Refusing key file: {exc}") from exc

    def _read_raw_key_file(self, key_file: Path) -> Optional[bytes]:
        """Return the raw key file's bytes, or ``None`` when it does not exist.

        ``None`` means *absent*, which is the only condition under which the
        caller may create a key. Anything else - a symlink, a non-regular file,
        another owner, group/other access, or an unverifiable ACL - raises, so an
        unreadable store is never mistaken for a missing one and replaced.
        """
        try:
            return read_protected(key_file, header=b"", expected_length=None)
        except ProtectedStoreMissing:
            return None
        except ProtectedStoreError as exc:
            raise KeyProviderError(f"Refusing key file: {exc}") from exc


#: File name of the passphrase-wrapped Tier-3 store, beside ``master.key``.
WRAPPED_KEY_FILENAME = "master.key.fvpw"

#: Lock file serializing Tier-3 creation and conversion across both store names.
TIER3_LOCK_FILENAME = "master.key.lock"


def protect_key_file(
    passphrase: Union[str, bytes],
    *,
    fallback_dir: Optional[Path | str] = None,
) -> Path:
    """Wrap an existing raw Tier-3 ``master.key`` under ``passphrase``.

    Writes ``master.key.fvpw`` (no-clobber), proves it unwraps to the same key,
    then overwrites the raw file with zeros, flushes it, and unlinks it. The
    master key is unchanged, so existing ciphertext stays readable.

    The overwrite is best effort: on copy-on-write or journaling filesystems,
    SSDs, snapshots and backups, earlier copies of the raw key can survive (the
    same residue limit as ``drop_plaintext_column``). Treat a key that has ever
    sat unwrapped on a backed-up disk as exposed, and rotate it if that matters.

    Returns the path of the wrapped store.
    """
    provider = AdaptiveKeyProvider(fallback_dir=fallback_dir, allow_disk_fallback=True)
    if not provider.fallback_dir.exists():
        raise KeyProviderError(
            f"no raw key file to protect at {provider.fallback_dir / 'master.key'}"
        )
    with provider._tier3_creation_lock():
        key_file = provider.fallback_dir / "master.key"
        wrapped_file = provider.fallback_dir / WRAPPED_KEY_FILENAME
        stored = provider._read_raw_key_file(key_file)
        if stored is None:
            raise KeyProviderError(f"no raw key file to protect at {key_file}")
        if len(stored) == 64:
            try:
                stored = bytes.fromhex(stored.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                raise KeyProviderError("Refusing malformed hexadecimal key file") from exc
        if len(stored) != 32:
            raise KeyProviderError(
                f"Refusing key file with unexpected length ({len(stored)} bytes)"
            )
        if provider._read_wrapped_key_file(wrapped_file) is not None:
            raise KeyProviderError(
                f"Refusing to overwrite the key file: {wrapped_file} already exists"
            )
        # Open the raw file for the final overwrite *before* publishing anything:
        # an owner-read-only (0400) key must fail here, with the directory
        # unchanged, rather than after the wrapped copy exists - which no-clobber
        # publication would then block a retry from replacing.
        try:
            descriptor = os.open(
                key_file, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            )
        except PermissionError as exc:
            raise KeyProviderError(
                f"{key_file} is not writable by its owner, so it could not be erased after "
                "wrapping; make it owner-writable (chmod 600) and retry - nothing was changed"
            ) from exc
        with os.fdopen(descriptor, "r+b", buffering=0) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise KeyProviderError(f"Refusing key file: {key_file} is not a regular file")
            master = bytearray(stored)
            try:
                payload = passphrase_store.wrap(master, passphrase)
                try:
                    write_protected(
                        payload,
                        wrapped_file,
                        header=passphrase_store.MAGIC,
                        expected_length=passphrase_store.PAYLOAD_BYTES,
                    )
                except ProtectedStoreError as exc:
                    raise KeyProviderError(f"Refusing to overwrite the key file: {exc}") from exc
                check = passphrase_store.unwrap(
                    provider._read_wrapped_key_file(wrapped_file) or b"", passphrase
                )
                try:
                    if bytes(check) != bytes(master):
                        raise KeyProviderError(
                            "wrapped key file does not round-trip; raw key left in place"
                        )
                finally:
                    check[:] = bytes(len(check))
            finally:
                master[:] = bytes(len(master))
            handle.write(bytes(info.st_size))
            os.fsync(handle.fileno())
        key_file.unlink()
        return wrapped_file

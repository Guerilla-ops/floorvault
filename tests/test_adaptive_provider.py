"""Tests for the 3-Tier Adaptive Key Provider."""

import os
import sys
from pathlib import Path

import pytest

from floorvault import platform_support
from floorvault.memory import HardenedMemoryKey
from floorvault.providers import adaptive as adaptive_module
from floorvault.providers import platform_custody as custody_module
from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.base import CustodyDowngradeError, KeyProviderError
from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider
from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider


def _force_machine_file_tier(monkeypatch):
    """Keep Tier 3 tests independent of a real host Keychain."""
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)


def test_adaptive_provider_env_variable(monkeypatch, tmp_path):
    hex_key = "0123456789abcdef" * 4  # gitleaks:allow
    monkeypatch.setenv("APPSTATE_KEY", hex_key)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    key = provider.resolve_key()

    assert key.get_bytes() == bytes.fromhex(hex_key)
    key.wipe()


def test_adaptive_provider_dispatches_windows_native_custody(monkeypatch, tmp_path):
    class FakeWindowsProvider:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        # The real store-path helper: the dispatch contract includes asking the
        # provider where its store lives, so the fake delegates rather than
        # inventing a path.
        default_store_path = staticmethod(WindowsDPAPIKeyProvider.default_store_path)

        def resolve_key(self, *, allow_create=True):
            assert allow_create is True
            return HardenedMemoryKey(b"W" * 32, mode="disabled")

    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: True, raising=False)
    monkeypatch.setattr(
        adaptive_module, "WindowsDPAPIKeyProvider", FakeWindowsProvider, raising=False
    )

    key = AdaptiveKeyProvider(fallback_dir=tmp_path).resolve_key()

    assert key.get_bytes() == b"W" * 32
    # The DPAPI store must not be the tier-3 raw key file.
    assert not (tmp_path / "master.key").exists()


def test_adaptive_provider_dispatches_linux_secret_service(monkeypatch, tmp_path):
    class FakeLinuxProvider:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        # Delegates to the real helper; see the Windows dispatch test.
        default_store_path = staticmethod(LinuxSecretServiceKeyProvider.default_store_path)

        def _secret_service_available(self):
            return True

        def resolve_key(self, *, allow_create=True):
            assert allow_create is True
            return HardenedMemoryKey(b"L" * 32, mode="disabled")

    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False, raising=False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True, raising=False)
    monkeypatch.setattr(
        adaptive_module, "LinuxSecretServiceKeyProvider", FakeLinuxProvider, raising=False
    )

    key = AdaptiveKeyProvider(fallback_dir=tmp_path).resolve_key()

    assert key.get_bytes() == b"L" * 32
    assert not (tmp_path / "master.key").exists()


def test_adaptive_provider_rejects_implicit_weak_environment_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSTATE_KEY", "password")
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    with pytest.raises(KeyProviderError, match="64 hexadecimal characters"):
        provider.resolve_key()


def test_adaptive_provider_records_missing_keychain_backend(monkeypatch, tmp_path):
    """Tier 2 must report why it is unavailable, not fail silently.

    Regression: import Security raised ModuleNotFoundError inside a broad
    except, so a stock install silently fell through to Tier 3 with no signal.
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    if sys.platform != "darwin":
        pytest.skip("macOS Keychain tier is darwin-only")
    try:
        import Security  # type: ignore[import-not-found]  # noqa: F401

        pytest.skip("pyobjc-framework-Security installed; unavailable path not reachable")
    except ImportError:
        pass

    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: True)
    with pytest.raises(KeyProviderError):
        provider.resolve_key()
    assert provider.keychain_unavailable_reason is not None
    assert "floorvault[macos]" in provider.keychain_unavailable_reason


def test_adaptive_provider_machine_file_fallback(monkeypatch, tmp_path):
    # Ensure env vars are unset
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)

    # Force Tier 3; the real macOS Keychain is intentionally capability-probed.
    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    key1 = provider.resolve_key(allow_create=True)
    assert len(key1.get_bytes()) == 32
    assert (tmp_path / "master.key").exists()

    # Second resolve reuses the same file key
    key2 = provider.resolve_key(allow_create=False)
    assert key1.get_bytes() == key2.get_bytes()

    key1.wipe()
    key2.wipe()


def test_adaptive_provider_fails_closed_by_default(monkeypatch, tmp_path):
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="disk key"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_adaptive_provider_strict_mode_refuses_disk_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)

    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="Refusing headless fallback to plaintext disk key"):
        provider.resolve_key()


def test_adaptive_provider_rejects_insecure_existing_key_file(monkeypatch, tmp_path):
    """The POSIX group/other gate must refuse, driven on every platform.

    This test used to be skipped on Windows ("POSIX permission bits are not
    implemented there"), which was true of the platform but wrong for the test:
    with nothing exercising the check on the Windows runner, the mutant that
    disables it (AD-1, `if has_posix_group_or_other_access(...)` -> `if False`)
    survived there and failed the mutation step of the gate. Patching the
    predicate exercises the real code path everywhere instead of skipping it.
    """
    # On Windows the helper short-circuits; force the POSIX branch this test is
    # about. The synthesised 0o644/0o666 mode Windows reports still has a
    # group/other bit set, so the gate must fire.
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)
    key_file = provider.fallback_dir / "master.key"
    key_file.write_bytes(b"x" * 32)
    key_file.chmod(0o644)

    with pytest.raises(KeyProviderError, match="permissions"):
        provider.resolve_key(allow_create=False)


def test_machine_file_fallback_survives_a_synthesised_mode(monkeypatch, tmp_path):
    """Regression for the Windows CI failure.

    The provider writes master.key with 0600; on Windows that same file then
    reports 0o666, and the second resolve refused the provider's own key file
    with "Refusing key file with insecure permissions".

    The synthesised mode is still not a reason to refuse - the decision on
    Windows now rests on the ACL, which this test supplies as owner-only. A
    world-accessible ACL is refused (see test_windows_store_with_a_world_... in
    test_protected_store_safety.py).
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    _force_machine_file_tier(monkeypatch)
    # Simulate the platform the gate must treat as Windows, including the ACL
    # the real query would return; patching only the platform flag would leave
    # the verification unrunnable, which is a different code path.
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(
        platform_support,
        "windows_dacl_sids",
        lambda path: (
            frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001"}),
            "S-1-5-21-1-2-3-1001",
        ),
    )

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    key1 = provider.resolve_key(allow_create=True)
    assert len(key1.get_bytes()) == 32

    # Whatever the ACL, this is the mode Windows reports for that file.
    (tmp_path / "master.key").chmod(0o666)

    key2 = provider.resolve_key(allow_create=False)
    assert key1.get_bytes() == key2.get_bytes()

    key1.wipe()
    key2.wipe()


# --------------------------------------------------------------------------
# F-5: a present-but-unusable keychain must fail closed, not downgrade custody
# --------------------------------------------------------------------------


def _fake_security(monkeypatch, *, copy_result=None, copy_raises=None, add_result=(0, None)):
    """Install a fake ``Security`` module so the Keychain tier is drivable here.

    The macOS Keychain cannot be exercised in CI or on a non-macOS host, so the
    module is injected into ``sys.modules`` and its two entry points scripted.

    ``IS_MACOS`` is patched too: the Keychain tier is macOS-gated, so on the
    Linux and Windows CI cells it would otherwise be skipped entirely and these
    tests would assert nothing (they were written on macOS, where the gate is
    already open). Patching the predicate keeps the F-5 fail-closed behaviour
    covered on every runner.
    """
    import types

    monkeypatch.setattr(platform_support, "IS_MACOS", True)
    # ``adaptive`` imports the predicate functions directly, so make the
    # simulated platform visible at that module boundary as well. Without
    # this, Linux CI correctly enters the Secret Service branch and these
    # macOS-specific tests never exercise the injected Security module.
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: True)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    module = types.ModuleType("Security")
    for name in (
        "kSecClass",
        "kSecClassGenericPassword",
        "kSecAttrService",
        "kSecAttrAccount",
        "kSecReturnData",
        "kSecMatchLimit",
        "kSecMatchLimitOne",
        "kSecValueData",
        "kSecAttrAccessible",
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    ):
        setattr(module, name, name)

    def SecItemCopyMatching(_query, _flags):
        if copy_raises is not None:
            raise copy_raises
        return copy_result

    def SecItemAdd(_query, _flags):
        return add_result

    module.SecItemCopyMatching = SecItemCopyMatching  # type: ignore[attr-defined]
    module.SecItemAdd = SecItemAdd  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "Security", module)
    return module


def _interactive_provider(monkeypatch, tmp_path, **kwargs):
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, **kwargs)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: True)
    return provider


def test_adaptive_machine_key_file_is_written_in_binary_mode(tmp_path, monkeypatch):
    """The machine-bound key file gets the same Windows binary-mode treatment.

    See the custody-layer test: without O_BINARY, Windows text mode would expand
    newlines in the 32 random key bytes and truncate reads at 0x1A. A sentinel is
    used rather than a real O_* bit, which differs across platforms.
    """
    sentinel = 0x40000000
    _force_machine_file_tier(monkeypatch)
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    seen: list[int] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        seen.append(flags)
        # Restore the platform's real binary flag; see the custody test.
        return real_open(path, (flags & ~sentinel) | getattr(os, "O_BINARY", 0), *args, **kwargs)

    # The tier-3 file is written by the shared protected-store writer, so the
    # binary-mode flag comes from that module's binding, not this one's.
    monkeypatch.setattr(adaptive_module.os, "open", recording_open)
    monkeypatch.setattr(custody_module, "binary_mode_flag", lambda: sentinel)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    key = provider.resolve_key(allow_create=True)
    assert key is not None

    assert seen, "the machine-bound key file was not written"
    for flags in seen:
        assert flags & sentinel, f"key file opened without the binary-mode flag: {flags:#x}"


# --------------------------------------------------------------------------
# Tier 3 gets the same write/read hardening as the platform custody stores
# --------------------------------------------------------------------------


def _tier3_provider(monkeypatch, tmp_path):
    """An explicitly opted-in provider forced onto its local-file tier."""
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)
    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)
    return provider


def test_machine_key_file_short_write_is_retried(monkeypatch, tmp_path):
    """A short ``os.write`` must not leave a truncated key file behind.

    Regression: tier 3 issued one bare ``os.write`` where the DPAPI/Secret
    Service stores already used a full-write loop. A short write left a 16-byte
    ``master.key`` that nothing reported at write time, and because the file
    then existed no replacement was ever minted - a later resolve refused it
    ("unexpected length") and the user's data was stranded behind it.
    """
    provider = _tier3_provider(monkeypatch, tmp_path)
    real_write = os.write
    lengths: list[int] = []

    def short_first(fd, data):
        lengths.append(len(data))
        if len(lengths) == 1:
            return real_write(fd, bytes(data)[:16])
        return real_write(fd, data)

    with monkeypatch.context() as patch:
        patch.setattr(os, "write", short_first)
        key = provider.resolve_key(allow_create=True)

    key_file = tmp_path / "master.key"
    assert key_file.stat().st_size == 32, "the short write was not retried"
    assert key_file.read_bytes() == key.get_bytes()
    assert len(lengths) == 2, "the writer must continue from where the short write stopped"
    assert provider.resolve_key(allow_create=False).get_bytes() == key.get_bytes()


def test_machine_key_file_write_is_never_partially_visible(monkeypatch, tmp_path):
    """The key file must be published atomically, not written in place.

    Nothing may observe a partially written store at the live path: the writer
    fills a temporary file beside the target and links it into place.
    """
    provider = _tier3_provider(monkeypatch, tmp_path)
    key_file = tmp_path / "master.key"
    real_link = os.link
    observed: list[bytes] = []

    def observing_link(src, dst, *args, **kwargs):
        observed.append(Path(src).read_bytes())
        assert not key_file.exists(), "the live path was occupied before the publish step"
        return real_link(src, dst, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "link", observing_link)
        key = provider.resolve_key(allow_create=True)

    assert observed == [key.get_bytes()], "the publish source was not the complete key"
    assert len(key.get_bytes()) == 32


def test_machine_key_file_read_refuses_a_symlink(monkeypatch, tmp_path):
    """Property guard: a symlink at the key path is refused, never followed.

    The ``lstat`` check already refused a symlink that is in place before the
    read; the read now goes through a descriptor opened ``O_NOFOLLOW`` so the
    swap-in window between the check and the open is closed as well. This pins
    the outcome so a later refactor cannot reintroduce a path-following read.
    """
    provider = _tier3_provider(monkeypatch, tmp_path)
    provider.resolve_key(allow_create=True)
    key_file = tmp_path / "master.key"
    attacker = tmp_path / "attacker.key"
    attacker.write_bytes(b"A" * 32)
    attacker.chmod(0o600)
    key_file.unlink()
    key_file.symlink_to(attacker)

    with pytest.raises(KeyProviderError):
        provider.resolve_key(allow_create=False)


def test_machine_key_file_write_refuses_to_replace_an_existing_store(monkeypatch, tmp_path):
    """Creating a key must never clobber one that is already there."""
    provider = _tier3_provider(monkeypatch, tmp_path)
    first = provider.resolve_key(allow_create=True)
    key_file = tmp_path / "master.key"
    existing = key_file.read_bytes()

    (key_file).chmod(0o600)
    again = provider.resolve_key(allow_create=True)

    assert again.get_bytes() == first.get_bytes()
    assert key_file.read_bytes() == existing


def test_disk_fallback_refusal_names_the_real_gate_and_the_remedy(monkeypatch, tmp_path):
    """The refusal must name the gate that actually fired.

    Regression: the message said "in strict mode" even when ``strict`` was
    False and the real cause was ``allow_disk_fallback`` not being enabled -
    pointing an operator at a switch that was never the problem - and it omitted
    the remedies the code already knew about. This message is the first thing a
    user on a stock install sees, because the README quickstart reaches it.
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)
    _force_machine_file_tier(monkeypatch)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError) as excinfo:
        provider.resolve_key()

    message = str(excinfo.value)
    assert "allow_disk_fallback" in message, message
    assert "strict mode" not in message, message
    assert "APPSTATE_KEY" in message, message


def test_disk_fallback_refusal_repeats_the_native_tier_reason(monkeypatch, tmp_path):
    """When the OS-native tier explained why it was unavailable, say so.

    On macOS without ``floorvault[macos]`` the provider records the fix
    ("install floorvault[macos]") and previously never surfaced it.
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: True)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setitem(sys.modules, "Security", None)  # `import Security` -> ImportError

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    with pytest.raises(KeyProviderError) as excinfo:
        provider.resolve_key()

    assert "floorvault[macos]" in str(excinfo.value)
    assert "allow_disk_fallback" in str(excinfo.value)


def test_keychain_error_fails_closed_instead_of_downgrading(monkeypatch, tmp_path):
    """A keychain that is present but broken must not silently fall back.

    Regression: ``except Exception: return None`` reported a Keychain
    malfunction as "tier unavailable", so custody silently dropped from the
    Keychain to a plaintext key file on disk.
    """
    _fake_security(monkeypatch, copy_raises=RuntimeError("keychain locked"))
    provider = _interactive_provider(monkeypatch, tmp_path, allow_disk_fallback=True)

    with pytest.raises(CustodyDowngradeError, match="unusable"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists(), "weaker custody tier was used anyway"


def test_keychain_deliberate_failure_is_not_swallowed(monkeypatch, tmp_path):
    """The explicit KeyProviderError must surface rather than become a silent None.

    Before the fix these raises were unreachable: the terminal
    ``except Exception`` caught them and returned None.
    """
    # Item not found -> creation path; insertion then fails unexpectedly.
    _fake_security(monkeypatch, copy_result=(-25300, None), add_result=(-25291, None))
    provider = _interactive_provider(monkeypatch, tmp_path, allow_disk_fallback=True)

    with pytest.raises(KeyProviderError, match="Keychain insert failed"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_keychain_non_not_found_status_fails_closed(monkeypatch, tmp_path):
    """A present Keychain error status must not downgrade to disk custody."""
    _fake_security(monkeypatch, copy_result=(-25308, None))  # errSecInteractionNotAllowed
    provider = _interactive_provider(monkeypatch, tmp_path, allow_disk_fallback=True)

    with pytest.raises(CustodyDowngradeError, match="unusable"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_absent_keychain_still_falls_through_and_is_fail_closed(monkeypatch, tmp_path):
    """A genuinely absent tier is not a downgrade: fall-through must be preserved."""
    _force_machine_file_tier(monkeypatch)
    monkeypatch.setitem(sys.modules, "Security", None)  # `import Security` -> ImportError
    provider = _interactive_provider(monkeypatch, tmp_path)

    # Tier 3 then refuses, because disk fallback was not explicitly allowed.
    with pytest.raises(KeyProviderError, match="Refusing headless fallback"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_working_keychain_still_returns_the_key(monkeypatch, tmp_path):
    """Guard against over-correcting: the success path must be untouched."""
    _fake_security(monkeypatch, copy_result=(0, b"\x11" * 32))
    provider = _interactive_provider(monkeypatch, tmp_path)

    assert provider.resolve_key().get_bytes() == b"\x11" * 32


def test_adaptive_provider_accepts_string_fallback_dir(tmp_path):
    """AdaptiveKeyProvider must accept string paths for fallback_dir without TypeError."""
    provider = AdaptiveKeyProvider(
        fallback_dir=str(tmp_path),
        allow_disk_fallback=True,
    )
    assert isinstance(provider.fallback_dir, Path)
    assert provider.fallback_dir == tmp_path


# --------------------------------------------------------------------------
# The Linux provider's masked-file tier obeys the caller's disk policy
# --------------------------------------------------------------------------


def _seed_ss_store(monkeypatch, tmp_path: Path, key: bytes) -> Path:
    """Write a valid master.key.ss through the provider's own fallback writer."""
    ss_path = LinuxSecretServiceKeyProvider.default_store_path(tmp_path)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
        monkeypatch.delenv(name, raising=False)
    seed = LinuxSecretServiceKeyProvider(
        store_path=ss_path,
        service="floorvault",
        attribute="default-v1",
        random_bytes=lambda n: key[:n],
    )
    created = seed.resolve_key()
    created.wipe()
    assert ss_path.exists()
    return ss_path


def _linux_dispatch_with_unavailable_service(monkeypatch):
    """Make the adaptive provider dispatch to a real Linux provider whose
    Secret Service resolves nothing, so resolve_key reaches the file tier."""
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    monkeypatch.setattr(
        LinuxSecretServiceKeyProvider, "_secret_service_available", lambda self: True
    )
    monkeypatch.setattr(
        LinuxSecretServiceKeyProvider,
        "_resolve_via_secret_service",
        lambda self, *, allow_create=True: None,
    )


def test_strict_mode_refuses_an_existing_secret_service_file_store(monkeypatch, tmp_path):
    """strict=True must forbid reading master.key.ss, not only master.key.

    Regression: the Linux provider's internal masked-file fallback never saw
    the caller's disk policy, so an existing .ss store was read even under
    strict=True - silently resolving the key from disk custody the caller had
    explicitly forbidden.
    """
    _seed_ss_store(monkeypatch, tmp_path, b"\x77" * 32)
    _linux_dispatch_with_unavailable_service(monkeypatch)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True)
    with pytest.raises(KeyProviderError, match="file-based key custody"):
        provider.resolve_key()


def test_default_policy_refuses_an_existing_secret_service_file_store(monkeypatch, tmp_path):
    """The default (no allow_disk_fallback) must not read the .ss file either."""
    _seed_ss_store(monkeypatch, tmp_path, b"\x77" * 32)
    _linux_dispatch_with_unavailable_service(monkeypatch)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    with pytest.raises(KeyProviderError, match="file-based key custody"):
        provider.resolve_key()


def test_disk_fallback_opt_in_reads_the_secret_service_file_store(monkeypatch, tmp_path):
    """The explicit opt-in still works: allow_disk_fallback=True reads .ss."""
    stored = b"\x77" * 32
    _seed_ss_store(monkeypatch, tmp_path, stored)
    _linux_dispatch_with_unavailable_service(monkeypatch)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    key = provider.resolve_key(allow_create=False)
    assert key.get_bytes() == stored
    key.wipe()

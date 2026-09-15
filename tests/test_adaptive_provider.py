"""Tests for the 3-Tier Adaptive Key Provider."""

import os
import sys

import pytest

from floorvault import platform_support
from floorvault.providers import adaptive as adaptive_module
from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.base import CustodyDowngradeError, KeyProviderError


def test_adaptive_provider_env_variable(monkeypatch, tmp_path):
    hex_key = "0123456789abcdef" * 4  # gitleaks:allow
    monkeypatch.setenv("APPSTATE_KEY", hex_key)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    key = provider.resolve_key()

    assert key.get_bytes() == bytes.fromhex(hex_key)
    key.wipe()


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

    # Mock non-desktop to force Tier 3 fallback
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

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="disk key"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_adaptive_provider_strict_mode_refuses_disk_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="Refusing headless fallback to plaintext disk key"):
        provider.resolve_key()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits are not implemented on Windows; the key file's "
    "protection there comes from the profile-directory ACL",
)
def test_adaptive_provider_rejects_insecure_existing_key_file(monkeypatch, tmp_path):
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

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

    The permission helper itself is unit-tested in test_protected_store_safety.py.
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    # Simulate the platform the gate must treat as Windows.
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)

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
    monkeypatch.setattr(adaptive_module, "binary_mode_flag", lambda: sentinel)
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    seen: list[int] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        seen.append(flags)
        # Strip the simulated bit before the real syscall; see the custody test.
        return real_open(path, flags & ~sentinel, *args, **kwargs)

    monkeypatch.setattr(adaptive_module.os, "open", recording_open)
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    key = provider.resolve_key(allow_create=True)
    assert key is not None

    assert seen, "the machine-bound key file was not written"
    for flags in seen:
        assert flags & sentinel, f"key file opened without the binary-mode flag: {flags:#x}"


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


def test_absent_keychain_still_falls_through_and_is_fail_closed(monkeypatch, tmp_path):
    """A genuinely absent tier is not a downgrade: fall-through must be preserved."""
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

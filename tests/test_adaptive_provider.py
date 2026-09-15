"""Tests for the 3-Tier Adaptive Key Provider."""

import sys

import pytest

from floorvault.providers import adaptive as adaptive_module
from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.base import KeyProviderError


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


def test_posix_mode_check_detects_group_or_other_access():
    """On POSIX the 0600 gate is meaningful and must stay strict."""
    assert adaptive_module.has_posix_group_or_other_access(0o644) is True
    assert adaptive_module.has_posix_group_or_other_access(0o640) is True
    assert adaptive_module.has_posix_group_or_other_access(0o606) is True
    assert adaptive_module.has_posix_group_or_other_access(0o600) is False
    assert adaptive_module.has_posix_group_or_other_access(0o400) is False


def test_synthesised_windows_mode_is_not_treated_as_insecure(monkeypatch):
    """Windows does not implement POSIX mode bits.

    ``os.stat()`` reports a synthesised mode (typically 0o666 for a writable
    file) regardless of the ACL, so applying the POSIX test there rejects every
    key file - including one the provider itself just wrote with 0600.
    """
    monkeypatch.setattr(adaptive_module, "IS_WINDOWS", True)
    assert adaptive_module.has_posix_group_or_other_access(0o666) is False
    assert adaptive_module.has_posix_group_or_other_access(0o644) is False


def test_machine_file_fallback_survives_a_synthesised_mode(monkeypatch, tmp_path):
    """Regression for the Windows CI failure.

    The provider writes master.key with 0600; on Windows that same file then
    reports 0o666, and the second resolve refused the provider's own key file
    with "Refusing key file with insecure permissions".
    """
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    # Simulate the platform the gate must treat as Windows.
    monkeypatch.setattr(adaptive_module, "IS_WINDOWS", True)

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

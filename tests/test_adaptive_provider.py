"""Tests for the 3-Tier Adaptive Key Provider."""

import pytest

from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.base import KeyProviderError


def test_adaptive_provider_env_variable(monkeypatch, tmp_path):
    hex_key = "0123456789abcdef" * 4  # gitleaks:allow
    monkeypatch.setenv("APPSTATE_KEY", hex_key)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    key = provider.resolve_key()

    assert key.get_bytes() == bytes.fromhex(hex_key)
    key.wipe()


def test_adaptive_provider_machine_file_fallback(monkeypatch, tmp_path):
    # Ensure env vars are unset
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
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
    for name in ("APPSTATE_KEY", "HERMES_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="disk key"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_adaptive_provider_strict_mode_refuses_disk_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    with pytest.raises(KeyProviderError, match="Refusing headless fallback to plaintext disk key"):
        provider.resolve_key()


def test_adaptive_provider_rejects_insecure_existing_key_file(monkeypatch, tmp_path):
    for name in ("APPSTATE_KEY", "HERMES_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)
    key_file = provider.fallback_dir / "master.key"
    key_file.write_bytes(b"x" * 32)
    key_file.chmod(0o644)

    with pytest.raises(KeyProviderError, match="permissions"):
        provider.resolve_key(allow_create=False)

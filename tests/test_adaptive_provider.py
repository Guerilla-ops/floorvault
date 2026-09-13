"""Tests for the 3-Tier Adaptive Key Provider."""

from floorvault.providers.adaptive import AdaptiveKeyProvider


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
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path)
    monkeypatch.setattr(provider, "_is_interactive_desktop", lambda: False)

    key1 = provider.resolve_key(allow_create=True)
    assert len(key1.get_bytes()) == 32
    assert (tmp_path / "master.key").exists()

    # Second resolve reuses the same file key
    key2 = provider.resolve_key(allow_create=False)
    assert key1.get_bytes() == key2.get_bytes()

    key1.wipe()
    key2.wipe()

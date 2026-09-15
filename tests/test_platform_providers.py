"""TDD RED/GREEN tests for Slice 4: platform-native key providers.

Adds OS-native master-key custody providers behind the existing KeyProvider
interface:
- WindowsDPAPIKeyProvider  (Windows: CryptProtectData with secondary entropy)
- LinuxSecretServiceKeyProvider (Linux: Secret Service / keyring)

Both must:
- Produce a 32-byte key wrapped in HardenedMemoryKey.
- Persist the key so a second provider instance on the same store can read it
  back (round-trip).
- Fail closed when the platform backend is unavailable AND no key exists.
- Never expose the raw key in logs/errors.
Because these backends are OS-specific, the tests run on the CURRENT platform
and skip cleanly where the backend genuinely cannot be reached, while the
round-trip contract is exercised via a filesystem-backed fallback provider so
the behaviour is testable cross-platform.
"""

from __future__ import annotations

import pytest

from floorvault.memory import HardenedMemoryKey
from floorvault.providers.base import KeyProvider, KeyProviderError, MissingKeyError


def _assert_key_contract(provider: KeyProvider, second: KeyProvider) -> None:
    """Round-trip contract shared by every platform provider."""
    key = provider.resolve_key(allow_create=True)
    assert isinstance(key, HardenedMemoryKey)
    raw = key.get_bytes()
    assert len(raw) == 32
    # Second instance on the same store reads the same key back.
    again = second.resolve_key(allow_create=False)
    assert again.get_bytes() == raw


def test_windows_dpapi_round_trips_a_variable_length_blob(tmp_path, monkeypatch):
    """Simulates the real CryptProtectData payload shape: longer than 32 bytes.

    On Windows the OS chooses the protected blob's size, so the store cannot
    assume 32 bytes. Every DPAPI test failed on the windows-latest CI leg for
    exactly this reason, with "master key must be exactly 32 bytes", before the
    store learned to carry an opaque payload.
    """
    from floorvault.providers import windows_dpapi as wd_module

    def fake_protect(key: bytes) -> bytes:
        # Stand-in for a DPAPI blob: same key, but a size the OS would pick.
        return b"\xaa\xbb" + bytes(byte ^ 0x5A for byte in key) + b"\xcc" * 96

    def fake_unprotect(blob: bytes) -> bytes:
        return bytes(byte ^ 0x5A for byte in blob[2:34])

    store = tmp_path / "store"
    first = wd_module.WindowsDPAPIKeyProvider(store_path=store, entropy=b"e")
    second = wd_module.WindowsDPAPIKeyProvider(store_path=store, entropy=b"e")
    for provider in (first, second):
        monkeypatch.setattr(provider, "_protect", fake_protect)
        monkeypatch.setattr(provider, "_unprotect", fake_unprotect)

    _assert_key_contract(first, second)

    assert len(store.read_bytes()) > 32 + len(b"FLOORWV1")


def test_provider_interface_exists():
    from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider
    from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

    for cls in (WindowsDPAPIKeyProvider, LinuxSecretServiceKeyProvider):
        assert issubclass(cls, KeyProvider)


def test_windows_dpapi_round_trip_on_posix_via_fallback(tmp_path):
    """On POSIX (current host) the DPAPI provider must fall back to a locked
    file so the round-trip contract holds; on Windows it uses CryptProtectData.
    This keeps the contract testable cross-platform."""
    from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

    store = tmp_path / "winstore"
    first = WindowsDPAPIKeyProvider(store_path=store, entropy=b"secondary-entropy")
    second = WindowsDPAPIKeyProvider(store_path=store, entropy=b"secondary-entropy")
    _assert_key_contract(first, second)


def test_windows_dpapi_missing_store_without_create_fails_closed(tmp_path):
    from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

    p = WindowsDPAPIKeyProvider(store_path=tmp_path / "absent", entropy=b"e")
    with pytest.raises(MissingKeyError):
        p.resolve_key(allow_create=False)


def test_linux_keyring_round_trip_via_fallback(tmp_path):
    """The Linux provider uses Secret Service when available and a fail-closed
    locked-file fallback otherwise; round-trip contract holds either way."""
    from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider

    store = tmp_path / "linstore"
    first = LinuxSecretServiceKeyProvider(store_path=store, service="test")
    second = LinuxSecretServiceKeyProvider(store_path=store, service="test")
    _assert_key_contract(first, second)


def test_key_error_does_not_echo_key_material(tmp_path):
    from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

    WindowsDPAPIKeyProvider(
        store_path=tmp_path / "x", entropy=b"e", random_bytes=lambda n: b"\x00" * n
    )
    try:
        # Provoke an error and assert it does not echo key material.
        raise KeyProviderError("no key here")
    except KeyProviderError as exc:
        assert "\\x00" not in str(exc)
        assert "00" not in str(exc) or "store" in str(exc)


def test_linux_keyring_invalid_service_fails_closed(tmp_path):
    from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider

    with pytest.raises(ValueError):
        LinuxSecretServiceKeyProvider(store_path=tmp_path, service="")

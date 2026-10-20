"""Every custody scheme must own its own key file.

Before this, three incompatible formats shared ``fallback_dir/master.key``:

* ``AdaptiveKeyProvider`` tier 3 - a bare 32-byte or 64-hex-char raw key, no header;
* ``LinuxSecretServiceKeyProvider`` - ``FLOORLV1`` header + service-masked payload (40 bytes);
* ``WindowsDPAPIKeyProvider`` - ``FLOORWV1`` header + DPAPI blob (OS-sized).

Each reader refuses the other's file, so whichever tier ran first locked the
others out of the user's own data. Both failure directions were real:

    desktop + tier-3 raw file  -> ProtectedStoreHeaderError ("unknown or missing header")
    headless + SS-provider file -> KeyProviderError ("unexpected length (40 bytes)")

They fail loudly rather than mixing up keys, but "your data is unreachable until
someone edits code" is still a defect reachable from a plausible sequence - a
host first used headless, then given a desktop session with ``secretstorage``
installed.

A split also has to be non-destructive: a store created by an earlier build
still sits at ``master.key``, and a provider that ignored it would mint a fresh
key and silently strand the existing data. So a provider adopts a pre-split
store when it is *this* scheme's, and ignores another scheme's file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from floorvault.providers import adaptive as adaptive_module
from floorvault.providers import linux_keyring as lk_module
from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider
from floorvault.providers.platform_custody import (
    LEGACY_STORE_NAME,
    ProtectedStoreError,
    ProtectedStoreHeaderError,
    read_protected,
    store_path_for,
    write_protected,
)
from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider


def _headless(monkeypatch):
    """Force the file-custody path rather than a live desktop service."""
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)


def _linux_provider(base, monkeypatch, **kwargs):
    _headless(monkeypatch)
    monkeypatch.setattr(lk_module, "is_linux", lambda: True)
    return LinuxSecretServiceKeyProvider(
        store_path=LinuxSecretServiceKeyProvider.default_store_path(base), **kwargs
    )


def _dpapi_provider(base, **kwargs):
    return WindowsDPAPIKeyProvider(
        store_path=WindowsDPAPIKeyProvider.default_store_path(base),
        allow_outside_user_profile=True,
        allow_nonwindows_stub=True,
        **kwargs,
    )


# --------------------------------------------------------------------------
# The split itself
# --------------------------------------------------------------------------


def test_custody_schemes_do_not_share_a_key_store_path(tmp_path):
    """The three schemes must resolve to three different files."""
    paths = {
        "tier3": store_path_for(tmp_path, None),
        "ss": LinuxSecretServiceKeyProvider.default_store_path(tmp_path),
        "dpapi": WindowsDPAPIKeyProvider.default_store_path(tmp_path),
    }
    assert len(set(paths.values())) == 3, f"custody schemes share a store path: {paths}"
    assert paths["tier3"].name == LEGACY_STORE_NAME, (
        "tier 3 keeps the historical bare name so existing raw key files are found"
    )
    for scheme, path in paths.items():
        if scheme != "tier3":
            assert path.parent == tmp_path


def test_provider_store_paths_use_their_own_suffix(tmp_path):
    assert LinuxSecretServiceKeyProvider.default_store_path(tmp_path).name.endswith(".ss")
    assert WindowsDPAPIKeyProvider.default_store_path(tmp_path).name.endswith(".dpapi")


# --------------------------------------------------------------------------
# The two directions that used to collide
# --------------------------------------------------------------------------


def test_linux_provider_leaves_a_tier3_raw_key_file_alone(tmp_path, monkeypatch):
    """The SS provider must not read - or trip over - a tier-3 raw key file.

    This is the reported S1 direction: a host used headless first writes a bare
    raw key at ``master.key``, then gains a desktop session with
    ``secretstorage`` installed. The SS provider now has its own path, so the
    raw file is neither adopted nor refused.
    """
    raw_key = b"\x11" * 32
    legacy = tmp_path / LEGACY_STORE_NAME
    write_protected(raw_key, legacy, header=b"")

    provider = _linux_provider(tmp_path, monkeypatch)
    key = provider.resolve_key(allow_create=True)

    assert key.get_bytes() != raw_key, "the tier-3 raw file was adopted as an SS store"
    assert legacy.read_bytes() == raw_key, "the tier-3 key file was modified"
    assert provider._path.exists(), "the SS provider did not create its own store"
    key.wipe()


def test_tier3_leaves_a_linux_provider_store_alone(tmp_path, monkeypatch):
    """The reported S2 direction: adaptive tier 3 must not meet the SS store."""
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    ss_provider = _linux_provider(tmp_path, monkeypatch)
    ss_key = ss_provider.resolve_key(allow_create=True)
    ss_store_bytes = ss_provider._path.read_bytes()

    adaptive = AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True)
    monkeypatch.setattr(adaptive, "_is_interactive_desktop", lambda: False)
    tier3_key = adaptive.resolve_key(allow_create=True)

    assert tier3_key.get_bytes() != ss_key.get_bytes()
    assert ss_provider._path.read_bytes() == ss_store_bytes, "the SS store was overwritten"
    assert (tmp_path / LEGACY_STORE_NAME).exists(), "tier 3 did not write its own file"

    tier3_key.wipe()
    ss_key.wipe()


# --------------------------------------------------------------------------
# Non-destructive adoption of a pre-split store
# --------------------------------------------------------------------------


def test_linux_provider_adopts_a_pre_split_store(tmp_path, monkeypatch):
    """A store written before the split sits at ``master.key`` and must be used.

    Minting a new key here would leave the existing data undecryptable, which is
    worse than the collision being fixed. Adoption requires an explicit opt-in
    because the masked payload is a public transform: a planted file is
    indistinguishable from a genuine pre-split store, so the upgrade must be
    an operator decision rather than a silent default.
    """
    key = b"\x2b" * 32
    provider_before_split = LinuxSecretServiceKeyProvider(store_path=tmp_path / LEGACY_STORE_NAME)
    write_protected(
        provider_before_split._mask(key), tmp_path / LEGACY_STORE_NAME, header=b"FLOORLV1"
    )

    provider = _linux_provider(tmp_path, monkeypatch, allow_legacy_adoption=True)
    resolved = provider.resolve_key(allow_create=True)

    assert resolved.get_bytes() == key, "the pre-split store was not adopted"
    assert not provider._path.exists(), "a second store was created alongside the adopted one"
    resolved.wipe()


def test_dpapi_provider_adopts_a_pre_split_store(tmp_path):
    """Same adoption rule for the Windows store."""
    key = b"\x3c" * 32
    legacy = tmp_path / LEGACY_STORE_NAME
    before = WindowsDPAPIKeyProvider(
        store_path=legacy,
        allow_outside_user_profile=True,
        allow_nonwindows_stub=True,
    )
    write_protected(before._protect(key), legacy, header=b"FLOORWV1", expected_length=None)

    provider = _dpapi_provider(tmp_path, allow_legacy_adoption=True)
    resolved = provider.resolve_key(allow_create=True)

    assert resolved.get_bytes() == key, "the pre-split DPAPI store was not adopted"
    assert not provider._path.exists()
    resolved.wipe()


def test_linux_provider_refuses_pre_split_store_without_opt_in(tmp_path, monkeypatch):
    """A legacy ``master.key`` parsing as this scheme is refused by default.

    Red-team P0 #8: because the scheme pads are public deterministic
    functions, an attacker with vault-directory write access can plant a
    ``master.key`` holding a key of their choosing and have it adopted - a
    silent custody downgrade. Refusal (not minting) keeps the data reachable.
    """
    key = b"\x2b" * 32
    provider_before_split = LinuxSecretServiceKeyProvider(store_path=tmp_path / LEGACY_STORE_NAME)
    write_protected(
        provider_before_split._mask(key), tmp_path / LEGACY_STORE_NAME, header=b"FLOORLV1"
    )

    provider = _linux_provider(tmp_path, monkeypatch)
    with pytest.raises(ProtectedStoreError, match="allow_legacy_adoption"):
        provider.resolve_key(allow_create=True)
    assert not provider._path.exists(), "a new store was minted beside the refused legacy file"


def test_dpapi_provider_refuses_pre_split_store_without_opt_in(tmp_path):
    """Same refusal rule for the Windows store."""
    key = b"\x3c" * 32
    legacy = tmp_path / LEGACY_STORE_NAME
    before = WindowsDPAPIKeyProvider(store_path=legacy, allow_outside_user_profile=True)
    write_protected(before._protect(key), legacy, header=b"FLOORWV1", expected_length=None)

    provider = _dpapi_provider(tmp_path)
    with pytest.raises(ProtectedStoreError, match="allow_legacy_adoption"):
        provider.resolve_key(allow_create=True)
    assert not provider._path.exists()


def test_adoption_does_not_hijack_another_scheme(tmp_path, monkeypatch):
    """A DPAPI-format file at the legacy path is not an SS store.

    Adoption is scheme-specific: the header decides. Ignoring a foreign file is
    correct now that each scheme has its own path; adopting it would be a key
    mix-up, and failing on it would block a legitimate create.
    """
    legacy = tmp_path / LEGACY_STORE_NAME
    write_protected(b"\x4d" * 48, legacy, header=b"FLOORWV1", expected_length=None)

    provider = _linux_provider(tmp_path, monkeypatch)
    key = provider.resolve_key(allow_create=True)

    assert len(key.get_bytes()) == 32
    assert provider._path.exists(), "the SS provider did not create its own store"
    assert legacy.read_bytes().startswith(b"FLOORWV1"), "the foreign store was overwritten"
    key.wipe()


# --------------------------------------------------------------------------
# Round trips: each provider can read back what it wrote
# --------------------------------------------------------------------------


def test_cross_reader_round_trip(tmp_path, monkeypatch):
    """Write-then-read through each scheme's own path, twice, stably."""
    linux_provider = _linux_provider(tmp_path, monkeypatch)
    first = linux_provider.resolve_key(allow_create=True)
    second = linux_provider.resolve_key(allow_create=False)
    assert first.get_bytes() == second.get_bytes()

    dpapi_provider = _dpapi_provider(tmp_path)
    dpapi_first = dpapi_provider.resolve_key(allow_create=True)
    dpapi_second = dpapi_provider.resolve_key(allow_create=False)
    assert dpapi_first.get_bytes() == dpapi_second.get_bytes()

    # The two schemes coexisting in one directory must not interfere.
    assert first.get_bytes() != dpapi_first.get_bytes()

    for key in (first, second, dpapi_first, dpapi_second):
        key.wipe()


def test_each_scheme_store_carries_its_own_header(tmp_path, monkeypatch):
    """The header is what makes a foreign file detectable rather than adopted."""
    linux_provider = _linux_provider(tmp_path, monkeypatch)
    linux_provider.resolve_key(allow_create=True).wipe()
    assert linux_provider._path.read_bytes().startswith(b"FLOORLV1")

    dpapi_provider = _dpapi_provider(tmp_path)
    dpapi_provider.resolve_key(allow_create=True).wipe()
    assert dpapi_provider._path.read_bytes().startswith(b"FLOORWV1")


def test_scheme_store_reads_back_only_its_own_header(tmp_path):
    """A cross-scheme read is refused, not silently mis-decoded."""
    path = store_path_for(tmp_path, "ss")
    write_protected(b"\x5e" * 32, path, header=b"FLOORLV1")

    # ProtectedStoreError (specifically the header subclass), not KeyProviderError:
    # the file-store boundary keeps its own error family.
    with pytest.raises(ProtectedStoreHeaderError):
        read_protected(path, header=b"FLOORWV1", expected_length=None)


def test_adaptive_forwards_legacy_adoption_to_the_platform_provider(tmp_path, monkeypatch):
    """``allow_legacy_adoption`` must reach the platform provider it gates.

    Adaptive is the tier most callers construct; the opt-in would be
    unreachable if it stopped at the adaptive constructor.
    """
    captured = {}

    class _Spy:
        @staticmethod
        def default_store_path(base):
            return Path(base) / "master.key.ss"

        def __init__(self, **kwargs):
            captured.update(kwargs)

        def _secret_service_available(self):
            return False

        def resolve_key(self, *, allow_create=True):
            return None

    _headless(monkeypatch)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _Spy)
    for name in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        monkeypatch.delenv(name, raising=False)

    provider = AdaptiveKeyProvider(
        fallback_dir=tmp_path, allow_disk_fallback=True, allow_legacy_adoption=True
    )
    provider._resolve_from_system_keyring(allow_create=True)

    assert captured["allow_legacy_adoption"] is True

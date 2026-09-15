"""Tests for the centralised platform predicates and the Windows store-location policy.

These pin two review items:

* **F-6** - the codebase mixed ``os.name`` and ``sys.platform``, which disagree on
  Cygwin/MSYS (``os.name == "posix"`` there, ``sys.platform == "cygwin"``). That
  produced an unreachable branch in the DPAPI provider and let the Linux
  Secret-Service provider treat macOS as eligible.
* **F-1 residual** - on Windows the POSIX permission check is a no-op and
  FloorVault cannot inspect NT ACLs, so the store is required to live inside the
  user profile, with an explicit opt-out for locations secured independently.
"""

from __future__ import annotations

import sys
import types

import pytest

from floorvault import platform_support
from floorvault.providers import linux_keyring as linux_module
from floorvault.providers import windows_dpapi as wd_module
from floorvault.providers.platform_custody import ProtectedStoreError

# --------------------------------------------------------------------------
# Predicates
# --------------------------------------------------------------------------


def test_at_most_one_platform_predicate_is_true():
    """Guards against the Cygwin-style double-classification this replaced."""
    assert (
        sum(
            [
                platform_support.is_windows(),
                platform_support.is_macos(),
                platform_support.is_linux(),
            ]
        )
        <= 1
    )


def test_predicates_read_the_module_flags_at_call_time(monkeypatch):
    """Tests (and callers) must be able to patch one attribute and be believed."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(platform_support, "IS_LINUX", False)
    assert platform_support.is_windows() is True
    assert platform_support.is_linux() is False


def test_group_or_other_helper_is_strict_on_posix(monkeypatch):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    assert platform_support.has_posix_group_or_other_access(0o644) is True
    assert platform_support.has_posix_group_or_other_access(0o660) is True
    assert platform_support.has_posix_group_or_other_access(0o600) is False
    assert platform_support.has_posix_group_or_other_access(0o700) is False


def test_group_or_other_helper_ignores_windows(monkeypatch):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    assert platform_support.has_posix_group_or_other_access(0o666) is False


def test_dpapi_windows_detection_no_longer_requires_sys_platform(monkeypatch):
    """The old conjunction `os.name == "nt" and sys.platform in ("win32","cygwin")`
    could never be true on Cygwin, where os.name is "posix"."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    assert wd_module.WindowsDPAPIKeyProvider._is_windows() is True

    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    assert wd_module.WindowsDPAPIKeyProvider._is_windows() is False


def test_linux_provider_does_not_activate_off_linux(monkeypatch, tmp_path):
    """On macOS `os.name` is "posix", so the old check was true there.

    secretstorage is faked as importable so the only reason availability can be
    False is the platform predicate.
    """
    monkeypatch.setattr(platform_support, "IS_LINUX", False)
    monkeypatch.setattr(linux_module, "_looks_interactive_desktop", lambda: True)
    monkeypatch.setitem(sys.modules, "secretstorage", types.ModuleType("secretstorage"))

    provider = linux_module.LinuxSecretServiceKeyProvider(store_path=tmp_path / "store")
    assert provider._secret_service_available() is False


# --------------------------------------------------------------------------
# Windows store-location policy (F-1 residual risk)
# --------------------------------------------------------------------------


def _fake_profile(monkeypatch, tmp_path):
    """Point ``~`` at a directory we control, so the check is platform-neutral."""
    profile = tmp_path / "home"
    profile.mkdir()
    monkeypatch.setattr(wd_module.os.path, "expanduser", lambda _: str(profile))
    return profile


def test_windows_refuses_a_store_outside_the_user_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    _fake_profile(monkeypatch, tmp_path)

    with pytest.raises(ProtectedStoreError, match="outside the user profile"):
        wd_module.WindowsDPAPIKeyProvider(store_path=tmp_path / "shared-volume", entropy=b"e")


def test_windows_accepts_a_store_inside_the_user_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    profile = _fake_profile(monkeypatch, tmp_path)

    provider = wd_module.WindowsDPAPIKeyProvider(
        store_path=profile / "AppData" / "Local" / "floorvault" / "store", entropy=b"e"
    )
    assert provider is not None


def test_windows_override_allows_an_independently_secured_location(monkeypatch, tmp_path):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    _fake_profile(monkeypatch, tmp_path)

    provider = wd_module.WindowsDPAPIKeyProvider(
        store_path=tmp_path / "externally-secured",
        entropy=b"e",
        allow_outside_user_profile=True,
    )
    assert provider is not None


def test_non_windows_is_unaffected_by_the_location_policy(monkeypatch, tmp_path):
    """POSIX has real permission bits, so the location policy must not apply."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)

    provider = wd_module.WindowsDPAPIKeyProvider(store_path=tmp_path / "anywhere", entropy=b"e")
    assert provider is not None

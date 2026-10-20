"""Issue #57: an OS key store appearing after Tier-3 file custody must not fork the key.

`AdaptiveKeyProvider` tries the OS tier before the Tier-3 file. Before the fix,
a host running on `master.key` that later gained a usable Keychain / Secret
Service / DPAPI tier got a brand-new OS key: old data stopped decrypting and
new writes went under the new key. Now the OS tier is only read while a Tier-3
store exists; a usable-but-empty OS tier refuses instead of creating.
"""

from __future__ import annotations

import sys
import types
import warnings

import pytest

from hermes_vault.memory import HardenedMemoryKey
from hermes_vault.providers import adaptive as adaptive_module
from hermes_vault.providers import passphrase_store
from hermes_vault.providers.adaptive import AdaptiveKeyProvider
from hermes_vault.providers.base import KeyProviderError, MissingKeyError


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name in ("is_macos", "is_linux", "is_windows"):
        monkeypatch.setattr(adaptive_module, name, lambda: False)
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)
    warnings.simplefilter("ignore", UserWarning)


def _provider(tmp_path, **kwargs):
    return AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True, **kwargs)


def _key(handle) -> bytes:
    return bytes(handle.get_buffer())


@pytest.fixture
def keychain(monkeypatch):
    """A stand-in `Security` module driving adaptive.py's real macOS branch."""
    store: dict[str, bytes] = {}
    calls = {"add": 0}
    sec = types.ModuleType("Security")
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
        setattr(sec, name, name)
    sec.SecItemCopyMatching = lambda query, _: (0, store["k"]) if "k" in store else (-25300, None)

    def add(query, _):
        calls["add"] += 1
        store["k"] = query["kSecValueData"]
        return (0, None)

    sec.SecItemAdd = add
    monkeypatch.setitem(sys.modules, "Security", sec)
    return types.SimpleNamespace(store=store, calls=calls)


def _keychain_appears(monkeypatch):
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: True)


def test_macos_keychain_appearing_after_file_custody_refuses_to_fork(
    tmp_path, monkeypatch, keychain
):
    file_key = _key(_provider(tmp_path).resolve_key())  # day 1: Tier-3 file
    _keychain_appears(monkeypatch)  # day 2: the macos extra is installed
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path).resolve_key()
    assert keychain.calls["add"] == 0  # no OS key was minted
    assert (tmp_path / "master.key").read_bytes() == file_key


def test_passphrase_wrapped_file_also_blocks_the_fork(tmp_path, monkeypatch, keychain):
    _provider(tmp_path, passphrase="pw").resolve_key()
    _keychain_appears(monkeypatch)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path, passphrase="pw").resolve_key()
    assert keychain.calls["add"] == 0


def test_dangling_symlink_at_the_file_path_also_blocks(tmp_path, monkeypatch, keychain):
    (tmp_path / "master.key").symlink_to(tmp_path / "nowhere")
    _keychain_appears(monkeypatch)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path).resolve_key()
    assert keychain.calls["add"] == 0


def _deny_key_file_lookups(monkeypatch, tmp_path):
    """Make lstat of the Tier-3 store paths fail as in an unsearchable directory.

    Simulated rather than chmod-ed: permission bits do not stop root, and the
    behaviour must be pinned on every runner.
    """
    real_lstat = adaptive_module.os.lstat
    targets = {str(tmp_path / "master.key"), str(tmp_path / adaptive_module.WRAPPED_KEY_FILENAME)}

    def lstat(path, *args, **kwargs):
        if str(path) in targets:
            raise PermissionError(13, "Permission denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(adaptive_module.os, "lstat", lstat)


def test_unsearchable_key_directory_blocks_the_fork(tmp_path, monkeypatch, keychain):
    """A lookup failure is not absence: it cannot rule the file key out."""
    _deny_key_file_lookups(monkeypatch, tmp_path)
    _keychain_appears(monkeypatch)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path).resolve_key()
    assert keychain.calls["add"] == 0


def test_unsearchable_key_directory_still_reads_an_existing_keychain_key(
    tmp_path, monkeypatch, keychain
):
    keychain.store["k"] = b"\x06" * 32
    _deny_key_file_lookups(monkeypatch, tmp_path)
    _keychain_appears(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key()) == b"\x06" * 32


def test_existing_keychain_key_still_wins(tmp_path, monkeypatch, keychain):
    """Unchanged: an OS key that already exists is used even beside a file."""
    _provider(tmp_path).resolve_key()
    keychain.store["k"] = b"\x05" * 32
    _keychain_appears(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key()) == b"\x05" * 32


def test_no_file_store_creates_the_keychain_key_as_before(tmp_path, monkeypatch, keychain):
    _keychain_appears(monkeypatch)
    key = _key(_provider(tmp_path).resolve_key())
    assert keychain.calls["add"] == 1 and keychain.store["k"] == key


def test_allow_create_false_still_reads_the_file_key(tmp_path, monkeypatch, keychain):
    """Unchanged: a read-only resolve with an empty Keychain falls to the file."""
    file_key = _key(_provider(tmp_path).resolve_key())
    _keychain_appears(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key(allow_create=False)) == file_key
    assert keychain.calls["add"] == 0


class _FakeNativeProvider:
    """Stand-in for the Linux Secret Service / Windows DPAPI providers."""

    instances: list = []

    def __init__(self, *, available=True, has_key=False, **kwargs):
        self.kwargs = kwargs
        self.available = available
        self.has_key = has_key
        self.create_calls = 0
        _FakeNativeProvider.instances.append(self)

    @staticmethod
    def default_store_path(directory):
        return directory / "native.store"

    def _secret_service_available(self):
        return self.available

    def resolve_key(self, *, allow_create=True):
        if self.has_key:
            return HardenedMemoryKey(b"\x06" * 32)
        if not allow_create:
            raise MissingKeyError("native store is missing; recovery is required")
        self.create_calls += 1
        return HardenedMemoryKey(b"\x07" * 32)


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_linux_and_windows_native_tiers_refuse_to_fork(tmp_path, monkeypatch, platform):
    file_key = _key(_provider(tmp_path).resolve_key())
    _FakeNativeProvider.instances = []
    if platform == "linux":
        monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _FakeNativeProvider)
        monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    else:
        monkeypatch.setattr(adaptive_module, "WindowsDPAPIKeyProvider", _FakeNativeProvider)
        monkeypatch.setattr(adaptive_module, "is_windows", lambda: True)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path).resolve_key()
    assert all(p.create_calls == 0 for p in _FakeNativeProvider.instances)
    assert (tmp_path / "master.key").read_bytes() == file_key


def test_unavailable_linux_tier_still_falls_through_to_the_file(tmp_path, monkeypatch):
    file_key = _key(_provider(tmp_path).resolve_key())

    class _Unavailable(_FakeNativeProvider):
        def __init__(self, **kwargs):
            super().__init__(available=False, **kwargs)

    monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _Unavailable)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    assert _key(_provider(tmp_path).resolve_key()) == file_key

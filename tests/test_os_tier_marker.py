"""Issue #63: a resolver without the OS tier must not fork a key that lives there.

Two resolvers can share one ``fallback_dir`` and still see different OS-tier
availability (a GUI session with a Keychain / Secret Service, an SSH or cron
session without one). Before the fix the first created an OS key, the second
never consulted the OS tier, found no file and minted ``master.key``: two
master keys for one home. Now an OS-tier key is recorded by a marker in
``fallback_dir`` (published under the Tier-3 creation lock) and Tier-3 creation
refuses while it exists.
"""

from __future__ import annotations

import contextlib
import os
import sys
import types
import warnings

import pytest

from hermes_vault.memory import HardenedMemoryKey
from hermes_vault.providers import adaptive as adaptive_module
from hermes_vault.providers import passphrase_store
from hermes_vault.providers.adaptive import (
    OS_TIER_MARKER_FILENAME,
    OS_TIER_MARKER_MAGIC,
    AdaptiveKeyProvider,
)
from hermes_vault.providers.base import KeyProviderError, MissingKeyError


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name in ("is_macos", "is_linux", "is_windows"):
        monkeypatch.setattr(adaptive_module, name, lambda: False)
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        yield


def _provider(tmp_path, **kwargs):
    return AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True, **kwargs)


def _key(handle) -> bytes:
    return bytes(handle.get_buffer())


@pytest.fixture
def keychain(monkeypatch):
    """A stand-in ``Security`` module driving adaptive.py's real macOS branch."""
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


def _gui_session(monkeypatch):
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: True)


def _headless_session(monkeypatch):
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)


def _marker(tmp_path):
    return tmp_path / OS_TIER_MARKER_FILENAME


# -- the fork from the issue --------------------------------------------------


def test_headless_resolver_refuses_to_fork_a_keychain_key(tmp_path, monkeypatch, keychain):
    _gui_session(monkeypatch)
    os_key = _key(_provider(tmp_path).resolve_key())
    assert keychain.calls["add"] == 1
    assert (
        _marker(tmp_path).read_bytes()
        == OS_TIER_MARKER_MAGIC + b"macos-keychain\0floorvault\0default-v1"
    )

    _headless_session(monkeypatch)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path).resolve_key()
    assert not (tmp_path / "master.key").exists()
    # The GUI session still gets the same key.
    _gui_session(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key()) == os_key


def test_headless_passphrase_resolver_refuses_too(tmp_path, monkeypatch, keychain):
    _gui_session(monkeypatch)
    _provider(tmp_path).resolve_key()
    _headless_session(monkeypatch)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path, passphrase="pw").resolve_key()
    assert not (tmp_path / adaptive_module.WRAPPED_KEY_FILENAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_marker_is_owner_only(tmp_path, monkeypatch, keychain):
    _gui_session(monkeypatch)
    _provider(tmp_path).resolve_key()
    assert _marker(tmp_path).stat().st_mode & 0o077 == 0


# -- existing installs and read-only resolution -------------------------------


def test_existing_keychain_key_is_recorded_on_first_resolve(tmp_path, monkeypatch, keychain):
    """A pre-upgrade install has an OS key but no marker: the next resolve adds it."""
    keychain.store["k"] = b"\x05" * 32
    _gui_session(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key()) == b"\x05" * 32
    assert keychain.calls["add"] == 0
    assert _marker(tmp_path).exists()
    _headless_session(monkeypatch)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path).resolve_key()


def test_read_only_resolution_writes_nothing(tmp_path, monkeypatch, keychain):
    keychain.store["k"] = b"\x05" * 32
    _gui_session(monkeypatch)
    assert _key(_provider(tmp_path).resolve_key(allow_create=False)) == b"\x05" * 32
    assert list(tmp_path.iterdir()) == []


def test_unavailable_os_tier_writes_no_marker_and_file_custody_still_works(tmp_path, monkeypatch):
    """No Security module: the OS tier is absent, so Tier-3 proceeds as before."""
    monkeypatch.setitem(sys.modules, "Security", None)
    _gui_session(monkeypatch)
    key = _key(_provider(tmp_path).resolve_key())
    assert not _marker(tmp_path).exists()
    assert (tmp_path / "master.key").exists()
    assert _key(_provider(tmp_path).resolve_key()) == key


def test_an_existing_file_key_beside_a_marker_still_reads(tmp_path, monkeypatch, keychain):
    """A fork that predates the fix is not bricked: only creation is refused."""
    file_key = _key(_provider(tmp_path).resolve_key())
    _marker(tmp_path).write_bytes(OS_TIER_MARKER_MAGIC + b"macos-keychain")
    assert _key(_provider(tmp_path).resolve_key()) == file_key


def test_reset_keychain_beside_a_file_key_and_marker_still_refuses(tmp_path, monkeypatch, keychain):
    """The file key wins over the marker's fast path: an emptied Keychain must
    not get a fresh key while a file key exists (the #57 rule still applies)."""
    file_key = _key(_provider(tmp_path).resolve_key())
    _marker(tmp_path).write_bytes(OS_TIER_MARKER_MAGIC + b"macos-keychain")
    _gui_session(monkeypatch)  # Keychain usable but empty (reset)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        _provider(tmp_path).resolve_key()
    assert keychain.calls["add"] == 0
    assert (tmp_path / "master.key").read_bytes() == file_key


def test_deleted_keychain_item_is_not_silently_replaced(tmp_path, monkeypatch, keychain):
    """The marker proves a key was created here: a missing one was deleted or
    the store reset, and minting a replacement would orphan the data."""
    _gui_session(monkeypatch)
    _provider(tmp_path).resolve_key()
    keychain.store.clear()  # the Keychain item is deleted
    with pytest.raises(KeyProviderError, match="missing now"):
        _provider(tmp_path).resolve_key()
    assert keychain.calls["add"] == 1  # only the original creation


def test_a_marker_for_another_service_does_not_refuse_this_one(tmp_path, monkeypatch, keychain):
    """Markers are per service/account: another identity's marker neither
    blocks nor falsely flags a first-time key for this one."""
    _gui_session(monkeypatch)
    _provider(tmp_path, service_name="other-app").resolve_key()
    other_marker = _marker(tmp_path).read_bytes()
    keychain.store.clear()  # a different Keychain item would be looked up
    _provider(tmp_path).resolve_key()  # creates this service's key
    assert keychain.calls["add"] == 2
    assert _marker(tmp_path).read_bytes() == other_marker
    # Tier-3 creation is still refused for every identity in this directory.
    _headless_session(monkeypatch)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path).resolve_key()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows symlink creation in pytest tmp dirs is unreliable",
)
def test_symlinked_fallback_dir_still_resolves_the_keychain_key(tmp_path, monkeypatch, keychain):
    """The owner-only directory policy refuses a symlinked fallback_dir; that
    must not break OS-tier resolution (Tier-3 creation there fails the same way,
    so there is no file-key fork to guard)."""
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    keychain.store["k"] = b"\x05" * 32
    _gui_session(monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert _key(_provider(link).resolve_key()) == b"\x05" * 32
    assert not any("OS-tier marker" in str(w.message) for w in caught)
    assert not (real / OS_TIER_MARKER_FILENAME).exists()


def test_directory_policy_refusal_still_resolves_the_keychain_key(tmp_path, monkeypatch, keychain):
    """Platform-independent form of the symlink case: _mkdir_owner_only raises
    ValueError for a fallback_dir that fails the owner-only policy."""
    provider = _provider(tmp_path)

    def policy_refuses():
        raise ValueError(f"vault directory must not be a symlink: {tmp_path}")

    monkeypatch.setattr(provider, "_tier3_creation_lock", policy_refuses)
    keychain.store["k"] = b"\x05" * 32
    _gui_session(monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert _key(provider.resolve_key()) == b"\x05" * 32
    assert not any("OS-tier marker" in str(w.message) for w in caught)


def test_unreadable_marker_cannot_be_ruled_out(tmp_path, monkeypatch):
    """A lookup failure on the marker path blocks Tier-3 creation, like a present marker."""
    real_lstat = adaptive_module.os.lstat
    target = str(_marker(tmp_path))

    def lstat(path, *args, **kwargs):
        if str(path) == target:
            raise PermissionError(13, "Permission denied", target)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(adaptive_module.os, "lstat", lstat)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path).resolve_key()


# -- interleavings: both sides serialize on the Tier-3 lock -------------------


def _lock_that_runs(provider, action):
    real = provider._tier3_creation_lock

    @contextlib.contextmanager
    def lock():
        with real():
            action()
            yield

    return lock


def test_file_key_published_before_the_os_side_takes_the_lock(tmp_path, monkeypatch, keychain):
    """The OS side checked "no file" without the lock; a headless resolver then
    published master.key. Under the lock the OS side must re-check and only read."""
    _gui_session(monkeypatch)
    provider = _provider(tmp_path)

    def headless_publishes_a_file_key():
        (tmp_path / "master.key").write_bytes(b"\x09" * 32)
        os.chmod(tmp_path / "master.key", 0o600)

    monkeypatch.setattr(
        provider, "_tier3_creation_lock", _lock_that_runs(provider, headless_publishes_a_file_key)
    )
    with pytest.raises(KeyProviderError, match="would silently replace"):
        provider.resolve_key()
    assert keychain.calls["add"] == 0


def test_marker_published_before_the_file_side_takes_the_lock(tmp_path, monkeypatch):
    """The headless side saw no file; the OS side then recorded its key. Under
    the lock the file side must see the marker and refuse."""
    provider = _provider(tmp_path)

    def gui_records_its_key():
        _marker(tmp_path).write_bytes(OS_TIER_MARKER_MAGIC + b"macos-keychain")

    monkeypatch.setattr(
        provider, "_tier3_creation_lock", _lock_that_runs(provider, gui_records_its_key)
    )
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        provider.resolve_key()
    assert not (tmp_path / "master.key").exists()


def test_fallback_dir_creation_race_retries_the_lock(tmp_path, monkeypatch, keychain):
    """Two first-time resolvers both see fallback_dir missing; a headless one
    wins the mkdir and publishes master.key. The loser's FileExistsError must
    lead to a retried lock and the re-check (read-only, refused), not to an
    unlocked OS-key creation."""
    home = tmp_path / "home"
    provider = _provider(home)
    real = provider._tier3_creation_lock
    calls = {"n": 0}

    def lock():
        calls["n"] += 1
        if calls["n"] == 1:
            home.mkdir(mode=0o700)  # the winner created the directory...
            (home / "master.key").write_bytes(b"\x09" * 32)  # ...and its file key
            raise FileExistsError(17, "File exists", str(home))
        return real()

    monkeypatch.setattr(provider, "_tier3_creation_lock", lock)
    _gui_session(monkeypatch)
    with pytest.raises(KeyProviderError, match="would silently replace"):
        provider.resolve_key()
    assert keychain.calls["add"] == 0
    assert calls["n"] == 2


# -- best effort when the marker cannot be written ----------------------------


def test_marker_write_failure_warns_and_still_returns_the_key(tmp_path, monkeypatch, keychain):
    real_write = adaptive_module.write_protected

    def write(payload, path, **kwargs):
        if path.name == OS_TIER_MARKER_FILENAME:
            raise PermissionError(13, "Permission denied", str(path))
        return real_write(payload, path, **kwargs)

    monkeypatch.setattr(adaptive_module, "write_protected", write)
    _gui_session(monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        key = _key(_provider(tmp_path).resolve_key())
    assert keychain.store["k"] == key
    assert any("could not record the OS-tier marker" in str(w.message) for w in caught)
    assert not _marker(tmp_path).exists()


def test_unusable_fallback_dir_warns_and_still_returns_the_key(tmp_path, monkeypatch, keychain):
    provider = _provider(tmp_path)

    def no_lock():
        raise PermissionError(13, "Permission denied", str(tmp_path))

    monkeypatch.setattr(provider, "_tier3_creation_lock", no_lock)
    _gui_session(monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        key = _key(provider.resolve_key())
    assert keychain.store["k"] == key
    assert any("could not record the OS-tier marker" in str(w.message) for w in caught)


# -- Linux Secret Service and Windows DPAPI -----------------------------------


class _FakeNativeProvider:
    """Stand-in for the Linux Secret Service / Windows DPAPI providers."""

    state = {"available": True, "key": None}

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @staticmethod
    def default_store_path(directory):
        return directory / "native.store"

    def _secret_service_available(self):
        return _FakeNativeProvider.state["available"]

    def resolve_key(self, *, allow_create=True):
        if _FakeNativeProvider.state["key"] is not None:
            return HardenedMemoryKey(_FakeNativeProvider.state["key"])
        if not allow_create:
            raise MissingKeyError("native store is missing; recovery is required")
        _FakeNativeProvider.state["key"] = b"\x07" * 32
        return HardenedMemoryKey(_FakeNativeProvider.state["key"])


@pytest.mark.parametrize(
    ("platform", "tier"), [("linux", b"linux-secret-service"), ("windows", b"windows-dpapi")]
)
def test_linux_and_windows_os_keys_are_recorded_and_protected(
    tmp_path, monkeypatch, platform, tier
):
    _FakeNativeProvider.state = {"available": True, "key": None}
    if platform == "linux":
        monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _FakeNativeProvider)
        monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    else:
        monkeypatch.setattr(adaptive_module, "WindowsDPAPIKeyProvider", _FakeNativeProvider)
        monkeypatch.setattr(adaptive_module, "is_windows", lambda: True)
    assert _key(_provider(tmp_path).resolve_key()) == b"\x07" * 32
    assert (
        _marker(tmp_path).read_bytes() == OS_TIER_MARKER_MAGIC + tier + b"\0floorvault\0default-v1"
    )

    # The OS tier disappears for this session (no session bus, a container).
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    with pytest.raises(KeyProviderError, match="lives in the OS key store"):
        _provider(tmp_path).resolve_key()
    assert not (tmp_path / "master.key").exists()


def test_linux_without_a_session_bus_writes_no_marker(tmp_path, monkeypatch):
    _FakeNativeProvider.state = {"available": False, "key": None}
    monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _FakeNativeProvider)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    _provider(tmp_path).resolve_key()
    assert not _marker(tmp_path).exists()
    assert (tmp_path / "master.key").exists()

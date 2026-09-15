"""Safety tests for the shared protected-file key store.

Two defects are pinned here.

1. Conflation of "unreadable" with "absent". Both platform providers did
   ``except ProtectedStoreError: blob = None``, so ANY read failure - a corrupt
   header, an unexpected key length, a non-0600 mode - was treated as "no store
   yet". The provider then minted a fresh master key and ``write_protected``
   overwrote the existing store via ``os.replace``. Net effect: silent master-key
   rotation and permanent loss of access to everything encrypted under the old
   key. Reproduces on macOS and Linux, not just Windows.

2. A POSIX-only permission test applied unconditionally. ``mode != 0o600`` can
   never pass on Windows, where os.stat() reports a synthesised mode (0o666 for
   a writable file).

The governing rule these tests enforce: a store that exists but cannot be read
must fail loudly, and must never be replaced.
"""

from __future__ import annotations

import sys

import pytest

from floorvault.providers import linux_keyring as linux_module
from floorvault.providers import platform_custody as custody
from floorvault.providers.platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    read_protected,
    write_protected,
)
from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

_HEADER = b"FLOORWV1"
_KEY = bytes(range(32))


# --------------------------------------------------------------------------
# read_protected: distinguish absent from unreadable
# --------------------------------------------------------------------------


def test_absent_store_raises_the_missing_error(tmp_path):
    with pytest.raises(ProtectedStoreMissing):
        read_protected(tmp_path / "nope.store", header=_HEADER)


def test_missing_error_is_still_a_protected_store_error(tmp_path):
    """Back-compat: existing `except ProtectedStoreError` handlers still catch it."""
    with pytest.raises(ProtectedStoreError):
        read_protected(tmp_path / "nope.store", header=_HEADER)


def test_corrupt_header_is_not_reported_as_missing(tmp_path):
    store = tmp_path / "store"
    store.write_bytes(b"XXXX" + _KEY)
    with pytest.raises(ProtectedStoreError) as excinfo:
        read_protected(store, header=_HEADER)
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_wrong_key_length_is_not_reported_as_missing(tmp_path):
    store = tmp_path / "store"
    store.write_bytes(_HEADER + b"short")
    with pytest.raises(ProtectedStoreError) as excinfo:
        read_protected(store, header=_HEADER)
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_read_protected_round_trips(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    assert read_protected(store, header=_HEADER) == _KEY


# --------------------------------------------------------------------------
# read_protected: the permission check is POSIX-only
# --------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_group_or_other_access_is_refused_on_posix(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o640)
    with pytest.raises(ProtectedStoreError, match="0600|group|other"):
        read_protected(store, header=_HEADER)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_owner_only_modes_are_accepted_on_posix(tmp_path):
    for mode in (0o600, 0o400, 0o700):
        store = tmp_path / f"store-{mode:o}"
        write_protected(_KEY, store, header=_HEADER)
        store.chmod(mode)
        assert read_protected(store, header=_HEADER) == _KEY


def test_synthesised_windows_mode_is_not_refused(tmp_path, monkeypatch):
    """Windows reports 0o666 for a writable file whatever its ACL."""
    monkeypatch.setattr(custody, "IS_WINDOWS", True)
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o666)
    assert read_protected(store, header=_HEADER) == _KEY


def test_posix_check_still_refuses_when_not_windows(monkeypatch, tmp_path):
    """Guard against the fix silently disabling the POSIX gate."""
    monkeypatch.setattr(custody, "IS_WINDOWS", False)
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o644)
    with pytest.raises(ProtectedStoreError):
        read_protected(store, header=_HEADER)


# --------------------------------------------------------------------------
# write_protected: never clobber an existing store
# --------------------------------------------------------------------------


def test_write_protected_refuses_to_overwrite(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    before = store.read_bytes()
    with pytest.raises(ProtectedStoreError, match="exist"):
        write_protected(b"\xff" * 32, store, header=_HEADER)
    assert store.read_bytes() == before


def test_write_protected_rejects_a_wrong_length_key(tmp_path):
    store = tmp_path / "store"
    with pytest.raises(ProtectedStoreError, match="32 bytes"):
        write_protected(b"too-short", store, header=_HEADER)
    assert not store.exists()


def test_write_protected_leaves_nothing_behind_when_the_write_fails(tmp_path, monkeypatch):
    """A failure mid-write must not leave a half-written key or a temp file."""
    store = tmp_path / "store"

    def explode(_fd):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(custody.os, "fsync", explode)
    with pytest.raises(OSError):
        write_protected(_KEY, store, header=_HEADER)

    assert not store.exists()
    assert list(tmp_path.glob(".*tmp")) == []


# --------------------------------------------------------------------------
# Providers: a corrupt store must never rotate the key
# --------------------------------------------------------------------------


def test_windows_dpapi_does_not_rotate_on_a_corrupt_store(tmp_path):
    store = tmp_path / "winstore"
    provider = WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy")
    provider.resolve_key(allow_create=True)

    # Corrupt the payload while keeping the store present.
    store.write_bytes(b"FLOORWV1" + b"not-a-valid-payload")
    corrupted = store.read_bytes()

    with pytest.raises(ProtectedStoreError):
        WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(allow_create=True)

    # The store must be byte-for-byte untouched: no rotation, no overwrite.
    assert store.read_bytes() == corrupted


def test_windows_dpapi_does_not_rotate_on_a_non_0600_store(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX permission bits")
    store = tmp_path / "winstore"
    provider = WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy")
    provider.resolve_key(allow_create=True)
    store.chmod(0o640)
    corrupted = store.read_bytes()

    with pytest.raises(ProtectedStoreError):
        WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(allow_create=True)
    assert store.read_bytes() == corrupted


def test_windows_dpapi_still_creates_when_genuinely_absent(tmp_path):
    store = tmp_path / "winstore"
    key = WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(
        allow_create=True
    )
    assert len(key.get_bytes()) == 32
    assert store.exists()


def test_windows_dpapi_fails_closed_when_absent_and_create_disallowed(tmp_path):
    from floorvault.providers.base import MissingKeyError

    store = tmp_path / "winstore"
    with pytest.raises(MissingKeyError):
        WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(
            allow_create=False
        )


def test_linux_provider_does_not_rotate_on_a_corrupt_store(tmp_path, monkeypatch):
    monkeypatch.setattr(linux_module, "_looks_interactive_desktop", lambda: False)
    store = tmp_path / "linuxstore"

    provider = linux_module.LinuxSecretServiceKeyProvider(store_path=store)
    provider.resolve_key(allow_create=True)

    store.write_bytes(b"FLOORLV1" + b"not-a-valid-payload")
    corrupted = store.read_bytes()

    with pytest.raises(ProtectedStoreError):
        linux_module.LinuxSecretServiceKeyProvider(store_path=store).resolve_key(allow_create=True)
    assert store.read_bytes() == corrupted

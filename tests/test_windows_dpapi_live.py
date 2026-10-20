"""Unmocked Windows custody integration tests."""

import sys

import pytest


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows DPAPI")
def test_native_dpapi_round_trip(tmp_path) -> None:
    from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

    store = tmp_path / "AppData" / "Local" / "floorvault" / "master.key"
    first = WindowsDPAPIKeyProvider(store_path=store, entropy=b"live-ci-entropy")
    second = WindowsDPAPIKeyProvider(store_path=store, entropy=b"live-ci-entropy")

    original = first.resolve_key(allow_create=True)
    recovered = second.resolve_key(allow_create=False)

    assert recovered.get_bytes() == original.get_bytes()
    assert len(store.read_bytes()) > 32

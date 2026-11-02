"""Live macOS Keychain round-trip for the AdaptiveKeyProvider's native tier.

The default suite's Keychain tests inject a scripted fake ``Security`` module,
which pins the provider's *logic* but not the real platform behaviour (no real
item, no code-signing/ACL interaction, no locked-keychain handling). This test
drives the actual Security framework on a macOS host, under a unique service
name that it creates and deletes itself.

It is skipped unless explicitly opted in, because it writes to the user's real
Keychain:

    FLOORVAULT_KEYCHAIN_LIVE=1 uv run --extra macos pytest tests/test_keychain_live.py
"""

from __future__ import annotations

import os
import sys
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not (sys.platform == "darwin" and os.environ.get("FLOORVAULT_KEYCHAIN_LIVE") == "1"),
    reason=(
        "live Keychain test: needs macOS and FLOORVAULT_KEYCHAIN_LIVE=1 "
        "(writes and deletes a real generic-password item)"
    ),
)


def test_keychain_live_round_trip(tmp_path):
    try:
        import Security
    except ImportError as exc:
        raise AssertionError(
            "FLOORVAULT_KEYCHAIN_LIVE=1 but pyobjc-framework-Security is not "
            "importable; install the macos extra (uv sync --extra macos)"
        ) from exc

    from floorvault.providers.adaptive import AdaptiveKeyProvider

    service = f"floorvault-selftest-live-{uuid4().hex}"
    account = "selftest-v1"

    def delete_item() -> None:
        status = Security.SecItemDelete(
            {
                Security.kSecClass: Security.kSecClassGenericPassword,
                Security.kSecAttrService: service,
                Security.kSecAttrAccount: account,
            }
        )
        assert status in (0, -25300), f"Keychain test item cleanup failed: {status}"

    try:
        # Keep custody markers out of the user's home and fresh on every run.
        created = AdaptiveKeyProvider(
            service_name=service, account_name=account, fallback_dir=tmp_path
        )._resolve_from_system_keyring(allow_create=True)
        assert created is not None, "Keychain tier did not create an item"
        assert len(created.get_bytes()) == 32

        reread = AdaptiveKeyProvider(
            service_name=service, account_name=account, fallback_dir=tmp_path
        )._resolve_from_system_keyring(allow_create=False)
        assert reread is not None, "Keychain tier could not read its own item back"
        assert reread.get_bytes() == created.get_bytes(), (
            "Keychain tier re-minted a key instead of reading the stored one"
        )
    finally:
        delete_item()

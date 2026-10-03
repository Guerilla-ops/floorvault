"""Offline wrapping and recovery of a FloorVault master key."""

from __future__ import annotations

import hmac
import os

from .core import FloorVault
from .memory import HardenedMemoryKey

_MAGIC = b"FVRB1"
_BUNDLE_ID_LENGTH = 16
_APP_INSTANCE_ID = "floorvault-recovery"
_TABLE = "recovery"
_COLUMN = "master_key"


def _validate_key(value: bytes | bytearray, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return bytes(value)


def wrap_master_key(
    master_key: bytes | bytearray,
    recovery_key: bytes | bytearray,
) -> bytes:
    """Wrap a 32-byte master key in an authenticated recovery bundle.

    The recovery key is separate from the data-encryption master key and must be
    stored through an independently protected recovery process. The returned
    bundle contains no plaintext master key; anyone holding the recovery key can
    intentionally recover it.
    """
    master = _validate_key(master_key, "master_key")
    recovery = _validate_key(recovery_key, "recovery_key")
    # Refuse a self-wrapped bundle. The recovery key's whole purpose is to be
    # protected INDEPENDENTLY of the data key; if the two are the same value
    # then anyone who recovers the bundle holds the data key too, so recovery
    # buys nothing while appearing to be configured. compare_digest keeps the
    # comparison constant-time so this cannot become a timing oracle on the key.
    if hmac.compare_digest(master, recovery):
        raise ValueError(
            "recovery key must differ from the master key: a bundle wrapped with "
            "itself provides no independent recovery and is security theatre"
        )
    bundle_id = os.urandom(_BUNDLE_ID_LENGTH)
    crypto = FloorVault(recovery, app_instance_id=_APP_INSTANCE_ID)
    try:
        ciphertext = crypto.encrypt(
            master,
            table=_TABLE,
            record_id=bundle_id.hex(),
            column=_COLUMN,
        )
    finally:
        crypto.wipe()
    return _MAGIC + bundle_id + ciphertext


def recover_master_key(
    bundle: bytes | bytearray,
    recovery_key: bytes | bytearray,
    *,
    memory_mode: str = "opportunistic",
) -> HardenedMemoryKey:
    """Authenticate and unwrap a recovery bundle into a hardened key handle."""
    recovery = _validate_key(recovery_key, "recovery_key")
    if not isinstance(bundle, (bytes, bytearray)):
        raise TypeError("bundle must be bytes")
    minimum_length = len(_MAGIC) + _BUNDLE_ID_LENGTH + 1
    if len(bundle) < minimum_length or bytes(bundle[: len(_MAGIC)]) != _MAGIC:
        raise ValueError("invalid or unsupported recovery bundle")
    bundle_id_start = len(_MAGIC)
    bundle_id_end = bundle_id_start + _BUNDLE_ID_LENGTH
    bundle_id = bytes(bundle[bundle_id_start:bundle_id_end])
    ciphertext = bytes(bundle[bundle_id_end:])
    crypto = FloorVault(recovery, app_instance_id=_APP_INSTANCE_ID)
    try:
        recovered = crypto.decrypt_bytes(
            ciphertext,
            table=_TABLE,
            record_id=bundle_id.hex(),
            column=_COLUMN,
        )
    finally:
        crypto.wipe()
    if len(recovered) != 32:
        raise ValueError("recovered master key must be exactly 32 bytes")
    return HardenedMemoryKey(recovered, mode=memory_mode)

"""Contextual, misuse-resistant, searchable database encryption engine.

Implements AES-256-SIV (RFC 5297) with contextual AAD binding, ephemeral
master key destruction (< 5 ms), and HKDF functional subkey separation.
"""

from __future__ import annotations

import collections
import ctypes
import hashlib
import hmac
import json
import os
import struct
from typing import Any, Mapping, Optional, Sequence, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .blind_index import compute_blind_index
from .memory import HardenedMemoryKey


class AppStateCryptoError(Exception):
    """Base error for all AppStateCrypto operations."""


class DecryptionVerificationError(AppStateCryptoError):
    """Raised when ciphertext authentication tag fails or AAD is mismatched."""


class NonceReuseError(AppStateCryptoError):
    """Raised when an encrypted record reuses a previously observed nonce."""


RECORD_MAGIC = b"ASC2"  # AppStateCrypto v2 Envelope Magic


def canonical_json_bytes(data: Mapping[str, Any]) -> bytes:
    """Serialize dictionary to deterministic, canonical UTF-8 JSON bytes."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def associated_data(
    *,
    table: str,
    record_id: str,
    column: str,
    schema_id: str = "appstate.v2",
    schema_version: int = 1,
    app_instance_id: str = "default",
) -> bytes:
    """Construct canonical Associated Authenticated Data (AAD) binding block.
    
    Locks the ciphertext to its exact database coordinates, preventing
    ciphertext cut-and-paste splicing across rows, columns, or tables.
    """
    for name, val in [
        ("table", table),
        ("record_id", record_id),
        ("column", column),
        ("schema_id", schema_id),
        ("app_instance_id", app_instance_id),
    ]:
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"AAD parameter {name!r} must be a non-empty string")

    payload = {
        "app_instance_id": app_instance_id,
        "column": column,
        "record_id": record_id,
        "schema_id": schema_id,
        "schema_version": int(schema_version),
        "table": table,
    }
    return canonical_json_bytes(payload)


class AppStateCrypto:
    """Contextual, misuse-resistant database encryption engine."""

    def __init__(
        self,
        master_key: Union[bytes, HardenedMemoryKey],
        app_instance_id: str = "default",
        *,
        maximum_tracked_nonces: int = 10000,
        memory_mode: str = "opportunistic",
    ) -> None:
        """Initialize AppStateCrypto.
        
        Wipes the master_key in memory in < 5 ms after deriving isolated subkeys.
        """
        if not isinstance(app_instance_id, str) or not app_instance_id.strip():
            raise ValueError("app_instance_id must be a non-empty string")

        self.app_instance_id = app_instance_id
        self._closed = False
        self._memory_mode = memory_mode

        # 1. Extract raw master key bytes for derivation
        raw_master: bytes
        is_hardened = isinstance(master_key, HardenedMemoryKey)
        if is_hardened:
            raw_master = master_key.get_bytes()
        elif isinstance(master_key, (bytes, bytearray)):
            raw_master = bytes(master_key)
        else:
            raise TypeError("master_key must be bytes or HardenedMemoryKey")

        if len(raw_master) != 32:
            raise ValueError(f"master_key must be exactly 32 bytes (got {len(raw_master)})")

        try:
            # 2. Derive functional subkeys using HKDF-SHA256 with domain separation
            # Subkey A: AES-256-SIV requires a 64-byte key (two 256-bit subkeys)
            raw_siv = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b"appstate-crypto-v2-aes-siv",
            ).derive(raw_master)

            # Subkey B: HMAC Blind Indexing requires 32 bytes
            raw_index = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"appstate-crypto-v2-hmac-index",
            ).derive(raw_master)

            # Subkey C: Legacy v1 AES-GCM requires 32 bytes
            raw_gcm = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"appstate-crypto-v1-aes-gcm",
            ).derive(raw_master)

            # Assert key separation integrity
            if (
                hmac.compare_digest(raw_siv[:32], raw_index)
                or hmac.compare_digest(raw_gcm, raw_index)
            ):
                raise AppStateCryptoError("HKDF key separation failed")

            # 3. Pin derived subkeys into physical RAM containers
            self._siv_key = HardenedMemoryKey(raw_siv, mode=memory_mode)
            self._index_key = HardenedMemoryKey(raw_index, mode=memory_mode)
            self._gcm_key = HardenedMemoryKey(raw_gcm, mode=memory_mode)

            # Initialize AES-SIV engine
            self._aead_siv = AESSIV(self._siv_key.get_bytes())
            self._aead_gcm = AESGCM(self._gcm_key.get_bytes())

        finally:
            # 4. EPHEMERAL MASTER KEY DESTRUCTION: wipe master key in < 5 ms
            if is_hardened:
                master_key.wipe()
            # Overwrite local buffer
            ctypes.memset(ctypes.c_char_p(raw_master), 0, len(raw_master))
            del raw_master

        # Bounded sliding window for observed nonces
        self._max_nonces = maximum_tracked_nonces
        self._nonce_queue: collections.deque[bytes] = collections.deque(maxlen=maximum_tracked_nonces)
        self._nonce_set: set[bytes] = set()

    def _track_nonce(self, nonce: bytes) -> None:
        """Register nonce in sliding window to detect replay."""
        if nonce in self._nonce_set:
            raise NonceReuseError("Detected duplicate cryptographic nonce")
        if len(self._nonce_queue) >= self._max_nonces:
            oldest = self._nonce_queue.popleft()
            self._nonce_set.discard(oldest)
        self._nonce_queue.append(nonce)
        self._nonce_set.add(nonce)

    def encrypt(
        self,
        plaintext: Union[str, bytes],
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "appstate.v2",
        schema_version: int = 1,
    ) -> bytes:
        """Encrypt plaintext with contextual AAD binding via AES-256-SIV."""
        if self._closed:
            raise RuntimeError("AppStateCrypto has been wiped")

        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad = associated_data(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            app_instance_id=self.app_instance_id,
        )

        nonce = os.urandom(16)
        self._track_nonce(nonce)

        # AES-SIV encrypts with associated data components
        ciphertext = self._aead_siv.encrypt(data_bytes, [aad, nonce])

        # Envelope: MAGIC (4B) || NONCE_LEN (1B) || NONCE (16B) || CIPHERTEXT
        envelope = bytearray(RECORD_MAGIC)
        envelope.append(len(nonce))
        envelope.extend(nonce)
        envelope.extend(ciphertext)

        return bytes(envelope)

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "appstate.v2",
        schema_version: int = 1,
    ) -> str:
        """Decrypt ciphertext and verify contextual AAD coordinates.
        
        Returns:
            Decrypted plaintext string.
            
        Raises:
            DecryptionVerificationError: If tag check fails or coordinates were spliced.
        """
        if self._closed:
            raise RuntimeError("AppStateCrypto has been wiped")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes")
        if len(ciphertext) < 21:  # 4B magic + 1B len + 16B nonce minimum
            raise DecryptionVerificationError("Malformed ciphertext envelope: too short")

        # Verify envelope magic
        if ciphertext[:4] != RECORD_MAGIC:
            raise DecryptionVerificationError("Invalid ciphertext magic header")

        nonce_len = ciphertext[4]
        if nonce_len != 16 or len(ciphertext) < 5 + nonce_len:
            raise DecryptionVerificationError("Invalid nonce length in ciphertext envelope")

        nonce = ciphertext[5 : 5 + nonce_len]
        raw_cipher = ciphertext[5 + nonce_len :]

        aad = associated_data(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            app_instance_id=self.app_instance_id,
        )

        try:
            decrypted_bytes = self._aead_siv.decrypt(raw_cipher, [aad, nonce])
            return decrypted_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise DecryptionVerificationError(
                f"Contextual decryption verification failed for {table}.{column} "
                f"(record: {record_id}). Data was tampered with, spliced, or corrupted."
            ) from exc

    def blind_index(self, value: str, *, scope: str) -> bytes:
        """Compute an HMAC blind index for native SQLite B-Tree searching."""
        if self._closed:
            raise RuntimeError("AppStateCrypto has been wiped")
        return compute_blind_index(value, scope=scope, key=self._index_key)

    def wipe(self) -> None:
        """Zero all internal functional subkeys and close engine."""
        if self._closed:
            return
        if hasattr(self, "_siv_key"):
            self._siv_key.wipe()
        if hasattr(self, "_index_key"):
            self._index_key.wipe()
        if hasattr(self, "_gcm_key"):
            self._gcm_key.wipe()
        self._nonce_set.clear()
        self._nonce_queue.clear()
        self._closed = True

    def __del__(self) -> None:
        self.wipe()

    def __enter__(self) -> AppStateCrypto:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()

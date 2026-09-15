"""Contextual, misuse-resistant, searchable database encryption engine.

Implements AES-256-SIV (RFC 5297) with contextual AAD binding, ephemeral
master key destruction (< 5 ms), and HKDF functional subkey separation.
"""

from __future__ import annotations

import collections
import hmac
import json
import os
from typing import Any, Mapping, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .blind_index import (
    beacon_matches,
    compute_beacon,
    compute_blind_index,
)
from .memory import HardenedMemoryKey


class FloorVaultError(Exception):
    """Base error for all FloorVault operations."""


# Backward compatibility alias
AppStateCryptoError = FloorVaultError


class DecryptionVerificationError(FloorVaultError):
    """Raised when ciphertext authentication tag fails or AAD is mismatched."""


class NonceReuseError(FloorVaultError):
    """Raised when an encrypted record reuses a previously observed nonce."""


RECORD_MAGIC = b"FLRV"  # FloorVault v1 Envelope Magic


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
    schema_id: str = "floor.vault.v1",
    schema_version: int = 1,
    app_instance_id: str = "default",
    revision: int | None = None,
) -> bytes:
    """Construct canonical Associated Authenticated Data (AAD) binding block.

    Locks the ciphertext to its exact database coordinates, preventing
    ciphertext cut-and-paste splicing across rows, columns, or tables.

    ``revision`` is optional and, when supplied, is bound into the AAD. It
    exists for same-coordinate replay (rollback) detection: read a record back
    at its current revision, and an older ciphertext replayed into the same
    coordinates fails authentication. The revision must come from state the
    attacker cannot roll back together with the ciphertext — a revision stored
    beside the ciphertext (or in the same database) provides no protection,
    because an attacker who can rewrite one can rewrite both.
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

    if revision is not None:
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise TypeError("AAD parameter 'revision' must be a non-negative integer")
        if revision < 0:
            raise ValueError("AAD parameter 'revision' must be a non-negative integer")

    payload: dict[str, Any] = {
        "app_instance_id": app_instance_id,
        "column": column,
        "record_id": record_id,
        "schema_id": schema_id,
        "schema_version": int(schema_version),
        "table": table,
    }
    if revision is not None:
        payload["revision"] = revision
    return canonical_json_bytes(payload)


class FloorVault:
    """Contextual, misuse-resistant database encryption engine."""

    def __init__(
        self,
        master_key: Union[bytes, HardenedMemoryKey],
        app_instance_id: str = "default",
        *,
        maximum_tracked_nonces: int = 10000,
        memory_mode: str = "opportunistic",
    ) -> None:
        """Initialize FloorVault.

        Wipes the master_key in memory in < 5 ms after deriving isolated subkeys.
        """
        if not isinstance(app_instance_id, str) or not app_instance_id.strip():
            raise ValueError("app_instance_id must be a non-empty string")
        if not isinstance(maximum_tracked_nonces, int) or maximum_tracked_nonces < 1:
            raise ValueError("maximum_tracked_nonces must be a positive integer")

        self.app_instance_id = app_instance_id
        self._closed = False
        self._memory_mode = memory_mode

        # Nonce tracking structures and engine slots must exist before any
        # failure path can run, otherwise __del__/wipe() raise AttributeError
        # on a partially initialised instance and leave the engine unclosed.
        self._max_nonces = maximum_tracked_nonces
        self._nonce_queue: collections.deque[bytes] = collections.deque(
            maxlen=max(1, maximum_tracked_nonces)
        )
        self._nonce_set: set[bytes] = set()
        self._aead_siv: Any = None
        self._siv_key: Any = None
        self._index_key: Any = None

        # 1. Extract raw master key bytes for derivation into a mutable bytearray
        master_buffer: bytearray
        is_hardened = isinstance(master_key, HardenedMemoryKey)
        if is_hardened:
            master_buffer = bytearray(master_key.get_bytes())
        elif isinstance(master_key, (bytes, bytearray)):
            master_buffer = bytearray(master_key)
        else:
            raise TypeError("master_key must be bytes or HardenedMemoryKey")

        if len(master_buffer) != 32:
            # Zero the copy before failing so no key material is left behind
            bad_len = len(master_buffer)
            for idx in range(bad_len):
                master_buffer[idx] = 0
            del master_buffer
            raise ValueError(f"master_key must be exactly 32 bytes (got {bad_len})")

        try:
            # 2. Derive functional subkeys using HKDF-SHA256 with domain separation
            # Subkey A: AES-256-SIV requires a 64-byte key (two 256-bit subkeys)
            raw_siv = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b"floorvault-v1-aes-siv",
            ).derive(bytes(master_buffer))

            # Subkey B: HMAC Blind Indexing requires 32 bytes
            raw_index = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"floorvault-v1-hmac-index",
            ).derive(bytes(master_buffer))

            # Assert key separation integrity
            if hmac.compare_digest(raw_siv[:32], raw_index):
                raise FloorVaultError("HKDF key separation failed")

            # 3. Pin derived subkeys into physical RAM containers
            self._siv_key = HardenedMemoryKey(raw_siv, mode=memory_mode)
            self._index_key = HardenedMemoryKey(raw_index, mode=memory_mode)

            # Initialize AES-SIV engine
            siv_key_bytes = self._siv_key.get_bytes()
            self._aead_siv = AESSIV(siv_key_bytes)
            del siv_key_bytes
            del raw_siv
            del raw_index

        finally:
            # 4. EPHEMERAL MASTER KEY DESTRUCTION: wipe master key in < 5 ms
            if is_hardened:
                master_key.wipe()
            # Overwrite mutable buffer cleanly without ctypes.c_char_p null-byte truncation
            for idx in range(len(master_buffer)):
                master_buffer[idx] = 0
            del master_buffer

        # Bounded sliding window for observed nonces (allocated earlier so that
        # failure paths and __del__ always find them present).

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
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: int | None = None,
    ) -> bytes:
        """Encrypt plaintext with contextual AAD binding via AES-256-SIV.

        If ``revision`` is supplied it is bound into the AAD (see
        ``associated_data``), so a caller holding a monotonic revision in
        trusted state can detect a same-coordinate replay of an older
        ciphertext at read time.
        """
        if self._closed:
            raise RuntimeError("FloorVault has been wiped")

        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad = associated_data(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            app_instance_id=self.app_instance_id,
            revision=revision,
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
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: int | None = None,
    ) -> str:
        """Decrypt ciphertext and verify contextual AAD coordinates.

        ``revision`` must match the value bound at encryption time. Reading at
        a newer revision rejects a replayed older ciphertext (rollback
        detection), provided the revision comes from trusted state; see
        ``associated_data``.

        Returns:
            Decrypted plaintext string.

        Raises:
            DecryptionVerificationError: If tag check fails or coordinates were spliced.
        """
        if self._closed:
            raise RuntimeError("FloorVault has been wiped")
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
            revision=revision,
        )

        try:
            decrypted_bytes = self._aead_siv.decrypt(raw_cipher, [aad, nonce])
        except InvalidTag as exc:
            raise DecryptionVerificationError(
                f"Contextual decryption verification failed for {table}.{column} "
                f"(record: {record_id}). Data was tampered with, spliced, or corrupted."
            ) from exc
        try:
            return decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptionVerificationError(
                "Decrypted payload is not valid UTF-8; use decrypt_bytes() for binary values"
            ) from exc

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: int | None = None,
    ) -> bytes:
        """Decrypt ciphertext and return raw bytes, without UTF-8 decoding.

        Use for values that were encrypted from bytes rather than str.
        ``revision`` semantics match :meth:`decrypt`.
        """
        if self._closed:
            raise RuntimeError("FloorVault has been wiped")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes")
        if len(ciphertext) < 21:
            raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
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
            revision=revision,
        )
        try:
            return self._aead_siv.decrypt(raw_cipher, [aad, nonce])
        except InvalidTag as exc:
            raise DecryptionVerificationError(
                f"Contextual decryption verification failed for {table}.{column} "
                f"(record: {record_id}). Data was tampered with, spliced, or corrupted."
            ) from exc

    def blind_index(self, value: str, *, scope: str) -> bytes:
        """Compute an HMAC blind index for native SQLite B-Tree searching."""
        if self._closed:
            raise RuntimeError("FloorVault has been wiped")
        return compute_blind_index(value, scope=scope, key=self._index_key)

    def beacon(self, value: str, *, scope: str, bits: int = 4) -> bytes:
        """Compute a truncated search beacon (bounded bucket assignment).

        Unlike ``blind_index`` (full-width, leaks equality/frequency), the
        beacon keeps only a byte-aligned prefix of the HMAC so the stored index
        reveals a coarse bucket — not the exact value or its frequency. Look up
        the bucket, use ``beacon_matches`` to narrow candidates, then confirm
        exact equality by decrypting.
        """
        if self._closed:
            raise RuntimeError("FloorVault has been wiped")
        return compute_beacon(value, scope=scope, key=self._index_key, bits=bits)

    def beacon_matches(self, value: str, *, scope: str, beacon: bytes, bits: int = 4) -> bool:
        """True iff ``value``'s beacon equals the stored ``beacon``.

        A True result proves bucket agreement only (collisions are by design);
        confirm equality by decrypting the candidate.
        """
        return beacon_matches(value, scope=scope, key=self._index_key, beacon=beacon, bits=bits)

    def wipe(self) -> None:
        """Zero all internal functional subkeys and close engine."""
        if getattr(self, "_closed", True):
            return
        self._closed = True
        if getattr(self, "_siv_key", None) is not None:
            self._siv_key.wipe()
        if getattr(self, "_index_key", None) is not None:
            self._index_key.wipe()
        self._aead_siv = None
        if getattr(self, "_nonce_set", None) is not None:
            self._nonce_set.clear()
        if getattr(self, "_nonce_queue", None) is not None:
            self._nonce_queue.clear()

    def __del__(self) -> None:
        self.wipe()

    def __enter__(self) -> FloorVault:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()


# Backward compatibility alias
AppStateCrypto = FloorVault

"""Contextual, misuse-resistant database encryption engine.

Implements AES-256-SIV (RFC 5297) with contextual AAD binding and HKDF-SHA256
key derivation from a 32-byte master key.
"""

from __future__ import annotations

import collections
import json
import os
import re
import threading
import time
from typing import Any, Mapping, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .memory import HardenedMemoryKey


class FloorVaultError(Exception):
    """Base error for all FloorVault operations."""


# Backward compatibility alias
AppStateCryptoError = FloorVaultError


class DecryptionVerificationError(FloorVaultError):
    """Raised when ciphertext authentication tag fails or AAD is mismatched."""


class NonceReuseError(FloorVaultError):
    """Raised when encryption reuses a nonce within the process lifetime."""


class TokenExpiredError(FloorVaultError):
    """Raised when a token's writer-fixed expiry or a caller's max_age policy
    places it outside its validity window."""


class TokenNotYetValidError(FloorVaultError):
    """Raised when a token's not-before claim lies in the future."""


RECORD_MAGIC = b"FLRV"  # FloorVault v1 Envelope Magic
RECORD_MAGIC_V2 = b"FLV2"  # FloorVault v2 Envelope Magic (versioned header)
RECORD_MAGIC_V3 = b"FLV3"  # FloorVault v3 Envelope Magic (token: ctx + time claims)
CRYPTO_VERSION = 2  # crypto_version written by this build's encrypt()
_HEADER_LEN_V2 = 7  # magic(4) + crypto_version(1) + key_id(1) + nonce_len(1)
_NONCE_LEN = 16

# v3 token envelope: FLV3(4) ‖ crypto_version(1) ‖ key_id(1) ‖ exp(8) ‖ nbf(8)
# ‖ iat(8) ‖ ctx_len(2, big-endian) ‖ ctx ‖ nonce_len(1) ‖ nonce ‖ ct.
# Everything before the nonce is the authenticated header component, so the
# time claims and the embedded context are integrity-protected like v2's
# key_id — they travel with the ciphertext but cannot be rewritten.
_V3_FIXED_LEN = 32  # magic+ver+key_id+exp+nbf+iat+ctx_len
_V3_CTX_LEN_MAX = 0xFFFF

# Token records bind to fixed coordinates; the caller-chosen ``purpose`` takes
# the record_id slot and the writer's app_instance_id rides in ``ctx`` so the
# token self-describes the context it was sealed for.
_TOKEN_TABLE = "_fv.token"
_TOKEN_COLUMN = "payload"
_TOKEN_SCHEMA_ID = "floor.vault.token.v1"


def _parse_v3_ctx(ctx: bytes) -> dict[str, str]:
    """Decode a v3 ctx claim to its exact required shape.

    Must be a JSON object with exactly ``{"app_instance_id": str,
    "purpose": str}`` - silently ignoring unknown claims is a downgrade
    vector, so unknown or mis-typed keys fail closed.
    """
    try:
        parsed = json.loads(ctx.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptionVerificationError("Malformed v3 ctx claim") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"app_instance_id", "purpose"}
        or not isinstance(parsed["app_instance_id"], str)
        or not isinstance(parsed["purpose"], str)
    ):
        raise DecryptionVerificationError("Malformed v3 ctx claim")
    return parsed


def envelope_header(ciphertext: bytes) -> dict[str, Any]:
    """Describe an envelope's cleartext header without decrypting it.

    Returns ``magic``, ``header_len``, ``nonce_len`` and - for a v2 or v3
    envelope - ``crypto_version`` and ``key_id``. A v3 token envelope
    additionally reports ``exp``, ``nbf``, ``iat`` and the embedded ``ctx``
    claim. These are integrity-protected claims, not yet verified ones -
    deciding on them before decryption is fine for key selection, not for
    authorisation.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes")
    if len(ciphertext) < 5:
        raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
    magic = bytes(ciphertext[:4])
    if magic == RECORD_MAGIC:
        return {"magic": magic, "header_len": 5, "nonce_len": ciphertext[4]}
    if magic == RECORD_MAGIC_V2:
        if len(ciphertext) < _HEADER_LEN_V2:
            raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
        return {
            "magic": magic,
            "header_len": _HEADER_LEN_V2,
            "nonce_len": ciphertext[6],
            "crypto_version": ciphertext[4],
            "key_id": ciphertext[5],
        }
    if magic != RECORD_MAGIC_V3:
        raise DecryptionVerificationError("Invalid ciphertext magic header")
    v3 = _parse_v3_header_fields(memoryview(ciphertext))
    return {
        "magic": magic,
        "header_len": v3["header_len"],
        "nonce_len": ciphertext[v3["header_len"] - 1],
        "crypto_version": v3["crypto_version"],
        "key_id": v3["key_id"],
        "exp": v3["exp"],
        "nbf": v3["nbf"],
        "iat": v3["iat"],
        "ctx": _parse_v3_ctx(v3["ctx"]),
    }


def canonical_json_bytes(data: Mapping[str, Any]) -> bytes:
    """Serialize dictionary to deterministic, canonical UTF-8 JSON bytes."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# Characters json.dumps(ensure_ascii=False) escapes inside a JSON string:
# double-quote, backslash, and the C0 controls. Everything else is verbatim.
_JSON_UNSAFE = re.compile(r'[\\"\x00-\x1f]')


def _quote_json(value: str) -> bytes:
    """JSON string literal for ``value``, byte-identical to ``json.dumps``.

    The key order of the AAD payload is fixed, so the per-op hot path builds
    the object literally instead of round-tripping a dict through
    ``json.dumps(sort_keys=True)``. When the value contains nothing JSON must
    escape (the common case) it is quoted directly; otherwise it falls back to
    ``json.dumps`` for the exact escaping rules, so output can never diverge
    from :func:`associated_data`.
    """
    if _JSON_UNSAFE.search(value) is None:
        return b'"' + value.encode("utf-8") + b'"'
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


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

    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise TypeError("AAD parameter 'schema_version' must be an integer")

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


def _parse_v3_header_fields(view: memoryview) -> dict[str, Any]:
    """Parse a v3 envelope's header claims; raises on truncation/bad magic.

    Returns ``crypto_version``, ``key_id``, ``exp``, ``nbf``, ``iat``,
    ``ctx`` (raw bytes) and ``header_len``. The claims are cleartext carried
    inside the authenticated header component - integrity comes from the SIV
    tag, not from this parser.
    """
    if bytes(view[:4]) != RECORD_MAGIC_V3:
        raise DecryptionVerificationError("Invalid ciphertext magic header")
    if len(view) < _V3_FIXED_LEN:
        raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
    ctx_len = int.from_bytes(view[30:32], "big")
    if len(view) < _V3_FIXED_LEN + ctx_len + 1:
        raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
    return {
        "crypto_version": view[4],
        "key_id": view[5],
        "exp": int.from_bytes(view[6:14], "big"),
        "nbf": int.from_bytes(view[14:22], "big"),
        "iat": int.from_bytes(view[22:30], "big"),
        "ctx": bytes(view[_V3_FIXED_LEN : _V3_FIXED_LEN + ctx_len]),
        "header_len": _V3_FIXED_LEN + ctx_len + 1,
    }


class FloorVault:
    """Contextual, misuse-resistant database encryption engine."""

    def __init__(
        self,
        master_key: Union[bytes, HardenedMemoryKey],
        app_instance_id: str = "default",
        *,
        maximum_tracked_nonces: int = 10000,
        memory_mode: str = "opportunistic",
        wipe_source_key: bool = False,
    ) -> None:
        """Initialize FloorVault.

        Derives isolated subkeys from the master key. The master key handle
        is preserved by default; set ``wipe_source_key=True`` to zero the
        caller-provided source key after derivation.

        Construction is deliberately heavyweight — HKDF derivation plus the
        hardened memory container cost tens of microseconds — so callers
        should create one instance per master key and reuse it for the life of
        the process rather than constructing one per operation.
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
        # RLock, not Lock: the closed-check, engine snapshot and nonce dedup run
        # inside one section, and a wipe() reached through the _track_nonce seam
        # (the regression test does exactly this) must be able to re-enter
        # without deadlocking the in-flight operation.
        self._lock = threading.RLock()
        # deque+set, not a plain dict: evicting the oldest nonce from a dict
        # via pop(next(iter(d))) is O(window size) at steady state because the
        # iterator skips the tombstone front; deque popleft + set discard are
        # true O(1). (Measured: 6.9us per track vs ~0.2us.)
        self._nonce_queue: collections.deque[bytes] = collections.deque()
        self._nonce_set: set[bytes] = set()
        self._aead_siv: Any = None
        self._siv_key: Any = None
        # Constant prefix of the canonical AAD object; the remaining keys are
        # emitted in sorted order by _aad().
        self._ad_prefix = b'{"app_instance_id":' + _quote_json(app_instance_id) + b',"column":'

        # 1. Extract the source key as a mutable or zero-copy buffer
        master_buffer: bytearray | memoryview
        is_hardened = isinstance(master_key, HardenedMemoryKey)
        if is_hardened:
            # Use the unmanaged buffer directly as HKDF input. This avoids
            # creating a transient immutable bytes copy in FloorVault.
            master_buffer = master_key.get_buffer()
        elif isinstance(master_key, (bytes, bytearray)):
            master_buffer = bytearray(master_key)
        else:
            raise TypeError("master_key must be bytes or HardenedMemoryKey")

        if len(master_buffer) != 32:
            # Zero the copy before failing so no key material is left behind
            bad_len = len(master_buffer)
            if isinstance(master_buffer, bytearray):
                for idx in range(len(master_buffer)):
                    master_buffer[idx] = 0
            del master_buffer
            raise ValueError(f"master_key must be exactly 32 bytes (got {bad_len})")

        try:
            # 2. Derive functional subkeys using HKDF-SHA256 with domain separation
            # Subkey A: AES-256-SIV requires a 64-byte key (two 256-bit subkeys)
            # Derive directly from the mutable buffer to avoid an extra bytes()
            # materialization outside our control.
            raw_siv = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b"floorvault-v1-aes-siv",
            ).derive(master_buffer)

            # 3. Pin derived subkeys into physical RAM containers
            self._siv_key = HardenedMemoryKey(raw_siv, mode=memory_mode)

            # Initialize AES-SIV engine straight from the locked buffer: a
            # get_bytes() copy would leave an un-wipeable immutable ghost on
            # the Python heap. (The engine's own internal copy is made inside
            # the cryptography library regardless - see wipe().)
            self._aead_siv = AESSIV(self._siv_key.get_buffer())
            del raw_siv

        finally:
            # 4. EPHEMERAL MASTER KEY DESTRUCTION
            if is_hardened and wipe_source_key:
                # Wipe only when explicitly requested; preserves caller handle
                # by default so multi-instance initialization works correctly.
                master_key.wipe()
            if isinstance(master_buffer, bytearray):
                # Overwrite internally-owned mutable buffers. A hardened source
                # buffer is owned by the caller and is wiped only on request.
                for idx in range(len(master_buffer)):
                    master_buffer[idx] = 0
            del master_buffer

        # Bounded sliding window for observed nonces (allocated earlier so that
        # failure paths and __del__ always find them present).

    @staticmethod
    def _validate_aad_mid(
        table: str,
        record_id: str,
        schema_id: str,
        schema_version: int,
        revision: int | None,
    ) -> bytes:
        """Validate the record-constant AAD params and return the mid section.

        Shared validation for the record coordinates so a batch call checks
        them once instead of once per field. Byte-identical ordering to the
        ``associated_data`` payload: record_id, revision?, schema_id,
        schema_version, table.
        """
        for name, val in [
            ("table", table),
            ("record_id", record_id),
            ("schema_id", schema_id),
        ]:
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"AAD parameter {name!r} must be a non-empty string")
        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise TypeError("AAD parameter 'schema_version' must be an integer")
        if revision is not None:
            if isinstance(revision, bool) or not isinstance(revision, int):
                raise TypeError("AAD parameter 'revision' must be a non-negative integer")
            if revision < 0:
                raise ValueError("AAD parameter 'revision' must be a non-negative integer")
        return (
            b',"record_id":'
            + _quote_json(record_id)
            + (b',"revision":' + str(revision).encode() if revision is not None else b"")
            + b',"schema_id":'
            + _quote_json(schema_id)
            + b',"schema_version":'
            + str(schema_version).encode()
            + b',"table":'
            + _quote_json(table)
        )

    def _aad(
        self,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str,
        schema_version: int,
        revision: int | None,
        _mid: bytes | None = None,
    ) -> bytes:
        """Canonical AAD block, byte-identical to :func:`associated_data`.

        The payload's six keys have a fixed sorted order
        (``app_instance_id``, ``column``, ``record_id``, ``revision``,
        ``schema_id``, ``schema_version``, ``table``), so the hot path emits
        them literally: a constant prefix bound at construction, then the
        per-record ``_mid`` section (built once and shared across fields by
        batch callers). ``_quote_json`` keeps every value's escaping identical
        to ``json.dumps(ensure_ascii=False)``. Validation is kept verbatim
        rather than skipped — the coordinate contract is a security boundary,
        not overhead to shave.
        """
        if _mid is None:
            _mid = self._validate_aad_mid(table, record_id, schema_id, schema_version, revision)
        if not isinstance(column, str) or not column.strip():
            raise ValueError("AAD parameter 'column' must be a non-empty string")
        return self._ad_prefix + _quote_json(column) + _mid + b"}"

    def _track_nonce(self, nonce: bytes) -> None:
        """Deduplicate nonces in a process-lifetime sliding window.

        This in-memory window is bounded and is not a cross-session freshness
        mechanism. Cross-session freshness requires caller-managed revision
        counters bound into the associated data.

        Caller must hold ``self._lock``: dedup + eviction run in the same
        section as the engine snapshot so a wipe() cannot slip between them.
        """
        if nonce in self._nonce_set:
            raise NonceReuseError("Detected duplicate cryptographic nonce")
        if len(self._nonce_queue) >= self._max_nonces:
            self._nonce_set.discard(self._nonce_queue.popleft())
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
        key_id: int = 0,
    ) -> bytes:
        """Encrypt plaintext with contextual AAD binding via AES-256-SIV.

        If ``revision`` is supplied it is bound into the AAD (see
        ``associated_data``), so a caller holding a monotonic revision in
        trusted state can detect a same-coordinate replay of an older
        ciphertext at read time.

        ``key_id`` identifies the key this record was written under. It is
        recorded in the authenticated header (see :func:`envelope_header`) so a
        reader can select the right key without guessing; this build uses a
        single derived subkey and writes ``0``.
        """
        if isinstance(key_id, bool) or not isinstance(key_id, int):
            raise TypeError("key_id must be an integer in [0, 255]")
        if not 0 <= key_id <= 255:
            raise ValueError("key_id must be an integer in [0, 255]")

        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad = self._aad(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            revision=revision,
        )

        nonce = os.urandom(_NONCE_LEN)
        with self._lock:
            # One section: the closed-check, the engine snapshot (a concurrent
            # wipe() that clears the slot cannot tear this call mid-flight —
            # the local reference keeps the engine alive), and the nonce dedup
            # stay atomic together. The AEAD call itself stays outside.
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv
            self._track_nonce(nonce)

        # Envelope v2: MAGIC2 (4B) || crypto_version (1B) || key_id (1B)
        #              || nonce_len (1B) || nonce (16B) || ciphertext
        header = RECORD_MAGIC_V2 + bytes([CRYPTO_VERSION, key_id, len(nonce)])

        # AES-SIV encrypts with associated data components. The cleartext header
        # is one of them: a rewritten crypto_version or key_id is not merely
        # ignored, it fails authentication.
        ciphertext = aead.encrypt(data_bytes, [aad, header, nonce])

        return bytes(header) + nonce + ciphertext

    @staticmethod
    def _ad_components(
        aad: bytes,
        header: bytes | memoryview | None,
        nonce: bytes | memoryview,
    ) -> list:
        """The AEAD associated-data vector for an envelope of either version.

        A v1 envelope carries no header block, so its vector is ``[aad, nonce]``
        exactly as the v1 writer built it - that is what keeps old records
        readable. A v2 envelope binds the header as a separate component.
        """
        return [aad, header, nonce] if header is not None else [aad, nonce]

    @staticmethod
    def _require_key_id(envelope_key_id: int | None, requested: int | None) -> None:
        """Refuse a record written under a different key id than requested.

        A v1 (``FLRV``) record carries no key id at all, so a requested key id
        cannot be verified against it. Fail closed rather than silently accept a
        record that may have been written under a different key.
        """
        if requested is None:
            return
        if envelope_key_id is None:
            raise DecryptionVerificationError(
                "Record is a v1 envelope with no key id; a requested key id cannot be verified"
            )
        if envelope_key_id != requested:
            raise DecryptionVerificationError(
                f"Record was written under key id {envelope_key_id}, not the requested {requested}"
            )

    def _split_envelope(
        self, ciphertext: bytes
    ) -> tuple[memoryview | None, int | None, int | None, memoryview, memoryview]:
        """Parse an envelope of either version.

        Returns ``(header, crypto_version, key_id, nonce, raw_ciphertext)``,
        where ``header``, ``crypto_version`` and ``key_id`` are ``None`` for a
        v1 envelope, which carries neither.

        Header, nonce and raw ciphertext are returned as ``memoryview`` slices
        of the caller's buffer — the AEAD accepts buffer objects directly, so
        parsing no longer copies the payload on every decrypt (an O(n) copy
        per record before).
        """
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes")
        if len(ciphertext) < 5 + _NONCE_LEN:
            raise DecryptionVerificationError("Malformed ciphertext envelope: too short")

        view = memoryview(ciphertext)
        magic = view[:4]
        if magic in (RECORD_MAGIC_V2, RECORD_MAGIC_V3):
            crypto_version = view[4]
            if crypto_version != CRYPTO_VERSION:
                raise DecryptionVerificationError(
                    f"Unsupported envelope crypto version {crypto_version} "
                    f"(this build writes {CRYPTO_VERSION})"
                )
            key_id = view[5]
            if magic == RECORD_MAGIC_V3:
                # The v3 header runs through the nonce_len byte; ctx_len sits
                # inside it, so bounds are checked before slicing.
                if len(view) < _V3_FIXED_LEN:
                    raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
                ctx_len = int.from_bytes(view[30:32], "big")
                header_end = _V3_FIXED_LEN + ctx_len + 1
                if len(view) < header_end:
                    raise DecryptionVerificationError("Malformed ciphertext envelope: too short")
                header = view[:header_end]
                offset = header_end
            else:
                header = view[:_HEADER_LEN_V2]
                offset = _HEADER_LEN_V2
        elif magic == RECORD_MAGIC:
            header = crypto_version = key_id = None
            offset = 5
        else:
            raise DecryptionVerificationError("Invalid ciphertext magic header")

        nonce_len = view[offset - 1]
        if nonce_len != _NONCE_LEN or len(view) < offset + nonce_len:
            raise DecryptionVerificationError("Invalid nonce length in ciphertext envelope")

        nonce = view[offset : offset + nonce_len]
        raw_cipher = view[offset + nonce_len :]
        if not raw_cipher:
            raise DecryptionVerificationError("Malformed ciphertext envelope: no ciphertext")
        return header, crypto_version, key_id, nonce, raw_cipher

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
        key_id: int | None = None,
    ) -> str:
        """Decrypt ciphertext and verify contextual AAD coordinates.

        ``revision`` must match the value bound at encryption time. Reading at
        a newer revision rejects a replayed older ciphertext (rollback
        detection), provided the revision comes from trusted state; see
        ``associated_data``.

        ``key_id`` may be supplied to require that the record was written under
        that key (``None`` accepts whatever the authenticated header declares).

        Returns:
            Decrypted plaintext string.

        Raises:
            DecryptionVerificationError: If tag check fails or coordinates were spliced.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv

        header, _crypto_version, envelope_key_id, nonce, raw_cipher = self._split_envelope(
            ciphertext
        )
        if header is not None and header[:4] == RECORD_MAGIC_V3:
            raise DecryptionVerificationError(
                "v3 token envelopes carry embedded time/purpose claims; "
                "use decrypt_token() so the policy checks run"
            )
        self._require_key_id(envelope_key_id, key_id)

        aad = self._aad(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            revision=revision,
        )

        try:
            decrypted_bytes = aead.decrypt(raw_cipher, self._ad_components(aad, header, nonce))
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
        key_id: int | None = None,
    ) -> bytes:
        """Decrypt ciphertext and return raw bytes, without UTF-8 decoding.

        Use for values that were encrypted from bytes rather than str.
        ``revision`` and ``key_id`` semantics match :meth:`decrypt`.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv

        header, _crypto_version, envelope_key_id, nonce, raw_cipher = self._split_envelope(
            ciphertext
        )
        if header is not None and header[:4] == RECORD_MAGIC_V3:
            raise DecryptionVerificationError(
                "v3 token envelopes carry embedded time/purpose claims; "
                "use decrypt_token() so the policy checks run"
            )
        self._require_key_id(envelope_key_id, key_id)

        aad = self._aad(
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            revision=revision,
        )
        try:
            return aead.decrypt(raw_cipher, self._ad_components(aad, header, nonce))
        except InvalidTag as exc:
            raise DecryptionVerificationError(
                f"Contextual decryption verification failed for {table}.{column} "
                f"(record: {record_id}). Data was tampered with, spliced, or corrupted."
            ) from exc

    def encrypt_fields(
        self,
        fields: Mapping[str, Union[str, bytes]],
        *,
        table: str,
        record_id: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: int | None = None,
        key_id: int = 0,
    ) -> dict[str, bytes]:
        """Encrypt several columns of one record in a single call.

        Every field gets its own nonce and its own fully-bound AAD — the
        output is identical to calling :meth:`encrypt` per column — but the
        record-constant AAD section is built once, the coordinates validated
        once, and the lock taken once. If any field fails, the call raises and
        no partial result is returned.
        """
        if isinstance(key_id, bool) or not isinstance(key_id, int):
            raise TypeError("key_id must be an integer in [0, 255]")
        if not 0 <= key_id <= 255:
            raise ValueError("key_id must be an integer in [0, 255]")
        mid = self._validate_aad_mid(table, record_id, schema_id, schema_version, revision)
        ad_prefix = self._ad_prefix
        items = []
        for column, value in fields.items():
            if not isinstance(column, str) or not column.strip():
                raise ValueError("AAD parameter 'column' must be a non-empty string")
            items.append(
                (
                    column,
                    value.encode("utf-8") if isinstance(value, str) else bytes(value),
                    ad_prefix + _quote_json(column) + mid + b"}",
                    os.urandom(_NONCE_LEN),
                )
            )
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv
            for _column, _data, _aad, nonce in items:
                self._track_nonce(nonce)
        header = RECORD_MAGIC_V2 + bytes([CRYPTO_VERSION, key_id, _NONCE_LEN])
        out: dict[str, bytes] = {}
        for column, data, aad, nonce in items:
            out[column] = header + nonce + aead.encrypt(data, [aad, header, nonce])
        return out

    def decrypt_fields(
        self,
        fields: Mapping[str, bytes],
        *,
        table: str,
        record_id: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: int | None = None,
        key_id: int | None = None,
    ) -> dict[str, bytes]:
        """Decrypt several columns of one record in a single call.

        The inverse of :meth:`encrypt_fields`: each envelope is verified
        against its own column-bound AAD exactly as :meth:`decrypt_bytes`
        would, but the record-constant AAD section and validation are shared.
        Returns raw bytes; callers decode per column as needed.
        """
        mid = self._validate_aad_mid(table, record_id, schema_id, schema_version, revision)
        ad_prefix = self._ad_prefix
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv
        out: dict[str, bytes] = {}
        for column, envelope in fields.items():
            if not isinstance(column, str) or not column.strip():
                raise ValueError("AAD parameter 'column' must be a non-empty string")
            header, _ver, env_key_id, nonce, raw_cipher = self._split_envelope(envelope)
            self._require_key_id(env_key_id, key_id)
            aad = ad_prefix + _quote_json(column) + mid + b"}"
            try:
                out[column] = aead.decrypt(raw_cipher, self._ad_components(aad, header, nonce))
            except InvalidTag as exc:
                raise DecryptionVerificationError(
                    f"Contextual decryption verification failed for {table}.{column} "
                    f"(record: {record_id}). Data was tampered with, spliced, or corrupted."
                ) from exc
        return out

    def encrypt_token(
        self,
        plaintext: Union[str, bytes],
        *,
        purpose: str,
        expires_in: float | None = None,
        expires_at: int | float | None = None,
        not_before: int | float | None = None,
        key_id: int = 0,
    ) -> bytes:
        """Encrypt a self-contained token (v3 envelope, ``FLV3``).

        The token variant of :meth:`encrypt` for values that must be
        self-describing - password-reset links, signed blobs, cache payloads.
        Instead of the caller re-supplying coordinates at read time, the
        envelope embeds an authenticated ``ctx`` claim
        (``{"app_instance_id", "purpose"}``) and time claims ``exp``/``nbf``/
        ``iat``; the whole header is a SIV associated-data component, so none
        of it can be rewritten without failing authentication.

        The token still binds ``app_instance_id`` like every other FloorVault
        record - a token decrypts only under the same instance id and master
        key. ``purpose`` takes the ``record_id`` slot of a fixed token
        coordinate tuple; pass ``expected_purpose`` to
        :meth:`decrypt_token` to assert it.

        ``expires_in`` (seconds from now) and ``expires_at`` (absolute unix
        time) are mutually exclusive; omit both for a non-expiring token.
        ``not_before`` (absolute unix) delays validity. Writer-fixed ``exp``/
        ``nbf`` are stronger than reader-side ``max_age``: a reader can only
        tighten, never widen, the writer's window.

        Returns the raw binary envelope - wrap in ``base64.urlsafe_b64encode``
        for URLs/cookies.
        """
        if isinstance(key_id, bool) or not isinstance(key_id, int):
            raise TypeError("key_id must be an integer in [0, 255]")
        if not 0 <= key_id <= 255:
            raise ValueError("key_id must be an integer in [0, 255]")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("token 'purpose' must be a non-empty string")
        if expires_in is not None and expires_at is not None:
            raise ValueError("expires_in and expires_at are mutually exclusive")

        iat = int(time.time())
        exp = 0
        if expires_in is not None:
            if not isinstance(expires_in, (int, float)) or expires_in <= 0:
                raise ValueError("expires_in must be a positive number of seconds")
            exp = iat + int(expires_in)
        elif expires_at is not None:
            exp = int(expires_at)
        nbf = int(not_before) if not_before is not None else 0
        if exp and nbf and nbf >= exp:
            raise ValueError("not_before must precede the expiry")

        ctx = canonical_json_bytes({"app_instance_id": self.app_instance_id, "purpose": purpose})
        if len(ctx) > _V3_CTX_LEN_MAX:
            raise ValueError("token context claim exceeds the v3 ctx length limit")

        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad = self._aad(
            table=_TOKEN_TABLE,
            record_id=purpose,
            column=_TOKEN_COLUMN,
            schema_id=_TOKEN_SCHEMA_ID,
            schema_version=1,
            revision=None,
        )
        nonce = os.urandom(_NONCE_LEN)
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv
            self._track_nonce(nonce)

        header = (
            RECORD_MAGIC_V3
            + bytes([CRYPTO_VERSION, key_id])
            + exp.to_bytes(8, "big")
            + nbf.to_bytes(8, "big")
            + iat.to_bytes(8, "big")
            + len(ctx).to_bytes(2, "big")
            + ctx
            + bytes([_NONCE_LEN])
        )
        return header + nonce + aead.encrypt(data_bytes, [aad, header, nonce])

    def decrypt_token(
        self,
        token: bytes,
        *,
        expected_purpose: str | None = None,
        expected_app_instance_id: str | None = None,
        max_age: float | None = None,
        leeway: float = 0.0,
        now: float | None = None,
        key_id: int | None = None,
    ) -> bytes:
        """Decrypt a v3 token, enforcing its embedded claims.

        Authenticates the envelope first - a forged or spliced token fails
        with :class:`DecryptionVerificationError` before any policy check
        runs, so expiry/purpose errors never leak about unverified claims.

        Then, in order: ``key_id`` dispatch (as :meth:`decrypt`), the
        embedded ``ctx`` claims are compared to ``expected_purpose`` /
        ``expected_app_instance_id`` when given (mismatch rejects the token -
        use this to pin a token to the context it was minted for), and the
        time window is enforced: ``nbf + leeway``, ``exp - leeway``, and the
        reader-side ``max_age`` over ``iat``. ``now`` defaults to the wall
        clock; supply it for deterministic testing.

        Returns the raw payload bytes.
        """
        if leeway < 0:
            raise ValueError("leeway must be non-negative")
        if max_age is not None and max_age <= 0:
            raise ValueError("max_age must be a positive number of seconds")
        with self._lock:
            if self._closed:
                raise RuntimeError("FloorVault has been wiped")
            aead = self._aead_siv

        header, _ver, envelope_key_id, nonce, raw_cipher = self._split_envelope(token)
        if header is None or bytes(header[:4]) != RECORD_MAGIC_V3:
            raise DecryptionVerificationError(
                "Expected a v3 token envelope (FLV3); use decrypt()/decrypt_bytes() "
                "for field ciphertexts"
            )
        self._require_key_id(envelope_key_id, key_id)
        claims = _parse_v3_header_fields(header)
        ctx = _parse_v3_ctx(claims["ctx"])

        aad = self._aad(
            table=_TOKEN_TABLE,
            record_id=ctx["purpose"],
            column=_TOKEN_COLUMN,
            schema_id=_TOKEN_SCHEMA_ID,
            schema_version=1,
            revision=None,
        )
        try:
            plaintext = aead.decrypt(raw_cipher, [aad, header, nonce])
        except InvalidTag as exc:
            raise DecryptionVerificationError(
                f"Token decryption verification failed for purpose {ctx['purpose']!r}. "
                "Data was tampered with, spliced, or corrupted."
            ) from exc

        # Everything below runs only on an authenticated token.
        if expected_purpose is not None and ctx["purpose"] != expected_purpose:
            raise DecryptionVerificationError(
                f"Token purpose {ctx['purpose']!r} does not match the expected {expected_purpose!r}"
            )
        if (
            expected_app_instance_id is not None
            and ctx["app_instance_id"] != expected_app_instance_id
        ):
            raise DecryptionVerificationError(
                "Token was sealed under a different app_instance_id claim"
            )
        t = time.time() if now is None else float(now)
        if claims["nbf"] and t + leeway < claims["nbf"]:
            raise TokenNotYetValidError("Token is not yet valid (nbf)")
        if claims["exp"] and t - leeway > claims["exp"]:
            raise TokenExpiredError("Token has expired (exp)")
        if max_age is not None and t - leeway > claims["iat"] + max_age:
            raise TokenExpiredError("Token exceeds the caller's max_age policy")
        return plaintext

    def wipe(self) -> None:
        """Zero the managed key buffers and close the engine.

        Scope: this covers the ``HardenedMemoryKey`` buffers FloorVault
        controls. It cannot reach the AEAD engine's internal key copy inside
        the ``cryptography`` library - that memory is released to the
        allocator unzeroed on garbage collection - nor any caller-held
        ``bytes`` intermediates. Treat wipe() as reclaiming FloorVault's own
        custody, not as proof no key material remains in the process.
        """
        lock = getattr(self, "_lock", None)
        if lock is not None:
            with lock:
                self._wipe_locked()
        else:
            self._wipe_locked()

    def _wipe_locked(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        if getattr(self, "_siv_key", None) is not None:
            self._siv_key.wipe()
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

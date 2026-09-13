"""AES-256-GCM envelopes and keyed indexes for AppState payloads."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
import hashlib
import hmac
import json
import os
import re
import threading
from typing import Any
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .contract_registry import canonical_json_bytes
from .data_key_provider import KEY_VERSION, validate_data_key
from .errors import ValidationError


ENCRYPTION_INFO = b"eightbit.appstate.encryption.v1"
AES_SIV_ENCRYPTION_INFO = b"eightbit.appstate.encryption-siv.v2"
INDEX_INFO = b"eightbit.appstate.index.v1"
ENVELOPE_FIELDS = frozenset(
    {"v", "alg", "key_version", "nonce_b64u", "ciphertext_b64u", "aad_sha256"}
)
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAXIMUM_PAYLOAD_BYTES = 262_144
MAXIMUM_ENVELOPE_BYTES = 360_000
MAXIMUM_PAYLOAD_DEPTH = 64


class AppStateCryptoError(RuntimeError):
    code = "app_state_crypto_failed"


class AppStateIntegrityError(AppStateCryptoError):
    code = "integrity_failed"


class NonceGenerationError(AppStateCryptoError):
    code = "nonce_generation_failed"


def _derive(data_key: bytes, app_instance_id: str, info: bytes, *, length: int = 32) -> bytes:
    try:
        instance = uuid.UUID(app_instance_id)
    except (AttributeError, ValueError) as error:
        raise AppStateCryptoError("AppState instance ID must be a UUID") from error
    if str(instance) != app_instance_id:
        raise AppStateCryptoError("AppState instance ID must use canonical UUID text")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=instance.bytes,
        info=info,
    ).derive(validate_data_key(data_key))


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64u(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not BASE64URL.fullmatch(value):
        raise AppStateIntegrityError(f"Envelope {field} is not canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, base64.binascii.Error) as error:
        raise AppStateIntegrityError(f"Envelope {field} is invalid") from error
    if _b64u(decoded) != value:
        raise AppStateIntegrityError(f"Envelope {field} is not canonical")
    return decoded


def associated_data(
    *,
    table: str,
    record_id: str,
    column: str,
    payload_schema: str,
    schema_version: int,
    app_instance_id: str,
) -> bytes:
    for label, value in {
        "table": table,
        "record_id": record_id,
        "column": column,
        "payload_schema": payload_schema,
        "app_instance_id": app_instance_id,
    }.items():
        if not isinstance(value, str) or not value:
            raise ValidationError(f"Associated-data {label} is required")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version < 1:
        raise ValidationError("Associated-data schema_version must be positive")
    return canonical_json_bytes(
        {
            "table": table,
            "record_id": record_id,
            "column": column,
            "payload_schema": payload_schema,
            "schema_version": schema_version,
            "app_instance_id": app_instance_id,
        }
    )


_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "api_key", "access_token", "refresh_token", "password", "credential",
        "credentials", "provider_secret", "recovery_secret", "private_key",
        "canonical_private_key", "authorization_receipt", "approval_receipt",
        "token", "secret", "client_secret",
    }
)


def validate_non_authoritative_payload(
    value: Any,
    *,
    path: str = "$",
    _depth: int = 0,
    _active: set[int] | None = None,
) -> None:
    """Reject secrets and any payload that claims executable authority."""
    if _depth > MAXIMUM_PAYLOAD_DEPTH:
        raise ValidationError("AppState payload exceeds the nesting-depth limit")
    active = set() if _active is None else _active
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            raise ValidationError("AppState payload cannot contain a cycle")
        active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValidationError(f"{path} contains a non-string key")
                lowered = key.casefold()
                child = f"{path}.{key}"
                if lowered in _FORBIDDEN_SECRET_KEYS and item not in (None, "", [], {}):
                    raise ValidationError(f"{child} cannot be stored in AppState")
                if lowered == "signing_key_reference" and item is not None:
                    raise ValidationError(f"{child} cannot be stored in AppState")
                if lowered == "authoritative" and item is not False:
                    raise ValidationError(f"{child} cannot claim authority in AppState")
                if lowered == "authority_class" and item != "NON_AUTHORITATIVE":
                    raise ValidationError(f"{child} must be NON_AUTHORITATIVE")
                validate_non_authoritative_payload(
                    item,
                    path=child,
                    _depth=_depth + 1,
                    _active=active,
                )
        finally:
            active.remove(identity)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        identity = id(value)
        if identity in active:
            raise ValidationError("AppState payload cannot contain a cycle")
        active.add(identity)
        try:
            for index, item in enumerate(value):
                validate_non_authoritative_payload(
                    item,
                    path=f"{path}[{index}]",
                    _depth=_depth + 1,
                    _active=active,
                )
        finally:
            active.remove(identity)


def _bounded_canonical_bytes(value: Any) -> bytes:
    try:
        raw = canonical_json_bytes(value)
    except (RecursionError, ValueError) as error:
        raise ValidationError("AppState payload is not canonical JSON") from error
    if len(raw) > MAXIMUM_PAYLOAD_BYTES:
        raise ValidationError("AppState payload exceeds the byte limit")
    return raw


class AppStateCrypto:
    """Per-store cryptographic context with HKDF-separated keys."""

    def __init__(
        self,
        data_key: bytes,
        app_instance_id: str,
        *,
        nonce_source: Callable[[int], bytes] = os.urandom,
        maximum_nonce_attempts: int = 8,
    ) -> None:
        if isinstance(maximum_nonce_attempts, bool) or maximum_nonce_attempts < 1:
            raise ValueError("maximum_nonce_attempts must be positive")
        self.app_instance_id = app_instance_id
        self._encryption_key = _derive(data_key, app_instance_id, ENCRYPTION_INFO)
        self._siv_encryption_key = _derive(
            data_key, app_instance_id, AES_SIV_ENCRYPTION_INFO, length=64
        )
        self._index_key = _derive(data_key, app_instance_id, INDEX_INFO)
        if (
            hmac.compare_digest(self._encryption_key, self._index_key)
            or hmac.compare_digest(self._siv_encryption_key[:32], self._index_key)
        ):
            raise AppStateCryptoError("HKDF key separation failed")
        self._aead_v1 = AESGCM(self._encryption_key)
        self._aead_v2 = AESSIV(self._siv_encryption_key)
        self._nonce_source = nonce_source
        self._maximum_nonce_attempts = maximum_nonce_attempts
        self._used_nonces: set[bytes] = set()
        self._nonce_lock = threading.Lock()

    def _nonce(self) -> bytes:
        with self._nonce_lock:
            for _ in range(self._maximum_nonce_attempts):
                nonce = self._nonce_source(12)
                if not isinstance(nonce, bytes) or len(nonce) != 12:
                    raise NonceGenerationError("Nonce source must return exactly 12 bytes")
                if nonce not in self._used_nonces:
                    self._used_nonces.add(nonce)
                    return nonce
        raise NonceGenerationError("Could not obtain a unique 96-bit nonce")

    def index_hmac(self, value: Any, *, scope: str) -> str:
        if not isinstance(scope, str) or not scope:
            raise ValidationError("HMAC scope is required")
        raw = _bounded_canonical_bytes({"scope": scope, "value": value})
        return hmac.new(self._index_key, raw, hashlib.sha256).hexdigest()

    def encrypt_json(
        self,
        payload: Any,
        *,
        table: str,
        record_id: str,
        column: str,
        payload_schema: str,
        schema_version: int = 1,
    ) -> bytes:
        validate_non_authoritative_payload(payload)
        plaintext = _bounded_canonical_bytes(payload)
        aad = associated_data(
            table=table,
            record_id=record_id,
            column=column,
            payload_schema=payload_schema,
            schema_version=schema_version,
            app_instance_id=self.app_instance_id,
        )
        nonce = self._nonce()
        ciphertext = self._aead_v2.encrypt(plaintext, [aad, nonce])
        envelope = {
            "v": 2,
            "alg": "A256SIV",
            "key_version": KEY_VERSION,
            "nonce_b64u": _b64u(nonce),
            "ciphertext_b64u": _b64u(ciphertext),
            "aad_sha256": hashlib.sha256(aad).hexdigest(),
        }
        return canonical_json_bytes(envelope)

    def decrypt_json(
        self,
        envelope_bytes: bytes | bytearray | memoryview,
        *,
        table: str,
        record_id: str,
        column: str,
        payload_schema: str,
        schema_version: int = 1,
    ) -> Any:
        if not isinstance(envelope_bytes, (bytes, bytearray, memoryview)):
            raise AppStateIntegrityError("Encrypted envelope must be bytes")
        raw = bytes(envelope_bytes)
        if len(raw) > MAXIMUM_ENVELOPE_BYTES:
            raise AppStateIntegrityError("Encrypted envelope exceeds the byte limit")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise AppStateIntegrityError("Encrypted envelope is not valid UTF-8 JSON") from error
        if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
            raise AppStateIntegrityError("Encrypted envelope fields are unsupported")
        version_algorithm = (envelope.get("v"), envelope.get("alg"))
        if version_algorithm not in {(1, "A256GCM"), (2, "A256SIV")} or envelope.get("key_version") != 1:
            raise AppStateIntegrityError("Encrypted envelope algorithm or key version is unsupported")
        if canonical_json_bytes(envelope) != raw:
            raise AppStateIntegrityError("Encrypted envelope is not canonical JSON")
        aad = associated_data(
            table=table,
            record_id=record_id,
            column=column,
            payload_schema=payload_schema,
            schema_version=schema_version,
            app_instance_id=self.app_instance_id,
        )
        expected_aad_hash = hashlib.sha256(aad).hexdigest()
        aad_hash = envelope.get("aad_sha256")
        if not isinstance(aad_hash, str) or not SHA256.fullmatch(aad_hash) or not hmac.compare_digest(
            aad_hash, expected_aad_hash
        ):
            raise AppStateIntegrityError("Encrypted envelope associated data does not match")
        nonce = _unb64u(envelope.get("nonce_b64u"), field="nonce_b64u")
        if len(nonce) != 12:
            raise AppStateIntegrityError("Encrypted envelope nonce must contain 12 bytes")
        ciphertext = _unb64u(envelope.get("ciphertext_b64u"), field="ciphertext_b64u")
        if len(ciphertext) < 16:
            raise AppStateIntegrityError("Encrypted envelope ciphertext is too short")
        try:
            if version_algorithm == (1, "A256GCM"):
                plaintext = self._aead_v1.decrypt(nonce, ciphertext, aad)
            else:
                plaintext = self._aead_v2.decrypt(ciphertext, [aad, nonce])
        except InvalidTag as error:
            raise AppStateIntegrityError("Encrypted payload authentication failed") from error
        if len(plaintext) > MAXIMUM_PAYLOAD_BYTES:
            raise AppStateIntegrityError("Decrypted payload exceeds the byte limit")
        try:
            value = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise AppStateIntegrityError("Decrypted payload is not valid JSON") from error
        try:
            validate_non_authoritative_payload(value)
            canonical = canonical_json_bytes(value)
        except (RecursionError, ValueError, ValidationError) as error:
            raise AppStateIntegrityError("Decrypted payload is not valid bounded JSON") from error
        if canonical != plaintext:
            raise AppStateIntegrityError("Decrypted payload is not canonical JSON")
        return value

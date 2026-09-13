"""Narrow data-key provider contract for AppState encryption."""

from __future__ import annotations

import base64
from collections.abc import Callable
import fcntl
import json
import os
from pathlib import Path
import stat
import threading
from typing import Protocol, runtime_checkable
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .contract_registry import canonical_json_bytes


DATA_KEY_BYTES = 32
KEY_VERSION = 1
KEY_ID = "key-000001"


class DataKeyError(RuntimeError):
    code = "data_key_unavailable"


class MissingDataKeyError(DataKeyError):
    code = "recovery_required"


class InvalidDataKeyError(DataKeyError):
    code = "data_key_invalid"


class LegacyPlaintextDataKeyError(InvalidDataKeyError):
    """An old raw key file needs an explicit, out-of-band migration."""

    code = "legacy_plaintext_data_key"


class _EncryptedKeyAlreadyExistsError(InvalidDataKeyError):
    """Another creator published the lifetime key first."""


def validate_data_key(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise InvalidDataKeyError("AppState data key must be bytes")
    key = bytes(value)
    if len(key) != DATA_KEY_BYTES:
        raise InvalidDataKeyError("AppState data key must contain exactly 32 bytes")
    return key


@runtime_checkable
class DataKeyProvider(Protocol):
    """Load the fixed lifetime key, creating it only for a new empty store."""

    def get_data_key(self, *, allow_create: bool) -> bytes:
        ...


class InMemoryDataKeyProvider:
    """Injected deterministic provider for tests and in-memory compositions."""

    def __init__(
        self,
        key: bytes | None = None,
        *,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self._key = validate_data_key(key) if key is not None else None
        self._random_bytes = random_bytes
        self._lock = threading.Lock()

    def get_data_key(self, *, allow_create: bool) -> bytes:
        with self._lock:
            if self._key is None:
                if not allow_create:
                    raise MissingDataKeyError(
                        "The existing AppState key is missing; recovery is required"
                    )
                self._key = validate_data_key(self._random_bytes(DATA_KEY_BYTES))
            return self._key

    @property
    def has_key(self) -> bool:
        return self._key is not None


class FileDataKeyProvider:
    """Persistent file-backed data key provider.

    Reads an existing 32-byte key file, or creates one (0600, owned by the
    caller) when the store does not exist yet. This lets the AppState
    repository run without the macOS Keychain, which is required for a
    headless/airgapped live service that must not block on securityd.
    """

    def __init__(self, path: str | os.PathLike[str], *, random_bytes: Callable[[int], bytes] = os.urandom) -> None:
        self._path = Path(path)
        self._random_bytes = random_bytes
        self._lock = threading.Lock()

    def get_data_key(self, *, allow_create: bool) -> bytes:
        with self._lock:
            if self._path.exists():
                raw = self._path.read_bytes()
                if len(raw) != DATA_KEY_BYTES:
                    raise InvalidDataKeyError("AppState data key file must contain exactly 32 bytes")
                return raw
            if not allow_create:
                raise MissingDataKeyError(
                    "The existing AppState key is missing; recovery is required"
                )
            key = validate_data_key(self._random_bytes(DATA_KEY_BYTES))
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_bytes(key)
            os.chmod(self._path, 0o600)
            return key

    @property
    def has_key(self) -> bool:
        return self._path.exists()


ENCRYPTED_KEY_ENVELOPE_SCHEMA = "eightbit.appstate.data-key-envelope.v1"
ENCRYPTED_KEY_ENVELOPE_VERSION = 1
ENCRYPTED_KEY_KDF = {"name": "scrypt", "n": 32768, "r": 8, "p": 1}
ENCRYPTED_KEY_SALT_BYTES = 16
ENCRYPTED_KEY_NONCE_BYTES = 12
MINIMUM_UNLOCK_SECRET_BYTES = 16
_MAXIMUM_ENCRYPTED_KEY_ENVELOPE_BYTES = 4096


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64u(value: object, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise InvalidDataKeyError(f"Encrypted data-key envelope {field} is invalid")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, base64.binascii.Error) as error:
        raise InvalidDataKeyError(f"Encrypted data-key envelope {field} is invalid") from error
    if _b64u(decoded) != value:
        raise InvalidDataKeyError(f"Encrypted data-key envelope {field} is not canonical")
    return decoded


def _validate_owned_private_regular_file(metadata: os.stat_result, *, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise InvalidDataKeyError(f"{label} must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise InvalidDataKeyError(f"{label} must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise InvalidDataKeyError(f"{label} must have mode 0600")
    if metadata.st_nlink != 1:
        raise InvalidDataKeyError(f"{label} must not have hard links")


class EncryptedFileDataKeyProvider:
    """Store the AppState key in an owner-only, password-encrypted envelope."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        unlock_secret: bytes,
        *,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if not isinstance(unlock_secret, bytes):
            raise InvalidDataKeyError("AppState unlock secret must be bytes")
        if len(unlock_secret) < MINIMUM_UNLOCK_SECRET_BYTES:
            raise InvalidDataKeyError(
                f"AppState unlock secret must contain at least {MINIMUM_UNLOCK_SECRET_BYTES} bytes"
            )
        self._path = Path(path)
        self._unlock_secret = unlock_secret
        self._random_bytes = random_bytes
        self._lock = threading.Lock()

    @staticmethod
    def _identity(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    def _derive_kek(self, salt: bytes) -> bytes:
        return Scrypt(
            salt=salt,
            length=DATA_KEY_BYTES,
            n=ENCRYPTED_KEY_KDF["n"],
            r=ENCRYPTED_KEY_KDF["r"],
            p=ENCRYPTED_KEY_KDF["p"],
        ).derive(self._unlock_secret)

    @staticmethod
    def _envelope_aad(*, salt_b64u: str, nonce_b64u: str) -> bytes:
        return canonical_json_bytes(
            {
                "schema": ENCRYPTED_KEY_ENVELOPE_SCHEMA,
                "version": ENCRYPTED_KEY_ENVELOPE_VERSION,
                "kdf": ENCRYPTED_KEY_KDF,
                "salt_b64u": salt_b64u,
                "nonce_b64u": nonce_b64u,
            }
        )

    def _read_envelope_bytes(self) -> bytes:
        try:
            first = self._path.lstat()
        except FileNotFoundError:
            raise
        _validate_owned_private_regular_file(first, label="AppState encrypted key file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags)
        except OSError as error:
            raise InvalidDataKeyError("AppState encrypted key file cannot be opened safely") from error
        try:
            second = os.fstat(descriptor)
            _validate_owned_private_regular_file(second, label="AppState encrypted key file")
            if self._identity(first) != self._identity(second):
                raise InvalidDataKeyError("AppState encrypted key file changed during inspection")
            raw = os.read(descriptor, _MAXIMUM_ENCRYPTED_KEY_ENVELOPE_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > _MAXIMUM_ENCRYPTED_KEY_ENVELOPE_BYTES:
            raise InvalidDataKeyError("AppState encrypted key file is too large")
        return raw

    def _decode_envelope(self, raw: bytes) -> bytes:
        if len(raw) == DATA_KEY_BYTES:
            raise LegacyPlaintextDataKeyError(
                "Raw AppState data key files require explicit migration"
            )
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidDataKeyError("AppState encrypted key file is not valid JSON") from error
        expected_fields = {
            "schema", "version", "kdf", "salt_b64u", "nonce_b64u", "ciphertext_b64u",
        }
        if not isinstance(envelope, dict) or set(envelope) != expected_fields:
            raise InvalidDataKeyError("AppState encrypted key envelope fields are unsupported")
        if canonical_json_bytes(envelope) != raw:
            raise InvalidDataKeyError("AppState encrypted key envelope is not canonical JSON")
        if (
            envelope["schema"] != ENCRYPTED_KEY_ENVELOPE_SCHEMA
            or envelope["version"] != ENCRYPTED_KEY_ENVELOPE_VERSION
            or envelope["kdf"] != ENCRYPTED_KEY_KDF
        ):
            raise InvalidDataKeyError("AppState encrypted key envelope parameters are unsupported")
        salt = _unb64u(envelope["salt_b64u"], field="salt_b64u")
        nonce = _unb64u(envelope["nonce_b64u"], field="nonce_b64u")
        ciphertext = _unb64u(envelope["ciphertext_b64u"], field="ciphertext_b64u")
        if len(salt) != ENCRYPTED_KEY_SALT_BYTES or len(nonce) != ENCRYPTED_KEY_NONCE_BYTES:
            raise InvalidDataKeyError("AppState encrypted key envelope has invalid salt or nonce")
        if len(ciphertext) != DATA_KEY_BYTES + 16:
            raise InvalidDataKeyError("AppState encrypted key envelope has invalid ciphertext")
        try:
            return validate_data_key(
                AESGCM(self._derive_kek(salt)).decrypt(
                    nonce,
                    ciphertext,
                    self._envelope_aad(
                        salt_b64u=envelope["salt_b64u"], nonce_b64u=envelope["nonce_b64u"]
                    ),
                )
            )
        except InvalidTag as error:
            raise InvalidDataKeyError("AppState encrypted key unlock secret is invalid") from error

    def _private_parent(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as error:
            raise InvalidDataKeyError("AppState encrypted key parent cannot be created") from error
        try:
            parent = self._path.parent.lstat()
        except OSError as error:
            raise InvalidDataKeyError("AppState encrypted key parent is unavailable") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise InvalidDataKeyError("AppState encrypted key parent is unsafe")

    def _write_key(self, key: bytes) -> None:
        self._private_parent()
        try:
            self._path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise _EncryptedKeyAlreadyExistsError("AppState encrypted key file already exists")
        salt = self._random_bytes(ENCRYPTED_KEY_SALT_BYTES)
        nonce = self._random_bytes(ENCRYPTED_KEY_NONCE_BYTES)
        if not isinstance(salt, bytes) or len(salt) != ENCRYPTED_KEY_SALT_BYTES:
            raise InvalidDataKeyError("Random source must return a 16-byte salt")
        if not isinstance(nonce, bytes) or len(nonce) != ENCRYPTED_KEY_NONCE_BYTES:
            raise InvalidDataKeyError("Random source must return a 12-byte nonce")
        salt_b64u = _b64u(salt)
        nonce_b64u = _b64u(nonce)
        envelope = {
            "schema": ENCRYPTED_KEY_ENVELOPE_SCHEMA,
            "version": ENCRYPTED_KEY_ENVELOPE_VERSION,
            "kdf": ENCRYPTED_KEY_KDF,
            "salt_b64u": salt_b64u,
            "nonce_b64u": nonce_b64u,
            "ciphertext_b64u": _b64u(
                AESGCM(self._derive_kek(salt)).encrypt(
                    nonce, key, self._envelope_aad(salt_b64u=salt_b64u, nonce_b64u=nonce_b64u)
                )
            ),
        }
        payload = canonical_json_bytes(envelope)
        temporary = self._path.parent / f".{self._path.name}.{uuid.uuid4().hex}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            # Every publisher (including explicit migration) locks the same
            # parent inode. Recheck absence under this cross-process lock so
            # a competing creator cannot replace the lifetime key.
            parent_descriptor = os.open(
                self._path.parent,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
                try:
                    os.stat(self._path.name, dir_fd=parent_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise _EncryptedKeyAlreadyExistsError(
                        "AppState encrypted key file already exists"
                    )
                os.replace(
                    temporary.name, self._path.name,
                    src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
                )
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)  # Also releases the directory lock.
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def get_data_key(self, *, allow_create: bool) -> bytes:
        with self._lock:
            try:
                return self._decode_envelope(self._read_envelope_bytes())
            except FileNotFoundError:
                if not allow_create:
                    raise MissingDataKeyError(
                        "The existing AppState key is missing; recovery is required"
                    )
            key = validate_data_key(self._random_bytes(DATA_KEY_BYTES))
            try:
                self._write_key(key)
            except _EncryptedKeyAlreadyExistsError:
                return self._decode_envelope(self._read_envelope_bytes())
            return key

    @property
    def has_key(self) -> bool:
        try:
            self._read_envelope_bytes()
        except (FileNotFoundError, InvalidDataKeyError):
            return False
        return True


def migrate_plaintext_key(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    unlock_secret: bytes,
    *,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> bytes:
    """Explicitly copy an owned private raw key into a new encrypted envelope."""
    source_path = Path(source)
    destination_path = Path(destination)
    if source_path.absolute() == destination_path.absolute():
        raise InvalidDataKeyError("Plaintext key migration source and destination must differ")
    try:
        metadata = source_path.lstat()
    except OSError as error:
        raise MissingDataKeyError("Plaintext AppState key is missing") from error
    _validate_owned_private_regular_file(metadata, label="Plaintext AppState key file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source_path, flags)
    except OSError as error:
        raise InvalidDataKeyError("Plaintext AppState key cannot be opened safely") from error
    try:
        current = os.fstat(descriptor)
        _validate_owned_private_regular_file(current, label="Plaintext AppState key file")
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise InvalidDataKeyError("Plaintext AppState key changed during inspection")
        key = validate_data_key(os.read(descriptor, DATA_KEY_BYTES + 1))
    finally:
        os.close(descriptor)
    provider = EncryptedFileDataKeyProvider(
        destination_path, unlock_secret, random_bytes=random_bytes
    )
    provider._write_key(key)
    return key

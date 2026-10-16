"""Passphrase-wrapped Tier-3 key file (``FVPW1``).

The plain Tier-3 store (``~/.floorvault/master.key``) *is* the key: a copy of
the file decrypts everything. This scheme wraps the master key under a key
derived from a caller-held passphrase, so a stolen disk, backup, or copied
file (attackers A1/A2 in ``SECURITY.md`` §5) also needs the passphrase.

What it is not: protection against anyone who can observe the passphrase
(the process, its environment, a keylogger) or who can run the application
as the user - the same limits as every other custody tier. Its strength is
the passphrase's: scrypt raises the cost of guessing, it does not make a
weak passphrase strong.

Format (``docs/SPEC.md`` §10.8)::

    "FVPW1" || log2_n (1) || r (1) || p (1) || salt (16) || siv (48)

    kek = scrypt(passphrase, salt, n=2**log2_n, r, p, dklen=64)
    siv = AES-SIV(kek).encrypt(master_key, [header])   # header = all bytes before siv

Every byte before the ciphertext is authenticated as associated data, so the
cost parameters and salt cannot be altered without the unwrap failing. Cost
parameters read from a file are bounded before any derivation runs: a
planted file can neither downgrade the work factor below the floor nor demand
gigabytes of memory.
"""

from __future__ import annotations

import os
import unicodedata
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FVPW1"

#: Default scrypt work factor (OWASP's minimum recommendation for scrypt:
#: N=2**17, r=8, p=1 - about 128 MiB and a few hundred milliseconds).
DEFAULT_LOG2_N = 17
#: Bounds enforced on read. Below the floor a stolen file is cheap to attack;
#: above the ceiling a planted file becomes a memory-exhaustion lever.
MIN_LOG2_N = 15
MAX_LOG2_N = 20
_R = 8
_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32
_SIV_BYTES = _KEY_BYTES + 16

#: Payload length after ``MAGIC``, for the protected-store reader.
PAYLOAD_BYTES = 3 + _SALT_BYTES + _SIV_BYTES


class PassphraseStoreError(Exception):
    """A passphrase-wrapped key file is malformed or cannot be opened."""


def _normalize_passphrase(passphrase: Union[str, bytes, bytearray]) -> bytes:
    """Return the passphrase as bytes, NFC-normalising text input.

    NFC makes the same visible passphrase derive the same key whichever input
    method composed it; bytes are used verbatim for callers that manage their
    own encoding.
    """
    if isinstance(passphrase, str):
        encoded = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray)):
        encoded = bytes(passphrase)
    else:
        raise TypeError("passphrase must be str or bytes")
    if not encoded:
        raise ValueError("passphrase must not be empty")
    return encoded


def _kek(passphrase: bytes, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=64, n=2**log2_n, r=r, p=p).derive(passphrase)


def wrap(
    master_key: Union[bytes, bytearray, memoryview],
    passphrase: Union[str, bytes, bytearray],
    *,
    log2_n: int | None = None,
) -> bytes:
    """Return the ``FVPW1`` payload (everything after ``MAGIC``) for ``master_key``.

    ``log2_n`` defaults to :data:`DEFAULT_LOG2_N`, read at call time.
    """
    if log2_n is None:
        log2_n = DEFAULT_LOG2_N
    if len(master_key) != _KEY_BYTES:
        raise ValueError(f"master key must be exactly {_KEY_BYTES} bytes")
    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N:
        raise ValueError(f"log2_n must be within [{MIN_LOG2_N}, {MAX_LOG2_N}]")
    salt = os.urandom(_SALT_BYTES)
    params = bytes([log2_n, _R, _P]) + salt
    kek = _kek(_normalize_passphrase(passphrase), salt, log2_n, _R, _P)
    siv = AESSIV(kek).encrypt(bytes(master_key), [MAGIC + params])
    return params + siv


def unwrap(payload: bytes, passphrase: Union[str, bytes, bytearray]) -> bytearray:
    """Recover the master key from an ``FVPW1`` payload, as a wipeable buffer.

    Raises :class:`PassphraseStoreError` for a malformed payload, out-of-bounds
    cost parameters, or a wrong passphrase (indistinguishable from tampering).
    """
    if len(payload) != PAYLOAD_BYTES:
        raise PassphraseStoreError("passphrase-wrapped key file has the wrong length")
    log2_n, r, p = payload[0], payload[1], payload[2]
    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N or (r, p) != (_R, _P):
        raise PassphraseStoreError(
            "passphrase-wrapped key file has out-of-bounds scrypt parameters; refusing to derive"
        )
    params = payload[: 3 + _SALT_BYTES]
    salt = params[3:]
    kek = _kek(_normalize_passphrase(passphrase), salt, log2_n, r, p)
    try:
        key = AESSIV(kek).decrypt(payload[3 + _SALT_BYTES :], [MAGIC + params])
    except InvalidTag:
        raise PassphraseStoreError(
            "could not unwrap the key file (wrong passphrase, or the file was altered)"
        ) from None
    if len(key) != _KEY_BYTES:  # pragma: no cover - AES-SIV preserves length
        raise PassphraseStoreError("unwrapped key has the wrong length")
    return bytearray(key)

"""Independent implementation of the FloorVault wire format (docs/SPEC.md).

It must never import floorvault; a test enforces that.

Dependencies are the Python standard library plus ``cryptography``'s AES-ECB
block primitive. Two deliberate independence choices:

* The AEAD is NOT PyCA ``AESSIV``. CMAC, S2V, dbl/pad/xorend and the CTR
  framing below are a from-spec RFC 5297 implementation (ported from the
  independent implementation anchored to the RFC Appendix A vectors in
  ``tests/test_rfc5297_independent.py``), so vector checks exercise a second
  code path for the one primitive FloorVault is built on.
* HKDF-SHA256 is implemented from RFC 5869 over ``hmac`` rather than calling
  ``cryptography``'s ``HKDF``, for the same reason.

Everything here follows docs/SPEC.md: canonical AAD (§5), v1/v2 envelopes and
their exact rejection order (§4.3), the version-matched S2V AD vector (§6),
HKDF subkeys (§3), search beacons (§9), and the FVRB1 recovery bundle (§11).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any, Mapping, NamedTuple, Optional, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --------------------------------------------------------------------------
# Errors. SPEC §16 allows a foreign implementation its own error hierarchy;
# the class set below mirrors the *rejection classes*, not the reference
# error names, so vectors can assert the exact stage that refused.
# --------------------------------------------------------------------------


class WireError(Exception):
    """Base class for all independent-wire failures."""


class EnvelopeRejectionError(WireError):
    """Base for §4.3 parse rejections (reference impl: DecryptionVerificationError)."""


class TooShortError(EnvelopeRejectionError):
    """len < 21 — checked before magic, so a short buffer with bad magic lands here."""


class BadMagicError(EnvelopeRejectionError):
    """magic not in {FLRV, FLV2}."""


class UnsupportedCryptoVersionError(EnvelopeRejectionError):
    """v2 crypto_version != 2."""


class BadNonceLengthError(EnvelopeRejectionError):
    """nonce_len != 16, or the buffer ends before nonce_len bytes elapse."""


class EmptyCiphertextError(EnvelopeRejectionError):
    """Zero bytes remain after the nonce."""


class AuthenticationError(WireError):
    """S2V/tag/AAD verification failed (§4.4 step 4 — single error class)."""


class KeyIdMismatchError(AuthenticationError):
    """§4.4 step 2: required key_id absent (v1) or different (v2)."""


# --------------------------------------------------------------------------
# Constants (SPEC §3, §4, §9, §11)
# --------------------------------------------------------------------------

MAGIC_V1 = b"FLRV"
MAGIC_V2 = b"FLV2"
CRYPTO_VERSION_V2 = 0x02
HEADER_LEN_V1 = 5
HEADER_LEN_V2 = 7
NONCE_LEN = 16
MIN_ENVELOPE_LEN = HEADER_LEN_V1 + NONCE_LEN  # 21 — §4.3 rule 2

MASTER_KEY_LEN = 32
SIV_KEY_INFO = b"floorvault-v1-aes-siv"  # §3, normative bytes
SIV_KEY_LEN = 64
BEACON_KEY_INFO = b"floorvault-v1-beacon-index"  # §3, normative bytes
BEACON_KEY_LEN = 32

MIN_BEACON_BITS = 4
MAX_BEACON_BITS = 64

RECOVERY_MAGIC = b"FVRB1"
RECOVERY_BUNDLE_ID_LEN = 16
RECOVERY_APP_INSTANCE_ID = "floorvault-recovery"
RECOVERY_TABLE = "recovery"
RECOVERY_COLUMN = "master_key"

DEFAULT_SCHEMA_ID = "floor.vault.v1"
DEFAULT_SCHEMA_VERSION = 1
DEFAULT_APP_INSTANCE_ID = "default"

BytesLike = Union[bytes, bytearray]


# --------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869), salt absent → HashLen zero octets (SPEC §3)
# --------------------------------------------------------------------------


def _hkdf_sha256(ikm: bytes, *, length: int, info: bytes) -> bytes:
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("HKDF length exceeds 255 * HashLen")
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, ikm, hashlib.sha256).digest()
    okm = b""
    previous = b""
    counter = 0
    while len(okm) < length:
        counter += 1
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm += previous
    return okm[:length]


def derive_siv_key(master_key: BytesLike) -> bytes:
    """64-byte AES-256-SIV subkey (SPEC §3)."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    if len(master_key) != MASTER_KEY_LEN:
        raise ValueError(f"master_key must be exactly {MASTER_KEY_LEN} bytes")
    return _hkdf_sha256(bytes(master_key), length=SIV_KEY_LEN, info=SIV_KEY_INFO)


def derive_beacon_key(master_key: BytesLike) -> bytes:
    """32-byte beacon index subkey (SPEC §3, §9.1) — derived from the master
    key directly, not from the SIV subkey."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    if len(master_key) != MASTER_KEY_LEN:
        raise ValueError(f"master_key must be exactly {MASTER_KEY_LEN} bytes")
    return _hkdf_sha256(bytes(master_key), length=BEACON_KEY_LEN, info=BEACON_KEY_INFO)


# --------------------------------------------------------------------------
# AES-SIV (RFC 5297), from spec; AES-ECB is the only library primitive.
# --------------------------------------------------------------------------


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _dbl(s: bytes) -> bytes:
    """RFC 5297 §2.3 doubling in GF(2^128), poly x^128+x^7+x^2+x+1."""
    n = int.from_bytes(s, "big")
    msb = (n >> 127) & 1
    n = (n << 1) & ((1 << 128) - 1)
    if msb:
        n ^= 0x87
    return n.to_bytes(16, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(s: bytes) -> bytes:
    """RFC 5297 pad(X): 0x80 then zeros to 16 bytes (for len < 128 bits)."""
    return s + b"\x80" + b"\x00" * (15 - len(s))


def _cmac(key: bytes, msg: bytes) -> bytes:
    """AES-CMAC (RFC 4493) built from AES-ECB."""
    zero = b"\x00" * 16
    k1 = _dbl(_aes_ecb(key, zero))
    k2 = _dbl(k1)
    if len(msg) == 0:
        n, last_complete = 1, False
    else:
        n = (len(msg) + 15) // 16
        last_complete = len(msg) % 16 == 0
    if last_complete:
        m_last = _xor(msg[-16:], k1)
    else:
        m_last = _xor(_pad(msg[(n - 1) * 16 :]), k2)
    x = zero
    for i in range(n - 1):
        x = _aes_ecb(key, _xor(x, msg[i * 16 : (i + 1) * 16]))
    return _aes_ecb(key, _xor(x, m_last))


def _xorend(a: bytes, b: bytes) -> bytes:
    """RFC 5297 xorend: right-aligned XOR of B onto A (len(A) >= len(B))."""
    return a[: len(a) - len(b)] + _xor(a[len(a) - len(b) :], b)


_ZERO = b"\x00" * 16
_ONE = b"\x00" * 15 + b"\x01"


def s2v(key: bytes, strings: list[bytes]) -> bytes:
    """RFC 5297 §2.4 S2V."""
    if not strings:
        return _cmac(key, _ONE)
    d = _cmac(key, _ZERO)
    for s in strings[:-1]:
        d = _xor(_dbl(d), _cmac(key, s))
    sn = strings[-1]
    t = _xorend(sn, d) if len(sn) >= 16 else _xor(_dbl(d), _pad(sn))
    return _cmac(key, t)


def _ctr_keystream(key2: bytes, v: bytes, length: int) -> bytes:
    """CTR per RFC 5297 §2.6, with bits 31 and 63 of the counter zeroed."""
    q = bytearray(v)
    q[8] &= 0x7F
    q[12] &= 0x7F
    m = (length + 15) // 16
    counter = int.from_bytes(bytes(q), "big")
    out = b""
    for i in range(m):
        out += _aes_ecb(key2, ((counter + i) & ((1 << 128) - 1)).to_bytes(16, "big"))
    return out[:length]


def siv_encrypt(key: bytes, plaintext: bytes, ad: list[bytes]) -> bytes:
    """RFC 5297 §2.6 SIV-ENCRYPT. Returns V || C (tag prepended)."""
    half = len(key) // 2
    v = s2v(key[:half], [*ad, plaintext])
    return v + _xor(plaintext, _ctr_keystream(key[half:], v, len(plaintext)))


def siv_decrypt(key: bytes, z: bytes, ad: list[bytes]) -> Optional[bytes]:
    """RFC 5297 §2.7 SIV-DECRYPT. Returns plaintext, or None on FAIL."""
    half = len(key) // 2
    v, c = z[:16], z[16:]
    p = _xor(c, _ctr_keystream(key[half:], v, len(c)))
    return p if s2v(key[:half], [*ad, p]) == v else None


# --------------------------------------------------------------------------
# Canonical AAD (SPEC §5). The object has a fixed sorted key order, so the
# bytes are emitted literally; string quoting reproduces the exact escaping
# of json.dumps(ensure_ascii=False): only '"', '\' and C0 controls escaped,
# short escapes where JSON defines them, \u00XX otherwise; DEL, C1 and all
# non-ASCII verbatim as UTF-8; NO Unicode normalization anywhere.
# --------------------------------------------------------------------------

_STRING_ESCAPES = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _quote_json_string(value: str) -> bytes:
    out = ['"']
    for ch in value:
        cp = ord(ch)
        esc = _STRING_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            # Verbatim UTF-8, including DEL, C1, U+2028 and BOM. A lone
            # surrogate raises UnicodeEncodeError here, as it does for the
            # reference implementation's encode step.
            out.append(ch)
    out.append('"')
    return "".join(out).encode("utf-8")


def build_aad(coords: Mapping[str, Any]) -> bytes:
    """Canonical associated-data block for a coordinate set (SPEC §5).

    ``coords`` maps the §5.1 members: ``table``, ``record_id``, ``column``
    (required), ``schema_id``/``schema_version``/``app_instance_id``
    (optional, reference defaults apply), ``revision`` (optional; omitted
    from the object when absent or None). Validation order and classes match
    the reference path: the five string coordinates first (non-str raises
    the same "non-empty string" ValueError — frozen quirk), then
    ``schema_version``, then ``revision``.
    """
    for name in ("table", "record_id", "column"):
        if name not in coords:
            raise ValueError(f"AAD coordinate {name!r} is required")
    table = coords["table"]
    record_id = coords["record_id"]
    column = coords["column"]
    schema_id = coords.get("schema_id", DEFAULT_SCHEMA_ID)
    schema_version = coords.get("schema_version", DEFAULT_SCHEMA_VERSION)
    app_instance_id = coords.get("app_instance_id", DEFAULT_APP_INSTANCE_ID)
    revision = coords.get("revision")

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

    out = [
        b'{"app_instance_id":',
        _quote_json_string(app_instance_id),
        b',"column":',
        _quote_json_string(column),
        b',"record_id":',
        _quote_json_string(record_id),
    ]
    if revision is not None:
        # int.__repr__ semantics (§5.2): decimal, arbitrary precision,
        # leading '-' permitted.
        out += [b',"revision":', int.__repr__(revision).encode("ascii")]
    out += [
        b',"schema_id":',
        _quote_json_string(schema_id),
        b',"schema_version":',
        int.__repr__(schema_version).encode("ascii"),
        b',"table":',
        _quote_json_string(table),
        b"}",
    ]
    return b"".join(out)


# --------------------------------------------------------------------------
# Envelope parse/build (SPEC §4) and the version-matched S2V AD vector (§6)
# --------------------------------------------------------------------------


class Envelope(NamedTuple):
    """A parsed record envelope. ``header``/``crypto_version``/``key_id`` are
    None for v1 (FLRV), which carries none of them."""

    version: int
    magic: bytes
    header: Optional[bytes]
    crypto_version: Optional[int]
    key_id: Optional[int]
    nonce: bytes
    ciphertext: bytes  # SIV tag || CTR ciphertext


def parse_envelope(data: BytesLike) -> Envelope:
    """Parse an envelope applying §4.3's checks in their frozen order:
    type → length(<21) → magic → crypto_version → nonce_len → non-empty ct."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("envelope must be bytes")
    data = bytes(data)
    if len(data) < MIN_ENVELOPE_LEN:
        raise TooShortError("Malformed ciphertext envelope: too short")
    magic = data[:4]
    if magic == MAGIC_V2:
        crypto_version = data[4]
        if crypto_version != CRYPTO_VERSION_V2:
            raise UnsupportedCryptoVersionError(
                f"Unsupported envelope crypto version {crypto_version}"
            )
        version = 2
        header: Optional[bytes] = data[:HEADER_LEN_V2]
        key_id: Optional[int] = data[5]
        offset = HEADER_LEN_V2
    elif magic == MAGIC_V1:
        version = 1
        crypto_version = key_id = None
        header = None
        offset = HEADER_LEN_V1
    else:
        raise BadMagicError("Invalid ciphertext magic header")

    nonce_len = data[offset - 1]
    if nonce_len != NONCE_LEN or len(data) < offset + nonce_len:
        raise BadNonceLengthError("Invalid nonce length in ciphertext envelope")

    nonce = data[offset : offset + nonce_len]
    ciphertext = data[offset + nonce_len :]
    if not ciphertext:
        raise EmptyCiphertextError("Malformed ciphertext envelope: no ciphertext")
    return Envelope(version, magic, header, crypto_version, key_id, nonce, ciphertext)


def ad_vector(env: Envelope, aad: bytes) -> list[bytes]:
    """S2V associated-data vector matching the envelope version (§6):
    v2 → [aad, header, nonce]; v1 → [aad, nonce]. Not interchangeable."""
    if env.version == 2:
        assert env.header is not None
        return [aad, env.header, env.nonce]
    return [aad, env.nonce]


def build_envelope(
    *,
    siv_key: bytes,
    plaintext: BytesLike,
    aad: bytes,
    nonce: BytesLike,
    version: int = 2,
    key_id: int = 0,
) -> bytes:
    """Seal ``plaintext`` into a v1 or v2 envelope with a caller-supplied nonce.

    The nonce is a parameter (never drawn here) so vector generation and the
    byte-identity re-encryption check can pin it. This module performs no
    nonce-window tracking — §7 marks that as an implementation detail.
    """
    nonce = bytes(nonce)
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be exactly {NONCE_LEN} bytes")
    if version == 2:
        if isinstance(key_id, bool) or not isinstance(key_id, int):
            raise TypeError("key_id must be an integer in [0, 255]")
        if not 0 <= key_id <= 255:
            raise ValueError("key_id must be an integer in [0, 255]")
        header = MAGIC_V2 + bytes([CRYPTO_VERSION_V2, key_id, NONCE_LEN])
        return header + nonce + siv_encrypt(siv_key, bytes(plaintext), [aad, header, nonce])
    if version == 1:
        header = MAGIC_V1 + bytes([NONCE_LEN])
        return header + nonce + siv_encrypt(siv_key, bytes(plaintext), [aad, nonce])
    raise ValueError("version must be 1 or 2")


def decrypt_envelope(
    siv_key: bytes,
    data: BytesLike,
    coords: Mapping[str, Any],
    *,
    require_key_id: Optional[int] = None,
) -> bytes:
    """Open an envelope under claimed coordinates (SPEC §4.4, in order):
    parse → key_id requirement → reconstruct AAD → AEAD-open.
    Returns raw plaintext bytes; UTF-8 decoding is the reader's business and
    a decode failure there is a verification failure, not a partial success."""
    env = parse_envelope(data)
    if require_key_id is not None:
        if env.key_id is None:
            raise KeyIdMismatchError("v1 envelope carries no key_id to check against")
        if env.key_id != require_key_id:
            raise KeyIdMismatchError(
                f"envelope was written under key id {env.key_id}, not {require_key_id}"
            )
    aad = build_aad(coords)
    plaintext = siv_decrypt(siv_key, env.ciphertext, ad_vector(env, aad))
    if plaintext is None:
        raise AuthenticationError("envelope verification failed")
    return plaintext


# --------------------------------------------------------------------------
# Search beacons (SPEC §9)
# --------------------------------------------------------------------------


def beacon_bucket_bytes(bits: int) -> int:
    """Stored width for ``bits`` — byte-aligned, so 4..8 bits store 1 byte."""
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError("beacon bits must be an integer")
    if not MIN_BEACON_BITS <= bits <= MAX_BEACON_BITS:
        raise ValueError(f"beacon bits must be in [{MIN_BEACON_BITS}, {MAX_BEACON_BITS}]")
    return (bits + 7) // 8


def compute_beacon(
    value: str,
    *,
    scope: str,
    key: BytesLike,
    bits: int = 8,
) -> bytes:
    """Truncated keyed beacon: HMAC-SHA256(key, u32be(len(scope)) || scope ||
    value)[:ceil(bits/8)]. Validation order matches the reference: bits →
    key length → value type → scope."""
    bucket = beacon_bucket_bytes(bits)
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("beacon key must be bytes")
    if len(key) < BEACON_KEY_LEN:
        raise ValueError(f"beacon key must be at least {BEACON_KEY_LEN} bytes")
    if not isinstance(value, str):
        raise TypeError(f"beacon value must be str, got {type(value).__name__}")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("beacon scope must be a non-empty string for domain separation")
    scope_bytes = scope.encode("utf-8")
    payload = struct.pack(">I", len(scope_bytes)) + scope_bytes + value.encode("utf-8")
    return hmac.new(bytes(key), payload, hashlib.sha256).digest()[:bucket]


# --------------------------------------------------------------------------
# Recovery bundle FVRB1 (SPEC §11)
# --------------------------------------------------------------------------


def recovery_coords(bundle_id: bytes) -> dict[str, Any]:
    """Sealing coordinates of a bundle's inner envelope (§11, exact)."""
    return {
        "app_instance_id": RECOVERY_APP_INSTANCE_ID,
        "table": RECOVERY_TABLE,
        "record_id": bundle_id.hex(),
        "column": RECOVERY_COLUMN,
        "schema_id": DEFAULT_SCHEMA_ID,
        "schema_version": DEFAULT_SCHEMA_VERSION,
    }


def build_recovery_bundle(
    master_key: BytesLike,
    recovery_key: BytesLike,
    *,
    bundle_id: BytesLike,
    nonce: BytesLike,
) -> bytes:
    """Wrap ``master_key`` under ``recovery_key`` (an ordinary master key),
    with caller-pinned bundle_id and envelope nonce for determinism."""
    master = bytes(master_key)
    recovery = bytes(recovery_key)
    bundle_id = bytes(bundle_id)
    if len(master) != MASTER_KEY_LEN or len(recovery) != MASTER_KEY_LEN:
        raise ValueError("master_key and recovery_key must each be exactly 32 bytes")
    if len(bundle_id) != RECOVERY_BUNDLE_ID_LEN:
        raise ValueError(f"bundle_id must be {RECOVERY_BUNDLE_ID_LEN} bytes")
    siv_key = derive_siv_key(recovery)
    aad = build_aad(recovery_coords(bundle_id))
    envelope = build_envelope(
        siv_key=siv_key, plaintext=master, aad=aad, nonce=nonce, version=2, key_id=0
    )
    return RECOVERY_MAGIC + bundle_id + envelope


def parse_recovery_bundle(data: BytesLike) -> tuple[bytes, bytes]:
    """Split an FVRB1 bundle into ``(bundle_id, embedded v2 envelope)``."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("bundle must be bytes")
    data = bytes(data)
    if len(data) < len(RECOVERY_MAGIC) + RECOVERY_BUNDLE_ID_LEN + 1:
        raise ValueError("invalid or unsupported recovery bundle")
    if data[: len(RECOVERY_MAGIC)] != RECOVERY_MAGIC:
        raise ValueError("invalid or unsupported recovery bundle")
    start = len(RECOVERY_MAGIC)
    return data[start : start + RECOVERY_BUNDLE_ID_LEN], data[start + RECOVERY_BUNDLE_ID_LEN :]


def recover_master_key(bundle: BytesLike, recovery_key: BytesLike) -> bytes:
    """Authenticate and unwrap a recovery bundle; returns the 32-byte master key."""
    recovery = bytes(recovery_key)
    if len(recovery) != MASTER_KEY_LEN:
        raise ValueError("recovery_key must be exactly 32 bytes")
    bundle_id, envelope = parse_recovery_bundle(bundle)
    siv_key = derive_siv_key(recovery)
    master = decrypt_envelope(siv_key, envelope, recovery_coords(bundle_id))
    if len(master) != MASTER_KEY_LEN:
        raise ValueError("recovered master key must be exactly 32 bytes")
    return master

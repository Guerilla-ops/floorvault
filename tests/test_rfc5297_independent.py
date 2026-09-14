"""Independent RFC 5297 (AES-SIV) validation for FloorVault.

Why this file exists
--------------------
The third-party name-based scanners (crypto-scanner, CryptoScan) and the
primitive test suite (crypto-condor) cannot see AES-SIV at all: crypto-condor
ships no SIV vector set, and the scanners have no SIV pattern. So none of them
can validate the one primitive FloorVault is built on.

This module closes that gap with an *independent, from-spec* RFC 5297
implementation that uses AES-ECB as its only library primitive: CMAC, S2V,
dbl/pad/xorend, the CTR framing and the counter-bit zeroing are implemented
here directly from the RFC 5297 text. It is then anchored to:

  1. The RFC's own published intermediate S2V values (Appendix A.1).
  2. The two official Appendix A vectors (A.1 deterministic, A.2 nonce-based).
  3. PyCA's ``AESSIV`` on random AES-256-SIV inputs (independent code path).
  4. PyCryptodome's ``MODE_SIV`` (optional; skipped if not installed).
  5. FloorVault's own ciphertext, recovered by this independent implementation.

Note on key sizes: RFC 5297's Appendix A vectors use a 256-bit key (AES-128 for
each of the S2V/CTR halves). FloorVault uses a 512-bit key (AES-256-SIV). The
construction is key-length agnostic; the vectors anchor the construction, and
point 3/5 anchor the 512-bit instantiation.
"""

from __future__ import annotations

import os
import random

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from floorvault import FloorVault, associated_data
from floorvault.core import RECORD_MAGIC
from floorvault.memory import HardenedMemoryKey

# --------------------------------------------------------------------------
# Reference RFC 5297 implementation (from spec; AES-ECB is the only primitive)
# --------------------------------------------------------------------------


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _dbl(s: bytes) -> bytes:
    """RFC 5297 Sec 2.3 doubling in GF(2^128), poly x^128+x^7+x^2+x+1."""
    n = int.from_bytes(s, "big")
    msb = (n >> 127) & 1
    n = (n << 1) & ((1 << 128) - 1)
    if msb:
        n ^= 0x87
    return n.to_bytes(16, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(s: bytes) -> bytes:
    """RFC 5297 pad(X): append 0x80 then zeros to 16 bytes (for len < 128 bits)."""
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
    """RFC 5297 Sec 2.4 S2V."""
    if not strings:
        return _cmac(key, _ONE)
    d = _cmac(key, _ZERO)
    for s in strings[:-1]:
        d = _xor(_dbl(d), _cmac(key, s))
    sn = strings[-1]
    t = _xorend(sn, d) if len(sn) >= 16 else _xor(_dbl(d), _pad(sn))
    return _cmac(key, t)


def _ctr_keystream(key2: bytes, v: bytes, length: int) -> bytes:
    """CTR as defined by RFC 5297 Sec 2.6, with bits 31 and 63 zeroed."""
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
    """RFC 5297 Sec 2.6 SIV-ENCRYPT. Returns V || C."""
    half = len(key) // 2
    v = s2v(key[:half], [*ad, plaintext])
    return v + _xor(plaintext, _ctr_keystream(key[half:], v, len(plaintext)))


def siv_decrypt(key: bytes, z: bytes, ad: list[bytes]) -> bytes | None:
    """RFC 5297 Sec 2.7 SIV-DECRYPT. Returns plaintext, or None on FAIL."""
    half = len(key) // 2
    v, c = z[:16], z[16:]
    p = _xor(c, _ctr_keystream(key[half:], v, len(c)))
    return p if s2v(key[:half], [*ad, p]) == v else None


# --------------------------------------------------------------------------
# 1. The RFC's own published intermediate values (Appendix A.1)
# --------------------------------------------------------------------------


def test_a1_published_s2v_intermediates():
    """Every intermediate S2V value printed in RFC 5297 Appendix A.1 must match."""
    key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = bytes.fromhex("112233445566778899aabbccddee")
    k1 = key[:16]

    c_cmac_zero = _cmac(k1, _ZERO)
    assert c_cmac_zero.hex() == "0e04dfafc1efbf040140582859bf073a"

    d0 = _dbl(c_cmac_zero)
    assert d0.hex() == "1c09bf5f83df7e080280b050b37e0e74"

    c_cmac_ad = _cmac(k1, ad)
    assert c_cmac_ad.hex() == "f1f922b7f5193ce64ff80cb47d93f23b"

    x1 = _xor(d0, c_cmac_ad)
    assert x1.hex() == "edf09de876c642ee4d78bce4ceedfc4f"

    d1 = _dbl(x1)
    assert d1.hex() == "dbe13bd0ed8c85dc9af179c99ddbf819"

    assert _pad(pt).hex() == "112233445566778899aabbccddee8000"

    x2 = _xor(d1, _pad(pt))
    assert x2.hex() == "cac30894b8eaf254035bc20540357819"

    assert _cmac(k1, x2).hex() == "85632d07c6e8f37f950acd320a2ecc93"


# --------------------------------------------------------------------------
# 2. The two official Appendix A vectors
# --------------------------------------------------------------------------


def test_a1_deterministic_vector_end_to_end():
    key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = bytes.fromhex("112233445566778899aabbccddee")
    expected = bytes.fromhex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
    assert siv_encrypt(key, pt, [ad]) == expected
    assert siv_decrypt(key, expected, [ad]) == pt


def test_a2_nonce_based_vector_end_to_end():
    key = bytes.fromhex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
    ad1 = bytes.fromhex(
        "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
    )
    ad2 = bytes.fromhex("102030405060708090a0")
    nonce = bytes.fromhex("09f911029d74e35bd84156c5635688c0")
    pt = bytes.fromhex(
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074"
        "207573696e67205349562d414553"
    )
    expected = bytes.fromhex(
        "7bdb6e3b432667eb06f4d14bff2fbd0f"
        "cb900f2fddbe404326601965c889bf17"
        "dba77ceb094fa663b7a3f748ba8af829"
        "ea64ad544a272e9c485b62a3fd5c0d"
    )
    assert siv_encrypt(key, pt, [ad1, ad2, nonce]) == expected
    assert siv_decrypt(key, expected, [ad1, ad2, nonce]) == pt


def test_a2_agrees_with_pyca_aessiv():
    """PyCA's AESSIV must reproduce the official vector (independent code path)."""
    key = bytes.fromhex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
    ad1 = bytes.fromhex(
        "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
    )
    ad2 = bytes.fromhex("102030405060708090a0")
    nonce = bytes.fromhex("09f911029d74e35bd84156c5635688c0")
    pt = bytes.fromhex(
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074"
        "207573696e67205349562d414553"
    )
    assert AESSIV(key).encrypt(pt, [ad1, ad2, nonce]) == siv_encrypt(key, pt, [ad1, ad2, nonce])


# --------------------------------------------------------------------------
# 3. Random cross-check at the 512-bit key size FloorVault actually uses
# --------------------------------------------------------------------------


def test_random_aes256_siv_matches_pyca():
    """At 64-byte keys, the from-spec implementation must equal PyCA AESSIV."""
    rng = random.Random(20260915)
    for _ in range(200):
        key = os.urandom(64)
        ad = [os.urandom(rng.randint(0, 40)) for _ in range(rng.randint(0, 4))]
        pt = os.urandom(rng.randint(0, 200))
        mine = siv_encrypt(key, pt, ad)
        assert mine == AESSIV(key).encrypt(pt, ad)
        assert siv_decrypt(key, mine, ad) == pt


def test_random_aes256_siv_matches_pycryptodome():
    """Second independent implementation (PyCryptodome MODE_SIV), if present."""
    pydome = pytest.importorskip("Crypto.Cipher.AES")
    rng = random.Random(4242)
    for _ in range(100):
        key = os.urandom(64)
        ad = [os.urandom(rng.randint(0, 40)) for _ in range(rng.randint(0, 4))]
        pt = os.urandom(rng.randint(0, 200))
        c = pydome.new(key, pydome.MODE_SIV)
        for a in ad:
            c.update(a)
        ct, tag = c.encrypt_and_digest(pt)
        assert tag + ct == siv_encrypt(key, pt, ad)


# --------------------------------------------------------------------------
# 4. FloorVault's own ciphertext, verified by the independent implementation
# --------------------------------------------------------------------------


def _floorvault() -> FloorVault:
    return FloorVault(HardenedMemoryKey(bytes.fromhex("ab" * 32)))


def test_floorvault_key_schedule_matches_independent_hkdf():
    """FloorVault's derived SIV key equals an independent HKDF derivation."""
    master = bytes.fromhex("ab" * 32)
    expected = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"floorvault-v1-aes-siv"
    ).derive(master)
    fv = _floorvault()
    assert fv._siv_key.get_bytes() == expected
    assert len(expected) == 64  # AES-256-SIV


def test_floorvault_ciphertext_recovers_with_independent_rfc5297():
    """FloorVault's real ciphertext must be openable by the from-spec impl.

    This is the load-bearing assertion: an implementation written only from the
    RFC text, with no knowledge of FloorVault, recovers the plaintext. That
    proves FloorVault's records are genuine RFC 5297 SIV, not merely
    self-consistent.
    """
    master = bytes.fromhex("ab" * 32)
    siv_key = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"floorvault-v1-aes-siv"
    ).derive(master)
    fv = _floorvault()

    cases = [
        ("users", "u-1", "email", "alice@example.com"),
        ("secrets", "s-42", "payload_cipher", "unicode \u00e9\u4e2d\u6587 \U0001f512"),
        ("notes", "n-0", "body", ""),
    ]
    for table, rec, col, value in cases:
        env = fv.encrypt(value, table=table, record_id=rec, column=col)
        assert env[:4] == RECORD_MAGIC
        assert env[4] == 16
        nonce, z = env[5:21], env[21:]
        aad = associated_data(
            table=table,
            record_id=rec,
            column=col,
            schema_id="floor.vault.v1",
            schema_version=1,
            app_instance_id=fv.app_instance_id,
        )
        recovered = siv_decrypt(siv_key, z, [aad, nonce])
        assert recovered is not None
        assert recovered.decode("utf-8") == value


def test_independent_impl_rejects_spliced_context_and_tamper():
    """Wrong AAD coordinates or a flipped ciphertext bit must FAIL closed."""
    master = bytes.fromhex("ab" * 32)
    siv_key = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"floorvault-v1-aes-siv"
    ).derive(master)
    fv = _floorvault()

    env = fv.encrypt("sensitive", table="users", record_id="u-1", column="email")
    nonce, z = env[5:21], env[21:]
    aad = associated_data(
        table="users",
        record_id="u-1",
        column="email",
        schema_id="floor.vault.v1",
        schema_version=1,
        app_instance_id=fv.app_instance_id,
    )
    assert siv_decrypt(siv_key, z, [aad, nonce]) == b"sensitive"

    # Wrong column -> different AAD -> FAIL.
    wrong_aad = associated_data(
        table="users",
        record_id="u-1",
        column="other",
        schema_id="floor.vault.v1",
        schema_version=1,
        app_instance_id=fv.app_instance_id,
    )
    assert siv_decrypt(siv_key, z, [wrong_aad, nonce]) is None
    # Wrong nonce -> FAIL.
    assert siv_decrypt(siv_key, z, [aad, b"\x00" * 16]) is None
    # Flipped ciphertext bit -> FAIL.
    flipped = bytearray(z)
    flipped[-1] ^= 0x01
    assert siv_decrypt(siv_key, bytes(flipped), [aad, nonce]) is None
    # And FloorVault's own decrypt fails closed on the same splice.
    from floorvault.core import DecryptionVerificationError

    with pytest.raises(DecryptionVerificationError):
        fv.decrypt(env, table="users", record_id="u-1", column="other")

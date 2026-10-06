"""Independent, from-spec RFC 5297 (AES-SIV) implementation.

This module is the same code FloorVault uses internally to anchor its own
AES-256-SIV envelope to the RFC text, the two published Appendix A vectors,
the 1,342 Project Wycheproof AES-SIV-CMAC vectors, and an independent
PyCryptodome implementation. Promoting it here lets an external consumer
(e.g. the Floor lecompound backend's AppState envelope) cross-check its own
AES-SIV usage against the same reference FloorVault is pinned to, rather
than against the library implementation both projects share.

Construction
------------
AES-ECB is the only library primitive. CMAC (RFC 4493), S2V (RFC 5297
Sec 2.4), the dbl / pad / xorend helpers, the CTR framing, and the
counter-bit zeroing (Sec 2.6) are implemented directly from the RFC text.

Key sizes
---------
RFC 5297 Appendix A anchors a 256-bit key (AES-128 for each of the
S2V / CTR halves). The construction is key-length agnostic; this module
accepts any even-length key up to 512 bits, which covers both
AES-128-SIV and AES-256-SIV.

Provenance
----------
Originally implemented in ``tests/test_rfc5297_independent.py`` to anchor
FloorVault's own envelope. Promoted here unchanged so external consumers
can run the same independent code path.

Not exported
------------
This module is NOT re-exported from ``floorvault.__init__``. Import it
explicitly: ``from floorvault.testing.siv_reference import siv_encrypt``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    # AES-ECB is the RFC 5297 construction's only required primitive; CMAC
    # (RFC 4493) is built from it and SIV's CTR keystream is built from it.
    # Bandit flags this as B305 (insecure cipher mode); the suppression is
    # deliberate because every ECB call here is single-block (always 16 bytes)
    # and the construction is the from-spec RFC 5297 implementation FloorVault
    # itself anchors against. This is the same code as
    # tests/test_rfc5297_independent.py, where Bandit skips it because
    # bandit skips test files by default; this module is in src/ so the
    # suppression must be explicit.
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # nosec B305
    return enc.update(block) + enc.finalize()


def _dbl(s: bytes) -> bytes:
    """RFC 5297 Sec 2.3 doubling in GF(2^128), poly x^128 + x^7 + x^2 + x + 1."""
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
    """RFC 5297 Sec 2.4 S2V.

    ``key`` is the S2V half of the SIV key (128 bits for AES-128-SIV,
    256 bits for AES-256-SIV). ``strings`` is the list of AD components
    in the order they appear in the SIV input; the last element is the
    synthetic component per the spec.
    """
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
    """RFC 5297 Sec 2.6 SIV-ENCRYPT. Returns ``V || C``.

    ``key`` is the full SIV key (256 bits for AES-128-SIV, 512 bits for
    AES-256-SIV); it is split in half internally. ``ad`` is the list of
    associated-data components in declaration order; the synthetic last
    component is appended automatically.
    """
    half = len(key) // 2
    v = s2v(key[:half], [*ad, plaintext])
    return v + _xor(plaintext, _ctr_keystream(key[half:], v, len(plaintext)))


def siv_decrypt(key: bytes, z: bytes, ad: list[bytes]) -> bytes | None:
    """RFC 5297 Sec 2.7 SIV-DECRYPT.

    Returns the plaintext on success, or ``None`` on SIV authentication
    failure. A returned ``None`` is the only safe signal: the caller MUST
    treat the input as unauthenticated, not as "decryption produced this
    garbage I should now log".
    """
    half = len(key) // 2
    v, c = z[:16], z[16:]
    p = _xor(c, _ctr_keystream(key[half:], v, len(c)))
    return p if s2v(key[:half], [*ad, p]) == v else None


__all__ = ["s2v", "siv_encrypt", "siv_decrypt"]

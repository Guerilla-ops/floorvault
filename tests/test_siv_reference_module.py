"""Test for the floorvault.testing.siv_reference module.

This module exists so external consumers (e.g. the Floor lecompound backend's
AppState envelope) can cross-check their own AES-SIV usage against the same
from-spec RFC 5297 implementation that anchors FloorVault's internal envelope.

The module is opt-in: it is NOT exported from ``floorvault.__init__`` and is
only reachable by an explicit ``from floorvault.testing.siv_reference import ...``.
A test that pulls it in is opting in; the import error below is the failure
this test was written to surface until the module exists.
"""

from __future__ import annotations

import pytest

from floorvault.testing.siv_reference import s2v, siv_decrypt, siv_encrypt


def test_module_imports_public_functions():
    """The module must expose s2v, siv_encrypt, siv_decrypt as its public API."""
    assert callable(s2v)
    assert callable(siv_encrypt)
    assert callable(siv_decrypt)


def test_round_trip_with_known_aes256_siv_inputs():
    """siv_decrypt(siv_encrypt(key, pt, ad), ad) == pt for arbitrary AES-256-SIV inputs."""
    key = bytes(range(64))  # 512-bit key
    plaintext = b"floorvault.testing.siv_reference round-trip payload"
    ad = [b"first-component", b"second-component", b"third"]
    ciphertext = siv_encrypt(key, plaintext, ad)
    assert ciphertext != plaintext  # not the identity
    assert siv_decrypt(key, ciphertext, ad) == plaintext


def test_siv_decrypt_returns_none_on_wrong_ad():
    """Wrong AD must cause SIV authentication to FAIL (return None), not silently return garbage."""
    key = bytes(range(64))
    plaintext = b"tamper-target plaintext"
    ad = [b"original", b"second"]
    ciphertext = siv_encrypt(key, plaintext, ad)
    assert siv_decrypt(key, ciphertext, [b"TAMPERED", b"second"]) is None


def test_s2v_matches_rfc_5297_appendix_a1_final_intermediate():
    """RFC 5297 Appendix A.1 published S2V final intermediate must match.

    For two components (a 24-byte AD and a 14-byte plaintext), the spec
    prints the full chain:

        d   = CMAC(K1, <zero>)               = 0e04dfaf...
        d0  = dbl(d)                          = 1c09bf5f...
        x1  = d0 XOR CMAC(K1, AD)             = edf09de8...
        d1  = dbl(x1)                         = dbe13bd0...
        x2  = d1 XOR pad(pt)                  = cac30894...
        T   = CMAC(K1, x2)                    = 85632d07...

    The terminal value T is what s2v must return for that input. This anchors
    the promoted module to the RFC text rather than to PyCA's AESSIV, which
    is what makes the cross-check independent of the library both FloorVault
    and the Floor backend use.
    """
    key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = bytes.fromhex("112233445566778899aabbccddee")
    assert s2v(key[:16], [ad, pt]).hex() == "85632d07c6e8f37f950acd320a2ecc93"


@pytest.mark.parametrize(
    "ad",
    [
        [b""],
        [b"only-component"],
        [b"first", b"second"],
        [b"a", b"", b"c", b"d", b"e"],
        [b"\x00" * 16],  # boundary: AD component equal to the AES block size
    ],
)
def test_round_trip_across_ad_shapes(ad):
    """Round-trip must hold across the AD shapes a real envelope might emit."""
    key = b"\x11" * 64
    plaintext = b"x" * 1024
    ciphertext = siv_encrypt(key, plaintext, ad)
    assert siv_decrypt(key, ciphertext, ad) == plaintext

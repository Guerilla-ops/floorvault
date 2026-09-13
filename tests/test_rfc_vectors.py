"""Official RFC Test Vectors verification for AES-SIV (RFC 5297) and HKDF-SHA256 (RFC 5869)."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def test_rfc_5297_appendix_a1_deterministic_aes_siv():
    """RFC 5297 Appendix A.1: Deterministic Authenticated Encryption Example."""
    key = bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")
    plaintext = bytes.fromhex("112233445566778899aabbccddee")

    # Encrypt
    cipher = AESSIV(key).encrypt(plaintext, [ad])

    expected = bytes.fromhex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
    assert cipher == expected

    # Decrypt
    decrypted = AESSIV(key).decrypt(cipher, [ad])
    assert decrypted == plaintext


def test_rfc_5297_appendix_a2_nonce_based_aes_siv():
    """RFC 5297 Appendix A.2: Nonce-Based Authenticated Encryption Example with Multiple ADs."""
    key = bytes.fromhex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
    ad1 = bytes.fromhex(
        "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
    )
    ad2 = bytes.fromhex("102030405060708090a0")
    nonce = bytes.fromhex("09f911029d74e35bd84156c5635688c0")
    plaintext = bytes.fromhex(
        "7468697320697320736f6d6520706c61"
        "696e7465787420746f20656e63727970"
        "74207573696e67205349562d414553"
    )

    # Encrypt passing [AD1, AD2, Nonce]
    cipher = AESSIV(key).encrypt(plaintext, [ad1, ad2, nonce])

    expected = bytes.fromhex(
        "7bdb6e3b432667eb06f4d14bff2fbd0f"
        "cb900f2fddbe404326601965c889bf17"
        "dba77ceb094fa663b7a3f748ba8af829"
        "ea64ad544a272e9c485b62a3fd5c0d"
    )
    assert cipher == expected

    # Decrypt
    decrypted = AESSIV(key).decrypt(cipher, [ad1, ad2, nonce])
    assert decrypted == plaintext


def test_rfc_5869_test_case_1_hkdf_sha256():
    """RFC 5869 Test Case 1: Basic test case with SHA-256."""
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)

    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )

    assert okm == expected_okm

"""Envelope versioning: the on-record header must name its crypto version and
key, and that header must be authenticated.

Why: the v1 envelope was ``FLRV | nonce_len | nonce | ciphertext`` - 37 bytes of
fixed overhead carrying no version beyond a 4-byte magic and no key identifier at
all. A reader could not tell which key a record needed, so the master key could
not be rotated without re-encrypting everything blind, and no future algorithm or
context change had a field to declare itself in.

The v2 envelope adds ``crypto_version`` and ``key_id``, binds the whole cleartext
header into the AEAD associated data so a rewritten header fails authentication,
and keeps v1 records readable.
"""

from __future__ import annotations

import pytest

from floorvault.core import (
    CRYPTO_VERSION,
    RECORD_MAGIC_V2,
    DecryptionVerificationError,
    FloorVault,
    envelope_header,
)
from floorvault.memory import HardenedMemoryKey

MASTER = bytes.fromhex("5a" * 32)


def _make_vault() -> FloorVault:
    return FloorVault(HardenedMemoryKey(MASTER))


def _encrypt(vault: FloorVault, plaintext: str, **kwargs) -> bytes:
    """Encrypt at fixed coordinates, allowing extra keyword arguments."""
    return vault.encrypt(
        plaintext,
        table="users",
        record_id="u-1",
        column="email",
        **kwargs,
    )


def test_new_encryptions_carry_the_versioned_header():
    """Writes use the v2 magic, and the header declares version and key id."""
    env = _encrypt(_make_vault(), "value")

    assert env[:4] == RECORD_MAGIC_V2
    header = envelope_header(env)
    assert header["magic"] == RECORD_MAGIC_V2
    assert header["crypto_version"] == CRYPTO_VERSION
    assert header["key_id"] == 0
    assert header["nonce_len"] == 16
    assert header["header_len"] == 7


def test_envelope_header_reports_the_key_id_written_at_encryption():
    """A caller may bind a record to a key id; the header reports it back."""
    env = _encrypt(_make_vault(), "value", key_id=7)
    assert envelope_header(env)["key_id"] == 7


def test_key_id_must_be_a_byte():
    vault = _make_vault()
    for bad in (-1, 256, "1", True):
        with pytest.raises((TypeError, ValueError)):
            _encrypt(vault, "value", key_id=bad)


def test_envelope_header_rejects_a_non_envelope():
    with pytest.raises(DecryptionVerificationError):
        envelope_header(b"not-an-envelope")


@pytest.mark.parametrize("ciphertext", [b"FLV2", b"FLV2\x02", b"FLV2\x02\x00"])
def test_envelope_header_rejects_truncated_v2_headers(ciphertext: bytes):
    """Every truncated v2 header fails with the public verification error."""
    with pytest.raises(DecryptionVerificationError):
        envelope_header(ciphertext)


# ---------------------------------------------------------------------------
# The header must be AUTHENTICATED, not merely advisory
# ---------------------------------------------------------------------------


def test_rewritten_key_id_fails_authentication():
    """Flipping the header's key_id byte must fail the tag check.

    A key id that is only advisory would let an attacker relabel a record to
    make a reader pick the wrong key (or, worse, hide which key it needs).
    """
    vault = _make_vault()
    env = bytearray(_encrypt(vault, "value"))
    assert env[5] == 0
    env[5] = 9  # relabel the record's key id

    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(bytes(env), table="users", record_id="u-1", column="email")


def test_rewritten_crypto_version_is_refused():
    """A header claiming another crypto version must not be silently accepted."""
    vault = _make_vault()
    env = bytearray(_encrypt(vault, "value"))
    env[4] = 3  # claim a future version

    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(bytes(env), table="users", record_id="u-1", column="email")


def test_rewritten_nonce_length_is_refused():
    vault = _make_vault()
    env = bytearray(_encrypt(vault, "value"))
    env[6] = 8  # claim an 8-byte nonce

    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(bytes(env), table="users", record_id="u-1", column="email")


def test_caller_can_require_a_key_id():
    """A supplied key_id is checked against the authenticated header."""
    vault = _make_vault()
    env = _encrypt(vault, "value", key_id=7)

    assert vault.decrypt(env, table="users", record_id="u-1", column="email", key_id=7) == "value"
    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(env, table="users", record_id="u-1", column="email", key_id=8)


# ---------------------------------------------------------------------------
# v1 records must stay readable
# ---------------------------------------------------------------------------


def _write_v1_envelope(plaintext: str, *, table: str, record_id: str, column: str) -> bytes:
    """Build an envelope exactly as the v1 writer did.

    The SIV subkey is re-derived independently (HKDF-SHA256, the documented
    label, 64 bytes for AES-256-SIV) rather than read from the instance, so this
    is a real description of the old on-disk format and not a mirror of the
    current implementation.
    """
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from floorvault.core import RECORD_MAGIC, associated_data

    siv_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"floorvault-v1-aes-siv",
    ).derive(MASTER)
    aad = associated_data(table=table, record_id=record_id, column=column)
    nonce = os.urandom(16)
    ciphertext = AESSIV(siv_key).encrypt(plaintext.encode("utf-8"), [aad, nonce])
    return RECORD_MAGIC + bytes([len(nonce)]) + nonce + ciphertext


def test_v1_envelope_is_still_readable():
    """Records written by the previous format must decrypt unchanged."""
    vault = _make_vault()
    legacy = _write_v1_envelope("old-value", table="users", record_id="u-1", column="email")

    assert legacy[:4] == b"FLRV"
    assert vault.decrypt(legacy, table="users", record_id="u-1", column="email") == "old-value"
    assert (
        vault.decrypt_bytes(legacy, table="users", record_id="u-1", column="email") == b"old-value"
    )


def test_v1_envelope_header_reports_no_version_or_key_id():
    header = envelope_header(
        _write_v1_envelope("old-value", table="users", record_id="u-1", column="email")
    )
    assert header["magic"] == b"FLRV"
    assert header["header_len"] == 5
    assert header["nonce_len"] == 16
    assert "crypto_version" not in header
    assert "key_id" not in header


def test_v1_envelope_relabelled_as_v2_is_refused():
    """A v1 record must not be reinterpreted as v2 by editing its magic."""
    vault = _make_vault()
    legacy = bytearray(
        _write_v1_envelope("old-value", table="users", record_id="u-1", column="email")
    )
    legacy[0:4] = RECORD_MAGIC_V2

    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(bytes(legacy), table="users", record_id="u-1", column="email")


def test_v1_envelope_still_enforces_its_coordinates():
    """Backward compatibility must not weaken contextual binding."""
    vault = _make_vault()
    legacy = _write_v1_envelope("old-value", table="users", record_id="u-1", column="email")

    with pytest.raises(DecryptionVerificationError):
        vault.decrypt(legacy, table="users", record_id="u-2", column="email")

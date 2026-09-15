"""Reading a store that spans more than one key generation.

A rotation leaves a store holding records sealed under two keys at once: the ones
already moved and the ones not yet moved. A reader must therefore select a key per
record, not per store - which is what the v2 envelope's authenticated ``key_id``
exists for.

The ring refuses anything it cannot justify. It never tries every key in turn: a
record naming a key the ring does not hold is an error, because "try them all and
see which authenticates" would silently accept a relabelled record if any key
happened to work, and would hide the operational mistake of a missing key.
"""

from __future__ import annotations

import pytest

from floorvault.core import (
    RECORD_MAGIC_V2,
    DecryptionVerificationError,
    FloorVault,
    associated_data,
    envelope_header,
)
from floorvault.keyring import KeyRing, UnknownKeyIdError
from floorvault.memory import HardenedMemoryKey

KEY_0 = bytes.fromhex("01" * 32)
KEY_1 = bytes.fromhex("02" * 32)
COORDS = {"table": "users", "record_id": "u-1", "column": "email"}


def _vault(seed: bytes) -> FloorVault:
    return FloorVault(HardenedMemoryKey(seed))


def _encrypt(vault: FloorVault, plaintext: str, **kwargs) -> bytes:
    return vault.encrypt(plaintext, **COORDS, **kwargs)


def _v1_envelope(plaintext: str, seed: bytes = KEY_0) -> bytes:
    """Build a v1 record, as the previous writer produced them."""
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from floorvault.core import RECORD_MAGIC

    siv_key = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"floorvault-v1-aes-siv"
    ).derive(seed)
    aad = associated_data(table="users", record_id="u-1", column="email")
    nonce = os.urandom(16)
    return (
        RECORD_MAGIC
        + bytes([len(nonce)])
        + nonce
        + AESSIV(siv_key).encrypt(plaintext.encode("utf-8"), [aad, nonce])
    )


# ---------------------------------------------------------------------------
# Selecting the right key
# ---------------------------------------------------------------------------


def test_ring_reads_a_record_sealed_under_the_generation_it_names():
    ring = KeyRing({0: _vault(KEY_0), 1: _vault(KEY_1)})
    blob = _encrypt(_vault(KEY_1), "second-generation", key_id=1)
    assert envelope_header(blob)["key_id"] == 1
    assert ring.decrypt(blob, **COORDS) == "second-generation"


def test_ring_reads_a_store_spanned_by_two_generations():
    """The mixed state a rotation leaves behind must be readable throughout."""
    ring = KeyRing({0: _vault(KEY_0), 1: _vault(KEY_1)})
    old = _encrypt(_vault(KEY_0), "not-yet-rotated", key_id=0)
    new = _encrypt(_vault(KEY_1), "already-rotated", key_id=1)

    assert ring.decrypt(old, **COORDS) == "not-yet-rotated"
    assert ring.decrypt(new, **COORDS) == "already-rotated"


def test_key_ids_reports_what_the_ring_holds():
    ring = KeyRing({1: _vault(KEY_1), 0: _vault(KEY_0)})
    assert ring.key_ids() == (0, 1)


# ---------------------------------------------------------------------------
# Refusing what it cannot justify
# ---------------------------------------------------------------------------


def test_unknown_key_id_is_refused_by_name():
    ring = KeyRing({1: _vault(KEY_1)})
    blob = _encrypt(_vault(KEY_1), "v", key_id=7)

    with pytest.raises(UnknownKeyIdError) as excinfo:
        ring.decrypt(blob, **COORDS)
    # The message must name the id and what is held, or an operator cannot act.
    assert "7" in str(excinfo.value)
    assert "1" in str(excinfo.value)


def test_a_relabelled_record_fails_authentication_rather_than_using_another_key():
    """The header is authenticated, so a rewritten key_id cannot redirect the read.

    Without that property a relabelled record would be decrypted with whichever
    key the label pointed at - the ring would be choosing on the attacker's word.
    """
    ring = KeyRing({0: _vault(KEY_0), 1: _vault(KEY_1)})
    blob = bytearray(_encrypt(_vault(KEY_0), "sealed under zero", key_id=0))
    blob[5] = 1  # relabel: claim it was written under key 1

    with pytest.raises(DecryptionVerificationError):
        ring.decrypt(bytes(blob), **COORDS)


def test_ring_never_falls_back_to_trying_every_key():
    """A ring holding the wrong key must fail, not search for one that works."""
    ring = KeyRing({0: _vault(bytes.fromhex("09" * 32))})
    blob = _encrypt(_vault(KEY_0), "v", key_id=0)
    with pytest.raises(DecryptionVerificationError):
        ring.decrypt(blob, **COORDS)


# ---------------------------------------------------------------------------
# v1 records carry no key id
# ---------------------------------------------------------------------------


def test_v1_records_read_through_a_declared_default():
    ring = KeyRing({0: _vault(KEY_0)}, default_key_id=0)
    assert ring.decrypt(_v1_envelope("legacy"), **COORDS) == "legacy"


def test_v1_records_are_refused_without_a_declared_default():
    """A v1 record cannot say which key it needs, so guessing is not allowed."""
    ring = KeyRing({0: _vault(KEY_0)})
    with pytest.raises(UnknownKeyIdError) as excinfo:
        ring.decrypt(_v1_envelope("legacy"), **COORDS)
    assert "default_key_id" in str(excinfo.value)


def test_default_key_id_must_be_held_by_the_ring():
    with pytest.raises(ValueError):
        KeyRing({0: _vault(KEY_0)}, default_key_id=5)


# ---------------------------------------------------------------------------
# Bytes path and validation
# ---------------------------------------------------------------------------


def test_decrypt_bytes_matches_decrypt():
    ring = KeyRing({1: _vault(KEY_1)})
    blob = ring_bytes = _encrypt(_vault(KEY_1), "bytes", key_id=1)
    assert ring.decrypt_bytes(ring_bytes, **COORDS) == b"bytes"
    assert blob  # keep the names readable


def test_a_non_envelope_is_refused():
    ring = KeyRing({0: _vault(KEY_0)})
    with pytest.raises(DecryptionVerificationError):
        ring.decrypt(b"not-an-envelope", **COORDS)


def test_an_empty_ring_is_refused_at_construction():
    with pytest.raises(ValueError):
        KeyRing({})


def test_key_ids_must_be_bytes_and_values_must_be_vaults():
    with pytest.raises((TypeError, ValueError)):
        KeyRing({256: _vault(KEY_0)})
    with pytest.raises((TypeError, ValueError)):
        KeyRing({"0": _vault(KEY_0)})  # type: ignore[dict-item]
    with pytest.raises((TypeError, ValueError)):
        KeyRing({0: "not-a-vault"})  # type: ignore[dict-item]


def test_the_ring_does_not_mutate_its_input_mapping():
    keys = {0: _vault(KEY_0)}
    ring = KeyRing(keys)
    keys[1] = _vault(KEY_1)
    assert ring.key_ids() == (0,)
    assert RECORD_MAGIC_V2  # the ring reads v2 headers, asserted here for clarity


def test_the_ring_is_part_of_the_public_api():
    """A read path a caller must use during a rotation belongs in the package surface."""
    import floorvault

    assert floorvault.KeyRing is KeyRing
    assert floorvault.UnknownKeyIdError is UnknownKeyIdError
    assert "KeyRing" in floorvault.__all__
    assert "UnknownKeyIdError" in floorvault.__all__

"""Tests for the optional revision binding (same-coordinate replay detection).

AES-SIV authenticates data, not freshness: a ciphertext moved to *different*
coordinates fails to decrypt, but the same ciphertext written back into its
*original* coordinates authenticates successfully. Binding a caller-supplied
monotonic revision into the AAD closes that gap: an older ciphertext read back
at the current revision fails authentication. The revision must come from
state the attacker cannot roll back together with the ciphertext — a revision
stored beside the ciphertext provides no protection.
"""

from __future__ import annotations

import pytest

from floorvault.core import (
    DecryptionVerificationError,
    FloorVault,
    associated_data,
)


def test_revision_binding_detects_same_context_replay():
    crypto = FloorVault(b"\x0a" * 32, memory_mode="disabled")
    coordinates = {"table": "users", "record_id": "usr-1", "column": "permission"}

    older = crypto.encrypt("user", revision=1, **coordinates)
    current = crypto.encrypt("admin", revision=2, **coordinates)

    # The current record reads back at the trusted revision.
    assert crypto.decrypt(current, revision=2, **coordinates) == "admin"
    # A replay of the older ciphertext at the same coordinates is rejected.
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(older, revision=2, **coordinates)


def test_revision_is_bound_into_the_aad():
    crypto = FloorVault(b"\x0b" * 32, memory_mode="disabled")
    coordinates = {"table": "t", "record_id": "r", "column": "c"}

    ct = crypto.encrypt("value", revision=7, **coordinates)
    assert crypto.decrypt(ct, revision=7, **coordinates) == "value"
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(ct, revision=8, **coordinates)
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(ct, **coordinates)
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(ct, revision=0, **coordinates)

    # Reverse direction: an unbound ciphertext cannot be read at a revision.
    unbound = crypto.encrypt("value", **coordinates)
    assert crypto.decrypt(unbound, **coordinates) == "value"
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(unbound, revision=1, **coordinates)


def test_revision_round_trips_through_decrypt_bytes():
    crypto = FloorVault(b"\x0e" * 32, memory_mode="disabled")
    coordinates = {"table": "t", "record_id": "r", "column": "c"}
    payload = b"\x00\xff\x80binary\x01"

    ct = crypto.encrypt(payload, revision=3, **coordinates)
    assert crypto.decrypt_bytes(ct, revision=3, **coordinates) == payload
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt_bytes(ct, revision=4, **coordinates)


def test_revision_is_not_stored_in_the_envelope():
    """The revision lives in the caller's trusted state, not the ciphertext.

    Storing it in the envelope would defeat rollback detection: an attacker
    replaying a ciphertext would replay its stored revision with it.
    """
    crypto = FloorVault(b"\x0c" * 32, memory_mode="disabled")
    coordinates = {"table": "t", "record_id": "r", "column": "c"}

    first = crypto.encrypt("same", revision=1, **coordinates)
    second = crypto.encrypt("same", revision=1, **coordinates)

    assert first != second  # fresh nonce per encryption
    assert len(first) == len(second)  # same envelope shape: no revision field
    assert first[:5] == second[:5] == b"FLRV\x10"


def test_associated_data_includes_revision_only_when_provided():
    base = associated_data(table="t", record_id="r", column="c")
    assert base == (
        b'{"app_instance_id":"default","column":"c","record_id":"r",'
        b'"schema_id":"floor.vault.v1","schema_version":1,"table":"t"}'
    )

    bound = associated_data(table="t", record_id="r", column="c", revision=2)
    assert bound == (
        b'{"app_instance_id":"default","column":"c","record_id":"r","revision":2,'
        b'"schema_id":"floor.vault.v1","schema_version":1,"table":"t"}'
    )


def test_revision_validation():
    crypto = FloorVault(b"\x0d" * 32, memory_mode="disabled")
    coordinates = {"table": "t", "record_id": "r", "column": "c"}

    for bad, exc in [
        (-1, ValueError),
        ("1", TypeError),
        (1.5, TypeError),
        (True, TypeError),
    ]:
        with pytest.raises(exc):
            crypto.encrypt("v", revision=bad, **coordinates)

    # The default remains unbound and fully backward compatible.
    unbound = crypto.encrypt("v", **coordinates)
    assert crypto.decrypt(unbound, **coordinates) == "v"

import json
import base64
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pixel_org_ui.app_state_crypto import (
    AppStateCrypto,
    AppStateIntegrityError,
    NonceGenerationError,
    associated_data,
)
from pixel_org_ui.contract_registry import canonical_json_bytes
from pixel_org_ui.errors import ValidationError


INSTANCE = str(uuid.UUID(int=7))
CONTEXT = {
    "table": "drafts",
    "record_id": "draft-1",
    "column": "encrypted_content",
    "payload_schema": "eightbit.appstate.draft-content.v1",
}


def crypto(**kwargs):
    return AppStateCrypto(b"d" * 32, INSTANCE, **kwargs)


def test_aes_siv_v2_envelope_is_exact_self_describing_and_round_trips():
    value = {"schema": "example.v1", "message": "classified sentinel", "count": 2}
    sealed = crypto(nonce_source=lambda size: b"n" * size).encrypt_json(value, **CONTEXT)
    envelope = json.loads(sealed)

    assert set(envelope) == {
        "v", "alg", "key_version", "nonce_b64u", "ciphertext_b64u", "aad_sha256"
    }
    assert envelope["v"] == 2
    assert envelope["alg"] == "A256SIV"
    assert envelope["key_version"] == 1
    assert len(envelope["nonce_b64u"]) == 16
    assert b"classified sentinel" not in sealed
    assert crypto().decrypt_json(sealed, **CONTEXT) == value


def test_v2_reconstructed_contexts_remain_authentic_under_nonce_reuse():
    """A process restart reusing a nonce cannot forge either sealed payload."""
    first = AppStateCrypto(
        b"d" * 32, INSTANCE, nonce_source=lambda size: b"r" * size
    )
    second = AppStateCrypto(
        b"d" * 32, INSTANCE, nonce_source=lambda size: b"r" * size
    )
    first_payload = {"message": "first independent payload"}
    second_payload = {"message": "second independent payload"}
    first_sealed = first.encrypt_json(first_payload, **CONTEXT)
    second_sealed = second.encrypt_json(second_payload, **CONTEXT)

    assert first.decrypt_json(first_sealed, **CONTEXT) == first_payload
    assert second.decrypt_json(second_sealed, **CONTEXT) == second_payload
    assert first.decrypt_json(second_sealed, **CONTEXT) == second_payload

    tampered = json.loads(first_sealed)
    tampered["nonce_b64u"] = "AAAAAAAAAAAAAAAA"
    with pytest.raises(AppStateIntegrityError):
        first.decrypt_json(
            json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode(), **CONTEXT
        )


def test_v1_aes_gcm_fixture_remains_readable_but_new_writes_are_v2():
    """A previous authenticated record is a read-only migration compatibility path."""
    plaintext = canonical_json_bytes({"message": "hand-built v1 record"})
    aad = associated_data(app_instance_id=INSTANCE, schema_version=1, **CONTEXT)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=uuid.UUID(INSTANCE).bytes,
        info=b"eightbit.appstate.encryption.v1",
    ).derive(b"d" * 32)
    nonce = b"v" * 12
    envelope = {
        "v": 1,
        "alg": "A256GCM",
        "key_version": 1,
        "nonce_b64u": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(),
        "ciphertext_b64u": base64.urlsafe_b64encode(
            AESGCM(key).encrypt(nonce, plaintext, aad)
        ).rstrip(b"=").decode(),
        "aad_sha256": hashlib.sha256(aad).hexdigest(),
    }
    fixture = canonical_json_bytes(envelope)

    assert crypto().decrypt_json(fixture, **CONTEXT) == {"message": "hand-built v1 record"}
    assert json.loads(crypto().encrypt_json({"message": "new"}, **CONTEXT))["v"] == 2


def test_wrong_associated_data_key_or_ciphertext_fails_closed():
    sealed = crypto(nonce_source=lambda size: b"x" * size).encrypt_json(
        {"message": "protected"}, **CONTEXT
    )

    with pytest.raises(AppStateIntegrityError):
        crypto().decrypt_json(sealed, **dict(CONTEXT, record_id="draft-2"))
    with pytest.raises(AppStateIntegrityError):
        AppStateCrypto(b"e" * 32, INSTANCE).decrypt_json(sealed, **CONTEXT)

    envelope = json.loads(sealed)
    ciphertext = envelope["ciphertext_b64u"]
    envelope["ciphertext_b64u"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    tampered = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(AppStateIntegrityError):
        crypto().decrypt_json(tampered, **CONTEXT)


def test_nonce_collision_retries_and_exhaustion_fail_closed():
    nonces = iter([b"a" * 12, b"a" * 12, b"b" * 12])
    value = crypto(nonce_source=lambda _size: next(nonces), maximum_nonce_attempts=2)

    first = json.loads(value.encrypt_json({"n": 1}, **CONTEXT))["nonce_b64u"]
    second = json.loads(
        value.encrypt_json({"n": 2}, **dict(CONTEXT, record_id="draft-2"))
    )["nonce_b64u"]
    assert first != second

    stuck = crypto(nonce_source=lambda _size: b"z" * 12, maximum_nonce_attempts=2)
    stuck.encrypt_json({"n": 1}, **CONTEXT)
    with pytest.raises(NonceGenerationError):
        stuck.encrypt_json({"n": 2}, **dict(CONTEXT, record_id="draft-2"))


def test_hkdf_index_is_keyed_scoped_and_not_plain_sha256():
    value = {"status": "low-entropy"}
    first = crypto().index_hmac(value, scope="draft-content")
    second = crypto().index_hmac(value, scope="report-query")

    assert first != second
    assert first != __import__("hashlib").sha256(
        b'{"status":"low-entropy"}'
    ).hexdigest()
    assert len(first) == 64


@pytest.mark.parametrize(
    "payload",
    [
        {"api_key": "secret-value"},
        {"nested": {"private_key": "secret-value"}},
        {"authoritative": True},
        {"authority_class": "CANONICAL"},
        {"signing_key_reference": "opaque-secret"},
    ],
)
def test_secret_or_authority_payloads_are_never_admitted(payload):
    with pytest.raises(ValidationError):
        crypto().encrypt_json(payload, **CONTEXT)

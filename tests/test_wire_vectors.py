"""Cross-language wire-format vectors.

``tests/vectors/floorvault_wire_vectors.json`` pins the byte-exact contract a
port must satisfy: canonical-AAD JSON, HKDF key derivation, envelope layout,
and the SIV associated-data vector order. Each vector was built independently
of the envelope writer (see scripts/generate_wire_vectors.py); this test
asserts three things per vector:

1. FloorVault accepts the spec-constructed envelope (a port's writer output
   must decrypt here).
2. Rebuilding the envelope from the documented fields reproduces the pinned
   bytes exactly (the spec is complete - nothing is implicit).
3. ``associated_data`` still emits the pinned canonical JSON (the AAD
   contract a port must reproduce).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from floorvault import (
    DecryptionVerificationError,
    FloorVault,
    TokenExpiredError,
)

VECTORS_PATH = Path(__file__).parent / "vectors/floorvault_wire_vectors.json"


@pytest.fixture(scope="module")
def corpus() -> dict:
    return json.loads(VECTORS_PATH.read_text())


@pytest.fixture(scope="module")
def crypto(corpus) -> FloorVault:
    return FloorVault(
        bytes.fromhex(corpus["master_key_hex"]),
        memory_mode="disabled",
    )


def canon(fields: dict) -> bytes:
    """Re-derive the canonical AAD with nothing but the documented rules."""
    payload = {
        "app_instance_id": fields["app_instance_id"],
        "column": fields["column"],
        "record_id": fields["record_id"],
        "schema_id": fields["schema_id"],
        "schema_version": fields["schema_version"],
        "table": fields["table"],
    }
    if fields.get("revision") is not None:
        payload["revision"] = fields["revision"]
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def derive_siv(corpus: dict) -> AESSIV:
    kdf = corpus["kdf"]
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=kdf["length"],
        salt=None,
        info=kdf["info"].encode(),
    ).derive(bytes.fromhex(corpus["master_key_hex"]))
    return AESSIV(raw)


def rebuild(v: dict, aead: AESSIV) -> bytes:
    """Spec-constructed envelope - the byte contract a port must match."""
    nonce = bytes.fromhex(v["nonce_hex"])
    aad = canon(v["aad_fields"])
    pt = v["plaintext_utf8"].encode("utf-8")
    if v["envelope"] == "v1":
        return b"FLRV" + bytes([16]) + nonce + aead.encrypt(pt, [aad, nonce])
    if v["envelope"] == "v2":
        header = b"FLV2" + bytes([2, v["key_id"], 16])
        return header + nonce + aead.encrypt(pt, [aad, header, nonce])
    ctx = v["ctx_json"].encode("utf-8")
    header = (
        b"FLV3"
        + bytes([2, v["key_id"]])
        + v["exp"].to_bytes(8, "big")
        + v["nbf"].to_bytes(8, "big")
        + v["iat"].to_bytes(8, "big")
        + len(ctx).to_bytes(2, "big")
        + ctx
        + bytes([16])
    )
    return header + nonce + aead.encrypt(pt, [aad, header, nonce])


def test_vectors_reconstruct_byte_exact(corpus):
    aead = derive_siv(corpus)
    for v in corpus["vectors"]:
        assert rebuild(v, aead).hex() == v["envelope_hex"], v["name"]


def test_aad_pins_match_associated_data(corpus):
    from floorvault.core import associated_data

    for v in corpus["vectors"]:
        assert associated_data(**v["aad_fields"]).decode("utf-8") == v["aad_json"], v["name"]


def test_field_vectors_decrypt(crypto, corpus):
    for v in corpus["vectors"]:
        if v["envelope"] not in ("v1", "v2"):
            continue
        f = v["aad_fields"]
        pt = crypto.decrypt(
            bytes.fromhex(v["envelope_hex"]),
            table=f["table"],
            record_id=f["record_id"],
            column=f["column"],
            schema_id=f["schema_id"],
            schema_version=f["schema_version"],
            revision=f["revision"],
            key_id=v.get("key_id"),
        )
        assert pt == v["plaintext_utf8"], v["name"]


def test_token_vectors_decrypt_and_enforce(crypto, corpus):
    for v in corpus["vectors"]:
        if v["envelope"] != "v3":
            continue
        env = bytes.fromhex(v["envelope_hex"])
        # A fixed read time inside the validity window: iat + 30s is after
        # v3-full-claims' nbf (iat+60 is the nbf — use iat+120 to clear it)
        # and before exp (iat+900).
        read_at = v["iat"] + 120
        if not v["expect_ok"]:
            with pytest.raises(TokenExpiredError):
                crypto.decrypt_token(env, now=v["exp"] + 1)
            continue
        pt = crypto.decrypt_token(
            env,
            expected_purpose=v["purpose"],
            now=read_at,
            key_id=v["key_id"],
        )
        assert pt.decode("utf-8") == v["plaintext_utf8"], v["name"]


def test_token_vector_wrong_key_id_fails_closed(crypto, corpus):
    v3 = next(v for v in corpus["vectors"] if v["envelope"] == "v3")
    with pytest.raises(DecryptionVerificationError, match="key id"):
        crypto.decrypt_token(
            bytes.fromhex(v3["envelope_hex"]),
            key_id=(v3["key_id"] + 1) % 256,
            now=v3["iat"] + 120,
        )

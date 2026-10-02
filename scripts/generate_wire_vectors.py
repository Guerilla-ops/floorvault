#!/usr/bin/env python3
"""Generate tests/vectors/floorvault_wire_vectors.json.

Every vector is built INDEPENDENTLY of FloorVault's envelope code — raw
AESSIV + the documented canonical-JSON + HKDF rules — so the corpus pins the
wire contract itself rather than echoing the implementation. A port that
reproduces these envelopes byte-for-byte is wire-compatible in both
directions (FloorVault must read them; they must equal what FloorVault
writes given the same nonce).

Nonces and iat are fixed constants so output is deterministic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from floorvault.core import canonical_json_bytes  # noqa: E402

MASTER_KEY_HEX = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
NONCES = [
    bytes(range(16)),
    bytes(range(16, 32)),
    bytes(range(32, 48)),
    bytes(range(48, 64)),
    bytes(range(64, 80)),
    bytes(range(80, 96)),
    bytes(range(96, 112)),
]

IAT_FIXED = 1_759_459_200  # 2025-10-02T00:00:00Z, deterministic


def siv_key(master_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"floorvault-v1-aes-siv",
    ).derive(master_key)


def aad_json(fields: dict) -> bytes:
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
    return canonical_json_bytes(payload)


def build_v2(aead: AESSIV, fields: dict, key_id: int, nonce: bytes, pt: bytes) -> bytes:
    header = b"FLV2" + bytes([2, key_id, len(nonce)])
    return header + nonce + aead.encrypt(pt, [aad_json(fields), header, nonce])


def build_v1(aead: AESSIV, fields: dict, nonce: bytes, pt: bytes) -> bytes:
    return b"FLRV" + bytes([len(nonce)]) + nonce + aead.encrypt(pt, [aad_json(fields), nonce])


def build_v3(
    aead: AESSIV,
    fields: dict,
    key_id: int,
    exp: int,
    nbf: int,
    iat: int,
    nonce: bytes,
    pt: bytes,
) -> tuple[bytes, bytes]:
    ctx = canonical_json_bytes(
        {
            "app_instance_id": fields["app_instance_id"],
            "purpose": fields["record_id"],
        }
    )
    header = (
        b"FLV3"
        + bytes([2, key_id])
        + exp.to_bytes(8, "big")
        + nbf.to_bytes(8, "big")
        + iat.to_bytes(8, "big")
        + len(ctx).to_bytes(2, "big")
        + ctx
        + bytes([len(nonce)])
    )
    return header + nonce + aead.encrypt(pt, [aad_json(fields), header, nonce]), ctx


def base_fields(**over) -> dict:
    f = {
        "table": "users",
        "record_id": "u-1001",
        "column": "email",
        "schema_id": "floor.vault.v1",
        "schema_version": 1,
        "app_instance_id": "default",
        "revision": None,
    }
    f.update(over)
    return f


def token_fields(purpose: str) -> dict:
    return base_fields(
        table="_fv.token",
        record_id=purpose,
        column="payload",
        schema_id="floor.vault.token.v1",
    )


def main() -> None:
    master = bytes.fromhex(MASTER_KEY_HEX)
    aead = AESSIV(siv_key(master))
    vectors = []

    def v2_entry(name, fields, key_id, nonce, pt):
        env = build_v2(aead, fields, key_id, nonce, pt)
        vectors.append(
            {
                "name": name,
                "envelope": "v2",
                "aad_fields": fields,
                "aad_json": aad_json(fields).decode("utf-8"),
                "key_id": key_id,
                "nonce_hex": nonce.hex(),
                "plaintext_utf8": pt.decode("utf-8"),
                "envelope_hex": env.hex(),
            }
        )

    v2_entry("v2-basic", base_fields(), 0, NONCES[0], b"alice@example.com")
    v2_entry(
        "v2-unicode-escape",
        base_fields(
            record_id='rec-"日本語"\\\n\t',
            column="na\x00me",
        ),
        0,
        NONCES[1],
        "valeur-日本語-\U0001f512".encode(),
    )
    v2_entry(
        "v2-revision-keyid",
        base_fields(column="ssn", revision=7),
        42,
        NONCES[2],
        b"000-00-0000",
    )

    # v1 read-compat vector (FLRV: no header, AD = [aad, nonce])
    fields_v1 = base_fields(record_id="legacy-1", column="token")
    vectors.append(
        {
            "name": "v1-legacy",
            "envelope": "v1",
            "aad_fields": fields_v1,
            "aad_json": aad_json(fields_v1).decode("utf-8"),
            "nonce_hex": NONCES[3].hex(),
            "plaintext_utf8": "legacy-token",
            "envelope_hex": build_v1(aead, fields_v1, NONCES[3], b"legacy-token").hex(),
        }
    )

    def v3_entry(name, purpose, key_id, exp, nbf, iat, nonce, pt, expect_ok=True):
        fields = token_fields(purpose)
        env, ctx = build_v3(aead, fields, key_id, exp, nbf, iat, nonce, pt)
        vectors.append(
            {
                "name": name,
                "envelope": "v3",
                "purpose": purpose,
                "aad_fields": fields,
                "aad_json": aad_json(fields).decode("utf-8"),
                "ctx_json": ctx.decode("utf-8"),
                "key_id": key_id,
                "exp": exp,
                "nbf": nbf,
                "iat": iat,
                "nonce_hex": nonce.hex(),
                "plaintext_utf8": pt.decode("utf-8"),
                "envelope_hex": env.hex(),
                "expect_ok": expect_ok,
            }
        )

    v3_entry("v3-basic", "pw-reset", 0, 0, 0, IAT_FIXED, NONCES[4], b"reset-payload")
    v3_entry(
        "v3-full-claims",
        "email-verify-日本語",
        3,
        IAT_FIXED + 900,
        IAT_FIXED + 60,
        IAT_FIXED,
        NONCES[5],
        "verify-日本語".encode(),
    )
    # Still decrypts (auth is fine); the time window just fails the policy.
    v3_entry(
        "v3-expired",
        "one-shot",
        0,
        IAT_FIXED + 60,
        0,
        IAT_FIXED,
        NONCES[6],
        b"stale",
        expect_ok=False,
    )

    corpus = {
        "format": "floorvault-wire-vectors-v1",
        "comment": (
            "Deterministic wire-format pins for ports. aad_json/ctx_json are the "
            "exact canonical-JSON bytes that must enter the SIV AD vector. "
            "Envelopes are independently constructed and must decrypt under "
            "FloorVault; FloorVault output with the same nonce must equal them."
        ),
        "kdf": {
            "algo": "HKDF-SHA256",
            "salt": None,
            "info": "floorvault-v1-aes-siv",
            "length": 64,
        },
        "master_key_hex": MASTER_KEY_HEX,
        "vectors": vectors,
    }

    out = Path(__file__).resolve().parent.parent / "tests/vectors/floorvault_wire_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()

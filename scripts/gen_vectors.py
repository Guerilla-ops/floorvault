"""Deterministic generator for tests/vectors/floorvault_wire_vectors.json.

The vectors pin down the FloorVault wire format described by docs/SPEC.md so
that ``tests/test_wire_vectors.py`` can check the reference implementation
against the independent implementation in ``tests/vectors/independent_wire.py``.

Determinism: FloorVault draws envelope nonces (and the recovery bundle_id)
from ``os.urandom``. During generation — and only there — this module
replaces ``os.urandom`` with a counter-mode HMAC-SHA256 stream keyed by a
fixed seed, so every run draws the identical byte stream and the JSON output
is byte-stable. This is legitimate because envelopes' nonces are cleartext
test data; it affects nothing outside this generator process. ``generate()``
is importable so the drift check can regenerate the document in memory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import sys
from contextlib import contextmanager
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_VECTORS_DIR = _ROOT / "tests" / "vectors"
JSON_PATH = _VECTORS_DIR / "floorvault_wire_vectors.json"
if str(_VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(_VECTORS_DIR))

import independent_wire as iw  # noqa: E402

from floorvault import FloorVault, associated_data  # noqa: E402
from floorvault.beacons import compute_beacon, derive_beacon_key  # noqa: E402
from floorvault.key_recovery import wrap_master_key  # noqa: E402

# Fixed keys, derived from labels so they are obviously synthetic test data.
MASTER_KEY = hashlib.sha256(b"floorvault-vector-master-key-v1").digest()
RECOVERY_KEY = hashlib.sha256(b"floorvault-vector-recovery-key-v1").digest()

_URANDOM_SEED = b"floorvault-wire-vector-nonce-stream-v1"


class _DeterministicUrandom:
    """``os.urandom`` replacement: HMAC-SHA256 blocks keyed by a fixed seed.

    Each request consumes whole 32-byte counter blocks, so the stream is
    identical across runs and platforms regardless of the real CSPRNG.
    """

    def __init__(self) -> None:
        self._counter = 0

    def urandom(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hmac.new(
                _URANDOM_SEED, struct.pack(">Q", self._counter), hashlib.sha256
            ).digest()
            self._counter += 1
        return out[:n]


@contextmanager
def _deterministic_urandom():
    """Patch ``os.urandom`` for the duration of generation, then restore."""
    original = os.urandom
    stream = _DeterministicUrandom()
    os.urandom = stream.urandom
    try:
        yield
    finally:
        os.urandom = original


_VAULTS: dict[str, FloorVault] = {}


def _vault_for(app_instance_id: str) -> FloorVault:
    if app_instance_id not in _VAULTS:
        _VAULTS[app_instance_id] = FloorVault(
            MASTER_KEY, app_instance_id=app_instance_id, memory_mode="disabled"
        )
    return _VAULTS[app_instance_id]


def _full_coords(coords: dict) -> dict:
    """Fill in the reference defaults so the stored vector is self-documenting."""
    full = {
        "app_instance_id": "default",
        "schema_id": "floor.vault.v1",
        "schema_version": 1,
        **coords,
    }
    return full


def _op_kwargs(full_coords: dict) -> dict:
    """encrypt/decrypt kwargs: every coordinate except ``app_instance_id``,
    which is bound at FloorVault construction rather than per call."""
    return {k: v for k, v in full_coords.items() if k != "app_instance_id"}


def _emit_positive(spec: dict, envelope: bytes, plaintext: bytes) -> dict:
    full = _full_coords(spec["coords"])
    vec = {
        "id": spec["id"],
        "comment": spec["comment"],
        "version": spec.get("version", 2),
        "producer": spec.get("producer", "encrypt"),
        "key_id": None if spec.get("version", 2) == 1 else spec.get("key_id", 0),
        "coords": full,
        "nonce_hex": envelope[7:23].hex() if spec.get("version", 2) == 2 else envelope[5:21].hex(),
        "aad_hex": associated_data(**full).hex(),
        "plaintext_hex": plaintext.hex(),
        "envelope_hex": envelope.hex(),
    }
    try:
        vec["plaintext_utf8"] = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return vec


def _pt_bytes(value) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


# fmt: off
def _positive_specs() -> list[dict]:
    return [
        {
            "id": "pos-ascii",
            "comment": "Baseline v2 envelope: ASCII coords and plaintext, default schema triple.",
            "coords": {"table": "users", "record_id": "u-1", "column": "email"},
            "plaintext": "alice@example.com",
        },
        {
            "id": "pos-unicode-pt",
            "comment": "Non-ASCII UTF-8 plaintext.",
            "coords": {"table": "secrets", "record_id": "s-42", "column": "note"},
            "plaintext": "pässwörd 🔐 中文",
        },
        {
            "id": "pos-nonutf8-bytes",
            "comment": "Bytes plaintext that is not valid UTF-8; only decrypt_bytes may read it "
                       "(its text-path refusal is negative vector neg-not-utf8).",
            "coords": {"table": "blobs", "record_id": "b-7", "column": "data"},
            "plaintext": b"\xff\xfe\x00binary\x80",
        },
        {
            "id": "pos-empty",
            "comment": "Empty plaintext → 39-byte record (16-byte tag only, §4.1).",
            "coords": {"table": "notes", "record_id": "n-0", "column": "body"},
            "plaintext": "",
        },
        {
            "id": "pos-coords-nfc",
            "comment": "NFC spelling of 'café' in record_id.",
            "coords": {"table": "places", "record_id": "café", "column": "city"},
            "plaintext": "nfc",
        },
        {
            "id": "pos-coords-nfd",
            "comment": "NFD spelling of the same logical string — NO normalization (§5.2): "
                       "different AAD bytes, different ciphertext.",
            "coords": {"table": "places", "record_id": "café", "column": "city"},
            "plaintext": "nfd",
        },
        {
            "id": "pos-coords-escapes",
            "comment": "Quote, backslash, C0 controls, DEL, U+2028 and BOM inside coordinates — "
                       "only \", \\ and C0 are escaped; everything else is verbatim UTF-8.",
            "coords": {
                "table": 'ta"ble\\x',
                "record_id": "r\x01\x0b\x7f ﻿y",
                "column": "col\n",
            },
            "plaintext": "escapes",
        },
        {
            "id": "pos-revision",
            "comment": "revision bound into the AAD (same-coordinate replay protection, §5/§7).",
            "coords": {"table": "kv", "record_id": "k-9", "column": "v", "revision": 7},
            "plaintext": "rev-7",
        },
        {
            "id": "pos-revision-huge",
            "comment": "revision beyond 64 bits — int.__repr__ arbitrary precision (§5.2).",
            "coords": {"table": "kv", "record_id": "k-10", "column": "v", "revision": 2**70 + 9},
            "plaintext": "rev-huge",
        },
        {
            "id": "pos-nondefault-schema",
            "comment": "Non-default schema_id / schema_version / app_instance_id.",
            "coords": {
                "table": "billing",
                "record_id": "inv-001",
                "column": "secret",
                "schema_id": "acme.billing.v9",
                "schema_version": 42,
                "app_instance_id": "acme-eu",
            },
            "plaintext": "custom schema",
        },
        {
            "id": "pos-schema-version-negative",
            "comment": "Negative schema_version is accepted and produces valid AAD (§5.2 quirk).",
            "coords": {"table": "t", "record_id": "r-neg", "column": "c", "schema_version": -3},
            "plaintext": "neg-schema",
        },
        {
            "id": "pos-schema-version-huge",
            "comment": "schema_version beyond 64 bits is accepted (§5.2 quirk).",
            "coords": {
                "table": "t",
                "record_id": "r-huge",
                "column": "c",
                "schema_version": 2**70 + 5,
            },
            "plaintext": "huge-schema",
        },
        {
            "id": "pos-keyid-7",
            "comment": "Non-zero key_id written into the authenticated header (§4.5).",
            "coords": {"table": "users", "record_id": "u-77", "column": "token"},
            "key_id": 7,
            "plaintext": "rotated-key-record",
        },
        {
            "id": "pos-v1-legacy",
            "comment": "v1 FLRV envelope built by the independent implementation — this build "
                       "has no v1 writer, so the spec-conformant record is the vector (§4.2). "
                       "floorvault must still read it with the v1 AD vector [aad, nonce].",
            "version": 1,
            "producer": "independent_v1",
            "coords": {"table": "users", "record_id": "u-1", "column": "email"},
            "plaintext": "legacy-secret",
        },
    ]
# fmt: on

# Batch pair: one encrypt_fields call, two columns. Per §8 each field's
# envelope is identical to a single encrypt() of that column modulo the
# independently drawn nonce — the vectors prove interchangeability because
# the checker opens them through the single-record path.
_BATCH_SPEC = {
    "id": "pos-batch",
    "comment": "encrypt_fields() output; each field's envelope is a plain v2 record "
    "for its own column-bound AAD (§8) — no batch framing exists.",
    "coords": {"table": "vault_items", "record_id": "vault_abc123"},
    "fields": {"meta:label": "label text", "payload": '{"secret": true, "otp": 123456}'},
}


def _build_positives() -> tuple[list[dict], dict[str, bytes]]:
    """Encrypt every positive spec under the patched stream.

    Returns the vector list plus a raw-envelope lookup for negative mutation.
    """
    vectors: list[dict] = []
    envs: dict[str, bytes] = {}
    for spec in _positive_specs():
        coords = _full_coords(spec["coords"])
        vault = _vault_for(coords["app_instance_id"])
        plaintext = _pt_bytes(spec["plaintext"])
        if spec.get("version") == 1:
            # No v1 writer exists in floorvault; construct the record with the
            # independent implementation per §4.2 — that is the point.
            aad = iw.build_aad(coords)
            nonce = os.urandom(16)
            env = iw.build_envelope(
                siv_key=iw.derive_siv_key(MASTER_KEY),
                plaintext=plaintext,
                aad=aad,
                nonce=nonce,
                version=1,
            )
        else:
            env = vault.encrypt(plaintext, **_op_kwargs(coords), key_id=spec.get("key_id", 0))
        vectors.append(_emit_positive(spec, env, plaintext))
        envs[spec["id"]] = env

    batch_coords = _full_coords(_BATCH_SPEC["coords"])
    vault = _vault_for(batch_coords["app_instance_id"])
    fields_kwargs = _op_kwargs(batch_coords)
    out = vault.encrypt_fields(dict(_BATCH_SPEC["fields"]), **fields_kwargs, key_id=0)
    for column, env in out.items():
        spec = {
            "id": f"pos-batch-{column}",
            "comment": f"{_BATCH_SPEC['comment']} (field {column!r} of '{_BATCH_SPEC['id']}')",
            "coords": {**batch_coords, "column": column},
            "producer": "encrypt_fields",
        }
        plaintext = _pt_bytes(_BATCH_SPEC["fields"][column])
        vectors.append(_emit_positive(spec, env, plaintext))
        envs[spec["id"]] = env
    return vectors, envs


def _flip(env: bytes, offset: int) -> bytes:
    buf = bytearray(env)
    buf[offset] ^= 0x01
    return bytes(buf)


def _build_negatives(envs: dict[str, bytes], positives: list[dict]) -> list[dict]:
    """One vector per §16/§4.3 rejection class. ``expect`` names the class each
    side must raise; ``floorvault_msg`` is a required substring of the
    reference error (the spec names classes, not messages, for foreign impls)."""
    by_id = {v["id"]: v for v in positives}
    base = envs["pos-ascii"]
    base_coords = by_id["pos-ascii"]["coords"]
    kid7_coords = by_id["pos-keyid-7"]["coords"]
    v1_coords = by_id["pos-v1-legacy"]["coords"]

    def corrupt(vid, comment, data, expect, msg, coords=None):
        return {
            "id": vid,
            "kind": "corrupt",
            "comment": comment,
            "input_hex": data.hex(),
            "coords": coords or base_coords,
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": msg,
                "independent": expect,
            },
        }

    return [
        corrupt(
            "neg-too-short-bad-magic",
            "§4.3 ordering: the length check precedes the magic check, so a <21-byte "
            "buffer reports 'too short' even with a wrong magic.",
            b"XXXX" + base[4:20],
            "TooShortError",
            "too short",
        ),
        corrupt(
            "neg-bad-magic",
            "Wrong magic on a full-length buffer.",
            b"BAD!" + base[4:],
            "BadMagicError",
            "magic",
        ),
        corrupt(
            "neg-bad-crypto-version",
            "FLV2 with crypto_version=3; this build accepts only 2 (§4.3 rule 4).",
            base[:4] + b"\x03" + base[5:],
            "UnsupportedCryptoVersionError",
            "crypto version",
        ),
        corrupt(
            "neg-bad-nonce-len",
            "nonce_len byte is 8, not 16 (§4.3 rule 5).",
            base[:6] + b"\x08" + base[7:],
            "BadNonceLengthError",
            "nonce length",
        ),
        corrupt(
            "neg-truncated-nonce",
            "nonce_len=16 declared but the buffer ends at 22 bytes (< 7+16): same "
            "'invalid nonce length' rejection via the truncation branch.",
            base[:22],
            "BadNonceLengthError",
            "nonce length",
        ),
        corrupt(
            "neg-no-ciphertext",
            "Header + nonce and nothing else: zero ciphertext remainder (§4.3 rule 6).",
            base[:23],
            "EmptyCiphertextError",
            "no ciphertext",
        ),
        corrupt(
            "neg-flipped-tag-bit",
            "One bit flipped inside the 16-byte SIV tag → AEAD verification failure.",
            _flip(base, 24),
            "AuthenticationError",
            "verification failed",
        ),
        corrupt(
            "neg-flipped-body-bit",
            "One bit flipped in the final CTR ciphertext byte → verification failure.",
            _flip(base, len(base) - 1),
            "AuthenticationError",
            "verification failed",
        ),
        corrupt(
            "neg-rewritten-key-id",
            "key_id byte rewritten 0→9: the header is an authenticated AD element, "
            "so this is a verification failure, not an ignored field (§6).",
            base[:5] + b"\x09" + base[6:],
            "AuthenticationError",
            "verification failed",
        ),
        {
            "id": "neg-spliced-record",
            "kind": "splice",
            "comment": "A valid envelope presented at the wrong record_id — the AAD the "
            "reader reconstructs no longer matches (§5).",
            "input_hex": base.hex(),
            "coords": {**base_coords, "record_id": "u-2"},
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": "verification failed",
                "independent": "AuthenticationError",
            },
        },
        {
            "id": "neg-spliced-column",
            "kind": "splice",
            "comment": "Batch field 'meta:label' presented under sibling column 'payload' "
            "— a column splice inside one record must also fail (§8).",
            "input_hex": envs["pos-batch-meta:label"].hex(),
            "coords": by_id["pos-batch-payload"]["coords"],
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": "verification failed",
                "independent": "AuthenticationError",
            },
        },
        {
            "id": "neg-v1-under-v2-ad",
            "kind": "v1_as_v2",
            "comment": "A v1 record MUST fail against the v2 AD vector [aad, header, "
            "nonce] (§6). FloorVault cannot express that directly — its "
            "equivalent refusal is a v1 record presented with a requested "
            "key_id ('no key id'). The checker asserts both.",
            "input_hex": envs["pos-v1-legacy"].hex(),
            "coords": v1_coords,
            "require_key_id": 0,
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": "no key id",
                "independent": "KeyIdMismatchError",
            },
        },
        {
            "id": "neg-key-id-mismatch",
            "kind": "key_id_mismatch",
            "comment": "Caller requires key_id=3 but the authenticated header declares 7 "
            "(§4.4 step 2, §16 'written under key id').",
            "input_hex": envs["pos-keyid-7"].hex(),
            "coords": kid7_coords,
            "require_key_id": 3,
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": "written under key id 7",
                "independent": "KeyIdMismatchError",
            },
        },
        {
            "id": "neg-non-bytes-input",
            "kind": "non_bytes",
            "comment": "Envelope input must be bytes/bytearray; anything else is a type "
            "error (§16, first row).",
            "input_str": "FLV2 this is not bytes",
            "coords": base_coords,
            "expect": {
                "floorvault": "TypeError",
                "floorvault_msg": "bytes",
                "independent": "TypeError",
            },
        },
        {
            "id": "neg-memoryview-input",
            "kind": "non_bytes",
            "comment": "memoryview is bytes-like but is NOT bytes/bytearray, so it is refused "
            "(§16 row 1 is exact; §4.3's looser 'bytes-like' wording is what the "
            "code actually narrows to bytes/bytearray).",
            "input_memoryview_hex": base.hex(),
            "coords": base_coords,
            "expect": {
                "floorvault": "TypeError",
                "floorvault_msg": "bytes",
                "independent": "TypeError",
            },
        },
        {
            "id": "neg-not-utf8",
            "kind": "text_decode",
            "comment": "The pos-nonutf8-bytes envelope through the text reader: a UTF-8 "
            "decode failure is a verification failure, not a partial success "
            "(§4.4 step 5).",
            "ref": "pos-nonutf8-bytes",
            "expect": {
                "floorvault": "DecryptionVerificationError",
                "floorvault_msg": "not valid UTF-8",
                "independent": "UnicodeDecodeError",
            },
        },
    ]


def _build_aad_vectors(positives: list[dict]) -> list[dict]:
    """One golden AAD per unique coordinate set used by the positives, plus
    entries for the §5.2 validation rejections."""
    seen: dict[str, dict] = {}
    vectors: list[dict] = []
    for vec in positives:
        key = vec["aad_hex"]
        if key in seen:
            continue
        seen[key] = vec
        vectors.append(
            {
                "id": f"aad-{vec['id']}",
                "comment": f"Golden AAD for coordinates of '{vec['id']}'.",
                "coords": vec["coords"],
                "aad_hex": vec["aad_hex"],
            }
        )
    vectors += [
        {
            "id": "aad-reject-whitespace",
            "comment": "Whitespace-after-strip() string coordinate → ValueError (§5.2).",
            "coords": {"table": "   ", "record_id": "r", "column": "c"},
            "expect_error": {"floorvault": "ValueError", "independent": "ValueError"},
        },
        {
            "id": "aad-reject-non-string",
            "comment": "Non-str coordinate raises the same 'non-empty string' ValueError, "
            "not a type error (§5.2 quirk).",
            "coords": {"table": "t", "record_id": 42, "column": "c"},
            "expect_error": {"floorvault": "ValueError", "independent": "ValueError"},
        },
        {
            "id": "aad-reject-bool-schema-version",
            "comment": "bool is rejected where int is required → TypeError (§5.2).",
            "coords": {"table": "t", "record_id": "r", "column": "c", "schema_version": True},
            "expect_error": {"floorvault": "TypeError", "independent": "TypeError"},
        },
        {
            "id": "aad-reject-negative-revision",
            "comment": "revision must be non-negative when present → ValueError (§5.2).",
            "coords": {"table": "t", "record_id": "r", "column": "c", "revision": -1},
            "expect_error": {"floorvault": "ValueError", "independent": "ValueError"},
        },
    ]
    return vectors


def _build_beacons(beacon_key: bytes) -> list[dict]:
    specs = [
        # bits 4 and 8 share the same stored byte width (§9.2) — the pair is
        # intentional: the checker asserts the digests are identical.
        ("beacon-bits-4", "users.email", "alice@example.com", 4, "w1"),
        ("beacon-bits-8", "users.email", "alice@example.com", 8, "w1"),
        ("beacon-bits-16", "users.email", "alice@example.com", 16, None),
        ("beacon-bits-32", "users.name", "张三", 32, None),
        ("beacon-bits-64", "vault.origin", "https://例え.jp/path", 64, None),
    ]
    out = []
    for vid, scope, value, bits, group in specs:
        vec = {
            "id": vid,
            "scope": scope,
            "value": value,
            "bits": bits,
            "beacon_hex": compute_beacon(value, scope=scope, key=beacon_key, bits=bits).hex(),
        }
        if group:
            vec["group"] = group
        out.append(vec)
    return out


def generate() -> dict:
    """Build the complete vector document. Deterministic and import-safe:
    the os.urandom patch is applied and restored inside this call."""
    with _deterministic_urandom():
        positives, envs = _build_positives()
        bundle = wrap_master_key(MASTER_KEY, RECOVERY_KEY)
    negatives = _build_negatives(envs, positives)
    beacon_key = derive_beacon_key(MASTER_KEY)
    beacons = _build_beacons(beacon_key)
    return {
        "format_version": 1,
        "_doc": {
            "purpose": "Pinned wire vectors for docs/SPEC.md, checked by tests/test_wire_vectors.py "
            "against both floorvault and tests/vectors/independent_wire.py.",
            "encodings": "All *_hex fields are lowercase hex of raw bytes; 'coords' objects are "
            "literal JSON strings mapping to associated_data(...) kwargs. "
            "'app_instance_id' is bound at FloorVault construction, not per call; "
            "an absent 'revision' member means unbound.",
            "positive": "floorvault.decrypt_bytes(envelope, **coords) == plaintext_hex; when "
            "'plaintext_utf8' is present floorvault.decrypt() returns that str. "
            "'producer' names the writing API; 'independent_v1' records were built "
            "by independent_wire because this build has no v1 writer.",
            "negative": "'expect.floorvault'/'expect.independent' name the error class each side "
            "must raise; 'floorvault_msg' is a required substring of the reference "
            "error message. 'kind' selects the checker's harness path; 'ref' points "
            "at a positive vector's envelope.",
            "determinism": "Regenerate with `PYTHONPATH=src .venv/bin/python scripts/gen_vectors.py`. "
            "Nonces and the bundle_id come from a patched os.urandom "
            "(HMAC-SHA256 counter stream), so output is byte-stable.",
        },
        "master_key": MASTER_KEY.hex(),
        "positive": positives,
        "negative": negatives,
        "aad_vectors": _build_aad_vectors(positives),
        "beacon_key": beacon_key.hex(),
        "beacon_vectors": beacons,
        "recovery": {
            "comment": "FVRB1 bundle per §11: master_key wrapped under recovery_key at "
            "coordinates app_instance_id='floorvault-recovery', table='recovery', "
            "record_id=hex(bundle_id), column='master_key'.",
            "master_key": MASTER_KEY.hex(),
            "recovery_key": RECOVERY_KEY.hex(),
            "bundle_id": bundle[5:21].hex(),
            "bundle_hex": bundle.hex(),
        },
    }


def main() -> None:
    data = generate()
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    JSON_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {JSON_PATH} ({len(text.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()

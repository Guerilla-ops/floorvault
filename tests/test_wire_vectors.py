"""Wire-format vectors: floorvault vs. an independent implementation.

Why this file exists
--------------------
The committed vectors in ``tests/vectors/floorvault_wire_vectors.json`` pin
down the byte-level contract of docs/SPEC.md. Every vector is checked twice:

* **floorvault** — the reference implementation must decrypt each positive
  envelope and refuse each negative one, in the documented rejection class.
* **independent_wire** — a second implementation of the same spec (own AAD
  serializer, own RFC 5297 SIV over AES-ECB, own RFC 5869 HKDF) must parse
  the envelopes, reproduce the AAD bytes, and re-encrypt each positive
  plaintext under the *same nonce* to a byte-identical ciphertext body. Two
  implementations that agree only with themselves prove nothing; agreement
  here means the bytes on disk are what the spec says they are.

A drift check regenerates the document in memory and compares it to the
committed file, so the vectors can never silently diverge from the code
that produced them. An independence check proves ``independent_wire`` never
imports ``floorvault`` — otherwise the "second implementation" would be a
tautology.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
_VECTORS_DIR = _TESTS_DIR / "vectors"
for _p in (str(_VECTORS_DIR), str(_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gen_vectors  # noqa: E402
import independent_wire as iw  # noqa: E402

from floorvault import FloorVault, associated_data, recover_master_key  # noqa: E402
from floorvault.beacons import compute_beacon, derive_beacon_key  # noqa: E402
from floorvault.core import DecryptionVerificationError  # noqa: E402

VECTOR_PATH = _VECTORS_DIR / "floorvault_wire_vectors.json"
VECTORS = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

MASTER_KEY = bytes.fromhex(VECTORS["master_key"])
SIV_KEY = iw.derive_siv_key(MASTER_KEY)

POSITIVE = VECTORS["positive"]
NEGATIVE = VECTORS["negative"]
AAD_VECTORS = VECTORS["aad_vectors"]
BEACON_VECTORS = VECTORS["beacon_vectors"]

_POS_BY_ID = {v["id"]: v for v in POSITIVE}

# One engine per app_instance_id: it is bound at construction, not per call.
_VAULTS: dict[str, FloorVault] = {}


def _vault(app_instance_id: str = "default") -> FloorVault:
    if app_instance_id not in _VAULTS:
        _VAULTS[app_instance_id] = FloorVault(
            MASTER_KEY, app_instance_id=app_instance_id, memory_mode="disabled"
        )
    return _VAULTS[app_instance_id]


def _op_kwargs(coords: dict) -> dict:
    """Per-call encrypt/decrypt kwargs: coords minus app_instance_id."""
    return {k: v for k, v in coords.items() if k != "app_instance_id"}


def _aad_kwargs(coords: dict) -> dict:
    """``FloorVault._aad`` takes ``revision`` with no default."""
    kw = _op_kwargs(coords)
    kw.setdefault("revision", None)
    return kw


def _envelope_of(vector_id: str) -> bytes:
    return bytes.fromhex(_POS_BY_ID[vector_id]["envelope_hex"])


def _coords_of(vector_id: str) -> dict:
    return _POS_BY_ID[vector_id]["coords"]


_FV_ERRORS = {
    "DecryptionVerificationError": DecryptionVerificationError,
    "TypeError": TypeError,
    "ValueError": ValueError,
}

_IW_ERRORS = {
    "TooShortError": iw.TooShortError,
    "BadMagicError": iw.BadMagicError,
    "UnsupportedCryptoVersionError": iw.UnsupportedCryptoVersionError,
    "BadNonceLengthError": iw.BadNonceLengthError,
    "EmptyCiphertextError": iw.EmptyCiphertextError,
    "AuthenticationError": iw.AuthenticationError,
    "KeyIdMismatchError": iw.KeyIdMismatchError,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "UnicodeDecodeError": UnicodeDecodeError,
}


# ---------------------------------------------------------------------------
# Positive vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", POSITIVE, ids=[v["id"] for v in POSITIVE])
def test_positive_floorvault_decrypts(vec):
    """floorvault opens every envelope: bytes always, text when it is UTF-8."""
    env = bytes.fromhex(vec["envelope_hex"])
    fv = _vault(vec["coords"].get("app_instance_id", "default"))
    kwargs = _op_kwargs(vec["coords"])
    assert fv.decrypt_bytes(env, **kwargs) == bytes.fromhex(vec["plaintext_hex"])
    if "plaintext_utf8" in vec:
        assert fv.decrypt(env, **kwargs) == vec["plaintext_utf8"]


@pytest.mark.parametrize("vec", POSITIVE, ids=[v["id"] for v in POSITIVE])
def test_positive_independent_reencrypts_byte_identical(vec):
    """The independent impl rebuilds the AAD and re-encrypts under the same
    nonce to a byte-identical tag||ciphertext — the strongest possible check
    that both sides agree on AAD bytes, AD vector order, and SIV itself."""
    raw = bytes.fromhex(vec["envelope_hex"])
    env = iw.parse_envelope(raw)
    assert env.version == vec["version"]
    assert env.key_id == vec["key_id"]
    assert env.nonce.hex() == vec["nonce_hex"]

    aad = iw.build_aad(vec["coords"])
    assert aad.hex() == vec["aad_hex"]

    plaintext = bytes.fromhex(vec["plaintext_hex"])
    ad = iw.ad_vector(env, aad)
    assert iw.siv_encrypt(SIV_KEY, plaintext, ad) == env.ciphertext
    assert iw.siv_decrypt(SIV_KEY, env.ciphertext, ad) == plaintext
    assert iw.decrypt_envelope(SIV_KEY, raw, vec["coords"]) == plaintext


# ---------------------------------------------------------------------------
# AAD golden vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", AAD_VECTORS, ids=[v["id"] for v in AAD_VECTORS])
def test_aad_vectors(vec):
    """All three AAD paths — the public ``associated_data``, the hot-path
    ``FloorVault._aad``, and ``independent_wire.build_aad`` — must produce the
    stored bytes, or raise the documented error class."""
    coords = vec["coords"]
    if "expect_error" in vec:
        expect = vec["expect_error"]
        with pytest.raises(_FV_ERRORS[expect["floorvault"]]):
            associated_data(**coords)
        with pytest.raises(_IW_ERRORS[expect["independent"]]):
            iw.build_aad(coords)
        return
    expected = bytes.fromhex(vec["aad_hex"])
    assert associated_data(**coords) == expected
    fv = _vault(coords.get("app_instance_id", "default"))
    assert fv._aad(**_aad_kwargs(coords)) == expected
    assert iw.build_aad(coords) == expected


# ---------------------------------------------------------------------------
# Search beacons
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", BEACON_VECTORS, ids=[v["id"] for v in BEACON_VECTORS])
def test_beacon_vectors(vec):
    """floorvault and the independent impl produce the stored digest, which
    is exactly ceil(bits/8) bytes of HMAC-SHA256."""
    fv_key = derive_beacon_key(MASTER_KEY)
    assert fv_key.hex() == VECTORS["beacon_key"]
    assert fv_key == iw.derive_beacon_key(MASTER_KEY)

    expected = bytes.fromhex(vec["beacon_hex"])
    assert len(expected) == (vec["bits"] + 7) // 8
    kwargs = {"scope": vec["scope"], "key": fv_key, "bits": vec["bits"]}
    assert compute_beacon(vec["value"], **kwargs) == expected
    assert iw.compute_beacon(vec["value"], **kwargs) == expected


def test_beacon_bits_4_and_8_share_one_byte_width():
    """§9.2: storage is byte-aligned, so 4 and 8 bits are the same index —
    the pair proves the stored width, not the requested bits, is emitted."""
    pair = [v for v in BEACON_VECTORS if v.get("group") == "w1"]
    assert [v["bits"] for v in pair] == [4, 8]
    assert pair[0]["beacon_hex"] == pair[1]["beacon_hex"]


# ---------------------------------------------------------------------------
# Recovery bundle
# ---------------------------------------------------------------------------


def test_recovery_bundle():
    """floorvault unwraps the FVRB1 bundle; the independent parser splits it
    and opens the inner envelope under the §11 coordinates."""
    rec = VECTORS["recovery"]
    bundle = bytes.fromhex(rec["bundle_hex"])
    master = bytes.fromhex(rec["master_key"])
    recovery = bytes.fromhex(rec["recovery_key"])

    assert recover_master_key(bundle, recovery).get_bytes() == master

    bundle_id, envelope = iw.parse_recovery_bundle(bundle)
    assert bundle_id.hex() == rec["bundle_id"]
    assert iw.parse_envelope(envelope).version == 2
    # The bundle_id binds itself: record_id = hex(bundle_id), from the bundle.
    coords = iw.recovery_coords(bundle_id)
    assert coords["record_id"] == rec["bundle_id"]
    assert iw.decrypt_envelope(iw.derive_siv_key(recovery), envelope, coords) == master
    assert iw.recover_master_key(bundle, recovery) == master


def test_envelope_bytearray_input_accepted():
    """bytearray is accepted by both readers (§4.3 rule 1's positive side);
    it is snapshotted to bytes before parsing, so mutation cannot race."""
    vec = _POS_BY_ID["pos-ascii"]
    env = bytearray(bytes.fromhex(vec["envelope_hex"]))
    fv = _vault(vec["coords"].get("app_instance_id", "default"))
    plaintext = bytes.fromhex(vec["plaintext_hex"])
    assert fv.decrypt_bytes(env, **_op_kwargs(vec["coords"])) == plaintext
    assert iw.decrypt_envelope(SIV_KEY, env, vec["coords"]) == plaintext


# ---------------------------------------------------------------------------
# Negative vectors — one per rejection class (§16 / §4.3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vec", NEGATIVE, ids=[v["id"] for v in NEGATIVE])
def test_negative_floorvault(vec):
    """floorvault must refuse in the documented class (and message)."""
    expect = vec["expect"]
    err_cls = _FV_ERRORS[expect["floorvault"]]
    msg = expect["floorvault_msg"]
    coords = vec.get("coords") or {}
    fv = _vault(coords.get("app_instance_id", "default"))

    if vec["kind"] == "non_bytes":
        if "input_memoryview_hex" in vec:
            bad_input = memoryview(bytes.fromhex(vec["input_memoryview_hex"]))
        else:
            bad_input = vec["input_str"]
        with pytest.raises(err_cls, match=msg):
            fv.decrypt_bytes(bad_input, **_op_kwargs(coords))
    elif vec["kind"] == "text_decode":
        ref_coords = _coords_of(vec["ref"])
        with pytest.raises(err_cls, match=msg):
            fv.decrypt(_envelope_of(vec["ref"]), **_op_kwargs(ref_coords))
    else:
        data = bytes.fromhex(vec["input_hex"])
        with pytest.raises(err_cls, match=msg):
            fv.decrypt_bytes(data, key_id=vec.get("require_key_id"), **_op_kwargs(coords))


@pytest.mark.parametrize("vec", NEGATIVE, ids=[v["id"] for v in NEGATIVE])
def test_negative_independent(vec):
    """The independent impl must make the same accept/refuse decision."""
    expect = vec["expect"]
    err_cls = _IW_ERRORS[expect["independent"]]
    coords = vec.get("coords") or {}
    kind = vec["kind"]

    if kind == "non_bytes":
        if "input_memoryview_hex" in vec:
            bad_input = memoryview(bytes.fromhex(vec["input_memoryview_hex"]))
        else:
            bad_input = vec["input_str"]
        with pytest.raises(err_cls):
            iw.decrypt_envelope(SIV_KEY, bad_input, coords)
    elif kind == "text_decode":
        # Bytes path succeeds; the reader-side UTF-8 decode must not.
        plaintext = iw.decrypt_envelope(SIV_KEY, _envelope_of(vec["ref"]), _coords_of(vec["ref"]))
        with pytest.raises(err_cls):
            plaintext.decode("utf-8")
    elif kind == "v1_as_v2":
        data = bytes.fromhex(vec["input_hex"])
        with pytest.raises(err_cls):
            iw.decrypt_envelope(SIV_KEY, data, coords, require_key_id=vec["require_key_id"])
        # The literal §6 check: a v1 ciphertext MUST NOT verify against the
        # v2 AD vector [aad, header, nonce] — the vectors are not
        # interchangeable and the magic is what chooses between them.
        env = iw.parse_envelope(data)
        assert env.version == 1
        aad = iw.build_aad(coords)
        v2_header = iw.MAGIC_V2 + bytes([iw.CRYPTO_VERSION_V2, 0, iw.NONCE_LEN])
        assert iw.siv_decrypt(SIV_KEY, env.ciphertext, [aad, v2_header, env.nonce]) is None
    else:
        data = bytes.fromhex(vec["input_hex"])
        with pytest.raises(err_cls):
            iw.decrypt_envelope(SIV_KEY, data, coords, require_key_id=vec.get("require_key_id"))


# ---------------------------------------------------------------------------
# Drift check and independence check
# ---------------------------------------------------------------------------


def _first_diff(a, b, path: str = "$") -> str | None:
    """Return a dotted key path to the first difference, or None."""
    if type(a) is not type(b):
        return f"{path}: type {type(a).__name__} != {type(b).__name__} ({a!r} vs {b!r})"
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                return f"{path}.{key}: present in file, missing in regenerated output"
            if key not in b:
                return f"{path}.{key}: present in regenerated output, missing in file"
            diff = _first_diff(a[key], b[key], f"{path}.{key}")
            if diff is not None:
                return diff
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: list length {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            diff = _first_diff(x, y, f"{path}[{i}]")
            if diff is not None:
                return diff
        return None
    return None if a == b else f"{path}: {a!r} != {b!r}"


def test_committed_vector_file_is_not_stale():
    """CI drift check: regenerating must reproduce the committed document
    exactly; the failure message names the first differing key path."""
    regenerated = gen_vectors.generate()
    diff = _first_diff(regenerated, VECTORS)
    assert diff is None, (
        f"vector file is stale — first difference at {diff}; "
        "re-run `PYTHONPATH=src .venv/bin/python scripts/gen_vectors.py`"
    )


def test_independent_wire_source_never_imports_floorvault():
    """Source-level guard: no import statement may name floorvault."""
    src = (_VECTORS_DIR / "independent_wire.py").read_text(encoding="utf-8")
    offenders = re.findall(r"^\s*(?:from|import)\s+floorvault\b[^\n]*", src, re.MULTILINE)
    assert not offenders, f"floorvault import found in independent_wire: {offenders}"


def test_independent_wire_imports_without_floorvault_in_subprocess():
    """Hard independence check: in a fresh interpreter, importing
    independent_wire must leave no floorvault module in sys.modules — this
    catches transitive leaks the source scan could miss."""
    code = (
        "import sys; sys.path.insert(0, {p!r}); import independent_wire; "
        "assert not any(m == 'floorvault' or m.startswith('floorvault.') "
        "for m in sys.modules), 'floorvault leaked into sys.modules'"
    ).format(p=str(_VECTORS_DIR))
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(_ROOT),
    )
    assert proc.returncode == 0, proc.stderr

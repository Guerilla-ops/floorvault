"""Project Wycheproof AES-SIV-CMAC vectors, run against both SIV code paths.

Wycheproof (C2SP, originally Google) publishes adversarial test vectors written
by people who have no stake in FloorVault: edge-case SIVs that catch counter
overflow bugs, modified tags, and every key size. The RFC 5297 Appendix A
vectors in ``test_rfc_vectors.py`` are two cases; these are 1,342.

Two files are vendored, byte-for-byte, from a pinned upstream commit:

* ``aes_siv_cmac_test.json`` - deterministic AES-SIV, one associated-data
  component (442 tests, 256/384/512-bit keys).
* ``aead_aes_siv_cmac_test.json`` - nonce-based AES-SIV, where the nonce is the
  *last* associated-data component (900 tests). The 512-bit-key / 128-bit-nonce
  group is exactly FloorVault's instantiation: AES-256-SIV with a 16-byte nonce
  as the final S2V input (``core.py`` passes ``[aad, header, nonce]``).

Each vector runs against PyCA's ``AESSIV`` - the primitive ``FloorVault`` is
built on - and against the independent from-spec RFC 5297 implementation in
``test_rfc5297_independent.py``, so a defect in either is caught by a third
party's expectations rather than by agreement between our two implementations.

The files are pinned by SHA-256: an edited or re-downloaded vector file must
fail here, not silently change what "passing" means.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from test_rfc5297_independent import siv_decrypt, siv_encrypt

VECTOR_DIR = Path(__file__).resolve().parent / "vectors" / "wycheproof"

#: https://github.com/C2SP/wycheproof/tree/<commit>/testvectors_v1 (Apache-2.0,
#: licence vendored alongside the files).
UPSTREAM_COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230"
PINNED_SHA256 = {
    "aes_siv_cmac_test.json": "8619a04fbe63c0431caaade07f94c688261a0f3ee4850d761bec1200b590930c",
    "aead_aes_siv_cmac_test.json": "1932de9a77d4c81815466b6f748351dbe533cfa6b5154cf1112965f709c408f1",
}


def _load(name: str) -> dict:
    return json.loads((VECTOR_DIR / name).read_bytes())


def _cases(name: str) -> list[tuple[dict, dict]]:
    data = _load(name)
    return [(group, test) for group in data["testGroups"] for test in group["tests"]]


def _vector(test: dict) -> tuple[bytes, list[bytes], bytes, bytes]:
    """Return ``(key, associated_data, msg, siv_output)`` for one vector.

    The associated-data component is present even when empty: S2V over
    ``[b""]`` and over ``[]`` differ, and Wycheproof's expected outputs are
    computed with the component present. The AEAD files split the output into
    ``ct`` and ``tag``; SIV places the synthetic IV (the tag) first.
    """
    key = bytes.fromhex(test["key"])
    ads = [bytes.fromhex(test["aad"])]
    if "iv" in test:
        ads.append(bytes.fromhex(test["iv"]))
        output = bytes.fromhex(test["tag"]) + bytes.fromhex(test["ct"])
    else:
        output = bytes.fromhex(test["ct"])
    return key, ads, bytes.fromhex(test["msg"]), output


@pytest.mark.parametrize("name", sorted(PINNED_SHA256))
def test_vendored_vectors_match_the_pinned_upstream_bytes(name: str):
    digest = hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest()
    assert digest == PINNED_SHA256[name], (
        f"{name} differs from the Wycheproof file pinned at {UPSTREAM_COMMIT}; "
        "re-vendor deliberately and update the pin, never edit vectors in place"
    )


def test_the_upstream_licence_is_vendored_with_the_vectors():
    assert "Apache License" in (VECTOR_DIR / "LICENSE").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", sorted(PINNED_SHA256))
def test_every_declared_vector_is_executed(name: str):
    """A loader that silently dropped groups would report a green it never earned."""
    data = _load(name)
    assert len(_cases(name)) == data["numberOfTests"]


def test_floorvaults_exact_instantiation_is_covered():
    """AES-256-SIV (512-bit key) with a 16-byte nonce as the last component."""
    covered = [
        test
        for group, test in _cases("aead_aes_siv_cmac_test.json")
        if group["keySize"] == 512 and group["ivSize"] == 128
    ]
    assert len(covered) >= 100
    assert {test["result"] for test in covered} == {"valid", "invalid"}


@pytest.mark.parametrize("name", sorted(PINNED_SHA256))
def test_pyca_aessiv_agrees_with_every_vector(name: str):
    failures: list[str] = []
    for _group, test in _cases(name):
        key, ads, msg, output = _vector(test)
        siv = AESSIV(key)
        if test["result"] == "valid":
            if siv.encrypt(msg, ads) != output:
                failures.append(f"tcId {test['tcId']}: encryption differs")
            elif siv.decrypt(output, ads) != msg:
                failures.append(f"tcId {test['tcId']}: decryption differs")
            continue
        try:
            siv.decrypt(output, ads)
        except InvalidTag:
            continue
        failures.append(f"tcId {test['tcId']}: invalid vector was accepted ({test['comment']})")
    assert not failures, failures[:20]


@pytest.mark.parametrize("name", sorted(PINNED_SHA256))
def test_independent_rfc5297_implementation_agrees_with_every_vector(name: str):
    failures: list[str] = []
    for _group, test in _cases(name):
        key, ads, msg, output = _vector(test)
        if test["result"] == "valid":
            if siv_encrypt(key, msg, ads) != output:
                failures.append(f"tcId {test['tcId']}: encryption differs")
            elif siv_decrypt(key, output, ads) != msg:
                failures.append(f"tcId {test['tcId']}: decryption differs")
        elif siv_decrypt(key, output, ads) is not None:
            failures.append(f"tcId {test['tcId']}: invalid vector was accepted ({test['comment']})")
    assert not failures, failures[:20]


def test_the_secret_scan_allowlist_covers_exactly_the_pinned_vector_files():
    """The vectors' public test keys are allowlisted by path; nothing else may be.

    The allowlist is only safe because the files it covers are pinned by SHA-256
    above. A broader pattern would silently exempt files no test pins.
    """
    root = VECTOR_DIR.parent.parent.parent
    config = (root / ".gitleaks.toml").read_text(encoding="utf-8")
    patterns = re.findall(r"'''(.+?)'''", config)
    assert len(patterns) == 1, f"unexpected gitleaks allowlist entries: {patterns}"
    allow = re.compile(patterns[0])
    pinned = {f"tests/vectors/wycheproof/{name}" for name in PINNED_SHA256}
    matched = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and ".venv" not in path.parts
        and ".git" not in path.parts
        and allow.search(path.relative_to(root).as_posix())
    }
    assert matched == pinned, (
        f"allowlist covers {sorted(matched)}, pinned files are {sorted(pinned)}"
    )

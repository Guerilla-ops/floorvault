from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

from floorvault.beacons import BeaconIndexer

ROOT = Path(__file__).resolve().parents[1]
KEY = b"\x2b" * 32


def _exercise():
    spec = importlib.util.spec_from_file_location(
        "realworld_exercise", ROOT / "scripts" / "realworld_exercise.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scope_binding_accepts_legitimate_truncated_collisions():
    indexer = BeaconIndexer(KEY, bits=8)
    value = "scope-collision-80"
    assert indexer.beacon(value, scope="users.email") == b"\x90"
    assert indexer.beacon(value, scope="other.scope") == b"\x90"
    assert _exercise()._scope_binding_matches(indexer, value, "users.email")


def test_scope_binding_detects_an_indexer_that_ignores_the_scope():
    indexer = BeaconIndexer(KEY, bits=8)

    class ScopeIgnoringIndexer:
        bucket_bytes = 1

        def beacon(self, value, *, scope):
            return indexer.beacon(value, scope="users.email")

    assert not _exercise()._scope_binding_matches(
        ScopeIgnoringIndexer(), "alice@example.com", "users.email"
    )


@pytest.mark.parametrize(
    ("code", "stdout", "stderr", "expected"),
    [
        (0, "Value is not binary ciphertext; contents not displayed", "", True),
        (0, "Plaintext: not-encrypted-text", "", False),
        (1, "Value is not binary ciphertext; contents not displayed", "", False),
        (
            0,
            "Value is not binary ciphertext; contents not displayed",
            "not-encrypted-text",
            False,
        ),
    ],
)
def test_non_ciphertext_diagnostic_does_not_echo_plaintext(code, stdout, stderr, expected):
    result = subprocess.CompletedProcess(["inspect"], code, stdout, stderr)
    assert _exercise()._nonciphertext_diagnostic(result, "not-encrypted-text") is expected

"""Hypothesis property tests over the frozen wire semantics (roadmap 0f).

These complement the deterministic fuzz harness: Hypothesis searches a much
larger input space (arbitrary unicode coordinates, arbitrary-precision ints)
while ``derandomize=True`` keeps every run identical, so a failure is
reproducible rather than corpus-dependent.

Pinned properties:

  P1. Round-trip - decrypt_bytes(encrypt(p, coords), coords) == p for every
      valid payload/coordinate pair, including the frozen quirks (negative and
      arbitrary-precision schema_version).
  P2. Splice immunity - a ciphertext authenticated under one coordinate set
      fails closed under any different set.
  P3. Canonical AAD is injective over the accepted domain - distinct
      coordinate sets never share associated-data bytes (SPEC.md section 5.2).
  P4. Malformed input fails closed - arbitrary bytes decrypt to
      DecryptionVerificationError or TypeError, never an internal error.
"""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from floorvault import FloorVault
from floorvault.core import DecryptionVerificationError, associated_data

# Surrogates (category Cs) cannot be UTF-8 encoded; everything else is a legal
# coordinate per SPEC.md - including NFC/NFD variants, which MUST stay distinct.
_COORDINATE = st.text(
    alphabet=st.characters(exclude_categories=("Cs",)), min_size=1, max_size=48
).filter(lambda s: bool(s.strip()))

_COORDS = st.fixed_dictionaries(
    {
        "table": _COORDINATE,
        "record_id": _COORDINATE,
        "column": _COORDINATE,
    }
)

_SETTINGS = settings(derandomize=True, max_examples=150, deadline=None, database=None)


@pytest.fixture(scope="module")
def fv() -> FloorVault:
    return FloorVault(b"\x11" * 32, memory_mode="disabled")


@given(payload=st.binary(max_size=4096), coords=_COORDS)
@_SETTINGS
def test_p1_round_trip(fv: FloorVault, payload: bytes, coords: dict):
    ct = fv.encrypt(payload, **coords)
    assert fv.decrypt_bytes(ct, **coords) == payload


@given(payload=st.binary(max_size=4096), coords=_COORDS, schema_version=st.integers())
@_SETTINGS
def test_p1_round_trip_with_arbitrary_precision_schema_version(
    fv: FloorVault, payload: bytes, coords: dict, schema_version: int
):
    """Negative and >64-bit schema_version are accepted (frozen spec quirk)."""
    ct = fv.encrypt(payload, schema_version=schema_version, **coords)
    assert fv.decrypt_bytes(ct, schema_version=schema_version, **coords) == payload


@given(payload=st.binary(max_size=1024), coords=_COORDS, other=_COORDS)
@_SETTINGS
def test_p2_splice_immunity(fv: FloorVault, payload: bytes, coords: dict, other: dict):
    if other == coords:
        return
    ct = fv.encrypt(payload, **coords)
    with pytest.raises(DecryptionVerificationError):
        fv.decrypt_bytes(ct, **other)


@given(coords=_COORDS, other=_COORDS)
@_SETTINGS
def test_p3_associated_data_is_injective(coords: dict, other: dict):
    if other == coords:
        return
    assert associated_data(**coords) != associated_data(**other)


@given(blob=st.binary(max_size=4096), coords=_COORDS)
@_SETTINGS
def test_p4_malformed_input_fails_closed(fv: FloorVault, blob: bytes, coords: dict):
    try:
        fv.decrypt_bytes(blob, **coords)
    except (DecryptionVerificationError, TypeError):
        return
    # AEAD verification of attacker-chosen bytes is computationally
    # unreachable; a successful decrypt here is itself a finding.
    raise AssertionError("arbitrary bytes decrypted successfully")

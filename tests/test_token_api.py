"""v3 token envelope: self-contained encrypt_token/decrypt_token contracts.

The v3 envelope embeds the time claims (``exp``/``nbf``/``iat``) and the ctx
claim inside the authenticated header component, so tampering with either
fails the SIV tag, and ``decrypt_token`` enforces claims only *after* the
tag verifies - a forged token can never raise TokenExpiredError to leak
metadata.

Mode separation is part of the contract: ``decrypt``/``decrypt_bytes``
refuse v3 envelopes so the field path can never bypass token policy, and
``decrypt_token`` refuses v1/v2 field ciphertexts.
"""

from __future__ import annotations

import pytest

from floorvault import (
    DecryptionVerificationError,
    FloorVault,
    TokenExpiredError,
    TokenNotYetValidError,
)
from floorvault.core import envelope_header


@pytest.fixture
def crypto() -> FloorVault:
    return FloorVault(b"k" * 32, memory_mode="disabled")


# ---------------------------------------------------------------------------
# Roundtrip and envelope shape
# ---------------------------------------------------------------------------


def test_token_roundtrip_returns_bytes(crypto):
    token = crypto.encrypt_token(b"payload-data", purpose="pw-reset")
    assert token[:4] == b"FLV3"
    assert crypto.decrypt_token(token) == b"payload-data"


def test_token_roundtrip_accepts_str(crypto):
    token = crypto.encrypt_token("payload-data", purpose="p")
    assert crypto.decrypt_token(token) == b"payload-data"


def test_token_envelope_header_reports_claims(crypto):
    token = crypto.encrypt_token(b"x", purpose="pw-reset", expires_at=2_000_000_000, key_id=7)
    header = envelope_header(token)
    assert header["magic"] == b"FLV3"
    assert header["key_id"] == 7
    assert header["exp"] == 2_000_000_000
    assert header["nbf"] == 0
    assert header["iat"] > 0
    assert header["ctx"] == {"app_instance_id": "default", "purpose": "pw-reset"}
    assert header["nonce_len"] == 16


# ---------------------------------------------------------------------------
# Purpose binding and assertions
# ---------------------------------------------------------------------------


def test_expected_purpose_match_and_mismatch(crypto):
    token = crypto.encrypt_token(b"x", purpose="pw-reset")
    assert crypto.decrypt_token(token, expected_purpose="pw-reset") == b"x"
    with pytest.raises(DecryptionVerificationError, match="purpose"):
        crypto.decrypt_token(token, expected_purpose="email-verify")


def test_expected_app_instance_id_match_and_mismatch(crypto):
    token = crypto.encrypt_token(b"x", purpose="p")
    assert crypto.decrypt_token(token, expected_app_instance_id="default") == b"x"
    with pytest.raises(DecryptionVerificationError, match="app_instance_id"):
        crypto.decrypt_token(token, expected_app_instance_id="other-app")


def test_token_binds_app_instance_id_via_aad():
    a = FloorVault(b"k" * 32, app_instance_id="app-a", memory_mode="disabled")
    b = FloorVault(b"k" * 32, app_instance_id="app-b", memory_mode="disabled")
    token = a.encrypt_token(b"x", purpose="p")
    with pytest.raises(DecryptionVerificationError):
        b.decrypt_token(token)


def test_tampered_ctx_fails_authentication(crypto):
    token = bytearray(crypto.encrypt_token(b"x", purpose="pw-reset"))
    # ctx sits inside the authenticated header; flipping a byte in it must
    # fail the tag even though the ctx parses fine.
    idx = token.find(b"pw-reset")
    assert idx > 0
    token[idx] ^= 0x01
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt_token(bytes(token))


def test_tampered_exp_fails_authentication(crypto):
    token = bytearray(crypto.encrypt_token(b"x", purpose="p", expires_at=2_000_000_000))
    token[13] ^= 0xFF  # last byte of exp — now year ~7199, but tag fails first
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt_token(bytes(token))


# ---------------------------------------------------------------------------
# Time claims
# ---------------------------------------------------------------------------


def test_expired_token_raises(crypto):
    token = crypto.encrypt_token(b"x", purpose="p", expires_at=1_000_000_000)
    with pytest.raises(TokenExpiredError):
        crypto.decrypt_token(token)


def test_expires_in_and_at_are_mutually_exclusive(crypto):
    with pytest.raises(ValueError, match="mutually exclusive"):
        crypto.encrypt_token(b"x", purpose="p", expires_in=60, expires_at=1)


def test_exp_boundary_and_leeway(crypto):
    token = crypto.encrypt_token(b"x", purpose="p", expires_at=1_000)
    with pytest.raises(TokenExpiredError):
        crypto.decrypt_token(token, now=1001)
    assert crypto.decrypt_token(token, now=1001, leeway=1) == b"x"
    assert crypto.decrypt_token(token, now=1000) == b"x"


def test_not_yet_valid_raises(crypto):
    token = crypto.encrypt_token(b"x", purpose="p", not_before=2_000_000_000)
    with pytest.raises(TokenNotYetValidError):
        crypto.decrypt_token(token)
    assert crypto.decrypt_token(token, now=2_000_000_001) == b"x"


def test_nbf_leeway(crypto):
    token = crypto.encrypt_token(b"x", purpose="p", not_before=2000)
    with pytest.raises(TokenNotYetValidError):
        crypto.decrypt_token(token, now=1999, leeway=0.5)
    assert crypto.decrypt_token(token, now=1999, leeway=2) == b"x"


def test_nbf_after_exp_is_rejected_at_write(crypto):
    with pytest.raises(ValueError, match="not_before"):
        crypto.encrypt_token(b"x", purpose="p", expires_at=2000, not_before=3000)


def test_max_age_reader_policy(crypto):
    token = crypto.encrypt_token(b"x", purpose="p")
    # iat is pinned at encrypt; read at iat+10 with max_age=5 must fail even
    # with no writer-fixed expiry.
    iat = envelope_header(token)["iat"]
    with pytest.raises(TokenExpiredError, match="max_age"):
        crypto.decrypt_token(token, now=iat + 10, max_age=5)
    assert crypto.decrypt_token(token, now=iat + 4, max_age=5) == b"x"


def test_writer_expiry_wins_over_read_time(crypto):
    """A reader cannot widen the writer's window - there is no parameter to."""
    token = crypto.encrypt_token(b"x", purpose="p", expires_at=1000)
    with pytest.raises(TokenExpiredError):
        crypto.decrypt_token(token, now=5000)


def test_time_param_validation(crypto):
    token = crypto.encrypt_token(b"x", purpose="p")
    with pytest.raises(ValueError, match="leeway"):
        crypto.decrypt_token(token, leeway=-1)
    with pytest.raises(ValueError, match="max_age"):
        crypto.decrypt_token(token, max_age=0)


# ---------------------------------------------------------------------------
# Mode separation: field path refuses v3, token path refuses v1/v2
# ---------------------------------------------------------------------------


def test_decrypt_refuses_v3_token_envelope(crypto):
    token = crypto.encrypt_token(b"x", purpose="p")
    with pytest.raises(DecryptionVerificationError, match="decrypt_token"):
        crypto.decrypt(
            token,
            table="_fv.token",
            record_id="p",
            column="payload",
            schema_id="floor.vault.token.v1",
        )
    with pytest.raises(DecryptionVerificationError, match="decrypt_token"):
        crypto.decrypt_bytes(
            token,
            table="_fv.token",
            record_id="p",
            column="payload",
            schema_id="floor.vault.token.v1",
        )


def test_decrypt_token_refuses_field_envelopes(crypto):
    env = crypto.encrypt(b"x", table="t", record_id="r", column="c", schema_version=1)
    with pytest.raises(DecryptionVerificationError, match="v3"):
        crypto.decrypt_token(env)


def test_v2_field_envelope_still_reads_after_v3_added(crypto):
    env = crypto.encrypt("secret", table="t", record_id="r", column="c")
    assert crypto.decrypt(env, table="t", record_id="r", column="c") == "secret"


# ---------------------------------------------------------------------------
# Validation, keys, lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", 123, b"bytes-purpose"])
def test_purpose_must_be_nonempty_string(crypto, bad):
    with pytest.raises((ValueError, TypeError)):
        crypto.encrypt_token(b"x", purpose=bad)


def test_purpose_unicode_and_long(crypto):
    purpose = "pw-reset-日本語-" + "x" * 300  # ctx_len is 2 bytes, not 1
    token = crypto.encrypt_token(b"x", purpose=purpose)
    assert crypto.decrypt_token(token, expected_purpose=purpose) == b"x"


def test_token_key_id_dispatch(crypto):
    token = crypto.encrypt_token(b"x", purpose="p", key_id=3)
    assert crypto.decrypt_token(token, key_id=3) == b"x"
    with pytest.raises(DecryptionVerificationError, match="key id"):
        crypto.decrypt_token(token, key_id=4)


def test_expires_in_nonpositive_rejected(crypto):
    with pytest.raises(ValueError, match="expires_in"):
        crypto.encrypt_token(b"x", purpose="p", expires_in=0)


def test_wiped_instance_refuses_token_ops(crypto):
    token = crypto.encrypt_token(b"x", purpose="p")
    crypto.wipe()
    with pytest.raises(RuntimeError, match="wiped"):
        crypto.encrypt_token(b"x", purpose="p")
    with pytest.raises(RuntimeError, match="wiped"):
        crypto.decrypt_token(token)


def test_token_nonce_tracking_applies(crypto):
    """Token writes feed the same in-process nonce-reuse window."""
    before = len(crypto._nonce_set)
    crypto.encrypt_token(b"x", purpose="p")
    assert len(crypto._nonce_set) == before + 1


def test_token_malformed_envelopes(crypto):
    for bad in [
        b"FLV3",  # truncated fixed prefix
        b"FLV3" + b"\x02" * 28,  # truncated at ctx_len boundary
        crypto.encrypt_token(b"x", purpose="p")[:40],  # ctx cut mid-claim
        crypto.encrypt_token(b"x", purpose="p")[:-10],  # ct truncated
    ]:
        with pytest.raises(DecryptionVerificationError):
            crypto.decrypt_token(bad)


def test_ctx_strict_shape_rejected(crypto):
    """A forged-claim shape can't survive: ctx must be exactly the pair."""
    import json

    token = bytearray(crypto.encrypt_token(b"x", purpose="p"))
    ctx_len = int.from_bytes(token[30:32], "big")
    claims_ctx = json.loads(bytes(token[32 : 32 + ctx_len]))
    assert claims_ctx["purpose"] == "p"
    # Even well-formed JSON with an extra key must fail before decryption.
    forged = json.dumps(
        {"app_instance_id": "default", "purpose": "p", "extra": "evil"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert len(forged) > ctx_len
    new_token = (
        bytes(token[:30]) + len(forged).to_bytes(2, "big") + forged + bytes(token[32 + ctx_len :])
    )
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt_token(new_token)

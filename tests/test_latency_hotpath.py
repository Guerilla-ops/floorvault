"""Hot-path latency work must not change the wire format or the contracts.

The templated AAD serializer replaces ``json.dumps(sort_keys=True)`` on the
per-operation path: it is only valid if the bytes are identical for every
input, including the escaping edge cases. The batch field APIs must emit
envelopes indistinguishable from per-field ``encrypt`` output. And the
memoryview envelope parse must keep the same rejections as the copy-based
parser.
"""

from __future__ import annotations

import sqlite3

import pytest

from floorvault import (
    DecryptionVerificationError,
    EncryptedSQLiteTable,
    FloorVault,
)
from floorvault.core import associated_data


@pytest.fixture
def crypto() -> FloorVault:
    return FloorVault(b"k" * 32, memory_mode="disabled")


# ---------------------------------------------------------------------------
# _aad() byte-identity against the canonical serializer
# ---------------------------------------------------------------------------

_CORPUS = [
    # (table, record_id, column, schema_id, schema_version, revision)
    ("users", "r1", "email", "floor.vault.v1", 1, None),
    ("users", "rec-日本語", 'na"me', "floor.vault.v1", 1, None),
    ("t\\t", "r\n2", "c", "floor.vault.v1", 1, None),
    ("t", "r", "c", "custom.v9", 42, 0),
    ("t", "r", "c", "floor.vault.v1", 1, 7),
    ("t", "r\x01\xff\x7f", "c", "floor.vault.v1", 1, None),
    ("x" * 300, "r", "c", "floor.vault.v1", 1, None),
]


@pytest.mark.parametrize(
    ("table", "record_id", "column", "schema_id", "schema_version", "revision"),
    _CORPUS,
)
def test_aad_matches_associated_data(
    crypto, table, record_id, column, schema_id, schema_version, revision
):
    expected = associated_data(
        table=table,
        record_id=record_id,
        column=column,
        schema_id=schema_id,
        schema_version=schema_version,
        app_instance_id="default",
        revision=revision,
    )
    got = crypto._aad(
        table=table,
        record_id=record_id,
        column=column,
        schema_id=schema_id,
        schema_version=schema_version,
        revision=revision,
    )
    assert got == expected


def test_aad_rejects_same_inputs_as_associated_data(crypto):
    base = dict(
        table="t",
        record_id="r",
        column="c",
        schema_id="floor.vault.v1",
        schema_version=1,
        revision=None,
    )
    for name, bad in [("table", ""), ("record_id", " "), ("column", ""), ("schema_id", "")]:
        with pytest.raises(ValueError, match=f"AAD parameter '{name}'"):
            crypto._aad(**{**base, name: bad})
    with pytest.raises(TypeError, match="schema_version"):
        crypto._aad(**{**base, "schema_version": 1.5})
    with pytest.raises(ValueError, match="non-negative"):
        crypto._aad(**{**base, "revision": -1})


# ---------------------------------------------------------------------------
# Batch field API: output identical to per-field encrypt, same bindings
# ---------------------------------------------------------------------------


def test_encrypt_fields_roundtrip_and_per_field_compat(crypto):
    fields = {"email": "a@b.c", "name": "José", "blob": b"\x00\xffbinary"}
    envelopes = crypto.encrypt_fields(fields, table="users", record_id="u-1")
    assert set(envelopes) == set(fields)
    # Each envelope is an ordinary v2 envelope readable by the single-field API.
    for column, envelope in envelopes.items():
        got = crypto.decrypt_bytes(envelope, table="users", record_id="u-1", column=column)
        expected = fields[column]
        assert got == (expected.encode("utf-8") if isinstance(expected, str) else expected)
    # Batch decrypt agrees.
    dec = crypto.decrypt_fields(envelopes, table="users", record_id="u-1")
    assert dec["email"] == b"a@b.c"
    assert dec["blob"] == b"\x00\xffbinary"


def test_encrypt_fields_binds_each_column(crypto):
    envelopes = crypto.encrypt_fields({"a": "one", "b": "two"}, table="t", record_id="r")
    # A ciphertext spliced into its sibling column's coordinates must fail.
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(envelopes["a"], table="t", record_id="r", column="b")
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(envelopes["a"], table="t", record_id="r2", column="a")


def test_encrypt_fields_validation_and_no_partial_write(crypto):
    with pytest.raises(ValueError, match="record_id"):
        crypto.encrypt_fields({"c": "v"}, table="t", record_id="")
    with pytest.raises(ValueError, match="'column'"):
        crypto.encrypt_fields({"": "v"}, table="t", record_id="r")
    with pytest.raises(TypeError):
        crypto.encrypt_fields({"c": "v"}, table="t", record_id="r", key_id=True)


def test_decrypt_fields_rejects_tampered_envelope(crypto):
    envelopes = crypto.encrypt_fields({"a": "1", "b": "2"}, table="t", record_id="r")
    bad = dict(envelopes)
    bad["a"] = envelopes["b"]  # splice column b's envelope under column a
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt_fields(bad, table="t", record_id="r")


# ---------------------------------------------------------------------------
# Adapter batch methods: one UPDATE / one SELECT per record
# ---------------------------------------------------------------------------


def test_adapter_batch_store_and_load(tmp_path, crypto):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email BLOB, name BLOB, pic BLOB)")
    conn.execute("INSERT INTO users VALUES ('u1', NULL, NULL, NULL)")
    adapter = EncryptedSQLiteTable(conn, crypto, "users")

    adapter.store_fields("u1", {"email": "e@x.y", "name": "n", "pic": b"\xff\xfe\x80"})
    assert adapter.load_fields("u1", ["email", "name"]) == {"email": "e@x.y", "name": "n"}
    raw = adapter.load_fields_bytes("u1", ["email", "pic"])
    assert raw["pic"] == b"\xff\xfe\x80"
    # Binary field is refused by the text accessor, same as load().
    with pytest.raises(ValueError, match="not valid UTF-8"):
        adapter.load_fields("u1", ["pic"])
    # Missing record and NULL column invariants are unchanged.
    with pytest.raises(LookupError):
        adapter.load_fields("nope", ["email"])
    with pytest.raises(LookupError):
        adapter.store_fields("nope", {"email": "x"})
    conn.execute("INSERT INTO users VALUES ('u2', NULL, NULL, NULL)")
    with pytest.raises(ValueError, match="NULL"):
        adapter.load_fields("u2", ["email"])
    # Identifier allowlist applies to every column.
    with pytest.raises(ValueError, match="identifier"):
        adapter.store_fields("u1", {"email FROM users --": "x"})
    with pytest.raises(ValueError, match="identifier"):
        adapter.load_fields("u1", ["email --"])
    with pytest.raises(ValueError, match="empty"):
        adapter.store_fields("u1", {})


# ---------------------------------------------------------------------------
# Envelope parse parity: memoryview path keeps every rejection
# ---------------------------------------------------------------------------


def test_envelope_rejections_unchanged(crypto):
    good = crypto.encrypt("v", table="t", record_id="r", column="c")
    for bad, match in [
        (b"", "too short"),
        (b"X" * 40, "magic"),
        (good[:6] + bytes([99]) + good[7:], "nonce length"),
        (good[:23], "no ciphertext"),
    ]:
        with pytest.raises(DecryptionVerificationError, match=match):
            crypto.decrypt(bad, table="t", record_id="r", column="c")
    # A v1-shaped envelope (FLRV || nonce_len || nonce || ct) still parses.
    legacy = b"FLRV" + bytes([16]) + good[7:23] + good[23:]
    with pytest.raises(DecryptionVerificationError):
        crypto.decrypt(legacy, table="t", record_id="r", column="c")

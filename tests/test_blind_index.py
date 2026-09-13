"""Tests for HMAC-SHA256 blind indexing."""

import pytest

from appstate_crypto.blind_index import BlindIndexer, compute_blind_index


def test_blind_index_deterministic():
    key = b"\x10" * 32
    idx1 = compute_blind_index("scott@example.com", scope="users.email", key=key)
    idx2 = compute_blind_index("scott@example.com", scope="users.email", key=key)

    assert isinstance(idx1, bytes)
    assert len(idx1) == 32
    assert idx1 == idx2


def test_blind_index_scope_domain_separation():
    """Different scopes on the same value must produce different blind indices."""
    key = b"\x10" * 32
    idx_email = compute_blind_index("scott@example.com", scope="users.email", key=key)
    idx_contact = compute_blind_index("scott@example.com", scope="contacts.email", key=key)

    assert idx_email != idx_contact


def test_blind_index_truncation():
    key = b"\x10" * 32
    idx_short = compute_blind_index(
        "scott@example.com", scope="users.email", key=key, truncate_bytes=16
    )
    assert len(idx_short) == 16


def test_blind_indexer_helper_class():
    key = b"\x20" * 32
    indexer = BlindIndexer(key)

    idx1 = indexer.index("admin", scope="roles.name")
    idx2 = indexer.index("admin", scope="roles.name")
    assert idx1 == idx2


def test_blind_index_validation_errors():
    key = b"\x10" * 32
    with pytest.raises(TypeError, match="must be string"):
        compute_blind_index(12345, scope="users.id", key=key)  # type: ignore

    with pytest.raises(ValueError, match="Scope must be a non-empty string"):
        compute_blind_index("val", scope="  ", key=key)

    with pytest.raises(ValueError, match="must be at least 32 bytes"):
        compute_blind_index("val", scope="users.email", key=b"too_short")

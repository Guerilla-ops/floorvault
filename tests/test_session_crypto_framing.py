"""SessionCrypto record_id framing must be injective over (session, message).

The AAD binding pins a ciphertext to a record_id built as
``f"{session_id}\\x00{message_id}"``. That construction is injective only when
the components cannot themselves contain the separator: otherwise
``("sess-a", "msg-1\\x00tail")`` and ``("sess-a\\x00msg-1", "tail")`` map to
the same record_id, so a ciphertext sealed under one logical (session,
message) coordinate decrypts under the other — the splice the contextual
binding exists to prevent. This is the same defect class beacons fixed with
length-prefixing; here the components are validated instead, so existing
NUL-free record_ids stay readable while the ambiguous inputs are refused.

The tests pin both halves: the formerly-colliding pairs are rejected, and
ordinary distinct coordinates still cannot open each other's ciphertexts.
"""

from __future__ import annotations

import pytest

from floorvault import FloorVault
from floorvault.vaultkit import SessionCrypto, VaultError


@pytest.fixture
def session_crypto() -> SessionCrypto:
    return SessionCrypto(FloorVault(b"k" * 32, memory_mode="disabled"))


def test_message_roundtrip(session_crypto):
    cipher, _ = session_crypto.encrypt_message(
        session_id="sess-1", message_id="msg-9", content="hello"
    )
    assert (
        session_crypto.decrypt_message(
            session_id="sess-1", message_id="msg-9", payload_cipher=cipher
        )
        == "hello"
    )


@pytest.mark.parametrize(
    ("session_id", "message_id"),
    [
        ("sess-a\x00msg-1", "tail"),
        ("sess-a", "msg-1\x00tail"),
        ("s\x00m", "x"),
        ("s", "x\x00m"),
        ("\x00", "m"),
        ("s", "\x00"),
    ],
)
def test_nul_components_refused(session_crypto, session_id, message_id):
    with pytest.raises(VaultError, match="NUL"):
        session_crypto.encrypt_message(session_id=session_id, message_id=message_id, content="data")
    with pytest.raises(VaultError, match="NUL"):
        session_crypto.decrypt_message(
            session_id=session_id, message_id=message_id, payload_cipher=b"x"
        )


@pytest.mark.parametrize(
    ("session_id", "message_id"),
    [
        ("", "msg-1"),
        ("sess-1", ""),
        ("", ""),
        (None, "msg-1"),
        ("sess-1", None),
        (123, "msg-1"),
        ("sess-1", b"m"),
    ],
)
def test_empty_and_non_str_components_refused(session_crypto, session_id, message_id):
    with pytest.raises(VaultError, match="non-empty string"):
        session_crypto.encrypt_message(session_id=session_id, message_id=message_id, content="data")


def test_distinct_valid_coordinates_do_not_splice(session_crypto):
    cipher, _ = session_crypto.encrypt_message(
        session_id="sess-a", message_id="msg-1", content="secret"
    )
    with pytest.raises(Exception, match="verification failed"):
        session_crypto.decrypt_message(
            session_id="sess-b", message_id="msg-1", payload_cipher=cipher
        )
    with pytest.raises(Exception, match="verification failed"):
        session_crypto.decrypt_message(
            session_id="sess-a", message_id="msg-2", payload_cipher=cipher
        )


def test_formerly_colliding_pair_is_rejected(session_crypto):
    """The exact collision demonstrated in the security audit must not bind."""
    # ("sess-a", "msg-1\x00tail") and ("sess-a\x00msg-1", "tail") used to share
    # the record_id "sess-a\x00msg-1\x00tail"; both inputs are now refused, so
    # no ciphertext can ever be bound to that ambiguous coordinate.
    with pytest.raises(VaultError, match="NUL"):
        session_crypto.encrypt_message(session_id="sess-a", message_id="msg-1\x00tail", content="x")
    with pytest.raises(VaultError, match="NUL"):
        session_crypto.encrypt_message(session_id="sess-a\x00msg-1", message_id="tail", content="x")

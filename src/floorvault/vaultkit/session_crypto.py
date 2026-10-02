"""state.db session encryption helper."""

from __future__ import annotations

import re

from ..core import FloorVault
from .vault import VaultError


def _compose_record_id(session_id: str, message_id: str, *, allow_empty: bool) -> str:
    """Join session and message ids into one bound ``record_id``.

    ``\x00`` is the separator, so it must not occur inside either component:
    ``("a", "b\\x00c")`` and ``("a\\x00b", "c")`` would otherwise map to the
    same record_id, and a ciphertext sealed under one logical
    (session, message) coordinate would decrypt under the other - the
    splice-resistance the AAD binding exists for. The same class of defect was
    removed from beacons by length-prefixing; here the invariant is enforced
    instead, keeping existing NUL-free records readable.

    With NUL banned the composition is injective even over empty parts, so
    emptiness is refused only where it matters: the write path
    (``allow_empty=False``) keeps new records well-formed, while the read path
    (``allow_empty=True``) must still open records written before the refusal
    existed, which can carry an empty component.
    """
    for name, part in (("session_id", session_id), ("message_id", message_id)):
        if not isinstance(part, str) or (not part and not allow_empty):
            raise VaultError(f"{name} must be a non-empty string")
        if "\x00" in part:
            raise VaultError(
                f"{name} must not contain NUL bytes: the \\x00 separator would "
                "make distinct (session_id, message_id) pairs bind to the same "
                "record_id"
            )
    return f"{session_id}\x00{message_id}"


# Common secret regex patterns (API keys, bearer tokens) for FTS5 scrubbing
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"[a-f0-9]{32,64}", re.IGNORECASE),  # Raw hex tokens
    # AWS access key ids (AKIA/ASIA followed by 16 uppercase alphanumerics).
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Slack tokens (xoxb/xoxp/xoxa/xoxr/xoxs followed by hyphenated parts).
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    # Credential-bearing URIs: scheme://user:password@host
    re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
    # JSON Web Tokens: three dot-separated base64url segments.
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def scrub_secrets_for_fts(text: str) -> str:
    """Best-effort scrub of common credential formats from FTS text.

    This is defence in depth, not a guarantee: the pattern set covers the token
    formats listed in ``SECRET_PATTERNS`` and will always miss formats it does
    not know about. It is not a substitute for not indexing plaintext at all;
    ``allow_plaintext_fts`` is off by default.
    """
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)
    return scrubbed


class SessionCrypto:
    """Encrypted state.db message history without a searchable projection."""

    def __init__(self, crypto: FloorVault, *, allow_plaintext_fts: bool = False) -> None:
        self.crypto = crypto
        self.allow_plaintext_fts = allow_plaintext_fts

    def encrypt_message(
        self,
        *,
        session_id: str,
        message_id: str,
        content: str,
    ) -> tuple[bytes, str]:
        """Encrypt message with contextual AAD while extracting scrubbed FTS text.

        Returns:
            Tuple of (payload_cipher, fts_text).
        """
        payload_cipher = self.crypto.encrypt(
            content,
            table="messages",
            record_id=_compose_record_id(session_id, message_id, allow_empty=False),
            column="content",
        )
        fts_text = scrub_secrets_for_fts(content) if self.allow_plaintext_fts else ""
        return payload_cipher, fts_text

    def decrypt_message(
        self,
        *,
        session_id: str,
        message_id: str,
        payload_cipher: bytes,
    ) -> str:
        """Decrypt message while requiring the current session binding."""
        return self.crypto.decrypt(
            payload_cipher,
            table="messages",
            record_id=_compose_record_id(session_id, message_id, allow_empty=True),
            column="content",
        )

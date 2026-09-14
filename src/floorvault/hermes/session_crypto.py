"""Hermes state.db session encryption helper with FTS5 search preservation."""

from __future__ import annotations

import re

from ..core import FloorVault

# Common secret regex patterns (API keys, bearer tokens) for FTS5 scrubbing
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"[a-f0-9]{32,64}", re.IGNORECASE),  # Raw hex tokens
]
FTS_SCOPE = "hermes.messages.fts.v1"
SEARCH_TERM_PATTERN = re.compile(r"\w+(?:[-']\w+)*")


def scrub_secrets_for_fts(text: str) -> str:
    """Scrub raw API keys and secrets so FTS5 index contains zero credentials."""
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)
    return scrubbed


def _secure_search_tokens(text: str, crypto: FloorVault) -> str:
    """Return space-separated HMAC tokens suitable for an FTS index."""
    tokens: list[str] = []
    seen: set[str] = set()
    for term in SEARCH_TERM_PATTERN.findall(text.casefold()):
        token = crypto.blind_index(term, scope=FTS_SCOPE).hex()
        if token not in seen:
            tokens.append(token)
            seen.add(token)
    return " ".join(tokens)


class HermesSessionCrypto:
    """Hybrid split-projection for Hermes state.db message history."""

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
            record_id=f"{session_id}\x00{message_id}",
            column="content",
        )
        fts_text = scrub_secrets_for_fts(content) if self.allow_plaintext_fts else ""
        if not self.allow_plaintext_fts:
            fts_text = _secure_search_tokens(content, self.crypto)
        return payload_cipher, fts_text

    def secure_search_query(self, query: str) -> str:
        """Tokenize a query using the same keyed representation as the FTS index."""
        return _secure_search_tokens(query, self.crypto)

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
            record_id=f"{session_id}\x00{message_id}",
            column="content",
        )

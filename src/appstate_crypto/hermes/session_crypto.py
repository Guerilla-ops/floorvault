"""Hermes state.db session encryption helper with FTS5 search preservation."""

from __future__ import annotations

import re
from typing import Tuple

from ..core import AppStateCrypto

# Common secret regex patterns (API keys, bearer tokens) for FTS5 scrubbing
SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"[a-f0-9]{32,64}", re.IGNORECASE),  # Raw hex tokens
]


def scrub_secrets_for_fts(text: str) -> str:
    """Scrub raw API keys and secrets so FTS5 index contains zero credentials."""
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)
    return scrubbed


class HermesSessionCrypto:
    """Hybrid split-projection for Hermes state.db message history."""

    def __init__(self, crypto: AppStateCrypto) -> None:
        self.crypto = crypto

    def encrypt_message(
        self,
        *,
        session_id: str,
        message_id: str,
        content: str,
    ) -> Tuple[bytes, str]:
        """Encrypt message with contextual AAD while extracting scrubbed FTS text.

        Returns:
            Tuple of (payload_cipher, fts_text).
        """
        payload_cipher = self.crypto.encrypt(
            content,
            table="messages",
            record_id=message_id,
            column="content",
        )
        fts_text = scrub_secrets_for_fts(content)
        return payload_cipher, fts_text

    def decrypt_message(
        self,
        *,
        session_id: str,
        message_id: str,
        payload_cipher: bytes,
    ) -> str:
        """Decrypt message verifying contextual coordinates."""
        return self.crypto.decrypt(
            payload_cipher,
            table="messages",
            record_id=message_id,
            column="content",
        )

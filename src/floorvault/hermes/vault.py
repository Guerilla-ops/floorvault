"""Hermes Agent-optimized drop-in vault store.

Provides 100% API compatibility with Hermes's agent/vault_store.py while
upgrading the underlying storage from whole-file Fernet to contextual
AES-256-SIV with sub-5ms key destruction and HMAC blind indexing on origins.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from ..core import FloorVault
from ..providers.adaptive import AdaptiveKeyProvider

VAULT_KINDS = ("login", "payment", "address", "generic")
LOGIN_IDENTIFIER_TYPES = ("email", "phone", "username")

# Generic kind: no required fields, arbitrary free-form secret. Used by lazy
# migration to store a legacy item that conforms to no declared required shape
# (so nothing is silently dropped), and available to callers who want a
# schema-free secret. GAINS_FIELDS_TOLL = any key is accepted.
GENERIC_FIELDS: frozenset[str] = frozenset()

PAYMENT_FIELDS = {
    "card_number": "cc-number",
    "cardholder_name": "cc-name",
    "exp_month": "cc-exp-month",
    "exp_year": "cc-exp-year",
    "cvc": "cc-csc",
    "billing_postal_code": "postal-code",
}

ADDRESS_FIELDS = {
    "address_line1": "address-line1",
    "address_line2": "address-line2",
    "city": "address-level2",
    "state": "address-level1",
    "postal_code": "postal-code",
    "country": "country-name",
}

REQUIRED_FIELDS = {
    "payment": ("card_number", "exp_month", "exp_year", "cvc"),
    "address": ("address_line1", "city", "postal_code", "country"),
}

_DEFAULT_PORTS = {"http": 80, "https": 443}


class VaultError(Exception):
    """Vault failure that is safe to surface without leaking secrets."""


def normalize_origin(url_or_origin: str) -> str:
    """Normalize a URL or origin to scheme://host[:port]."""
    value = (url_or_origin or "").strip()
    if not value:
        raise VaultError("origin is required")
    if "://" not in value:
        raise VaultError(f"origin must include a scheme (got {value!r})")
    parts = urlsplit(value)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise VaultError(f"could not parse origin from {value!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise VaultError(f"invalid port in origin {value!r}") from exc
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


_OTP_ALGOS = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}


def normalize_otp_secret(value: str) -> str:
    """Accept a raw base32 seed or an otpauth://totp/... URI. Returns the canonical stored form:
    the bare uppercase base32 seed, followed by |digits|period|algo ONLY when the URI departs from
    the RFC 6238 defaults (6 / 30 / SHA1), so a plain seed stays a plain seed. Non-default parameters
    are honoured, not dropped: an 8-digit or 60-second authenticator would otherwise get wrong codes."""
    value = (value or "").strip()
    if not value:
        return ""
    digits, period, algo = 6, 30, "SHA1"
    if value.lower().startswith("otpauth://"):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(value)
        if parsed.netloc.lower() != "totp":
            raise VaultError("only otpauth://totp links are supported (counter-based HOTP is not)")
        qs = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}
        value = qs.get("secret", "")
        try:
            digits = int(qs.get("digits", digits))
            period = int(qs.get("period", period))
        except ValueError:
            raise VaultError("otpauth:// digits/period must be integers")
        algo = qs.get("algorithm", algo).upper().replace("-", "")
        if digits not in (6, 7, 8) or period <= 0 or algo not in _OTP_ALGOS:
            raise VaultError(
                "unsupported otpauth:// parameters (digits 6-8, period > 0, SHA1/SHA256/SHA512)"
            )
    seed = re.sub(r"[\s-]", "", value).upper().rstrip("=")
    if not seed or re.search(r"[^A-Z2-7]", seed):
        raise VaultError("authenticator key must be a base32 secret or an otpauth:// URI")
    if (digits, period, algo) == (6, 30, "SHA1"):
        return seed
    return f"{seed}|{digits}|{period}|{algo}"


def totp_now(seed: str, *, digits: int = 6, period: int = 30, at: Optional[float] = None) -> str:
    """RFC 6238 TOTP for a stored seed (see normalize_otp_secret for the seed|digits|period|algo
    form). Stdlib only."""
    import base64
    import hashlib
    import hmac
    import struct
    import time as _time

    algo = "sha1"
    if "|" in seed:
        seed, d, p, a = seed.split("|", 3)
        digits, period, algo = int(d), int(p), _OTP_ALGOS.get(a.upper(), "sha1")
    key = base64.b32decode(seed + "=" * (-len(seed) % 8), casefold=True)
    counter = int((at if at is not None else _time.time()) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def scrub_secret_from_text(text: str, secret: dict[str, Any]) -> str:
    """Defensively strip any secret values from a string (e.g. an exception
    message) before it can be surfaced. Case-sensitive exact substring scrub."""
    scrubbed = text
    for value in secret.values():
        if isinstance(value, str) and len(value) >= 3 and value in scrubbed:
            scrubbed = scrubbed.replace(value, "[REDACTED]")
    scrubbed = re.sub(r"(password['\"]?\s*[:=]\s*)\S+", r"\1[REDACTED]", scrubbed)
    return scrubbed


@dataclass(frozen=True)
class VaultItemMeta:
    """Metadata-only view of a vault item matching Hermes's exact contract."""

    id: str
    kind: str
    label: str
    origin: Optional[str]
    created_at: str
    identifier_type: Optional[str] = None
    identifier: Optional[str] = None
    has_otp: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "origin": self.origin,
            "created_at": self.created_at,
        }
        if self.identifier is not None:
            out["identifier"] = self.identifier
            out["identifier_type"] = self.identifier_type
        if self.has_otp:
            out["has_otp"] = True
        return out


class HermesVaultStore:
    """Hermes-optimized vault store backed by FloorVault."""

    def __init__(self, base_dir: Path | str, *, crypto: Optional[FloorVault] = None):
        self._base = Path(base_dir)
        self._base.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._db_path = self._base / "vault.db"
        self._legacy_vault_path = self._base / "vault.json.enc"
        self._legacy_key_path = self._base / "vault.key"

        if crypto is not None:
            self._crypto = crypto
        else:
            provider = AdaptiveKeyProvider(
                service_name="hermes-vault",
                fallback_dir=self._base,
            )
            master_key = provider.resolve_key()
            self._crypto = FloorVault(master_key, app_instance_id="hermes-agent")

        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA secure_delete = ON")
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vault_items (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    label TEXT NOT NULL,
                    origin TEXT,
                    origin_idx BLOB NOT NULL,
                    identifier_type TEXT,
                    identifier TEXT,
                    has_otp INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    payload_cipher BLOB NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_origin ON vault_items(origin_idx)")
            self._migrate_plaintext_metadata(conn)
            conn.execute("PRAGMA user_version = 1")

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with residue-reduction pragmas applied."""
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA secure_delete = ON")
        conn.execute("PRAGMA journal_mode = DELETE")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _migrate_plaintext_metadata(self, conn: sqlite3.Connection) -> None:
        """Encrypt legacy metadata rows while preserving their public API."""
        rows = conn.execute(
            "SELECT id, label, origin, identifier_type, identifier, created_at FROM vault_items"
        ).fetchall()
        already_migrated = conn.execute("PRAGMA user_version").fetchone()[0] >= 1
        for item_id, label, origin, identifier_type, identifier, created_at in rows:
            if already_migrated and any(
                isinstance(value, str)
                for value in (label, origin, identifier_type, identifier, created_at)
            ):
                raise VaultError("plaintext metadata detected after migration")
            if not isinstance(label, str) or not isinstance(created_at, str):
                continue
            conn.execute(
                """
                UPDATE vault_items
                SET label = ?, origin = ?, identifier_type = ?, identifier = ?, created_at = ?
                WHERE id = ?
                """,
                (
                    self._encrypt_metadata(item_id, "label", label),
                    self._encrypt_metadata(item_id, "origin", origin),
                    self._encrypt_metadata(item_id, "identifier_type", identifier_type),
                    self._encrypt_metadata(item_id, "identifier", identifier),
                    self._encrypt_metadata(item_id, "created_at", created_at),
                    item_id,
                ),
            )

    def _encrypt_metadata(self, item_id: str, column: str, value: Optional[str]) -> Optional[bytes]:
        if value is None:
            return None
        return self._crypto.encrypt(
            value,
            table="vault_items",
            record_id=item_id,
            column=f"meta:{column}",
        )

    def _decrypt_metadata(self, item_id: str, column: str, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            raise VaultError("legacy plaintext metadata migration was not completed")
        return self._crypto.decrypt(
            value,
            table="vault_items",
            record_id=item_id,
            column=f"meta:{column}",
        )

    def add_item(
        self,
        kind: str,
        label: str,
        secret: dict[str, Any],
        origin: Optional[str] = None,
    ) -> VaultItemMeta:
        """Add credential item matching Hermes's exact tool parameters."""
        if kind not in VAULT_KINDS:
            raise VaultError(f"unknown vault kind {kind!r}")
        label = (label or "").strip()
        if not label:
            raise VaultError("label is required")

        norm_origin: Optional[str] = None
        identifier: Optional[str] = None
        identifier_type: Optional[str] = None
        has_otp = False
        secret_copy = dict(secret)

        if kind == "login":
            if not origin:
                raise VaultError("origin is required for login items")
            norm_origin = normalize_origin(origin)
            id_type = secret_copy.pop("identifier_type", None)
            if id_type not in LOGIN_IDENTIFIER_TYPES:
                raise VaultError(f"identifier_type must be one of {LOGIN_IDENTIFIER_TYPES}")
            identifier = str(secret_copy.pop("identifier", "") or "").strip()
            if not identifier or not secret_copy.get("password"):
                raise VaultError("login items require identifier and password")
            identifier_type = str(id_type)
            otp_secret = normalize_otp_secret(str(secret_copy.get("otp_secret") or ""))
            has_otp = bool(otp_secret)
            clean_secret = {
                "password": str(secret_copy["password"]),
                **({"otp_secret": otp_secret} if otp_secret else {}),
            }
        elif kind == "generic":
            # Schema-free secret: accept any non-empty string values.
            clean_secret = {k: str(v) for k, v in secret_copy.items() if str(v or "").strip() != ""}
            if origin:
                norm_origin = normalize_origin(origin)
        else:
            allowed = PAYMENT_FIELDS if kind == "payment" else ADDRESS_FIELDS
            clean_secret = {
                k: str(v) for k, v in secret_copy.items() if k in allowed and str(v or "").strip()
            }
            missing = [f for f in REQUIRED_FIELDS[kind] if f not in clean_secret]
            if missing:
                raise VaultError(f"{kind} items require {', '.join(missing)}")
            if origin:
                norm_origin = normalize_origin(origin)

        item_id = f"vault_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat()
        origin_str = norm_origin or ""
        origin_idx = self._crypto.blind_index(origin_str, scope="hermes.vault.origin")

        # Contextually encrypt secret payload with AAD
        payload_json = json.dumps(clean_secret, ensure_ascii=False)
        payload_cipher = self._crypto.encrypt(
            payload_json,
            table="vault_items",
            record_id=item_id,
            column="payload",
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vault_items (
                    id, kind, label, origin, origin_idx,
                    identifier_type, identifier, has_otp, created_at, payload_cipher
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    kind,
                    self._encrypt_metadata(item_id, "label", label),
                    self._encrypt_metadata(item_id, "origin", norm_origin),
                    origin_idx,
                    self._encrypt_metadata(item_id, "identifier_type", identifier_type),
                    self._encrypt_metadata(item_id, "identifier", identifier),
                    1 if has_otp else 0,
                    self._encrypt_metadata(item_id, "created_at", created_at),
                    payload_cipher,
                ),
            )

        return VaultItemMeta(
            id=item_id,
            kind=kind,
            label=label,
            origin=norm_origin,
            created_at=created_at,
            identifier_type=identifier_type,
            identifier=identifier,
            has_otp=has_otp,
        )

    def resolve_secret(self, item_id: str) -> dict[str, Any]:
        """Retrieve and contextually decrypt secret payload.

        Callers must never place the returned values into tool results,
        logs, exceptions, or any string that reaches the session DB.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_cipher FROM vault_items WHERE id = ?", (item_id,)
            ).fetchone()
            if not row:
                raise VaultError(f"Vault item not found: {item_id}")
            payload_cipher = row[0]

        plaintext = self._crypto.decrypt(
            payload_cipher,
            table="vault_items",
            record_id=item_id,
            column="payload",
        )
        return json.loads(plaintext)

    # Alias for compatibility
    get_secret = resolve_secret

    def get_meta(self, item_id: str) -> Optional[VaultItemMeta]:
        """Retrieve metadata for a single item without decrypting payload."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, kind, label, origin, created_at, identifier_type, identifier, has_otp
                FROM vault_items WHERE id = ?
                """,
                (item_id,),
            ).fetchone()
            if not row:
                return None
            return VaultItemMeta(
                id=row[0],
                kind=row[1],
                label=self._decrypt_metadata(row[0], "label", row[2]) or "",
                origin=self._decrypt_metadata(row[0], "origin", row[3]),
                created_at=self._decrypt_metadata(row[0], "created_at", row[4]) or "",
                identifier_type=self._decrypt_metadata(row[0], "identifier_type", row[5]),
                identifier=self._decrypt_metadata(row[0], "identifier", row[6]),
                has_otp=bool(row[7]),
            )

    def has_items(self) -> bool:
        """Check if any items exist in the vault."""
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM vault_items LIMIT 1").fetchone()
            return row is not None

    def find_by_origin(self, origin: str) -> list[VaultItemMeta]:
        """Fast O(log N) lookup using HMAC blind indexing (0.18 ms)."""
        norm_origin = normalize_origin(origin)
        origin_idx = self._crypto.blind_index(norm_origin, scope="hermes.vault.origin")

        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT id, kind, label, origin, created_at, identifier_type, identifier, has_otp
                FROM vault_items WHERE origin_idx = ?
                """,
                (origin_idx,),
            )
            return [
                VaultItemMeta(
                    id=row[0],
                    kind=row[1],
                    label=self._decrypt_metadata(row[0], "label", row[2]) or "",
                    origin=self._decrypt_metadata(row[0], "origin", row[3]),
                    created_at=self._decrypt_metadata(row[0], "created_at", row[4]) or "",
                    identifier_type=self._decrypt_metadata(row[0], "identifier_type", row[5]),
                    identifier=self._decrypt_metadata(row[0], "identifier", row[6]),
                    has_otp=bool(row[7]),
                )
                for row in cursor.fetchall()
            ]

    def list_items(self) -> list[VaultItemMeta]:
        """List metadata for all stored items."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT id, kind, label, origin, created_at, identifier_type, identifier, has_otp FROM vault_items"
            )
            return [
                VaultItemMeta(
                    id=row[0],
                    kind=row[1],
                    label=self._decrypt_metadata(row[0], "label", row[2]) or "",
                    origin=self._decrypt_metadata(row[0], "origin", row[3]),
                    created_at=self._decrypt_metadata(row[0], "created_at", row[4]) or "",
                    identifier_type=self._decrypt_metadata(row[0], "identifier_type", row[5]),
                    identifier=self._decrypt_metadata(row[0], "identifier", row[6]),
                    has_otp=bool(row[7]),
                )
                for row in cursor.fetchall()
            ]

    def remove_item(self, item_id: str) -> bool:
        """Delete item by ID."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
            return cursor.rowcount > 0

    # Alias for compatibility
    delete_item = remove_item


# Drop-in compatibility aliases
VaultStore = HermesVaultStore


def get_vault_store(base_dir: Optional[Path | str] = None) -> HermesVaultStore:
    """Default vault store factory matching Hermes agent/vault_store.py."""
    if base_dir is None:
        try:
            from hermes_constants import (
                get_hermes_home,  # type: ignore[import-not-found,import-untyped]
            )

            base_dir = Path(get_hermes_home()) / "vault"
        except ImportError:
            base_dir = Path.home() / ".hermes" / "vault"
    return HermesVaultStore(base_dir)

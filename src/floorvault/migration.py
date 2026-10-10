"""Lazy, non-destructive migration from legacy Fernet / plaintext stores.

A facade that serves the MODERN floorvault-backed store first and, for records
that only exist in a legacy store, transparently reads them, lazily upgrades them
into the modern store, and keeps the legacy source untouched until an explicit
``verify()`` confirms every migrated item decrypts.

Non-destructive guarantees:
  * The legacy ``vault.json.enc`` / ``vault.key`` files are never written or
    deleted by reads or lazy upgrades.
  * ``migrate_all()`` creates a ``*.pre-migration.bak`` copy before converting
    everything, and refuses to discard the legacy source unless ``verify()``
    passes for every migrated item.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

from .providers.platform_custody import ProtectedStoreError, read_protected
from .vaultkit.vault import VaultError, VaultStore, normalize_origin, normalize_otp_secret


class LegacyVaultError(VaultError):
    """Raised when the legacy source is missing, corrupt, or not decryptable."""


#: Deepest JSON nesting a legacy payload may carry. A genuine legacy vault is
#: a flat ``{item_id: {field: value}}`` mapping; json.loads recurses on the C
#: stack, so a deeply-nested payload would otherwise crash every legacy entry
#: point with an unhandled RecursionError. The guard pre-flights the payload
#: and the parser's own RecursionError is still mapped as a second line.
_LEGACY_JSON_MAX_DEPTH = 64


def _json_nesting_depth(text: str) -> int:
    """Maximum ``[]``/``{}`` nesting in a JSON document, ignoring strings."""
    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
        elif char in "]}":
            depth -= 1
    return deepest


class LegacyRetiredError(VaultError):
    """Raised when a legacy id has been migrated and must not be read again.

    A migrated id is *retired*: the pre-migration source is permanently
    forbidden for it, even if the modern record has since disappeared. Serving
    the legacy value instead would silently resurrect the value from before the
    credential was rotated, and every cryptographic check would still pass
    because the old value is an authentic one - just retired.
    """


def _base64url_decode(s: str) -> bytes:
    import base64

    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as exc:  # noqa: BLE001
        raise LegacyVaultError("Legacy vault payload is not valid base64") from exc


class MigratingVaultStore:
    """Dual-read facade: modern store first, legacy Fernet store as fallback.

    Parameters
    ----------
    modern_store:
        The floorvault-backed VaultStore (the target of migration).
    legacy_base_dir:
        Directory that contains the legacy ``vault.json.enc`` + ``vault.key``.
    legacy_vault_name / legacy_key_name:
        Filenames of the legacy vault and key (defaults match the reference agent layout).
    """

    def __init__(
        self,
        *,
        modern_store: VaultStore,
        legacy_base_dir: Path | str,
        legacy_vault_name: str = "vault.json.enc",
        legacy_key_name: str = "vault.key",
        backup_suffix: str = ".pre-migration.bak",
    ) -> None:
        self.modern = modern_store
        self._base = Path(legacy_base_dir)
        self._vault_path = self._base / legacy_vault_name
        self._key_path = self._base / legacy_key_name
        self._backup_suffix = backup_suffix
        # legacy item id -> modern item id, set after each lazy upgrade so a
        # subsequent resolve/get by the legacy id reaches the migrated record.
        self._legacy_to_modern: dict[str, str] = {}
        self._modern_to_legacy: dict[str, str] = {}

    # ---- legacy Fernet access (non-destructive) ---------------------------

    def _has_legacy(self) -> bool:
        # lexists() also sees broken symlinks and non-regular files (FIFOs,
        # sockets), so a tampered entry is reported by _legacy_items instead of
        # silently treated as "no legacy vault present".
        return os.path.lexists(self._vault_path) and os.path.lexists(self._key_path)

    def _legacy_items(self) -> dict[str, dict[str, Any]]:
        """Decrypt the whole legacy Fernet vault once. Read-only; never mutates."""
        if not self._has_legacy():
            return {}
        if not self._vault_path.is_file():
            raise LegacyVaultError("Legacy vault is not a regular file")
        if not self._key_path.is_file():
            # A FIFO or socket at the key path must be refused before open():
            # opening one would block the caller indefinitely.
            raise LegacyVaultError("Legacy vault key is not a regular file")
        try:
            # The key is read through read_protected like every other key
            # store: symlinks, foreign owners and group/other-readable modes
            # are refused rather than silently adopted.
            key = read_protected(self._key_path, header=b"", expected_length=None).strip()
            fernet = Fernet(key)
            raw = _base64url_decode(self._vault_path.read_text(encoding="utf-8").strip())
            plaintext = fernet.decrypt(raw)
            document = plaintext.decode("utf-8")
            if _json_nesting_depth(document) > _LEGACY_JSON_MAX_DEPTH:
                raise LegacyVaultError(
                    f"Legacy vault nests JSON deeper than {_LEGACY_JSON_MAX_DEPTH} levels"
                )
            value = json.loads(document)
        except InvalidToken as exc:
            raise LegacyVaultError("Legacy vault key does not decrypt the vault") from exc
        except ProtectedStoreError as exc:
            raise LegacyVaultError(f"Refusing legacy key file: {exc}") from exc
        except RecursionError as exc:
            raise LegacyVaultError("Legacy vault JSON is too deeply nested") from exc
        except (ValueError, UnicodeDecodeError, OSError) as exc:
            raise LegacyVaultError(f"Legacy vault is corrupt: {exc}") from exc
        if not isinstance(value, dict):
            raise LegacyVaultError("Legacy vault is not a JSON object")
        return {str(k): dict(v) for k, v in value.items() if isinstance(v, dict)}

    def _upgrade_legacy_item(self, item_id: str, item: dict[str, Any]) -> None:
        """Lazily write one migrated item into the modern store (AES-256-SIV)."""
        item = dict(item)
        item_id = str(item_id)
        kind = item.pop("kind", None)
        label = item.pop("label", item_id)
        origin = item.pop("origin", None)
        identifier = item.pop("identifier", None)
        identifier_type = item.pop("identifier_type", None)
        secret = dict(item)
        # Heuristic: a legacy item whose fields match a known login shape keeps
        # login; otherwise it is migrated as a schema-free "generic" secret so
        # nothing is silently dropped. Explicit kinds are honoured as-is.
        if kind is None:
            has_login_fields = bool(identifier and identifier_type and secret.get("password"))
            kind = "login" if has_login_fields else "generic"
        kwargs: dict[str, Any] = {
            "kind": kind,
            "label": label,
            "secret": secret,
            "item_id": self._stable_modern_id(item_id),
        }
        if origin:
            kwargs["origin"] = origin
        elif kind == "login":
            # A legacy login item without a browsing origin has been imported
            # from a flat secret store; bind it to a local-sentinel origin so it
            # is still upgradeable rather than silently dropped.
            kwargs["origin"] = "https://_local.migration"
        if identifier and identifier_type:
            secret.setdefault("identifier", identifier)
            secret.setdefault("identifier_type", identifier_type)
        try:
            meta = self.modern.add_item(**kwargs)
        except sqlite3.IntegrityError as exc:
            # A process may have written the deterministic modern row before
            # crashing while recording its retirement tombstone. Reuse that row
            # only after proving it is the same normalized legacy item. Any
            # unrelated collision must fail closed and must not retire the source.
            existing = self.modern.get_meta(kwargs["item_id"])
            if existing is None:
                raise VaultError(f"Could not lazily migrate item {item_id}") from exc
            expected_origin = normalize_origin(origin) if origin else None
            expected_secret = {
                key: str(value) for key, value in secret.items() if str(value or "").strip()
            }
            if kind == "login" and "otp_secret" in expected_secret:
                expected_secret["otp_secret"] = normalize_otp_secret(expected_secret["otp_secret"])
            existing_secret = self.modern.resolve_secret(existing.id)
            if (
                existing.kind != kind
                or existing.label != str(label or "").strip()
                or existing.origin != expected_origin
                or existing.identifier != (str(identifier).strip() if identifier else None)
                or existing.identifier_type != identifier_type
                or existing_secret != expected_secret
            ):
                raise VaultError(
                    f"deterministic migration target conflicts for legacy item {item_id!r}"
                ) from exc
            meta = existing
        if meta is not None:
            # Retire the legacy id permanently. From here on the pre-migration
            # source must never answer for it again, even if this modern record
            # is later deleted or rolled back - otherwise the facade would serve
            # the value from before the credential was rotated.
            self.modern.retire_legacy_id(item_id, meta.id)
            self._legacy_to_modern[item_id] = meta.id
            self._modern_to_legacy[meta.id] = item_id

    @staticmethod
    def _stable_modern_id(legacy_id: str) -> str:
        """Return a collision-resistant ID stable across migration retries."""
        digest = hashlib.sha256(legacy_id.encode("utf-8")).hexdigest()[:24]
        return f"vault_migration_{digest}"

    # ---- public dual-read API ----------------------------------------------

    def _modern_id_for(self, item_id: str) -> str:
        """Map a legacy (or already-migrated) public id to the modern store id.

        The in-memory map is only a cache. The authoritative record of what has
        been migrated is the retirement tombstone in the modern store, so a
        fresh process resolves a legacy id correctly without it.
        """
        if item_id in self._legacy_to_modern:
            return self._legacy_to_modern[item_id]
        retired = self.modern.retired_modern_id(item_id)
        if retired is not None:
            self._legacy_to_modern[item_id] = retired
            self._modern_to_legacy.setdefault(retired, item_id)
            return retired
        return item_id

    def _refuse_retired_fallback(self, *candidate_ids: str) -> None:
        """Refuse the pre-migration source for any id that has been retired.

        Called only after the modern lookup has already failed, so reaching it
        with a retired id means the modern record is gone. Falling through to
        the legacy source at that point would silently serve the value from
        before the credential was rotated.
        """
        for candidate in candidate_ids:
            if not candidate:
                continue
            modern_id = self.modern.retired_modern_id(candidate)
            if modern_id is not None:
                raise LegacyRetiredError(
                    f"legacy item {candidate!r} was migrated to {modern_id!r} and is "
                    "retired; its modern record is missing, and reading the "
                    "pre-migration source in its place is refused"
                )

    def resolve_secret(self, item_id: str) -> dict[str, Any]:
        """Return the secret for ``item_id`` from modern, else legacy (lazy-upgraded)."""
        modern_id = self._modern_id_for(item_id)
        try:
            return self.modern.resolve_secret(modern_id)
        except VaultError:
            pass
        self._refuse_retired_fallback(item_id, modern_id)
        legacy = self._legacy_items()
        if item_id not in legacy and modern_id not in legacy:
            raise VaultError(f"Vault item not found: {item_id}")
        if modern_id in legacy and item_id not in legacy:
            item_id = modern_id
        self._upgrade_legacy_item(item_id, legacy[item_id])
        return self.modern.resolve_secret(self._legacy_to_modern[item_id])

    def get_meta(self, item_id: str) -> Optional[Any]:
        modern_id = self._modern_id_for(item_id)
        try:
            modern = self.modern.get_meta(modern_id)
            if modern is not None:
                return modern
        except VaultError:
            pass
        self._refuse_retired_fallback(item_id, modern_id)
        legacy = self._legacy_items()
        if item_id not in legacy and modern_id not in legacy:
            return None
        if modern_id in legacy and item_id not in legacy:
            item_id = modern_id
        self._upgrade_legacy_item(item_id, legacy[item_id])
        return self.modern.get_meta(self._legacy_to_modern[item_id])

    def has_items(self) -> bool:
        return self.modern.has_items() or self._has_legacy()

    def list_item_ids(self) -> list[str]:
        ids = {m.id for m in self.modern.list_items()}
        ids.update(self._legacy_items().keys())
        return sorted(ids)

    # ---- batch migration (non-destructive, verify-gated) ------------------

    def migrate_all(self) -> dict[str, Any]:
        """Convert every legacy item into the modern store.

        Creates a ``*.pre-migration.bak`` copy of the legacy vault FIRST, then
        converts each item, then runs the non-destructive ``verify()``. The
        legacy source files are NOT removed — the caller may remove them only
        after ``verify()`` has passed and they have made their own copy.

        Raises VaultError on any failure and leaves the legacy source intact.
        """
        legacy = self._legacy_items()
        if not legacy:
            return {"migrated": 0, "verified": True, "removed_legacy": False}
        # 1. Immutable backup (non-destructive). The vault copy and the key
        # copy are gated independently: a pre-existing vault backup must not
        # veto creating the key backup, or the migration would report success
        # beside a backup that cannot decrypt after the key is removed.
        backup = self._vault_path.with_name(f"{self._vault_path.name}{self._backup_suffix}")
        key_backup = self._key_path.with_name(f"{self._key_path.name}{self._backup_suffix}")
        if not backup.exists():
            shutil.copy2(self._vault_path, backup)
        if self._key_path.is_file() and not os.path.lexists(key_backup):
            shutil.copy2(self._key_path, key_backup)
            # copy2 preserves the source's owner-only mode, which
            # read_protected just verified; pin it anyway so the backup's
            # protection never depends on copy semantics.
            try:
                os.chmod(key_backup, 0o600)
            except OSError:
                # POSIX mode bits do not exist on Windows; the ACL check
                # below is the control there.
                pass
        # The key backup holds the legacy master key, so it is held to the
        # same protected-store bar as the key itself. A backup that already
        # existed never passed through read_protected - refuse to report a
        # successful migration while a readable copy of the key sits beside
        # the vault.
        if os.path.lexists(key_backup):
            try:
                read_protected(key_backup, header=b"", expected_length=None)
            except ProtectedStoreError as exc:
                raise LegacyVaultError(f"Refusing legacy key backup: {exc}") from exc
        # 2. Convert each legacy item lazily (idempotent for already-modern).
        migrated = 0
        for item_id, item in legacy.items():
            retired_modern_id = self.modern.retired_modern_id(item_id)
            if retired_modern_id is not None:
                if self.modern.get_meta(retired_modern_id) is None:
                    raise VaultError(
                        f"legacy item {item_id!r} is retired but its modern record "
                        f"{retired_modern_id!r} is missing"
                    )
                continue
            # A modern record that merely shares the legacy id proves nothing
            # about the legacy item - it may be unrelated data - and skipping on
            # that basis reported a verified migration while the legacy value
            # was never carried over or retired. Every unretired legacy id is
            # migrated onto its deterministic target and tombstoned; an
            # unrelated pre-existing record keeps its id and remains directly
            # readable from the modern store.
            self._upgrade_legacy_item(item_id, item)
            migrated += 1
        # 3. Verify every migrated item decrypts.  Pass the legacy items already
        # loaded above so verification does not decrypt and parse the legacy
        # source a second time; the legacy source is unchanged by this method.
        verified = self._verify(legacy)
        return {
            "migrated": migrated,
            "verified": verified,
            "removed_legacy": False,  # the caller removes only after verify
        }

    def verify(self) -> bool:
        """Decrypt every migrated (modern) item to confirm the migration is sound.

        Also checks that every retired legacy id still has a modern record. A
        tombstone whose record has disappeared means the value is unavailable -
        the fallback is refused - so the migration is no longer sound and this
        returns False rather than reporting success.

        Finally, every id still present in the legacy source must have a
        retirement tombstone. A legacy item that was never migrated (for
        example because an unrelated modern record happened to share its id)
        means the "migration" silently dropped it, so verification must fail.

        The legacy source is always read fresh: a caller-supplied snapshot
        could be incomplete or stale and would certify a migration that left
        untombstoned items behind.
        """
        try:
            return self._verify(self._legacy_items())
        except VaultError:
            return False

    def _verify(self, legacy: dict[str, dict[str, Any]]) -> bool:
        """Verify against an authoritative legacy snapshot (never caller-supplied)."""
        try:
            ids = list(self.modern.list_items())
            retirements = self.modern.list_legacy_retirements()
        except VaultError:
            return False
        present = {meta.id for meta in ids}
        if any(modern_id not in present for modern_id in retirements.values()):
            return False
        if any(legacy_id not in retirements for legacy_id in legacy):
            return False
        for meta in ids:
            try:
                self.modern.resolve_secret(meta.id)
            except Exception:  # noqa: BLE001
                return False
        return True

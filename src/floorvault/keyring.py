"""Reading a store that spans more than one key generation.

A rotation leaves a store holding records sealed under two keys at once: those
already moved and those not yet moved. A reader must therefore select a key per
record, not per store - which is what the v2 envelope's authenticated ``key_id``
exists for (see ``docs/RECORD-FORMAT-2026-09-15.md``).

The ring refuses anything it cannot justify. It never tries every key in turn: a
record naming a key the ring does not hold is an error, because "try them all and
see which authenticates" would hide the operational mistake of a missing key and
would let a relabelled record pick its own key if any candidate happened to work.

Safety rules this module encodes rather than advises:

* the key a record needs comes from the record (authenticated header), with an
  explicit ``default_key_id`` as the only concession to v1 records, which carry
  no key id at all;
* there is no fallback between keys, and no "best effort" search;
* a record whose header was rewritten fails authentication rather than being
  decrypted with the key the rewrite points at.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from .core import (
    FloorVault,
    FloorVaultError,
    envelope_header,
)


class UnknownKeyIdError(FloorVaultError):
    """Raised when a record names a key generation this ring does not hold.

    Distinct from a decryption failure on purpose: a missing key is an
    operational condition (the ring was constructed without it, or a rotation
    lost it) and must not be mistaken for tampering, or the other way round.
    """


class KeyRing:
    """Dispatch decryption to the key generation named by each record.

    Parameters
    ----------
    keys:
        Mapping of ``key_id`` (0..255) to the ``FloorVault`` holding that
        generation's subkey. Copied at construction, so a caller mutating its
        own dict afterwards cannot silently change what the ring can read.
    default_key_id:
        The generation to assume for **v1** records, which carry no key id. Left
        as ``None``, a v1 record is refused: the ring will not guess which key
        sealed a record that does not say.
    """

    def __init__(
        self,
        keys: Mapping[int, FloorVault],
        *,
        default_key_id: Optional[int] = None,
    ) -> None:
        if not isinstance(keys, Mapping) or not keys:
            raise ValueError("KeyRing needs at least one key generation")
        checked: dict[int, FloorVault] = {}
        for key_id, vault in keys.items():
            if isinstance(key_id, bool) or not isinstance(key_id, int):
                raise TypeError(f"key_id must be an integer, got {type(key_id).__name__}")
            if not 0 <= key_id <= 255:
                raise ValueError(f"key_id must be in [0, 255], got {key_id}")
            if not isinstance(vault, FloorVault):
                raise TypeError(f"key {key_id} must be a FloorVault, got {type(vault).__name__}")
            checked[key_id] = vault

        if default_key_id is not None:
            if isinstance(default_key_id, bool) or not isinstance(default_key_id, int):
                raise TypeError("default_key_id must be an integer or None")
            if default_key_id not in checked:
                raise ValueError(
                    f"default_key_id {default_key_id} is not among the held keys "
                    f"{sorted(checked)}; a default the ring cannot use is a trap"
                )

        self._keys = checked
        self._default_key_id = default_key_id

    # ---- introspection -----------------------------------------------------

    def key_ids(self) -> tuple[int, ...]:
        """The key generations this ring can read, ascending."""
        return tuple(sorted(self._keys))

    @property
    def default_key_id(self) -> Optional[int]:
        """The generation assumed for v1 records, if one was declared."""
        return self._default_key_id

    # ---- selection ---------------------------------------------------------

    def _vault_for(self, ciphertext: bytes) -> FloorVault:
        """Return the vault named by the record's authenticated header.

        Raises ``UnknownKeyIdError`` when the ring cannot honour the record, and
        whatever ``envelope_header`` raises for something that is not an envelope.
        """
        header: dict[str, Any] = envelope_header(ciphertext)
        if "key_id" not in header:
            # v1: the record is silent about its key, so the caller must have said.
            if self._default_key_id is None:
                raise UnknownKeyIdError(
                    "this record carries no key id (v1 envelope) and the ring has no "
                    "default_key_id; construct the ring with default_key_id=<generation> "
                    f"to read v1 records (held keys: {list(self.key_ids())})"
                )
            return self._keys[self._default_key_id]

        key_id = header["key_id"]
        try:
            return self._keys[key_id]
        except KeyError:
            raise UnknownKeyIdError(
                f"record was written under key id {key_id}, which this ring does not "
                f"hold (held keys: {list(self.key_ids())})"
            ) from None

    # ---- reading -----------------------------------------------------------

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: Optional[int] = None,
    ) -> str:
        """Decrypt with the generation the record names, returning text."""
        return self._vault_for(ciphertext).decrypt(
            ciphertext,
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            revision=revision,
        )

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: Optional[int] = None,
    ) -> bytes:
        """Decrypt with the generation the record names, returning raw bytes."""
        return self._vault_for(ciphertext).decrypt_bytes(
            ciphertext,
            table=table,
            record_id=record_id,
            column=column,
            schema_id=schema_id,
            schema_version=schema_version,
            revision=revision,
        )

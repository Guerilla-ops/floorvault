"""Driver-free record operations shared by the storage adapters.

The cryptographic core (:class:`floorvault.core.FloorVault`) already takes
plain coordinates and never touches a driver; what the SQLite and SQLAlchemy
adapters both need is a single definition of *which* coordinates a record
gets and how its field-level invariants behave. This module is that shared
layer: :class:`RecordBinding` binds a crypto engine to a table/schema
identity once, so the adapters only ever differ in how rows move in and out
of their driver - never in how a record is authenticated.

It also owns :func:`bound_record_id`, the unambiguous composite coordinate
used when a record is owned by a tenant, and :func:`require_envelope`, the
structural check an adapter uses to prove a value it is about to persist is
a real FloorVault envelope rather than plaintext staged through a side door.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Union

from .core import DecryptionVerificationError, FloorVault, FloorVaultError, envelope_header


class EncryptedWriteError(FloorVaultError):
    """A write to an encrypted field could not satisfy its binding contract.

    Raised by adapters at assignment/flush time: missing identity attributes,
    plaintext staged onto a ciphertext column, or an unsupported write path.
    Defined in the driver-free records layer so callers can ``except`` it
    without importing a specific adapter's dependencies.
    """


class UnsupportedWriteError(EncryptedWriteError):
    """A bulk or bypass write path named a registered ciphertext column.

    Bulk statements carry values for many records in one execution, so the
    per-record coordinates FloorVault binds cannot be derived row-by-row.
    These paths are rejected rather than silently encrypting against the
    wrong record - or not encrypting at all.
    """


@dataclass(frozen=True)
class RecordBinding:
    """The encryption-coordinate identity of one logical table.

    ``crypto`` is the engine; ``table``, ``schema_id`` and ``schema_version``
    are the record-constant AAD coordinates every field of this table shares.
    The remaining coordinates - ``record_id``, ``column`` and ``revision`` -
    stay per-call so one binding serves every record in the table.
    """

    crypto: FloorVault
    table: str
    schema_id: str = "floor.vault.v1"
    schema_version: int = 1

    def encrypt_field(
        self,
        record_id: str,
        column: str,
        value: Union[str, bytes],
        *,
        schema_version: int | None = None,
        revision: int | None = None,
        key_id: int = 0,
    ) -> bytes:
        """Encrypt one field bound to this table and record."""
        return self.crypto.encrypt(
            value,
            table=self.table,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=self._version(schema_version),
            revision=revision,
            key_id=key_id,
        )

    def decrypt_field(
        self,
        record_id: str,
        column: str,
        ciphertext: bytes,
        *,
        schema_version: int | None = None,
        revision: int | None = None,
        key_id: int | None = None,
    ) -> str:
        """Decrypt one field to text; binary payloads use ``decrypt_field_bytes``."""
        return self.crypto.decrypt(
            ciphertext,
            table=self.table,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=self._version(schema_version),
            revision=revision,
            key_id=key_id,
        )

    def decrypt_field_bytes(
        self,
        record_id: str,
        column: str,
        ciphertext: bytes,
        *,
        schema_version: int | None = None,
        revision: int | None = None,
        key_id: int | None = None,
    ) -> bytes:
        """Decrypt one field to raw bytes."""
        return self.crypto.decrypt_bytes(
            ciphertext,
            table=self.table,
            record_id=record_id,
            column=column,
            schema_id=self.schema_id,
            schema_version=self._version(schema_version),
            revision=revision,
            key_id=key_id,
        )

    def encrypt_fields(
        self,
        record_id: str,
        fields: Mapping[str, Union[str, bytes]],
        *,
        schema_version: int | None = None,
        revision: int | None = None,
        key_id: int = 0,
    ) -> dict[str, bytes]:
        """Encrypt several fields of one record, sharing the record-constant AAD."""
        return self.crypto.encrypt_fields(
            fields,
            table=self.table,
            record_id=record_id,
            schema_id=self.schema_id,
            schema_version=self._version(schema_version),
            revision=revision,
            key_id=key_id,
        )

    def decrypt_fields(
        self,
        record_id: str,
        envelopes: Mapping[str, bytes],
        *,
        schema_version: int | None = None,
        revision: int | None = None,
        key_id: int | None = None,
    ) -> dict[str, bytes]:
        """Decrypt several fields of one record to raw bytes."""
        return self.crypto.decrypt_fields(
            envelopes,
            table=self.table,
            record_id=record_id,
            schema_id=self.schema_id,
            schema_version=self._version(schema_version),
            revision=revision,
            key_id=key_id,
        )

    def _version(self, schema_version: int | None) -> int:
        return self.schema_version if schema_version is None else schema_version


def bound_record_id(record_id: str, tenant: str | None = None) -> str:
    """The record coordinate, optionally bound to a tenant/owner scope.

    With ``tenant`` set the coordinate is a length-prefixed composite,
    ``"<len>:<tenant><record_id>"``. Plain concatenation would be ambiguous
    (``("ab", "c")`` vs ``("a", "bc")`` would collide), so the tenant length
    is committed first; the AAD itself then binds the pair cryptographically.
    A record written under one tenant can never be read under another, and
    there is no opt-out: a caller that declares ``tenant_attr`` must produce
    a tenant value for every record it encrypts.
    """
    record_id = str(record_id)
    if tenant is None:
        return record_id
    tenant = str(tenant)
    return f"{len(tenant)}:{tenant}{record_id}"


def require_envelope(value: object, *, where: str) -> bytes:
    """Return ``value`` as bytes iff it is a structurally valid envelope.

    This is a format check, not decryption: a value that parses as a v1 or
    v2 FloorVault envelope passes regardless of whether it will authenticate.
    The check exists so adapters can refuse plaintext staged through paths
    that bypass their encrypting layer - only envelope-shaped bytes may ever
    occupy an encrypted column.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        candidate = bytes(value)
        try:
            envelope_header(candidate)
        except (DecryptionVerificationError, TypeError):
            candidate = b""
        if candidate:
            return candidate
    raise TypeError(f"{where}: value is not a FloorVault ciphertext envelope")

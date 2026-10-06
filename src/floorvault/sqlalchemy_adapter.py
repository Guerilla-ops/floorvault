"""SQLAlchemy ORM adapter: fail-closed encrypted fields on mapped classes.

The threat this adapter answers is not the crypto - that is
:class:`floorvault.core.FloorVault`, unchanged. It is the ORM write surface:
bulk ``insert()``/``update()`` statements, ``Query.update``, and direct
assignment to a mapped ciphertext column all bypass ordinary model code, so
an encryption layer that only listens to flush events cannot see them.
This adapter therefore enforces three invariants, each checked where it can
be violated, not only at flush:

1. Plaintext never occupies a registered column. ``EncryptedField`` is a
   plain (non-mapped) descriptor: ``obj.field = "secret"`` encrypts
   immediately and stores *ciphertext* on the mapped column attribute
   (``field_ct``). The identity attributes (``id_attr``, and ``tenant_attr``
   when declared) must already be set, otherwise the assignment fails
   closed - there is no "encrypt later" staging state to leak through.
2. Only FloorVault envelopes may reach a registered ciphertext column, from
   any path. An attribute ``set`` validator on each ciphertext column rejects
   any value that is not a structurally valid v1/v2 envelope, so
   ``obj.field_ct = b"plaintext"`` fails at assignment, not at flush.
3. Bulk write paths that cannot bind per-record coordinates are rejected.
   A ``do_orm_execute`` guard refuses ORM ``insert``/``update`` statements -
   including executemany parameter sets and ``Query.update`` - that supply a
   value for a registered ciphertext column. Records must be written through
   ``session.add`` with ``EncryptedField`` assignment.

Owner/tenant binding uses :func:`floorvault.records.bound_record_id`: the
AAD record coordinate is a length-prefixed ``tenant:record_id`` composite,
so a ciphertext written under one tenant cannot be replayed under another.

``revision_attr`` binds a per-record integer into the AAD, exactly like the
SQLite adapter's ``revision`` parameter. It detects same-coordinate replay
of an older ciphertext; it is NOT a whole-database rollback counter and
does not protect against restoring an earlier full database state.

Not covered, by design: raw ``Connection.execute``/driver-SQL writes made
outside the ORM session the policy produced. Applications that also write
directly to these tables must produce ciphertext through the same binding;
the structural validator cannot intercept statements the ORM never sees.
"""

from __future__ import annotations

from typing import Any, Union

try:
    from sqlalchemy import event
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.orm import ORMExecuteState, sessionmaker
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "floorvault.sqlalchemy_adapter requires SQLAlchemy 2.x; "
        "install the 'sqlalchemy' extra (pip install floorvault[sqlalchemy])"
    ) from exc

from .core import FloorVault
from .records import (
    EncryptedWriteError,
    RecordBinding,
    UnsupportedWriteError,
    bound_record_id,
    require_envelope,
)

__all__ = [
    "SqlAlchemyEncryption",
    "EncryptedField",
    "EncryptedWriteError",
    "UnsupportedWriteError",
]


class EncryptedField:
    """Plaintext-facing descriptor for one encrypted column.

    ``fields={"ssn": EncryptedField("ssn_ct")}`` on :meth:`protect` installs
    this descriptor on the model class under ``ssn``. Assignment encrypts and
    stores ciphertext on the mapped ``ssn_ct`` column; reads decrypt from it.
    The descriptor itself never appears in SQL and is never mapped - it is
    the only supported write path for the column.

    ``binary=True`` returns decrypted bytes instead of str (the counterpart
    to :meth:`EncryptedSQLiteTable.load_bytes`).
    """

    def __init__(self, column_attr: str, *, binary: bool = False) -> None:
        if not isinstance(column_attr, str) or not column_attr:
            raise ValueError("column_attr must name the mapped ciphertext attribute")
        self.column_attr = column_attr
        self.binary = binary
        self.name: str | None = None

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    def __set__(self, obj: Any, value: Union[str, bytes]) -> None:
        binding = _binding_for(obj)
        rid = binding.record_id(obj)
        revision = binding.revision(obj)
        ciphertext = binding.records.encrypt_field(rid, self.column_attr, value, revision=revision)
        setattr(obj, self.column_attr, ciphertext)

    def __get__(self, obj: Any, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        ciphertext = getattr(obj, self.column_attr)
        if ciphertext is None:
            return None
        binding = _binding_for(obj)
        rid = binding.record_id(obj)
        revision = binding.revision(obj)
        if self.binary:
            return binding.records.decrypt_field_bytes(
                rid, self.column_attr, ciphertext, revision=revision
            )
        return binding.records.decrypt_field(rid, self.column_attr, ciphertext, revision=revision)


class _ModelBinding:
    """Per-model record of what ``protect()`` declared for a class."""

    def __init__(
        self,
        records: RecordBinding,
        *,
        id_attr: str,
        tenant_attr: str | None,
        revision_attr: str | None,
        ct_columns: frozenset[str],
    ) -> None:
        self.records = records
        self.id_attr = id_attr
        self.tenant_attr = tenant_attr
        self.revision_attr = revision_attr
        self.ct_columns = ct_columns

    def record_id(self, obj: Any) -> str:
        pk = getattr(obj, self.id_attr, None)
        if pk is None:
            raise EncryptedWriteError(
                f"{type(obj).__name__}.{self.id_attr} must be set before "
                "encrypted fields; the record coordinate cannot be derived"
            )
        tenant = None
        if self.tenant_attr is not None:
            tenant = getattr(obj, self.tenant_attr, None)
            if tenant is None:
                raise EncryptedWriteError(
                    f"{type(obj).__name__}.{self.tenant_attr} must be set before "
                    "encrypted fields; the tenant coordinate cannot be derived"
                )
        return bound_record_id(str(pk), None if tenant is None else str(tenant))

    def revision(self, obj: Any) -> int | None:
        if self.revision_attr is None:
            return None
        value = getattr(obj, self.revision_attr, None)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise EncryptedWriteError(
                f"{type(obj).__name__}.{self.revision_attr} must be an integer "
                "revision bound into the record, or None"
            )
        return value


def _binding_for(obj: Any) -> _ModelBinding:
    binding = getattr(type(obj), "__fv_binding__", None)
    if binding is None:
        raise EncryptedWriteError(
            f"{type(obj).__name__} has no FloorVault binding; call "
            "SqlAlchemyEncryption.protect() on the mapped class first"
        )
    return binding


def _envelope_set_validator(model: type, column_key: str):
    """Reject any value staged on the ciphertext column that is not an envelope.

    This is the fail-closed core of the adapter: ``obj.ct = b"plaintext"``
    cannot queue plaintext for a flush, because the ``set`` listener raises
    before the attribute accepts it. ``None`` stays allowed - a nullable
    encrypted column is simply "unset" (reads return ``None``).
    """

    def validate(target, value, oldvalue, initiator):  # noqa: ARG001 - SA signature
        if value is None:
            return value
        try:
            return require_envelope(value, where=f"{model.__name__}.{column_key}")
        except TypeError as exc:
            raise EncryptedWriteError(
                f"{model.__name__}.{column_key} received a non-envelope value; "
                "write encrypted fields through their plaintext attribute "
                "(the EncryptedField descriptor) so coordinates can be bound"
            ) from exc

    return validate


def _flush_guard(model: type, ct_columns: frozenset[str]):
    """Verify, at INSERT/UPDATE emission, that ciphertext columns hold envelopes.

    The attribute validator already fails bad sets; this second barrier
    covers any path that staged a value without firing it (instrumentation
    edge cases, attribute-event suppression APIs). It checks structure, not
    provenance - an envelope from any source passes - which is sufficient:
    the guard's job is proving no *plaintext* reaches SQL.
    """

    def guard(mapper, connection, target):  # noqa: ARG001 - SA signature
        # The pending/dirty value lives in the instance dict; asking the
        # AttributeState for loaded_value returns the NO_VALUE sentinel for
        # never-populated attributes, which is not a value the flush emits.
        for key in ct_columns:
            value = target.__dict__.get(key)
            if value is None:
                continue
            try:
                require_envelope(value, where=f"{model.__name__}.{key}")
            except TypeError as exc:
                raise EncryptedWriteError(
                    f"{model.__name__}.{key} reached flush holding a non-envelope "
                    "value; refusing to write"
                ) from exc

    return guard


def _statement_ct_columns(statement, mapper_ct: frozenset[str]) -> set[str]:
    """Names of registered ciphertext columns a DML statement would write."""
    keys: set[str] = set()

    def collect(params) -> None:
        for key in params:
            if isinstance(key, str):
                name = key
            else:
                name = getattr(key, "key", None) or getattr(key, "name", None)
            if name in mapper_ct:
                keys.add(name)

    params = getattr(statement, "parameters", None)
    if isinstance(params, dict):
        collect(params)
    values = getattr(statement, "_values", None)
    if isinstance(values, dict):
        collect(values)
    return keys


class SqlAlchemyEncryption:
    """Bind FloorVault encryption to ORM-mapped classes, fail closed.

    ``protect()`` installs per-model encryption coordinates and write guards;
    ``session_factory()`` returns a ``sessionmaker`` whose sessions refuse
    bulk/ORM-statement writes to registered ciphertext columns.
    """

    def __init__(
        self,
        crypto: FloorVault,
        *,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
    ) -> None:
        if not isinstance(crypto, FloorVault):
            raise TypeError("crypto must be a FloorVault")
        self._crypto = crypto
        self._schema_id = schema_id
        self._schema_version = schema_version
        self._bindings: dict[type, _ModelBinding] = {}

    def protect(
        self,
        model: type,
        *,
        id_attr: str,
        fields: dict[str, EncryptedField | str],
        tenant_attr: str | None = None,
        revision_attr: str | None = None,
    ) -> type:
        """Declare encrypted fields on a mapped class and install its guards.

        ``fields`` maps a plaintext-facing attribute name to its mapped
        ciphertext column - either ``EncryptedField("ssn_ct")`` or, for the
        common text case, the bare column name ``"ssn_ct"``. The ciphertext
        column must already be a mapped ``LargeBinary``-compatible column on
        the model.

        Returns the class so it can be used as a decorator-free call at
        class-definition time. Repeat calls for the same class raise.
        """
        mapper = sa_inspect(model, raiseerr=True)
        if mapper is None or not hasattr(mapper, "column_attrs"):
            raise TypeError("protect() requires a mapped ORM class")
        if model in self._bindings or hasattr(model, "__fv_binding__"):
            raise EncryptedWriteError(
                f"{model.__name__} is already protected; a class gets one binding"
            )
        for required in (id_attr, tenant_attr, revision_attr):
            if required is not None and getattr(model, required, None) is None:
                raise EncryptedWriteError(f"{model.__name__}.{required} is not a mapped attribute")
        records = RecordBinding(
            self._crypto,
            mapper.local_table.name,
            schema_id=self._schema_id,
            schema_version=self._schema_version,
        )
        ct_columns: set[str] = set()
        for attr_name, spec in fields.items():
            field = spec if isinstance(spec, EncryptedField) else EncryptedField(spec)
            if field.column_attr in fields or field.column_attr == attr_name:
                raise EncryptedWriteError(
                    "ciphertext column name must differ from the plaintext field name"
                )
            ct_prop = mapper.column_attrs.get(field.column_attr)
            if ct_prop is None:
                raise EncryptedWriteError(
                    f"{model.__name__}.{field.column_attr} is not a mapped column; "
                    "declare the ciphertext Column on the model first"
                )
            ct_columns.add(field.column_attr)
            setattr(model, attr_name, field)
            if field.name is None:
                field.__set_name__(model, attr_name)
            validator = _envelope_set_validator(model, field.column_attr)
            event.listen(getattr(model, field.column_attr), "set", validator, retval=True)
        binding = _ModelBinding(
            records,
            id_attr=id_attr,
            tenant_attr=tenant_attr,
            revision_attr=revision_attr,
            ct_columns=frozenset(ct_columns),
        )
        model.__fv_binding__ = binding
        self._bindings[model] = binding
        guard = _flush_guard(model, binding.ct_columns)
        event.listen(model, "before_insert", guard)
        event.listen(model, "before_update", guard)
        return model

    def session_factory(self, **kwargs) -> sessionmaker:
        """A ``sessionmaker`` whose sessions enforce the bulk-write guard.

        The guard is attached to the sessionmaker class-level event so every
        session it produces refuses ORM-level writes that name a registered
        ciphertext column. Flushes of ordinary ``session.add`` objects do not
        pass through ``do_orm_execute``, so protected-field writes via the
        descriptor are unaffected.
        """
        factory = sessionmaker(**kwargs)
        event.listen(factory, "do_orm_execute", self._guard_orm_execute)
        return factory

    def _guard_orm_execute(self, state: ORMExecuteState) -> None:
        if not (state.is_insert or state.is_update):
            return
        mapper = state.bind_arguments.get("mapper") if state.bind_arguments else None
        model = getattr(mapper, "class_", None) if mapper is not None else None
        binding = self._bindings.get(model) if model is not None else None
        if binding is None:
            return
        named = _statement_ct_columns(state.statement, binding.ct_columns)
        params = state.parameters
        if params:
            for row in params if isinstance(params, list) else (params,):
                if isinstance(row, dict):
                    for key in row:
                        name = getattr(key, "key", None) or getattr(key, "name", None) or key
                        if name in binding.ct_columns:
                            named.add(name)
        if named:
            raise UnsupportedWriteError(
                f"bulk/ORM-statement writes cannot bind per-record encryption "
                f"coordinates; refused columns: {sorted(named)} on "
                f"{model.__name__}. Add instances via session.add() and set "
                "encrypted fields through their plaintext attributes"
            )

    def is_protected(self, model: type) -> bool:
        return model in self._bindings

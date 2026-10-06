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
   including executemany parameter sets, ``insert().from_select``,
   ``update().ordered_values`` and ``Query.update`` - that supply a value
   for a registered ciphertext column. ``Session`` objects come from
   ``session_factory()`` as ``_GuardedSession`` subclasses that refuse the
   legacy bulk APIs (``bulk_insert_mappings``/``bulk_update_mappings``/
   ``bulk_save_objects``), which never fire ``do_orm_execute``. Records must
   be written through ``session.add`` with ``EncryptedField`` assignment.

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
    from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker
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
        ct_names: frozenset[str],
    ) -> None:
        self.records = records
        self.id_attr = id_attr
        self.tenant_attr = tenant_attr
        self.revision_attr = revision_attr
        self.ct_columns = ct_columns
        #: Every name under which a registered column can appear in a
        #: statement: the mapped attribute key, ``Column.key`` and
        #: ``Column.name``. A column renamed at the DDL layer
        #: (``ssn_ct = Column("secret_cipher")``) reaches a statement under
        #: either spelling, so matching on the attribute name alone would
        #: let the physical name write through.
        self.ct_names = ct_names

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


def _key_names(key) -> frozenset[str]:
    """Every name a statement value-key may carry.

    SQLAlchemy keys ``_values``/``_multi_values`` by whichever token the
    caller used: a ``Column`` object (whose ``.key`` is the attribute name
    and ``.name`` the physical SQL name), an ``InstrumentedAttribute``, or
    the raw string when the token does not resolve to a mapped column.
    """
    if isinstance(key, str):
        return frozenset((key,))
    names: set[str] = set()
    for attr in ("key", "name"):
        candidate = getattr(key, attr, None)
        if isinstance(candidate, str):
            names.add(candidate)
    return frozenset(names)


def _statement_ct_columns(statement, binding: _ModelBinding) -> set[str]:
    """Registered ciphertext column names a DML statement would write.

    Values reach a statement through several distinct slots and every one
    must be scanned: ``_values`` (single-row ``values()``/parameters),
    ``_multi_values`` (executemany ``insert().values([dicts])``),
    ``_ordered_values`` (``update().ordered_values``) and ``_select_names``
    (``insert().from_select`` column names). A miss on any one of them is a
    plaintext write that bypasses the encryption boundary.
    """
    hit: set[str] = set()

    def collect(key_source) -> None:
        for key in key_source or ():
            matched = _key_names(key) & binding.ct_names
            if matched:
                hit.update(matched)

    values = getattr(statement, "_values", None)
    if isinstance(values, dict):
        collect(values)
    for group in getattr(statement, "_multi_values", None) or ():
        for row in group:
            collect(row)
    for pair in getattr(statement, "_ordered_values", None) or ():
        collect((pair[0],))
    collect(getattr(statement, "_select_names", None))
    params = getattr(statement, "parameters", None)
    if isinstance(params, dict):
        collect(params)
    return hit


class _GuardedSession(Session):
    """Session that refuses the legacy bulk APIs for protected classes.

    ``bulk_insert_mappings``, ``bulk_update_mappings`` and
    ``bulk_save_objects`` never fire ``do_orm_execute`` - they take an
    internal persistence path - so the statement guard cannot see them and
    mapper flush events do not run for them either. Refusing protected
    classes here is the only barrier on that path. Unprotected classes carry
    no FloorVault obligation and pass through.
    """

    _fv_bindings: dict[type, _ModelBinding] = {}

    def _bulk_guard(self, model_or_mapper, op: str) -> None:
        model = getattr(model_or_mapper, "class_", model_or_mapper)
        if isinstance(model, type) and model in self._fv_bindings:
            raise UnsupportedWriteError(
                f"Session.{op} bypasses the ORM event surface and cannot run "
                f"the envelope guards; refused for protected class "
                f"{model.__name__}. Add instances via session.add() and set "
                "encrypted fields through their plaintext attributes"
            )

    def bulk_insert_mappings(self, mapper, mappings, **kwargs):
        self._bulk_guard(mapper, "bulk_insert_mappings")
        return super().bulk_insert_mappings(mapper, mappings, **kwargs)

    def bulk_update_mappings(self, mapper, mappings, **kwargs):
        self._bulk_guard(mapper, "bulk_update_mappings")
        return super().bulk_update_mappings(mapper, mappings, **kwargs)

    def bulk_save_objects(self, objects, **kwargs):
        for obj in objects:
            self._bulk_guard(type(obj), "bulk_save_objects")
        return super().bulk_save_objects(objects, **kwargs)


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
            # ``fullname`` is schema-qualified: two schemas may carry the
            # same table name, and the AAD coordinate must name the real
            # relation or a ciphertext would replay across them.
            mapper.local_table.fullname,
            schema_id=self._schema_id,
            schema_version=self._schema_version,
        )
        ct_columns: set[str] = set()
        ct_names: set[str] = set()
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
            for column in ct_prop.columns:
                # A Python/SQL-side producer would place plaintext or
                # server-shaped values into the column outside the envelope
                # validator - defaults and server-generated values are
                # write paths the descriptor never sees.
                for opt in ("default", "server_default", "onupdate", "server_onupdate", "computed"):
                    if getattr(column, opt) is not None:
                        raise EncryptedWriteError(
                            f"{model.__name__}.{field.column_attr} declares a "
                            f"column-level {opt}; encrypted columns must take "
                            "values only through their EncryptedField so the "
                            "envelope invariant holds end to end"
                        )
                for alias in (column.key, column.name):
                    if isinstance(alias, str):
                        ct_names.add(alias)
            ct_columns.add(field.column_attr)
            ct_names.add(field.column_attr)
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
            ct_names=frozenset(ct_names),
        )
        model.__fv_binding__ = binding
        self._bindings[model] = binding
        guard = _flush_guard(model, binding.ct_columns)
        event.listen(model, "before_insert", guard)
        event.listen(model, "before_update", guard)
        return model

    def session_factory(self, **kwargs) -> sessionmaker:
        """A ``sessionmaker`` whose sessions enforce every write guard.

        Two mechanisms compose: a ``do_orm_execute`` listener refuses
        ORM-level ``insert``/``update`` statements naming a registered
        ciphertext column, and the sessions are ``_GuardedSession``
        subclasses that refuse the legacy bulk APIs (which never fire that
        event). Flushes of ordinary ``session.add`` objects pass through
        neither path, so protected-field writes via the descriptor are
        unaffected.
        """

        class _BoundSession(_GuardedSession):
            _fv_bindings = self._bindings

        factory = sessionmaker(class_=_BoundSession, **kwargs)
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
        named = _statement_ct_columns(state.statement, binding)
        params = state.parameters
        if params:
            # Executemany ORM statements carry their rows here, not on the
            # statement: session.execute(insert(T), [{...}, ...]).
            for row in params if isinstance(params, list) else (params,):
                if isinstance(row, dict):
                    for key in row:
                        named.update(_key_names(key) & binding.ct_names)
        if named:
            raise UnsupportedWriteError(
                f"bulk/ORM-statement writes cannot bind per-record encryption "
                f"coordinates; refused columns: {sorted(named)} on "
                f"{model.__name__}. Add instances via session.add() and set "
                "encrypted fields through their plaintext attributes"
            )

    def is_protected(self, model: type) -> bool:
        return model in self._bindings

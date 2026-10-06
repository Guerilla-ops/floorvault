"""The SQLAlchemy adapter must fail closed everywhere the ORM can write.

Ciphertext reaches the database only through the ``EncryptedField``
descriptor; the attribute validator and the ``do_orm_execute`` guard are the
two barriers proving plaintext and unbindable bulk writes cannot bypass it.
"""

from __future__ import annotations

import pytest

from floorvault import DecryptionVerificationError, FloorVault
from floorvault.sqlalchemy_adapter import (
    EncryptedField,
    EncryptedWriteError,
    SqlAlchemyEncryption,
    UnsupportedWriteError,
)

pytest.importorskip("sqlalchemy")
from sqlalchemy import (  # noqa: E402
    Column,
    Integer,
    LargeBinary,
    String,
    create_engine,
    insert,
    text,
    update,
)
from sqlalchemy.orm import DeclarativeBase  # noqa: E402


def _crypto() -> FloorVault:
    return FloorVault(b"\x42" * 32, app_instance_id="sa-adapter-test")


def _model(table_name="users", composite_pk=False):
    """A fresh mapped class per test: protect() mutates the class for good."""

    class TBase(DeclarativeBase):
        pass

    if composite_pk:

        class TUser(TBase):
            __tablename__ = table_name
            tenant = Column(String, primary_key=True)
            id = Column(String, primary_key=True)
            rev = Column(Integer, nullable=True)
            ssn_ct = Column(LargeBinary, nullable=True)
            note_ct = Column(LargeBinary, nullable=True)

    else:

        class TUser(TBase):
            __tablename__ = table_name
            id = Column(String, primary_key=True)
            tenant = Column(String, nullable=False)
            rev = Column(Integer, nullable=True)
            ssn_ct = Column(LargeBinary, nullable=True)
            note_ct = Column(LargeBinary, nullable=True)

    return TBase, TUser


def make_env(
    *, protect=True, fields=None, tenant_attr="tenant", revision_attr="rev", composite_pk=False
):
    TBase, TUser = _model(composite_pk=composite_pk)
    crypto = _crypto()
    vault = SqlAlchemyEncryption(crypto, schema_id="sa.test.v1", schema_version=1)
    if protect:
        vault.protect(
            TUser,
            id_attr="id",
            tenant_attr=tenant_attr,
            revision_attr=revision_attr,
            fields=fields or {"ssn": EncryptedField("ssn_ct"), "note": "note_ct"},
        )
    engine = create_engine("sqlite://")
    TBase.metadata.create_all(engine)
    Session = vault.session_factory(bind=engine)
    return vault, engine, Session, TUser


def test_plaintext_round_trip_and_ciphertext_at_rest():
    _, engine, Session, TUser = make_env()
    with Session() as session:
        user = TUser(id="u1", tenant="acme", rev=0)
        user.ssn = "123-45-6789"
        session.add(user)
        session.commit()

    row = engine.connect().execute(text("SELECT ssn_ct FROM users")).first()
    assert row is not None
    blob = row[0]
    assert isinstance(blob, bytes)
    assert blob[:4] == b"FLV2", "the stored value must be a FloorVault envelope"
    assert b"123-45-6789" not in blob

    with Session() as session:
        loaded = session.get(TUser, "u1")
        assert loaded.ssn == "123-45-6789"


def test_field_assignment_requires_identity_first():
    # No tenant binding: isolates the primary-key guard itself. With a tenant
    # attribute declared, a mutant that skips the pk check still raises on the
    # tenant guard and goes unnoticed (curated mutant SA-4).
    _, _, _, TUser = make_env(tenant_attr=None, revision_attr=None)
    user = TUser()
    with pytest.raises(EncryptedWriteError):
        user.ssn = "x"
    user.id = "u2"
    user.ssn = "x"  # bound once the identity exists

    # Tenant-declared binding: both coordinates must be set first.
    _, _, _, TTenant = make_env()
    tenant_user = TTenant(id="u3")
    with pytest.raises(EncryptedWriteError):
        tenant_user.ssn = "x"
    tenant_user.tenant = "acme"
    tenant_user.ssn = "x"


def test_direct_write_to_ciphertext_column_is_rejected_at_set_time():
    _, _, _, TUser = make_env()
    user = TUser(id="u1", tenant="acme")
    with pytest.raises(EncryptedWriteError):
        user.ssn_ct = b"this is plaintext, not an envelope"
    # A real envelope staged directly still passes the structural check - the
    # guard's invariant is "no plaintext", not "no ciphertext".
    crypto = _crypto()
    envelope = crypto.encrypt(
        "ok",
        table="users",
        record_id="u1",
        column="ssn_ct",
        schema_id="sa.test.v1",
        schema_version=1,
    )
    user.ssn_ct = envelope


def test_ciphertext_from_another_record_fails_to_decrypt():
    _, engine, Session, TUser = make_env()
    with Session() as session:
        a = TUser(id="a", tenant="acme")
        a.ssn = "alpha-secret"
        b = TUser(id="b", tenant="acme")
        b.ssn = "bravo-secret"
        session.add_all([a, b])
        session.commit()

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, ssn_ct FROM users ORDER BY id")).all()
        a_blob = rows[0][1]
        conn.execute(text("UPDATE users SET ssn_ct = :c WHERE id = 'b'"), {"c": a_blob})
        conn.commit()

    with Session() as session:
        b = session.get(TUser, "b")
        with pytest.raises(DecryptionVerificationError):
            _ = b.ssn


def test_tenant_binding_isolates_identical_records():
    # Real multi-tenant models key on (tenant, id); the same record id under
    # two tenants must produce different ciphertext and reject cross-splice.
    _, engine, Session, TUser = make_env(composite_pk=True)
    with Session() as session:
        a = TUser(id="same-id", tenant="tenant-a")
        a.ssn = "shared plaintext"
        b = TUser(id="same-id", tenant="tenant-b")
        b.ssn = "shared plaintext"
        session.add_all([a, b])
        session.commit()

    with engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT tenant, ssn_ct FROM users")).all())
    assert rows["tenant-a"] != rows["tenant-b"], "tenant must participate in AAD"

    # Splice A's ciphertext onto B's row: the tenant-bound coordinate rejects it.
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET ssn_ct = :c WHERE tenant = 'tenant-b'"),
            {"c": rows["tenant-a"]},
        )
        conn.commit()
    with Session() as session:
        b = session.query(TUser).filter_by(tenant="tenant-b").one()
        with pytest.raises(DecryptionVerificationError):
            _ = b.ssn


def test_revision_binds_and_detects_stale_replay():
    _, engine, Session, TUser = make_env()
    with Session() as session:
        user = TUser(id="u1", tenant="acme", rev=1)
        user.ssn = "rev-one"
        session.add(user)
        session.commit()

    with engine.connect() as conn:
        old = conn.execute(text("SELECT ssn_ct FROM users WHERE id='u1'")).scalar()

    with Session() as session:
        user = session.get(TUser, "u1")
        assert user.ssn == "rev-one"
        user.rev = 2
        user.ssn = "rev-two"
        session.commit()

    # Roll the ciphertext back to the rev-1 envelope while rev stays 2.
    with engine.connect() as conn:
        conn.execute(text("UPDATE users SET ssn_ct = :c WHERE id='u1'"), {"c": old})
        conn.commit()
    with Session() as session:
        user = session.get(TUser, "u1")
        with pytest.raises(DecryptionVerificationError):
            _ = user.ssn


def test_orm_insert_and_update_statements_to_ct_columns_are_rejected():
    _, _, Session, TUser = make_env()
    with Session() as session:
        with pytest.raises(UnsupportedWriteError):
            session.execute(insert(TUser).values(id="u1", tenant="t", ssn_ct=b"FLV2fake"))
        with pytest.raises(UnsupportedWriteError):
            session.execute(update(TUser).values(ssn_ct=b"FLV2fake"))


def test_bulk_parameter_sets_naming_ct_columns_are_rejected():
    _, _, Session, TUser = make_env()
    with Session() as session:
        with pytest.raises(UnsupportedWriteError):
            session.execute(
                insert(TUser),
                [{"id": "u1", "tenant": "t", "ssn_ct": b"FLV2fake"}],
            )
        # A bulk insert NOT touching encrypted columns is still fine.
        session.execute(insert(TUser), [{"id": "u9", "tenant": "t"}])
        session.commit()


def test_query_style_bulk_update_is_rejected():
    _, _, Session, TUser = make_env()
    with Session() as session:
        session.add(TUser(id="u1", tenant="t"))
        session.commit()
        with pytest.raises(UnsupportedWriteError):
            session.query(TUser).update({TUser.ssn_ct: b"FLV2fake"})


def test_binary_field_variant():
    _, engine, Session, TUser = make_env(fields={"blob": EncryptedField("ssn_ct", binary=True)})
    payload = b"\x00\xffbinary-not-utf8"
    with Session() as session:
        p = TUser(id="p1", tenant="t")
        p.blob = payload
        session.add(p)
        session.commit()
    with Session() as session:
        assert session.get(TUser, "p1").blob == payload


def test_protect_validates_the_mapping():
    _, _, _, TUser = make_env(protect=False)
    vault = SqlAlchemyEncryption(_crypto())
    with pytest.raises(EncryptedWriteError):
        vault.protect(TUser, id_attr="id", fields={"x": "missing_ct"})
    with pytest.raises(EncryptedWriteError):
        vault.protect(TUser, id_attr="nope", fields={"x": "ssn_ct"})
    vault.protect(TUser, id_attr="id", fields={"x": "ssn_ct"})
    with pytest.raises(EncryptedWriteError):
        vault.protect(TUser, id_attr="id", fields={"y": "ssn_ct"})


def test_flush_guard_catches_a_value_staged_without_the_set_event():
    """set_committed_value stages a write with no ``set`` event, so only the
    before_insert barrier stands between staged plaintext and the wire."""
    from sqlalchemy.orm import attributes

    _, _, Session, TUser = make_env()
    user = TUser(id="u1", tenant="acme")
    attributes.set_committed_value(user, "ssn_ct", b"staged plaintext")
    with Session() as session:
        session.add(user)
        with pytest.raises(EncryptedWriteError):
            session.flush()


def test_unprotected_model_encrypted_field_fails_closed():
    """A field on an unprotected class has no coordinates to bind; refuse."""
    _, _, _, TUser = make_env(protect=False)
    field = EncryptedField("ssn_ct")
    field.__set_name__(TUser, "ssn")
    TUser.ssn = field
    user = TUser(id="u1", tenant="acme")
    with pytest.raises(EncryptedWriteError):
        user.ssn = "x"


def test_records_layer_is_shared_not_duplicated():
    """records.py owns coordinate assembly; the ORM adapter must not reimplement it."""
    import floorvault.records as records
    import floorvault.sqlalchemy_adapter as adapter

    assert adapter.RecordBinding is records.RecordBinding
    assert adapter.bound_record_id is records.bound_record_id


def test_unprotected_model_writes_pass_through():
    """The guard must not interfere with tables it was never asked to protect."""
    _, engine, Session, _TUser = make_env()

    class OBase(DeclarativeBase):
        pass

    class Other(OBase):
        __tablename__ = "other"
        id = Column(String, primary_key=True)
        raw = Column(String, nullable=True)

    OBase.metadata.create_all(engine)
    with Session() as session:
        session.execute(insert(Other).values(id="o1", raw="plain text"))
        session.commit()

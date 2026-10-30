"""Opt-in sealing of vault listing metadata (``kind``/``has_otp``, SPEC §12.2).

Regression for the SECURITY.md §5 "schema metadata leakage" residual: in
``seal_listing_metadata`` mode the file shows no kinds or OTP flags, the fields
cannot be flipped or swapped undetected, and the mode cannot be downgraded by
anything stored in the database.
"""

from __future__ import annotations

import sqlite3

import pytest

from floorvault import FloorVault, KeyRing, rotate_vault_store
from floorvault.vaultkit import VaultError, VaultStore

KEY = b"\x07" * 32
LOGIN = {"identifier_type": "username", "identifier": "alice", "password": "pw"}
LOGIN_OTP = {**LOGIN, "otp_secret": "JBSWY3DPEHPK3PXP"}


def _crypto(key=KEY):
    return FloorVault(key, memory_mode="disabled")


def _sealed(path, **kwargs):
    return VaultStore(
        path, crypto=_crypto(kwargs.pop("key", KEY)), seal_listing_metadata=True, **kwargs
    )


def _raw(path):
    return sqlite3.connect(path / "vault.db")


@pytest.fixture
def vault(tmp_path):
    store = _sealed(tmp_path)
    store.add_item("login", "bank", LOGIN, origin="https://bank.example")
    store.add_item("login", "gh", LOGIN_OTP, origin="https://github.com")
    store.add_item("generic", "api", {"value": "x"})
    return tmp_path, store


def test_listing_round_trips(vault):
    _path, store = vault
    assert sorted((m.label, m.kind, m.has_otp) for m in store.list_items()) == [
        ("api", "generic", False),
        ("bank", "login", False),
        ("gh", "login", True),
    ]
    first = store.list_items()[0]
    assert store.get_meta(first.id) == first


def test_raw_file_reveals_no_kind_or_otp_flag(vault):
    path, _store = vault
    rows = (
        _raw(path)
        .execute(
            "SELECT typeof(kind), typeof(has_otp), length(kind), length(has_otp) FROM vault_items"
        )
        .fetchall()
    )
    assert {row[:2] for row in rows} == {("blob", "blob")}
    # Equal envelope lengths: the kind is not recoverable from its size.
    assert len({row[2] for row in rows}) == 1
    assert len({row[3] for row in rows}) == 1
    blob = (path / "vault.db").read_bytes()
    for word in (b"login", b"generic"):
        assert word not in blob


def test_sealed_kind_swapped_between_items_is_refused(vault):
    path, store = vault
    raw = _raw(path)
    ids = [row[0] for row in raw.execute("SELECT id FROM vault_items ORDER BY rowid")]
    generic_kind = raw.execute("SELECT kind FROM vault_items WHERE id = ?", (ids[2],)).fetchone()[0]
    raw.execute("UPDATE vault_items SET kind = ? WHERE id = ?", (generic_kind, ids[0]))
    raw.commit()
    with pytest.raises(Exception, match="(?i)verif|authentic"):
        store.get_meta(ids[0])


def test_sealed_has_otp_swapped_between_items_is_refused(vault):
    path, store = vault
    raw = _raw(path)
    ids = [row[0] for row in raw.execute("SELECT id FROM vault_items ORDER BY rowid")]
    otp_flag = raw.execute("SELECT has_otp FROM vault_items WHERE id = ?", (ids[1],)).fetchone()[0]
    raw.execute("UPDATE vault_items SET has_otp = ? WHERE id = ?", (otp_flag, ids[0]))
    raw.commit()
    with pytest.raises(Exception, match="(?i)verif|authentic"):
        store.list_items()


@pytest.mark.parametrize(
    "plant",
    ["UPDATE vault_items SET kind = 'generic'", "UPDATE vault_items SET has_otp = 1"],
)
def test_planted_cleartext_is_refused_on_open(vault, plant):
    """Nothing in the database can switch a sealed vault back to cleartext."""
    path, _store = vault
    raw = _raw(path)
    raw.execute(plant)
    raw.commit()
    with pytest.raises(VaultError, match="cleartext listing metadata"):
        _sealed(path)


def test_planted_cleartext_is_refused_on_read_too(vault):
    """Even past the open-time check (written after open), reads refuse it."""
    path, store = vault
    raw = _raw(path)
    raw.execute("UPDATE vault_items SET kind = 'generic', has_otp = 0")
    raw.commit()
    with pytest.raises(VaultError, match="cleartext"):
        store.list_items()


def test_sealed_vault_without_flag_is_refused_not_misread(vault):
    path, _store = vault
    with pytest.raises(VaultError, match="seal_listing_metadata=True"):
        VaultStore(path, crypto=_crypto())


def test_unpadded_sealed_kind_is_refused(vault):
    """A validly sealed but non-canonical (unpadded) kind is rejected."""
    path, store = vault
    item = store.list_items()[0]
    raw = _raw(path)
    forged = _crypto().encrypt("login", table="vault_items", record_id=item.id, column="meta:kind")
    raw.execute("UPDATE vault_items SET kind = ? WHERE id = ?", (forged, item.id))
    raw.commit()
    with pytest.raises(VaultError, match="unknown vault kind"):
        store.get_meta(item.id)


def test_sealed_has_otp_must_be_zero_or_one(vault):
    path, store = vault
    item = store.list_items()[0]
    raw = _raw(path)
    forged = _crypto().encrypt("yes", table="vault_items", record_id=item.id, column="meta:has_otp")
    raw.execute("UPDATE vault_items SET has_otp = ? WHERE id = ?", (forged, item.id))
    raw.commit()
    with pytest.raises(VaultError, match="0 or 1"):
        store.get_meta(item.id)


def test_migration_requires_the_explicit_flag(tmp_path):
    classic = VaultStore(tmp_path, crypto=_crypto())
    classic.add_item("login", "gh", LOGIN_OTP, origin="https://github.com")
    with pytest.raises(VaultError, match="migrate_listing_metadata=True"):
        _sealed(tmp_path)
    # The refused open changed nothing.
    assert _raw(tmp_path).execute("SELECT typeof(kind) FROM vault_items").fetchone() == ("text",)


def test_migration_seals_and_rederives_has_otp_from_the_payload(tmp_path):
    classic = VaultStore(tmp_path, crypto=_crypto())
    classic.add_item("login", "gh", LOGIN_OTP, origin="https://github.com")
    classic.add_item("login", "bank", LOGIN, origin="https://bank.example")
    raw = _raw(tmp_path)
    # A tampered cleartext flag must not survive into the sealed store.
    raw.execute("UPDATE vault_items SET has_otp = 1 - has_otp")
    raw.commit()

    migrated = _sealed(tmp_path, migrate_listing_metadata=True)

    assert sorted((m.label, m.has_otp) for m in migrated.list_items()) == [
        ("bank", False),
        ("gh", True),
    ]
    assert set(raw.execute("SELECT typeof(kind), typeof(has_otp) FROM vault_items")) == {
        ("blob", "blob")
    }
    # Afterwards the flag is not needed, and a plain sealed open works.
    assert len(_sealed(tmp_path).list_items()) == 2


def test_migration_refuses_an_unknown_cleartext_kind(tmp_path):
    classic = VaultStore(tmp_path, crypto=_crypto())
    classic.add_item("generic", "api", {"value": "x"})
    raw = _raw(tmp_path)
    raw.execute("UPDATE vault_items SET kind = 'admin'")
    raw.commit()
    with pytest.raises(VaultError, match="unknown vault kind"):
        _sealed(tmp_path, migrate_listing_metadata=True)


def test_migration_refuses_mixed_rows(vault):
    path, _store = vault
    raw = _raw(path)
    raw.execute("UPDATE vault_items SET has_otp = 0 WHERE rowid = 1")
    raw.commit()
    with pytest.raises(VaultError, match="mixed"):
        _sealed(path, migrate_listing_metadata=True)


def test_migrate_flag_requires_seal_flag(tmp_path):
    with pytest.raises(ValueError, match="requires seal_listing_metadata"):
        VaultStore(tmp_path, crypto=_crypto(), migrate_listing_metadata=True)


def test_rotation_reseals_listing_metadata(vault):
    path, store = vault
    new = _crypto(b"\x09" * 32)
    result = rotate_vault_store(
        store, source_ring=KeyRing({0: _crypto()}), new_vault=new, new_key_id=1
    )
    assert result["migrated"] == 3
    rotated = VaultStore(path, crypto=new, seal_listing_metadata=True)
    assert sorted((m.kind, m.has_otp) for m in rotated.list_items()) == [
        ("generic", False),
        ("login", False),
        ("login", True),
    ]
    # Every listing envelope moved: the old key reads none of them.
    with pytest.raises(Exception, match="(?i)verif|authentic|key"):
        _sealed(path).list_items()


def test_rotation_journal_covers_listing_columns(vault):
    _path, store = vault
    assert "kind" in store._SEALED_META_COLUMNS and "has_otp" in store._SEALED_META_COLUMNS
    # Cleartext-mode stores keep the original rotation unit set.
    assert "kind" not in VaultStore._SEALED_META_COLUMNS


def test_default_mode_is_unchanged(tmp_path):
    classic = VaultStore(tmp_path, crypto=_crypto())
    classic.add_item("login", "gh", LOGIN_OTP, origin="https://github.com")
    assert _raw(tmp_path).execute("SELECT kind, has_otp FROM vault_items").fetchone() == (
        "login",
        1,
    )
    assert [(m.kind, m.has_otp) for m in classic.list_items()] == [("login", True)]


def test_listing_migration_is_refused_while_a_rotation_is_in_progress(tmp_path):
    """The check runs after the first write, so a rotation cannot start in between (#98)."""
    plain = VaultStore(tmp_path, crypto=_crypto())
    item = plain.add_item("generic", "Item", {"value": "v"})
    plain.begin_rotation(1, target_vault=_crypto(b"\x08" * 32))
    with sqlite3.connect(tmp_path / "vault.db") as conn:
        before = conn.execute("SELECT kind, has_otp FROM vault_items").fetchall()
    with pytest.raises(VaultError, match="rotation is in progress; listing metadata was not"):
        _sealed(tmp_path, migrate_listing_metadata=True)
    with sqlite3.connect(tmp_path / "vault.db") as conn:
        assert conn.execute("SELECT kind, has_otp FROM vault_items").fetchall() == before
    assert before == [("generic", 0)]
    assert item.id

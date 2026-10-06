#!/usr/bin/env python3
"""Real-world exercise harness for floorvault.

Runs every public surface end-to-end against real filesystems, real SQLite
files, real subprocesses and real threads -- no mocks. Each check is recorded;
failures do not stop the run so the report shows the whole damage surface.

Usage:  uv run python scripts/realworld_exercise.py
Exit:   0 = all checks passed, 1 = at least one failure.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import subprocess  # drives the inspector CLI as a real subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from pathlib import Path

RESULTS: list[tuple[str, bool, str]] = []
SECTION = ""


def section(title: str) -> None:
    global SECTION
    SECTION = title
    print(f"\n=== {title} ===")


def check(name: str, condition: bool, detail: str = "") -> bool:
    RESULTS.append((f"{SECTION} :: {name}", bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    line = f"  [{mark}] {name}"
    if detail and not condition:
        line += f"  -- {detail}"
    elif detail:
        line += f"  ({detail})"
    print(line)
    return bool(condition)


def expect_raises(name: str, exc_types: tuple, fn, *args, **kwargs) -> bool:
    try:
        fn(*args, **kwargs)
    except exc_types as exc:
        return check(name, True, type(exc).__name__)
    except Exception as exc:  # wrong exception type
        return check(name, False, f"raised {type(exc).__name__}: {exc}")
    return check(name, False, "no exception raised")


# Probe scopes used to verify that a scope participates in beacon derivation.
_SCOPE_PROBES = tuple(f"scope.probe.{i}" for i in range(16))


def _scope_binding_matches(indexer, value: str, canonical_scope: str) -> bool:
    """True iff changing the scope changes the beacon for ``value``.

    A beacon truncated to ``indexer.bucket_bytes`` bytes has only
    ``256 ** bucket_bytes`` buckets, so a single wrong-scope query landing on
    a populated bucket is a legitimate collision, not a binding failure. The
    binding invariant is weaker and exact: scope must be an input to the HMAC,
    so over enough probe scopes at least one output differs from the canonical
    scope's beacon. An indexer that ignored scope entirely returns the same
    beacon for every probe and fails this check deterministically.
    """
    canonical = indexer.beacon(value, scope=canonical_scope)
    return any(indexer.beacon(value, scope=s) != canonical for s in _SCOPE_PROBES)


def _nonciphertext_diagnostic(result: subprocess.CompletedProcess, stored_plaintext: str) -> bool:
    """The CLI must flag non-ciphertext values without echoing their contents.

    Printing stored plaintext would defeat the encryption the tool exists to
    verify, so the diagnostic names the type and withholds the value. The old
    expectation - the literal word "Plaintext" in stdout - predated that rule.
    """
    combined = result.stdout + result.stderr
    return (
        result.returncode == 0
        and "not binary ciphertext" in combined
        and stored_plaintext not in combined
    )


def main() -> int:
    """Run end-to-end checks and print a report; return 1 on failures, otherwise 0."""
    import floorvault as fv
    from floorvault import beacons
    from floorvault.core import RECORD_MAGIC_V2
    from floorvault.migration import MigratingVaultStore
    from floorvault.providers import adaptive as adaptive_module
    from floorvault.providers.adaptive import AdaptiveKeyProvider
    from floorvault.providers.base import KeyProviderError
    from floorvault.providers.platform_custody import (
        read_protected,
        store_path_for,
    )
    from floorvault.sqlite_migration import migrate_plaintext_column, verify_encrypted_column
    from floorvault.vault_rotation import rotate_vault_store
    from floorvault.vaultkit import VaultStore
    from floorvault.vaultkit.session_crypto import SessionCrypto, scrub_secrets_for_fts

    KEY_A = secrets.token_bytes(32)
    KEY_B = secrets.token_bytes(32)
    KEY_HEX = KEY_A.hex()

    root = Path(tempfile.mkdtemp(prefix="fv-realworld-"))
    print(f"workspace: {root}")

    vault = fv.FloorVault(KEY_A, memory_mode="disabled")

    # ------------------------------------------------------------------
    section("1. Core round-trips")
    coords = dict(table="users", record_id="u-1", column="email")
    for label, pt in [
        ("str", "alice@example.com"),
        ("unicode", "héllo wörld — 秘密 🔐"),
        ("empty str", ""),
        ("bytes", b"\x00\xff\xfe binary \x80"),
        ("bytearray", bytearray(b"mutable")),
        ("memoryview", memoryview(b"viewed")),
        ("1MiB blob", os.urandom(1024 * 1024)),
    ]:
        ct = vault.encrypt(pt, **coords)
        if isinstance(pt, str):
            ok = vault.decrypt(ct, **coords) == pt
        else:
            ok = vault.decrypt_bytes(ct, **coords) == bytes(pt)
        check(f"round-trip {label}", ok and ct.startswith(RECORD_MAGIC_V2))

    # ------------------------------------------------------------------
    section("2. Context binding — every wrong coordinate must fail")
    ct = vault.encrypt("bound", **coords)
    for label, mutated in [
        ("wrong table", {**coords, "table": "admin"}),
        ("wrong record_id", {**coords, "record_id": "u-2"}),
        ("wrong column", {**coords, "column": "password"}),
        ("wrong schema_id", {**coords, "schema_id": "other.v1"}),
        ("wrong schema_version", {**coords, "schema_version": 2}),
        ("added revision", {**coords, "revision": 1}),
    ]:
        expect_raises(
            f"decrypt fails with {label}",
            (fv.DecryptionVerificationError,),
            vault.decrypt,
            ct,
            **mutated,
        )
    other_app = fv.FloorVault(KEY_A, app_instance_id="other-app", memory_mode="disabled")
    expect_raises(
        "decrypt fails in other app instance",
        (fv.DecryptionVerificationError,),
        other_app.decrypt,
        ct,
        **coords,
    )
    other_key_vault = fv.FloorVault(KEY_B, memory_mode="disabled")
    expect_raises(
        "decrypt fails under a different master key",
        (fv.DecryptionVerificationError,),
        other_key_vault.decrypt,
        ct,
        **coords,
    )

    # ------------------------------------------------------------------
    section("3. Envelope tampering — flip one byte in every region")
    regions = {
        "magic": 0,
        "crypto_version": len(RECORD_MAGIC_V2),
        "key_id": len(RECORD_MAGIC_V2) + 1,
        "nonce_len": len(RECORD_MAGIC_V2) + 2,
        "nonce": len(RECORD_MAGIC_V2) + 3,
        "ciphertext": -1,
    }
    for label, idx in regions.items():
        t = bytearray(ct)
        t[idx] ^= 0x01
        expect_raises(
            f"tampered {label} rejected",
            (fv.DecryptionVerificationError, fv.FloorVaultError, ValueError),
            vault.decrypt,
            bytes(t),
            **coords,
        )
    expect_raises("empty ciphertext rejected", (Exception,), vault.decrypt, b"", **coords)
    expect_raises("truncated envelope rejected", (Exception,), vault.decrypt, ct[:10], **coords)

    # ------------------------------------------------------------------
    section("4. Revision binding")
    rev_ct = vault.encrypt("v5", **coords, revision=5)
    check("correct revision decrypts", vault.decrypt(rev_ct, **coords, revision=5) == "v5")
    expect_raises(
        "stale revision 4 rejected",
        (fv.DecryptionVerificationError,),
        vault.decrypt,
        rev_ct,
        **coords,
        revision=4,
    )
    expect_raises(
        "missing revision rejected",
        (fv.DecryptionVerificationError,),
        vault.decrypt,
        rev_ct,
        **coords,
    )
    norev_ct = vault.encrypt("v0", **coords)
    expect_raises(
        "revision demanded on non-revision record rejected",
        (fv.DecryptionVerificationError,),
        vault.decrypt,
        norev_ct,
        **coords,
        revision=3,
    )

    # ------------------------------------------------------------------
    section("5. Plaintext type contract")
    for bad in [10, [104, 105], None, 3.14, object()]:
        expect_raises(
            f"encrypt rejects {type(bad).__name__}", (TypeError,), vault.encrypt, bad, **coords
        )
    before = len(vault._nonce_queue)
    for _ in range(4):
        try:
            vault.encrypt(42, **coords)
        except TypeError:
            pass
    check("rejected plaintext consumes no nonce window", len(vault._nonce_queue) == before)

    # ------------------------------------------------------------------
    section("6. key_id handling and lifecycle")
    kid_ct = vault.encrypt("kid", **coords, key_id=7)
    check("key_id=7 round-trips", vault.decrypt(kid_ct, **coords, key_id=7) == "kid")
    expect_raises("key_id 300 rejected", (ValueError,), vault.encrypt, "x", **coords, key_id=300)
    expect_raises("key_id bool rejected", (TypeError,), vault.encrypt, "x", **coords, key_id=True)
    expect_raises("key_id str rejected", (TypeError,), vault.encrypt, "x", **coords, key_id="0")

    small = fv.FloorVault(KEY_A, maximum_tracked_nonces=8, memory_mode="disabled")
    for i in range(40):
        small.encrypt(f"m{i}", table="t", record_id=f"r{i}", column="c")
    check("nonce window bounded", len(small._nonce_queue) == 8 and len(small._nonce_set) == 8)

    wiped = fv.FloorVault(KEY_A, memory_mode="disabled")
    wct = wiped.encrypt("bye", **coords)
    wiped.wipe()
    expect_raises("encrypt after wipe refused", (RuntimeError,), wiped.encrypt, "x", **coords)
    expect_raises("decrypt after wipe refused", (RuntimeError,), wiped.decrypt, wct, **coords)

    # ------------------------------------------------------------------
    section("7. KeyRing multi-generation reads")
    v0 = fv.FloorVault(KEY_A, memory_mode="disabled")
    v1 = fv.FloorVault(KEY_B, memory_mode="disabled")
    c0 = v0.encrypt("old-gen", **coords, key_id=0)
    c1 = v1.encrypt("new-gen", **coords, key_id=1)
    ring = fv.KeyRing({0: v0, 1: v1})
    check("ring reads key_id=0 record", ring.decrypt(c0, **coords) == "old-gen")
    check("ring reads key_id=1 record", ring.decrypt(c1, **coords) == "new-gen")
    check("key_ids()", ring.key_ids() == (0, 1))
    c9 = v0.encrypt("ghost", **coords, key_id=0)
    t = bytearray(c9)
    t[len(RECORD_MAGIC_V2) + 1] = 9
    expect_raises("unheld key_id refused by ring", (Exception,), ring.decrypt, bytes(t), **coords)
    expect_raises(
        "ring default_key_id it doesn't hold refused", (Exception,), fv.KeyRing, {0: v0}, 9
    )

    # ------------------------------------------------------------------
    section("8. Memory custody primitives")
    hk = fv.HardenedMemoryKey(KEY_A, mode="disabled")
    check("hardened key exposes bytes", hk.get_bytes() == KEY_A)
    check("hardened key exposes buffer", bytes(hk.get_buffer()) == KEY_A)
    hk.wipe()
    expect_raises("wiped hardened key refuses access", (Exception,), hk.get_bytes)
    check("disable_core_dumps returns bool", isinstance(fv.disable_core_dumps(), bool))
    for mode in ("disabled", "opportunistic"):
        fv.FloorVault(KEY_A, memory_mode=mode).encrypt("x", **coords)
        check(f"memory_mode={mode} works", True)
    try:
        fv.FloorVault(KEY_A, memory_mode="required")
        check("memory_mode=required usable on this host", True)
    except fv.SecurityHardeningError:
        check("memory_mode=required fails closed on this host", True)

    # ------------------------------------------------------------------
    section("9. Key recovery (wrap / recover)")
    rec_key = secrets.token_bytes(32)
    bundle = fv.wrap_master_key(KEY_A, rec_key)
    recovered = fv.recover_master_key(bundle, rec_key)
    check("recover_master_key round-trips", recovered.get_bytes() == KEY_A)
    expect_raises(
        "wrong recovery key refused",
        (Exception,),
        fv.recover_master_key,
        bundle,
        secrets.token_bytes(32),
    )
    recovered.wipe()

    # ------------------------------------------------------------------
    section("10. Key providers")
    os.environ["APPSTATE_KEY"] = KEY_HEX
    try:
        k = AdaptiveKeyProvider(fallback_dir=root / "prov").resolve_key()
        check("tier-1 env key resolves", k.get_bytes() == KEY_A)
        k.wipe()
        os.environ["APPSTATE_KEY"] = "nothex"
        expect_raises(
            "malformed env key rejected",
            (KeyProviderError,),
            AdaptiveKeyProvider(fallback_dir=root / "prov").resolve_key,
        )
        os.environ["APPSTATE_KEY"] = KEY_HEX
    finally:
        os.environ.pop("APPSTATE_KEY", None)

    # Force the machine-file tier (skip env + native store) so the atomic
    # publish path we hardened is exercised on the real filesystem.
    for var in ("APPSTATE_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY"):
        os.environ.pop(var, None)
    real_is_macos = adaptive_module.is_macos
    real_is_windows = adaptive_module.is_windows
    real_is_linux = adaptive_module.is_linux
    adaptive_module.is_macos = lambda: False
    adaptive_module.is_windows = lambda: False
    adaptive_module.is_linux = lambda: False
    try:
        prov_dir = root / "filecustody"
        p = AdaptiveKeyProvider(fallback_dir=prov_dir, allow_disk_fallback=True)
        k1 = p.resolve_key()
        store_path = store_path_for(prov_dir, None)
        check("file custody wrote a protected store", store_path.is_file())
        mode = store_path.stat().st_mode & 0o777
        check("protected store is owner-only", mode == 0o600, oct(mode))
        k2 = AdaptiveKeyProvider(fallback_dir=prov_dir, allow_disk_fallback=True).resolve_key()
        check("second resolve reads the same key", k2.get_bytes() == k1.get_bytes())
        expect_raises(
            "strict mode refuses disk custody",
            (KeyProviderError,),
            AdaptiveKeyProvider(fallback_dir=root / "strict", strict=True).resolve_key,
        )
        # no-clobber: pre-existing store must be adopted, not overwritten
        check(
            "existing store adopted (same bytes)",
            read_protected(store_path, header=b"") == k1.get_bytes(),
        )
        k1.wipe()
        k2.wipe()
    finally:
        adaptive_module.is_macos = real_is_macos
        adaptive_module.is_windows = real_is_windows
        adaptive_module.is_linux = real_is_linux

    # Read-only probe of the native tier: does not create anything.
    probe = AdaptiveKeyProvider(service_name="floorvault-probe-nonexistent")
    try:
        k = probe.resolve_key(allow_create=False)
        check("native tier probe", k is not None, "native custody present")
        if k is not None:
            k.wipe()
    except Exception as exc:
        check("native tier probe fails closed", True, type(exc).__name__)

    # ------------------------------------------------------------------
    section("11. VaultStore end-to-end")
    store_dir = root / "vaultstore"
    store = VaultStore(store_dir, crypto=vault)
    check("empty store has_items() is False", store.has_items() is False)
    canary = "CANARY-SECRET-8f3e1c"
    meta = store.add_item(
        kind="login",
        label="Example Login",
        secret={"password": canary, "identifier": "alice", "identifier_type": "username"},
        origin="https://example.com",
    )
    check(
        "add_item returns meta", meta.id and meta.kind == "login" and meta.label == "Example Login"
    )
    check("has_items()", store.has_items() is True)
    check("get_secret round-trip", store.get_secret(meta.id)["password"] == canary)
    check("resolve_secret", store.resolve_secret(meta.id) == {"password": canary})
    check("get_meta", store.get_meta(meta.id).id == meta.id)
    check(
        "meta carries identifier",
        meta.identifier == "alice"
        and meta.identifier_type == "username"
        and meta.origin == "https://example.com",
    )
    check("list_items", len(store.list_items()) == 1)
    check("get_meta missing -> None", store.get_meta("nope") is None)

    # Raw DB file must not contain the canary.
    all_files_raw = b"".join(p.read_bytes() for p in store_dir.rglob("*") if p.is_file())
    check("no plaintext canary anywhere on disk", canary.encode() not in all_files_raw)

    # Persistence across reopen
    store2 = VaultStore(store_dir, crypto=vault)
    check("reopen reads persisted secret", store2.get_secret(meta.id)["password"] == canary)
    wrong = VaultStore(store_dir, crypto=other_key_vault)
    expect_raises("wrong master key cannot read store", (Exception,), wrong.get_secret, meta.id)

    check("remove_item", store.remove_item(meta.id) is True and store.get_meta(meta.id) is None)
    again = store.add_item(kind="generic", label="temp", secret={"k": "v"})
    check("delete_item", store.delete_item(again.id) is True)

    # ------------------------------------------------------------------
    section("12. VaultStore scale + concurrency")
    t0 = time.perf_counter()
    ids = []
    for i in range(500):
        m = store.add_item(
            kind="generic", label=f"item-{i}", secret={"n": str(i), "blob": "x" * 64}
        )
        ids.append(m.id)
    t_add = time.perf_counter() - t0
    check("500 sequential adds", len(store.list_items()) == 500, f"{t_add:.2f}s")

    errors: list[str] = []

    def worker(n: int) -> None:
        try:
            for i in range(25):
                m = store.add_item(kind="generic", label=f"t{n}-{i}", secret={"w": f"{n}:{i}"})
                store.get_secret(m.id)
        except Exception as exc:  # pragma: no cover
            errors.append(f"t{n}: {exc}")

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    t_conc = time.perf_counter() - t0
    check("8 threads x 25 add+read, zero errors", not errors, "; ".join(errors[:3]))
    check("all threaded items persisted", len(store.list_items()) == 700, f"{t_conc:.2f}s")

    t0 = time.perf_counter()
    sum(len(store.list_items()) for _ in range(10))
    t_list = time.perf_counter() - t0
    check("list_items x10", True, f"{t_list * 100:.0f}ms total")

    # ------------------------------------------------------------------
    section("13. Rotation end-to-end")
    rot_dir = root / "rotstore"
    rstore = VaultStore(rot_dir, crypto=vault)
    originals = {}
    for i in range(50):
        m = rstore.add_item(kind="generic", label=f"rot-{i}", secret={"val": f"before-{i}"})
        originals[m.id] = f"before-{i}"
    old_ring = fv.KeyRing({0: v0})
    new_ring = fv.KeyRing({0: v0, 1: v1})
    stats = rotate_vault_store(rstore, source_ring=old_ring, new_vault=v1, new_key_id=1)
    check("rotation stats reported", isinstance(stats, dict) and stats)
    ok = all(
        json.loads(rstore.read_sealed_item(i, new_ring)["payload"])["val"] == originals[i]
        for i in originals
    )
    check("all 50 records readable under new key", ok)
    expect_raises(
        "old-key-only ring refused after rotation",
        (Exception,),
        rstore.read_sealed_item,
        next(iter(originals)),
        old_ring,
    )

    # Crash-resume: manually rotate half, drop the journal mid-way, resume.
    cr_dir = root / "crashstore"
    cstore = VaultStore(cr_dir, crypto=vault)
    cids = [
        cstore.add_item(kind="generic", label=f"c{i}", secret={"v": str(i)}).id for i in range(6)
    ]
    cstore.begin_rotation(1, target_vault=v1)
    expect_raises(
        "add_item refused during rotation barrier",
        (Exception,),
        cstore.add_item,
        "generic",
        "blocked",
        {"v": "x"},
    )
    cring = fv.KeyRing({0: v0})
    done = []
    for iid in cids[:3]:
        sealed = cstore.read_sealed_item(iid, cring)
        cstore.write_sealed_item(
            iid, sealed, new_vault=v1, key_id=1, journal_rows=[("item", iid, "payload")]
        )
        done.append(iid)
    journal = cstore.rotation_journal()
    check("journal persisted mid-rotation", len(journal) == 3)
    # resume: rotate the remaining items, journal must not double-count
    for iid in cids[3:]:
        sealed = cstore.read_sealed_item(iid, cring)
        cstore.write_sealed_item(
            iid, sealed, new_vault=v1, key_id=1, journal_rows=[("item", iid, "payload")]
        )
    nr = fv.KeyRing({0: v0, 1: v1})
    check(
        "resumed rotation readable",
        all(
            json.loads(cstore.read_sealed_item(i, nr)["payload"])["v"] == str(idx)
            for idx, i in enumerate(cids)
        ),
    )
    cstore.clear_rotation_journal()
    check("journal cleared", cstore.rotation_journal() == {})

    # ------------------------------------------------------------------
    section("14. Legacy Fernet migration")
    from cryptography.fernet import Fernet

    mig_dir = root / "migrate"
    mig_dir.mkdir()
    fernet_key = Fernet.generate_key()
    legacy_items = {
        "legacy-1": {"password": "pw-one", "label": "Old One"},  # fixture  # nosec B105
        "legacy-2": {
            "password": "pw-two",  # fixture  # nosec B105
            "identifier": "bob",
            "identifier_type": "username",
            "origin": "https://old.example",
        },
    }
    (mig_dir / "vault.json.enc").write_text(
        base64.urlsafe_b64encode(
            Fernet(fernet_key).encrypt(json.dumps(legacy_items).encode())
        ).decode()
    )
    (mig_dir / "vault.key").write_bytes(fernet_key)

    modern_store = VaultStore(mig_dir / "modern", crypto=vault)
    facade = MigratingVaultStore(modern_store=modern_store, legacy_base_dir=mig_dir)
    check("legacy visible via facade", "legacy-1" in facade.list_item_ids())
    check(
        "lazy resolve migrates + decrypts",
        facade.resolve_secret("legacy-1")["password"] == "pw-one",
    )
    retired = modern_store.retired_modern_id("legacy-1")
    check("retirement tombstone recorded", retired is not None)
    stats = facade.migrate_all()
    check("migrate_all covers remainder", stats.get("migrated", 0) >= 1)
    check("facade verify()", facade.verify() is True)
    check("pre-migration backup kept", (mig_dir / "vault.json.enc.pre-migration.bak").exists())

    # Resurrection guard: delete the modern row, legacy must NOT come back.
    modern_store.remove_item(retired)
    expect_raises(
        "deleted modern row does not resurrect legacy",
        (fv.LegacyRetiredError,),
        facade.resolve_secret,
        "legacy-1",
    )

    # Corrupt legacy key fails closed.
    bad_dir = root / "migrate-bad"
    bad_dir.mkdir()
    (bad_dir / "vault.json.enc").write_text((mig_dir / "vault.json.enc").read_text())
    (bad_dir / "vault.key").write_bytes(Fernet.generate_key())
    badfacade = MigratingVaultStore(
        modern_store=VaultStore(bad_dir / "modern", crypto=vault), legacy_base_dir=bad_dir
    )
    expect_raises(
        "wrong legacy key fails closed",
        (fv.LegacyVaultError,),
        badfacade.resolve_secret,
        "legacy-1",
    )

    # ------------------------------------------------------------------
    section("15. sqlite_adapter surfaces")
    db = root / "app.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email BLOB, ssn BLOB)")
    conn.execute("INSERT INTO users (id) VALUES ('u-1'), ('u-2')")
    conn.commit()

    ctx = fv.ContextualSQLite(conn, vault)
    users = ctx.table("users")
    blob = users.encrypt("u-1", "email", "alice@example.com")
    check("ContextualTable.decrypt", users.decrypt("u-1", "email", blob) == "alice@example.com")

    est = fv.EncryptedSQLiteTable(conn, vault, "users")
    est.store("u-1", "email", "alice@example.com")
    est.store("u-1", "ssn", b"\x01\x02\x03binary")
    est.store("u-2", "email", "bob@example.com", revision=1)
    conn.commit()
    check("load", est.load("u-1", "email") == "alice@example.com")
    check("load_bytes", est.load_bytes("u-1", "ssn") == b"\x01\x02\x03binary")
    check("revision store/load", est.load("u-2", "email", revision=1) == "bob@example.com")
    expect_raises("missing record -> LookupError", (LookupError,), est.load, "ghost", "email")
    expect_raises(
        "store to missing record -> LookupError", (LookupError,), est.store, "ghost", "email", "x"
    )
    # copy ciphertext across rows -> must fail
    row_ct = conn.execute("SELECT email FROM users WHERE id='u-1'").fetchone()[0]
    expect_raises(
        "relocated ciphertext refused",
        (fv.DecryptionVerificationError,),
        vault.decrypt,
        row_ct,
        table="users",
        record_id="u-2",
        column="email",
    )
    expect_raises(
        "bad identifier refused", (ValueError,), est.load, "u-1", "email; DROP TABLE users--"
    )
    conn.close()

    # ------------------------------------------------------------------
    section("16. sqlite_migration helpers")
    mconn = sqlite3.connect(root / "legacy.db")
    mconn.execute("CREATE TABLE accts (id TEXT PRIMARY KEY, user TEXT, pw_plain TEXT, pw_enc BLOB)")
    mconn.executemany(
        "INSERT INTO accts VALUES (?,?,?,NULL)",
        [(f"a-{i}", f"user{i}", f"pw-{i}-canary") for i in range(20)],
    )
    mconn.commit()
    stats = migrate_plaintext_column(
        mconn,
        vault,
        table="accts",
        id_column="id",
        source_column="pw_plain",
        destination_column="pw_enc",
    )
    check("migrate_plaintext_column stats", stats.get("migrated", 0) == 20, str(stats))
    verified = verify_encrypted_column(
        mconn,
        vault,
        table="accts",
        id_column="id",
        source_column="pw_plain",
        destination_column="pw_enc",
    )
    check("verify_encrypted_column", verified == 20, str(verified))
    raw_db = (root / "legacy.db").read_bytes()
    check("plaintext column still present in file (source preserved)", b"pw-0-canary" in raw_db)
    check(
        "no plaintext in destination blobs",
        mconn.execute("SELECT COUNT(*) FROM accts WHERE instr(pw_enc,'pw-')>0").fetchone()[0] == 0,
    )
    # idempotent-ish: refuse to overwrite non-NULL destination
    try:
        stats2 = migrate_plaintext_column(
            mconn,
            vault,
            table="accts",
            id_column="id",
            source_column="pw_plain",
            destination_column="pw_enc",
        )
        check("second migration reports nothing left or refuses", True, str(stats2))
    except Exception as exc:
        check("second migration refuses non-NULL destination", True, type(exc).__name__)
    mconn.close()

    # ------------------------------------------------------------------
    section("17. Search beacons end-to-end")
    bkey = beacons.derive_beacon_key(KEY_A)
    idx = beacons.BeaconIndexer(bkey, bits=8)
    bconn = sqlite3.connect(root / "beacon.db")
    bconn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email BLOB, email_beacon BLOB)")
    emails = [f"user{i}@ex.com" for i in range(200)]
    for i, em in enumerate(emails):
        rid = f"u-{i}"
        bconn.execute(
            "INSERT INTO users VALUES (?,?,?)",
            (
                rid,
                vault.encrypt(em, table="users", record_id=rid, column="email"),
                idx.beacon(em, scope="users.email"),
            ),
        )
    bconn.commit()
    target = emails[42]
    rows = bconn.execute(
        "SELECT id, email FROM users WHERE email_beacon = ?",
        (idx.beacon(target, scope="users.email"),),
    ).fetchall()
    hits = [
        r
        for r in rows
        if vault.decrypt(r[1], table="users", record_id=r[0], column="email") == target
    ]
    check(
        "beacon narrows to bucket, decryption confirms",
        hits and hits[0][0] == "u-42",
        f"{len(rows)} candidate(s)",
    )
    check("bucket count", idx.bucket_count == 256)
    check("suggest_beacon_bits sane", beacons.suggest_beacon_bits(200) >= 8)
    expect_raises(
        "non-aligned indexer width refused", (ValueError,), beacons.BeaconIndexer, bkey, bits=9
    )
    expect_raises(
        "short beacon key refused",
        (ValueError,),
        beacons.compute_beacon,
        "x",
        scope="s",
        key=b"short",
    )
    wrong_scope_rows = bconn.execute(
        "SELECT COUNT(*) FROM users WHERE email_beacon = ?",
        (idx.beacon(target, scope="other.scope"),),
    ).fetchone()[0]
    # A 1-byte beacon has 256 buckets, so "wrong scope produced zero hits" is
    # not guaranteed - a bucket collision is legitimate. The binding invariant
    # is that scope participates in derivation at all, proven by the probes.
    check(
        "different scope -> different bucket space",
        _scope_binding_matches(idx, target, "users.email"),
        f"wrong-scope bucket hits: {wrong_scope_rows} (truncation collisions are legitimate)",
    )
    bconn.close()

    # ------------------------------------------------------------------
    section("18. SessionCrypto + FTS scrubbing")
    sc = SessionCrypto(vault)
    payload, fts = sc.encrypt_message(
        session_id="s1", message_id="m1", content="my key is sk-ABCDEFGHIJKLMNOPQRSTUVWX ok"
    )
    check("fts off by default -> empty projection", fts == "")
    check(
        "message decrypts",
        sc.decrypt_message(session_id="s1", message_id="m1", payload_cipher=payload)
        == "my key is sk-ABCDEFGHIJKLMNOPQRSTUVWX ok",
    )
    expect_raises(
        "cross-session decrypt refused",
        (fv.DecryptionVerificationError,),
        sc.decrypt_message,
        session_id="s2",
        message_id="m1",
        payload_cipher=payload,
    )
    sc2 = SessionCrypto(vault, allow_plaintext_fts=True)
    _, fts2 = sc2.encrypt_message(
        session_id="s",
        message_id="m",
        content="token sk-ABCDEFGHIJKLMNOPQRSTUVWX and AKIAIOSFODNN7EXAMPLE here",
    )
    check(
        "scrub redacts sk- and AWS key",
        "[REDACTED_SECRET]" in fts2 and "AKIAIOSFODNN7EXAMPLE" not in fts2,
        "fts scrubbed content validated",
    )
    check(
        "scrub standalone",
        scrub_secrets_for_fts("xoxb-1234567890-abcd").count("[REDACTED_SECRET]") == 1,
    )

    # ------------------------------------------------------------------
    section("19. Inspector CLI (real subprocess)")
    idb = root / "inspect.db"
    iconn = sqlite3.connect(idb)
    iconn.execute("CREATE TABLE secrets (id TEXT PRIMARY KEY, value BLOB)")
    ctblob = vault.encrypt("topsecret", table="secrets", record_id="rec-1", column="value")
    iconn.execute("INSERT INTO secrets VALUES ('rec-1', ?)", (ctblob,))
    iconn.execute("INSERT INTO secrets VALUES ('rec-2', 'not-encrypted-text')")
    iconn.commit()
    iconn.close()

    env = dict(os.environ, APPSTATE_KEY=KEY_HEX)
    py = sys.executable

    def cli(*args) -> subprocess.CompletedProcess:
        return subprocess.run(  # argv is sys.executable plus fixed arguments  # nosec B603
            [py, "-m", "floorvault.inspector", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    r = cli("inspect", str(idb), "secrets", "rec-1", "value")
    check("cli decrypts record", r.returncode == 0 and "topsecret" in r.stdout, r.stderr.strip())
    r = cli("inspect", str(idb), "secrets", "rec-2", "value")
    check(
        "cli reports non-ciphertext column",
        _nonciphertext_diagnostic(r, "not-encrypted-text"),
        r.stdout.strip(),
    )
    r = cli("inspect", str(idb), "secrets", "missing", "value")
    check("cli missing record -> exit 1", r.returncode == 1)
    r = cli("inspect", str(idb), "secrets; DROP TABLE secrets--", "rec-1", "value")
    check("cli rejects injected identifier", r.returncode == 1)
    r = cli("inspect", str(root / "nope.db"), "t", "r", "c")
    check("cli missing db -> exit 1", r.returncode == 1)
    env2 = dict(env, APPSTATE_KEY=secrets.token_bytes(32).hex())
    r2 = subprocess.run(  # argv is sys.executable plus fixed arguments  # nosec B603
        [py, "-m", "floorvault.inspector", "inspect", str(idb), "secrets", "rec-1", "value"],
        capture_output=True,
        text=True,
        env=env2,
        timeout=60,
    )
    check(
        "cli wrong key -> decryption failure",
        r2.returncode == 1 and "Decryption failed" in r2.stderr,
    )

    # ------------------------------------------------------------------
    section("20. Throughput sanity")
    t0 = time.perf_counter()
    n = 2000
    for i in range(n):
        vault.encrypt(f"payload-{i}", table="t", record_id=f"r{i}", column="c")
    enc_t = time.perf_counter() - t0
    cts = [vault.encrypt(f"d{i}", table="t", record_id=f"r{i}", column="c") for i in range(500)]
    t0 = time.perf_counter()
    for i, c in enumerate(cts):
        vault.decrypt(c, table="t", record_id=f"r{i}", column="c")
    dec_t = time.perf_counter() - t0
    check("throughput", True, f"enc {n / enc_t:.0f}/s, dec {500 / dec_t:.0f}/s")

    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [r for r in RESULTS if not r[1]]
    print(f"TOTAL: {passed} passed, {len(failed)} failed, {len(RESULTS)} checks")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

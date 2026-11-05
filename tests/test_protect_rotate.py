"""``floorvault secrets protect --rotate`` (#84, part 4): move a store whose key is held anywhere
but a raw key file under a passphrase, by re-encrypting it under a new key.

Real stores, a scripted passphrase prompt, cheap scrypt. Each step an interrupted run could
stop at is stopped at on purpose, and the same command must finish it.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
from unittest import mock

import pytest

from floorvault import FloorVault, passphrase_custody, systemd_creds
from floorvault import custody_rotation as rotation
from floorvault.agent_cli import APP_CONTEXT
from floorvault.inspector import main
from floorvault.memory import HardenedMemoryKey
from floorvault.providers import passphrase_store
from floorvault.vaultkit.vault import VaultStore

PHRASE = "correct horse battery staple"
OTHER = "a different passphrase entirely"
VALUE = "fixture-secret-value"
OLD_KEY = bytes.fromhex("5a" * 32)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)


class Prompt:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def __call__(self, prompt="Passphrase: ", *, confirm=False):
        self.asked.append((prompt, confirm))
        if not self.answers:
            raise AssertionError("asked for a passphrase that the test did not script")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture()
def vault(tmp_path):
    return tmp_path / "vault"


@pytest.fixture()
def env(tmp_path):
    return {
        "HOME": str(tmp_path / "home"),
        "PATH": os.environ.get("PATH", ""),
        "FLOOR_VAULT_STATE_DIR": str(tmp_path / "state"),
    }


@pytest.fixture()
def keyfile(tmp_path):
    path = tmp_path / "old.key"
    path.write_text(OLD_KEY.hex(), encoding="utf-8")
    path.chmod(0o600)
    return path


def cli(args, env, prompt=None, *, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", *args]),
        mock.patch.object(sys, "stdin", io.StringIO(stdin)),
        mock.patch.object(passphrase_custody, "prompt_passphrase", prompt or Prompt()),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


BOUND = [
    sys.executable,
    "-c",
    "import os, sys; sys.exit(0 if os.environ['X'] == %r else 3)" % VALUE,
]


def make_store(vault, env, keyfile, *, items=2, bound="tok"):
    """A store whose key is the --key-file's, holding ``items`` items; ``bound`` is command-bound."""
    for n in range(items):
        item = bound if n == 0 else f"extra{n}"
        code, _out, err = cli(
            ["secrets", "add", "Token", "--id", item, "--stdin", "--vault", str(vault)]
            + ["--key-file", str(keyfile)],
            env,
            stdin=f"value={VALUE}\n",
        )
        assert code == 0, err
    code, _out, err = cli(
        ["secrets", "allow", bound, "--vault", str(vault), "--key-file", str(keyfile), "--"]
        + BOUND,
        env,
    )
    assert code == 0, err


def rotate(vault, env, keyfile, *answers, extra=()):
    args = ["secrets", "protect", "--rotate", "--vault", str(vault)]
    if keyfile is not None:
        args += ["--key-file", str(keyfile)]
    prompt = Prompt(*answers)
    return (*cli([*args, *extra], env, prompt), prompt)


def new_store(vault, phrase=PHRASE):
    key = passphrase_custody.read_key(vault, phrase)
    assert key is not None
    return VaultStore(vault, crypto=FloorVault(HardenedMemoryKey(key), app_instance_id=APP_CONTEXT))


def run_bound(vault, env, *answers):
    """``floorvault run`` of the bound command, with the launch captured (a real one execs).

    Returns ``(exit code, what the child would have received as X)``.
    """
    from floorvault import agent_cli

    seen = {}

    def launch(path, argv, child_env):
        seen["X"] = child_env.get("X")
        return 0

    with mock.patch.object(agent_cli, "_launch", launch):
        code, out, err = cli(
            ["run", "--vault", str(vault), "-e", "X=fv:tok", "--"] + BOUND,
            env,
            Prompt(*answers),
        )
    return code, seen.get("X"), out + err


# ---------------------------------------------------------------- the whole path


def test_a_key_file_store_moves_under_a_passphrase_and_everything_still_works(vault, env, keyfile):
    make_store(vault, env, keyfile)
    code, out, err, prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    assert prompt.asked == [("New passphrase: ", True)]
    # Wrapped key in place, nothing staged, old key file untouched.
    assert (vault / "master.key.fvpw").is_file()
    assert not passphrase_custody.staged_present(vault)
    assert keyfile.read_text(encoding="utf-8") == OLD_KEY.hex()
    assert "2 item(s) re-encrypted" in out and "no longer opens this store" in err
    # Items, and the binding, are readable under the passphrase.
    store = new_store(vault)
    assert store.resolve_secret("tok") == {"value": VALUE}
    assert store.resolve_secret("extra1") == {"value": VALUE}
    assert store.get_allowed_commands("tok") == [BOUND]
    # The binding record was updated: the bound command still runs, the unbound one is refused.
    assert run_bound(vault, env, PHRASE)[:2] == (0, VALUE)
    # The old key opens nothing now.
    code, _out, err = cli(
        ["secrets", "list", "--vault", str(vault), "--key-file", str(keyfile)], env
    )
    assert code != 0
    assert VALUE not in out + err + PHRASE


def test_the_old_key_is_a_different_key_from_the_new_one(vault, env, keyfile):
    make_store(vault, env, keyfile)
    assert rotate(vault, env, keyfile, PHRASE)[0] == 0
    assert passphrase_custody.read_key(vault, PHRASE) != OLD_KEY


@posix_only
def test_the_wrapped_key_is_owner_only_and_the_directory_holds_nothing_stray(vault, env, keyfile):
    make_store(vault, env, keyfile)
    assert rotate(vault, env, keyfile, PHRASE)[0] == 0
    names = sorted(p.name for p in vault.iterdir() if not p.name.startswith("vault.db"))
    assert "master.key.fvpw" in names and "master.key.fvpw.staged" not in names
    assert "master.key" not in names
    assert oct(os.stat(vault / "master.key.fvpw").st_mode & 0o777) == "0o600"


def test_a_key_env_store_moves_too(vault, env, keyfile, monkeypatch):
    for n, item in enumerate(("tok", "extra1")):
        code, _out, err = cli(
            ["secrets", "add", "Token", "--id", item, "--stdin", "--vault", str(vault)]
            + ["--key-env", "OLDKEY"],
            {**env, "OLDKEY": OLD_KEY.hex()},
            stdin=f"value={VALUE}\n",
        )
        assert code == 0, err
    prompt = Prompt(PHRASE)
    code, _out, err = cli(
        ["secrets", "protect", "--rotate", "--vault", str(vault), "--key-env", "OLDKEY"],
        {**env, "OLDKEY": OLD_KEY.hex()},
        prompt,
    )
    assert code == 0, err
    assert new_store(vault).resolve_secret("tok") == {"value": VALUE}
    assert "$OLDKEY" in err


def test_a_systemd_creds_store_loses_its_credential(vault, env, monkeypatch):
    store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    credential = vault / "master.key.sdcred"
    credential.write_bytes(b"sealed")
    monkeypatch.setattr(
        systemd_creds, "read_key", lambda vault_dir, **kw: OLD_KEY if credential.exists() else None
    )
    code, out, err, _prompt = rotate(vault, env, None, PHRASE)
    assert code == 0, err
    assert not credential.exists() and "master.key.sdcred" in out
    assert "systemd-creds credential" in err
    assert new_store(vault).resolve_secret("tok") == {"value": VALUE}


# ------------------------------------------------------- refusals change nothing


def test_it_refuses_a_raw_key_file_store_and_names_plain_protect(vault, env, keyfile):
    make_store(vault, env, keyfile)
    (vault / "master.key").write_text(OLD_KEY.hex(), encoding="utf-8")
    code, _out, err, prompt = rotate(vault, env, keyfile)
    assert code == 2 and "without --rotate" in err and prompt.asked == []
    assert not passphrase_custody.staged_present(vault)


def test_it_refuses_a_store_that_is_already_protected(vault, env):
    code, _out, err = cli(
        ["secrets", "init", "--custody", "passphrase", "--vault", str(vault)], env, Prompt(PHRASE)
    )
    assert code == 0, err
    code, _out, err, _prompt = rotate(vault, env, None)
    assert code == 2 and "already passphrase-protected" in err


def test_it_refuses_two_key_sources(vault, env, keyfile):
    make_store(vault, env, keyfile)
    (vault / "master.key.sdcred").write_bytes(b"sealed")
    code, _out, err, prompt = rotate(vault, env, keyfile)
    assert code == 2 and "name one key source" in err and prompt.asked == []
    assert not passphrase_custody.staged_present(vault)


def test_it_refuses_a_binding_that_changed_behind_its_back_before_writing_anything(
    vault, env, keyfile
):
    make_store(vault, env, keyfile)
    # Someone who can write vault.db clears the binding; the record outside the store notices.
    key_store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    key_store.set_allowed_commands("tok", None)
    code, _out, err, prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "command binding changed" in err
    assert prompt.asked == [] and not passphrase_custody.staged_present(vault)
    assert not (vault / "master.key.fvpw").exists()


def test_it_refuses_a_key_generation_counter_that_is_full(vault, env, keyfile, monkeypatch):
    make_store(vault, env, keyfile)
    monkeypatch.setattr(rotation, "generation", lambda store: rotation.MAX_GENERATION)
    code, _out, err, prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "cannot be rotated again" in err
    assert prompt.asked == [] and not passphrase_custody.staged_present(vault)


def test_differing_passphrase_entries_change_nothing(vault, env, keyfile):
    make_store(vault, env, keyfile)
    code, _out, _err, _prompt = rotate(
        vault, env, keyfile, passphrase_custody.PassphraseCustodyError("the two passphrases differ")
    )
    assert code == 1
    assert not passphrase_custody.staged_present(vault)
    assert not (vault / "master.key.fvpw").exists()
    assert cli(["secrets", "list", "--vault", str(vault), "--key-file", str(keyfile)], env)[0] == 0


def test_protect_still_refuses_key_options_without_rotate(vault, env):
    code, _out, err = cli(["secrets", "protect", "--vault", str(vault), "--key-env", "K"], env)
    assert code == 2 and "without --rotate" in err
    code, _out, err = cli(["secrets", "protect", "--vault", str(vault), "--sealed-listing"], env)
    assert code == 2 and "without --rotate" in err


# ------------------------------------------- an interrupted run is finished by running it again


def fail_on_second_write(monkeypatch):
    original = VaultStore.write_sealed_item
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated interruption")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(VaultStore, "write_sealed_item", flaky)
    return original


def test_a_stop_in_the_middle_of_the_rotation_is_resumed(vault, env, keyfile, monkeypatch):
    make_store(vault, env, keyfile, items=3)
    original = fail_on_second_write(monkeypatch)
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "Run the same command again to resume" in err
    # Half rotated: the new key is staged (so it can be resumed), no wrapped key yet.
    assert passphrase_custody.staged_present(vault)
    assert not (vault / "master.key.fvpw").exists()
    monkeypatch.setattr(VaultStore, "write_sealed_item", original)
    code, out, err, prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    assert prompt.asked == [(f"Passphrase for the staged key beside {vault}: ", False)]
    assert "3 item(s) re-encrypted" in out
    assert not passphrase_custody.staged_present(vault)
    store = new_store(vault)
    for item in ("tok", "extra1", "extra2"):
        assert store.resolve_secret(item) == {"value": VALUE}
    assert run_bound(vault, env, PHRASE)[:2] == (0, VALUE)


def test_a_stop_after_the_rotation_needs_no_old_key_to_finish(vault, env, keyfile, monkeypatch):
    make_store(vault, env, keyfile)
    real = passphrase_custody.publish_staged_key

    def stop(*args, **kwargs):
        raise passphrase_custody.PassphraseCustodyError("simulated stop before publishing")

    monkeypatch.setattr(passphrase_custody, "publish_staged_key", stop)
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "simulated stop" in err
    assert passphrase_custody.staged_present(vault) and not (vault / "master.key.fvpw").exists()
    monkeypatch.setattr(passphrase_custody, "publish_staged_key", real)
    # The store is rotated; the new key alone opens it, so no key option is given or read.
    code, _out, err, _prompt = rotate(vault, env, None, PHRASE)
    assert code == 0, err
    assert (vault / "master.key.fvpw").is_file() and not passphrase_custody.staged_present(vault)
    assert new_store(vault).resolve_secret("tok") == {"value": VALUE}
    assert run_bound(vault, env, PHRASE)[:2] == (0, VALUE)


def test_a_stop_after_publishing_only_has_the_old_custody_left_to_remove(vault, env, monkeypatch):
    store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    credential = vault / "master.key.sdcred"
    credential.write_bytes(b"sealed")
    monkeypatch.setattr(
        systemd_creds, "read_key", lambda vault_dir, **kw: OLD_KEY if credential.exists() else None
    )
    real = passphrase_custody.remove_replaced_custody

    def stop(*args, **kwargs):
        raise passphrase_custody.PassphraseCustodyError("simulated stop before removing")

    monkeypatch.setattr(passphrase_custody, "remove_replaced_custody", stop)
    code, _out, err, _prompt = rotate(vault, env, None, PHRASE)
    assert code == 1 and credential.exists() and (vault / "master.key.fvpw").is_file()
    # Two custodies beside the store: everything else refuses it until this is finished.
    code, _out, err = cli(["secrets", "list", "--vault", str(vault)], env, Prompt(PHRASE))
    assert code != 0
    monkeypatch.setattr(passphrase_custody, "remove_replaced_custody", real)
    code, out, err, prompt = rotate(vault, env, None, PHRASE)
    assert code == 0, err
    assert prompt.asked == [(f"Passphrase for {vault}: ", False)]
    assert not credential.exists() and "master.key.sdcred" in out
    assert cli(["secrets", "list", "--vault", str(vault)], env, Prompt(PHRASE))[0] == 0


def test_the_old_custody_is_kept_when_the_wrapped_key_does_not_open_the_store(
    vault, env, monkeypatch
):
    from floorvault.providers.platform_custody import write_protected

    store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    credential = vault / "master.key.sdcred"
    credential.write_bytes(b"sealed")
    # A wrapped key that is some other key: removing the credential for it would lose the store.
    write_protected(
        passphrase_store.wrap(bytes.fromhex("77" * 32), PHRASE),
        vault / "master.key.fvpw",
        header=passphrase_store.MAGIC,
        expected_length=passphrase_store.PAYLOAD_BYTES,
    )
    code, _out, _err, _prompt = rotate(vault, env, None, PHRASE)
    assert code == 1
    assert credential.exists()


def test_a_new_key_staged_but_never_used_is_the_key_the_run_finishes_with(vault, env, keyfile):
    make_store(vault, env, keyfile)
    staged_key = bytes.fromhex("c3" * 32)
    passphrase_custody.stage_wrapped_key(vault, staged_key, PHRASE)
    code, _out, err, prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    assert prompt.asked == [(f"Passphrase for the staged key beside {vault}: ", False)]
    assert passphrase_custody.read_key(vault, PHRASE) == staged_key
    assert new_store(vault).resolve_secret("tok") == {"value": VALUE}


def test_a_wrong_passphrase_for_the_staged_key_changes_nothing(vault, env, keyfile, monkeypatch):
    make_store(vault, env, keyfile)
    fail_on_second_write(monkeypatch)
    assert rotate(vault, env, keyfile, PHRASE)[0] == 1
    monkeypatch.undo()
    code, _out, err, _prompt = rotate(vault, env, keyfile, OTHER)
    assert code == 1
    assert passphrase_custody.staged_present(vault)
    assert not (vault / "master.key.fvpw").exists()
    assert VALUE not in err


# ------------------------------------------------------------------ the custody helpers


def test_staging_creates_exclusively_and_never_beside_a_wrapped_key(vault):
    vault.mkdir()
    key = bytes.fromhex("11" * 32)
    path = passphrase_custody.stage_wrapped_key(vault, key, PHRASE)
    assert path == vault / "master.key.fvpw.staged"
    assert passphrase_custody.read_staged_key(vault, PHRASE) == key
    with pytest.raises(passphrase_custody.PassphraseCustodyError):
        passphrase_custody.stage_wrapped_key(vault, bytes.fromhex("22" * 32), PHRASE)
    assert passphrase_custody.read_staged_key(vault, PHRASE) == key  # untouched
    with pytest.raises(passphrase_custody.PassphraseCustodyError):
        passphrase_custody.read_staged_key(vault, OTHER)
    passphrase_custody.publish_staged_key(vault, PHRASE)
    assert passphrase_custody.read_key(vault, PHRASE) == key
    assert not passphrase_custody.staged_present(vault)
    other = vault.parent / "v2"
    other.mkdir()
    passphrase_custody.create_wrapped_key(other, PHRASE)
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="already exists"):
        passphrase_custody.stage_wrapped_key(other, key, PHRASE)


@posix_only
def test_publishing_twice_is_harmless_and_never_replaces_a_different_wrapped_key(vault):
    vault.mkdir()
    key = bytes.fromhex("33" * 32)
    passphrase_custody.stage_wrapped_key(vault, key, PHRASE)
    final = passphrase_custody.publish_staged_key(vault, PHRASE)
    before = final.read_bytes()
    # A stop between publishing and removing the staged file leaves both; same payload is fine.
    staged = vault / "master.key.fvpw.staged"
    staged.write_bytes(before)  # both files, as after a stop
    staged.chmod(0o600)
    passphrase_custody.publish_staged_key(vault, PHRASE)
    assert final.read_bytes() == before and not passphrase_custody.staged_present(vault)
    # A different staged key never replaces the wrapped one.
    other = passphrase_store.wrap(bytes.fromhex("44" * 32), PHRASE)
    staged.write_bytes(passphrase_store.MAGIC + other)
    staged.chmod(0o600)
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="different wrapped key"):
        passphrase_custody.publish_staged_key(vault, PHRASE)
    assert final.read_bytes() == before


def test_the_replaced_custody_is_removed_only_beside_a_wrapped_key_and_never_a_raw_key(vault):
    vault.mkdir()
    for name in ("master.key.sdcred", "master.key.ostier", "master.key"):
        (vault / name).write_bytes(b"x")
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="no wrapped key"):
        passphrase_custody.remove_replaced_custody(vault)
    assert (vault / "master.key.sdcred").exists()
    (vault / "master.key.fvpw").write_bytes(b"x")
    assert passphrase_custody.replaceable_custody_files(vault) == [
        "master.key.sdcred",
        "master.key.ostier",
    ]
    removed = passphrase_custody.remove_replaced_custody(vault)
    assert removed == ["master.key.sdcred", "master.key.ostier"]
    assert (vault / "master.key").exists()  # a raw key is not this function's to remove


def test_rotation_refuses_a_key_generation_counter_that_is_full(vault):
    store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    store._write_key_id = rotation.MAX_GENERATION
    with pytest.raises(rotation.CustodyRotationError, match="cannot be rotated again"):
        rotation.rotate_store(
            store,
            FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT),
            bytes.fromhex("55" * 32),
            app_context=APP_CONTEXT,
        )


# ------------------------------------------- review of #131: what must be authenticated, and when


def clear_binding_in_db(vault, item="tok"):
    """What someone who can write vault.db but has no key can do (RUN-9)."""
    import sqlite3

    with contextlib.closing(sqlite3.connect(vault / "vault.db")) as db:
        db.execute("UPDATE vault_items SET allowed_commands = NULL WHERE id = ?", (item,))
        db.commit()


def tombstone_only_store(vault):
    """A store with no items, only a retirement record sealed under the old key."""
    store = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    store.retire_legacy_id("legacy1", "modern1")
    return store


def test_a_staged_key_that_was_never_used_is_not_taken_for_a_finished_rotation(vault, env, keyfile):
    """With no items, only retirement records can show whether the staged key opens the store."""
    tombstone_only_store(vault)
    passphrase_custody.stage_wrapped_key(vault, bytes.fromhex("c3" * 32), PHRASE)
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    # The retirement record opens under the wrapped key: the store really was rotated.
    assert new_store(vault).retired_modern_id("legacy1") == "modern1"


def test_the_old_custody_is_kept_when_only_a_retirement_record_could_show_the_key_is_wrong(
    vault, env, monkeypatch
):
    from floorvault.providers.platform_custody import write_protected

    tombstone_only_store(vault)
    credential = vault / "master.key.sdcred"
    credential.write_bytes(b"sealed")
    write_protected(
        passphrase_store.wrap(bytes.fromhex("77" * 32), PHRASE),
        vault / "master.key.fvpw",
        header=passphrase_store.MAGIC,
        expected_length=passphrase_store.PAYLOAD_BYTES,
    )
    code, _out, _err, _prompt = rotate(vault, env, None, PHRASE)
    assert code == 1
    assert credential.exists()


def test_a_binding_cleared_after_the_new_key_was_staged_is_still_refused(vault, env, keyfile):
    make_store(vault, env, keyfile)
    passphrase_custody.stage_wrapped_key(vault, bytes.fromhex("c3" * 32), PHRASE)
    clear_binding_in_db(vault)
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "command binding changed" in err
    assert not (vault / "master.key.fvpw").exists()
    old = VaultStore(
        vault, crypto=FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    )
    assert old.rotation_in_progress() is None  # nothing was rotated


def test_a_binding_cleared_in_the_middle_of_a_rotation_is_refused_on_resume(
    vault, env, keyfile, monkeypatch
):
    make_store(vault, env, keyfile, items=3)
    original = fail_on_second_write(monkeypatch)
    assert rotate(vault, env, keyfile, PHRASE)[0] == 1
    monkeypatch.setattr(VaultStore, "write_sealed_item", original)
    clear_binding_in_db(vault)  # `tok` sorts last, so it has not been re-sealed yet
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 1 and "command binding changed" in err
    assert not (vault / "master.key.fvpw").exists()
    assert passphrase_custody.staged_present(vault)


def test_a_store_holding_records_labelled_with_an_earlier_generation_is_rotated(
    vault, env, keyfile
):
    """Releases through 0.2.8 could write records labelled 0 after a rotation (SPEC 12.4)."""
    from floorvault import KeyRing
    from floorvault.vault_rotation import rotate_vault_store

    first = FloorVault(HardenedMemoryKey(OLD_KEY), app_instance_id=APP_CONTEXT)
    second_key = bytes.fromhex("66" * 32)
    second = FloorVault(HardenedMemoryKey(second_key), app_instance_id=APP_CONTEXT)
    store = VaultStore(vault, crypto=first)
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    rotate_vault_store(store, source_ring=KeyRing({0: first}), new_vault=second, new_key_id=1)
    sealed = store.read_sealed_item("tok", KeyRing({1: second}))
    store.write_sealed_item("tok", sealed, new_vault=second, key_id=0)  # an old release's label
    keyfile.write_text(second_key.hex(), encoding="utf-8")
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    assert new_store(vault).resolve_secret("tok") == {"value": VALUE}


def test_an_item_already_re_sealed_before_the_stop_does_not_make_the_resume_refuse(
    vault, env, keyfile, monkeypatch
):
    """The bound item sorts first, so it is re-sealed before the interruption: its fingerprint
    is then of ciphertext the record never saw, which a resume must not read as tampering."""
    make_store(vault, env, keyfile, items=3, bound="aaa")
    original = fail_on_second_write(monkeypatch)
    assert rotate(vault, env, keyfile, PHRASE)[0] == 1
    monkeypatch.setattr(VaultStore, "write_sealed_item", original)
    code, _out, err, _prompt = rotate(vault, env, keyfile, PHRASE)
    assert code == 0, err
    assert new_store(vault).get_allowed_commands("aaa") == [BOUND]

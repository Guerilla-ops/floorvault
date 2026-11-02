"""Passphrase custody in the CLI (#84, step 3): `secrets init --custody passphrase`,
`secrets protect`, and how `secrets` / `run` unlock a store with a wrapped key.

The prompt is replaced by a scripted one; scrypt is made cheap. Nothing here
touches a terminal or the OS key store.
"""

from __future__ import annotations

import contextlib
import io
import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

from floorvault import passphrase_custody
from floorvault.agent_cli import APP_CONTEXT
from floorvault.inspector import main
from floorvault.providers import passphrase_store
from floorvault.providers.adaptive import AdaptiveKeyProvider

PHRASE = "correct horse battery staple"
VALUE = "fixture-secret-value"

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)


class Prompt:
    """Scripted passphrase prompt: answers in order, records what was asked."""

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


def cli(args, env, prompt, *, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", *args]),
        mock.patch.object(sys, "stdin", io.StringIO(stdin)),
        mock.patch.object(passphrase_custody, "prompt_passphrase", prompt),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def init(vault, env, *answers):
    prompt = Prompt(*answers)
    return cli(["secrets", "init", "--custody", "passphrase", "--vault", str(vault)], env, prompt)


def add_item(vault, env, prompt):
    return cli(
        ["secrets", "add", "Token", "--id", "tok", "--stdin", "--vault", str(vault)],
        env,
        prompt,
        stdin=f"value={VALUE}\n",
    )


def test_init_wraps_a_new_key_and_creates_nothing_else(vault, env):
    code, out, err = init(vault, env, PHRASE)
    assert code == 0, err
    wrapped = vault / "master.key.fvpw"
    assert wrapped.is_file()
    assert sorted(p.name for p in vault.iterdir()) == ["master.key.fvpw"]
    assert "created" in out and str(wrapped) in out
    # The file is exactly an FVPW1 file that the passphrase opens.
    key = passphrase_custody.read_key(vault, PHRASE)
    assert key is not None and len(key) == 32
    with pytest.raises(passphrase_custody.PassphraseCustodyError):
        passphrase_custody.read_key(vault, "not the passphrase")
    assert PHRASE not in out + err


@posix_only
def test_init_creates_owner_only_files(vault, env):
    assert init(vault, env, PHRASE)[0] == 0
    assert stat.S_IMODE(os.stat(vault).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(vault / "master.key.fvpw").st_mode) == 0o600


def test_init_asks_twice_and_warns_about_a_short_passphrase(vault, env):
    prompt = Prompt("short")
    code, _out, err = cli(
        ["secrets", "init", "--custody", "passphrase", "--vault", str(vault)], env, prompt
    )
    assert code == 0
    assert prompt.asked == [("New passphrase: ", True)]
    assert "fewer than 12 characters" in err


def test_init_refuses_when_the_two_entries_differ_or_nothing_is_entered(vault, env):
    code, _out, err = init(
        vault, env, passphrase_custody.PassphraseCustodyError("the two passphrases differ")
    )
    assert code == 1 and "differ" in err
    assert not vault.exists()
    code, _out, err = init(
        vault, env, passphrase_custody.PassphraseCustodyError("the passphrase must not be empty")
    )
    assert code == 1 and not vault.exists()


def test_init_refuses_a_store_that_exists_and_another_custody(vault, env):
    vault.mkdir()
    (vault / "vault.db").write_bytes(b"")
    code, _out, err = init(vault, env, PHRASE)
    assert code == 2 and "already exists" in err and "protect" in err
    (vault / "vault.db").unlink()
    for name in ("master.key", "master.key.sdcred", "master.key.ostier"):
        (vault / name).write_bytes(b"x")
        code, _out, err = init(vault, env, PHRASE)
        assert code == 1 and name in err and "fork" in err
        assert not (vault / "master.key.fvpw").exists()
        (vault / name).unlink()


def test_init_takes_no_key_options(vault, env):
    prompt = Prompt()
    code, _out, err = cli(
        ["secrets", "init", "--custody", "passphrase", "--vault", str(vault), "--key-env", "K"],
        env,
        prompt,
    )
    assert code == 2 and "takes no --key-env or --key-file" in err
    assert prompt.asked == []


def test_secrets_unlock_the_store_with_the_passphrase(vault, env):
    assert init(vault, env, PHRASE)[0] == 0
    prompt = Prompt(PHRASE)
    code, _out, err = add_item(vault, env, prompt)
    assert code == 0, err
    assert prompt.asked and PHRASE not in "".join(p for p, _ in prompt.asked)
    # A later command asks again, and reads what the first one stored.
    code, out, err = cli(["secrets", "show", "tok", "--vault", str(vault)], env, Prompt(PHRASE))
    assert code == 0, err
    assert "1 set" in out and VALUE not in out + err
    # The only key file is still the wrapped one: nothing minted a second key.
    assert not (vault / "master.key").exists()


def test_a_wrong_passphrase_opens_nothing_and_falls_back_to_nothing(vault, env):
    assert init(vault, env, PHRASE)[0] == 0
    assert add_item(vault, env, Prompt(PHRASE))[0] == 0
    code, out, err = cli(
        ["secrets", "show", "tok", "--vault", str(vault)], env, Prompt("a wrong passphrase")
    )
    assert code == 1
    assert "wrong passphrase" in err and VALUE not in out + err
    assert not (vault / "master.key").exists()


def test_without_a_terminal_the_store_is_locked_and_nothing_replaces_the_key(vault, env):
    assert init(vault, env, PHRASE)[0] == 0
    before = sorted(p.name for p in vault.iterdir())
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", "secrets", "list", "--vault", str(vault)]),
        mock.patch.object(sys, "stdin", io.StringIO("")),
        mock.patch.object(passphrase_custody, "_has_controlling_terminal", lambda: False),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = main()
    assert code == 1
    assert "no terminal to ask for the passphrase" in err.getvalue()
    assert sorted(p.name for p in vault.iterdir()) == before


def test_a_wrapped_key_and_a_credential_together_open_nothing(vault, env):
    assert init(vault, env, PHRASE)[0] == 0
    (vault / "master.key.sdcred").write_bytes(b"x")
    prompt = Prompt(PHRASE)
    code, _out, err = cli(["secrets", "list", "--vault", str(vault)], env, prompt)
    assert code == 1 and "forked" in err
    assert prompt.asked == []


def raw_store(vault):
    """A store whose key sits in a raw Tier-3 ``master.key``, with one item in it."""
    from floorvault import FloorVault
    from floorvault.vaultkit.vault import VaultStore

    provider = AdaptiveKeyProvider(fallback_dir=vault, allow_disk_fallback=True)
    key = provider.resolve_key(allow_create=True)
    store = VaultStore(vault, crypto=FloorVault(key, app_instance_id=APP_CONTEXT))
    store.add_item("generic", "Token", {"value": VALUE}, item_id="tok")
    return key


@pytest.fixture()
def no_os_tier(monkeypatch):
    """Keep the provider on the file tier whatever the host has."""
    monkeypatch.setattr(AdaptiveKeyProvider, "_resolve_from_system_keyring", lambda *a, **k: None)


def test_protect_wraps_the_raw_key_and_the_data_stays_readable(vault, env, no_os_tier):
    raw_store(vault)
    assert (vault / "master.key").is_file()
    code, out, err = cli(["secrets", "protect", "--vault", str(vault)], env, Prompt(PHRASE))
    assert code == 0, err
    assert not (vault / "master.key").exists()
    assert (vault / "master.key.fvpw").is_file()
    assert "key itself is unchanged" in out and "best effort" in err
    # The same item opens under the passphrase.
    code, out, err = cli(["secrets", "show", "tok", "--vault", str(vault)], env, Prompt(PHRASE))
    assert code == 0, err
    assert "1 set" in out and VALUE not in out + err


def test_protect_refuses_what_it_cannot_wrap(vault, env):
    # Nothing there.
    code, _out, err = cli(["secrets", "protect", "--vault", str(vault)], env, Prompt())
    assert code == 2 and "no raw master.key" in err
    # Already wrapped.
    assert init(vault, env, PHRASE)[0] == 0
    code, _out, err = cli(["secrets", "protect", "--vault", str(vault)], env, Prompt())
    assert code == 2 and "already passphrase-protected" in err
    # A key sealed by systemd-creds is not a raw key file.
    (vault / "master.key.fvpw").unlink()
    (vault / "master.key.sdcred").write_bytes(b"x")
    code, _out, err = cli(["secrets", "protect", "--vault", str(vault)], env, Prompt())
    assert code == 2 and "sealed by systemd-creds" in err
    # Key options name a key somewhere else.
    code, _out, err = cli(
        ["secrets", "protect", "--vault", str(vault), "--key-env", "K"], env, Prompt()
    )
    assert code == 2 and "protect takes no --key-env or --key-file" in err


def test_protect_changes_nothing_when_the_passphrases_differ(vault, env, no_os_tier):
    raw_store(vault)
    before = (vault / "master.key").read_bytes()
    prompt = Prompt(passphrase_custody.PassphraseCustodyError("the two passphrases differ"))
    code, _out, _err = cli(["secrets", "protect", "--vault", str(vault)], env, prompt)
    assert code == 1
    assert (vault / "master.key").read_bytes() == before
    assert not (vault / "master.key.fvpw").exists()


def test_prompt_refuses_an_echoing_terminal(monkeypatch):
    import getpass
    import warnings

    monkeypatch.setattr(passphrase_custody, "_has_controlling_terminal", lambda: True)

    def echoing(_prompt):
        warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
        return "visible"

    monkeypatch.setattr(getpass, "getpass", echoing)
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="cannot hide"):
        passphrase_custody.prompt_passphrase()


def test_prompt_confirmation_and_empty_input(monkeypatch):
    import getpass

    monkeypatch.setattr(passphrase_custody, "_has_controlling_terminal", lambda: True)
    answers = iter(["abc", "abd"])
    monkeypatch.setattr(getpass, "getpass", lambda _p: next(answers))
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="differ"):
        passphrase_custody.prompt_passphrase(confirm=True)
    monkeypatch.setattr(getpass, "getpass", lambda _p: "")
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="must not be empty"):
        passphrase_custody.prompt_passphrase()


def test_create_refuses_a_second_key_and_reads_back_none_when_absent(vault):
    assert passphrase_custody.read_key(vault, PHRASE) is None
    assert not passphrase_custody.wrapped_present(vault)
    path = passphrase_custody.create_wrapped_key(vault, PHRASE)
    assert passphrase_custody.wrapped_present(vault) and Path(path).is_file()
    key = passphrase_custody.read_key(vault, PHRASE)
    assert key is not None and len(key) == 32
    with pytest.raises(passphrase_custody.PassphraseCustodyError):
        passphrase_custody.create_wrapped_key(vault, PHRASE)  # never replaced

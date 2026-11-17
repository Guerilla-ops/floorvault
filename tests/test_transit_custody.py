"""Vault Transit custody in the CLI: `secrets init --custody vault-transit`, and how
`secrets` / `run` open a store whose key Vault keeps wrapped.

Vault is replaced by a fake Transit engine. It is stateless (each wrapped blob
carries its own context and plaintext), so separate CLI processes share it: the
launcher below installs it in place of the provider's HTTPS transport. It checks
the token and the context binding the provider sends, as Transit with
``derived=true`` does. Nothing here reaches a network.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from floorvault import passphrase_custody, transit_custody
from floorvault.agent_cli import APP_CONTEXT
from floorvault.providers import vault_transit

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "hvs.test-transit-token-0123456789"
ADDR = "https://vault.test:8200"
VALUE = "s3cret-transit-value"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")

FAKE_VAULT = textwrap.dedent(
    """
    import base64, os
    from floorvault.providers.base import CustodyDowngradeError

    class FakeTransit:
        '''Transit with derived=true: the context is bound into every blob.'''

        def __init__(self, *args, **kwargs):
            pass

        def post(self, path, body, token):
            if os.environ.get("FV_TEST_VAULT_DOWN"):
                raise CustodyDowngradeError("Vault request failed (URLError)")
            if token != os.environ.get("FV_TEST_VAULT_GOOD_TOKEN"):
                raise CustodyDowngradeError("Vault refused the request (HTTP 403)")
            op = path.split("/")[3]
            context = body.get("context", "")
            if op == "datakey":
                plaintext = os.urandom(32)
                blob = "vault:v1:" + base64.b64encode(context.encode() + b"|" + plaintext).decode()
                return {"data": {"ciphertext": blob,
                                 "plaintext": base64.b64encode(plaintext).decode()}}
            if op == "decrypt":
                ctx, plaintext = base64.b64decode(body["ciphertext"].split(":", 2)[2]).split(b"|", 1)
                if ctx.decode() != context:
                    raise CustodyDowngradeError("Vault refused the request (HTTP 400)")
                return {"data": {"plaintext": base64.b64encode(plaintext).decode()}}
            raise AssertionError(path)

    def install():
        from floorvault.providers import vault_transit
        vault_transit.UrllibTransport = FakeTransit
    """
)

LAUNCH = (
    "import sys; sys.path.insert(0, {src!r}); sys.path.insert(0, {fake!r}); "
    "import fakevault; fakevault.install(); "
    "from floorvault.inspector import main; sys.exit(main())"
)


@pytest.fixture()
def vault(tmp_path):
    return tmp_path / "vault"


@pytest.fixture()
def cli(tmp_path, vault):
    fake_dir = tmp_path / "fake"
    fake_dir.mkdir()
    (fake_dir / "fakevault.py").write_text(FAKE_VAULT)
    home = tmp_path / "home"
    home.mkdir()
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FLOOR_VAULT", "HERMES", "VAULT_")) and k != "VAULT_MASTER_KEY"
    }
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "FLOOR_VAULT_DIR": str(vault),
            "FLOOR_VAULT_STATE_DIR": str(tmp_path / "state"),
            "FLOOR_VAULT_ALLOW_UNBOUND": "1",
            "VAULT_ADDR": ADDR,
            "VAULT_TOKEN": TOKEN,
            "FV_TEST_VAULT_GOOD_TOKEN": TOKEN,
            # A key variable that must be ignored for a vault whose key Vault keeps.
            "FLOOR_VAULT_KEY": os.urandom(32).hex(),
        }
    )

    def run(args, *, extra_env=None, drop=(), stdin=None):
        child_env = {**env, **(extra_env or {})}
        for name in drop:
            child_env.pop(name, None)
        return subprocess.run(
            [
                sys.executable,
                "-c",
                LAUNCH.format(src=str(ROOT / "src"), fake=str(fake_dir)),
                *args,
            ],
            input=stdin,
            capture_output=True,
            text=True,
            env=child_env,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            timeout=120,
        )

    return run


def _dump(tmp_path):
    script = tmp_path / "dump.py"
    script.write_text("import json, os, sys\nsys.stdout.write(json.dumps(dict(os.environ)))\n")
    return [sys.executable, str(script)]


def _init_and_add(cli):
    made = cli(["secrets", "init", "--custody", "vault-transit"])
    assert made.returncode == 0, made.stderr
    added = cli(["secrets", "add", "Token", "--id", "tok", "--stdin"], stdin=f"value={VALUE}\n")
    assert added.returncode == 0, added.stderr
    return made


# ------------------------------------------------------------------ the CLI


def test_init_then_add_list_show_and_run_use_the_vault_wrapped_key(tmp_path, cli, vault):
    made = _init_and_add(cli)
    assert f"created {vault / 'vault-transit'}" in made.stdout
    assert "the token is now the credential that opens this store" in made.stderr
    assert "Revoking it locks the store everywhere" in made.stderr
    # Only the wrapped key and the store: no raw key, no OS key store marker.
    assert sorted(p.name for p in vault.iterdir()) == ["vault-transit", "vault.db"]
    assert cli(["secrets", "list"]).stdout.split()[0] == "tok"
    assert "1 field(s): 1 set" in cli(["secrets", "show", "tok"]).stdout

    ran = cli(["run", "-e", "A=fv:tok", "--", *_dump(tmp_path)])
    assert ran.returncode == 0, ran.stderr
    child = json.loads(ran.stdout)
    assert child["A"] == VALUE
    # The token opens the store, so the child gets neither it nor a copy of it.
    assert "VAULT_TOKEN" not in child
    assert TOKEN not in json.dumps(child)
    # Where Vault is, and which key, is configuration: it passes through.
    assert child["VAULT_ADDR"] == ADDR


def test_a_copy_of_the_token_under_another_name_is_removed_too(tmp_path, cli):
    _init_and_add(cli)
    ran = cli(
        ["run", "-e", "A=fv:tok", "--", *_dump(tmp_path)],
        extra_env={"MY_COPY": TOKEN},
    )
    assert ran.returncode == 0, ran.stderr
    assert "MY_COPY" not in json.loads(ran.stdout)


def test_the_token_passes_through_for_a_store_with_another_custody(tmp_path, cli, vault):
    """`run -- vault ...` must keep working where the token is not this store's key."""
    ran = cli(["run", "--", *_dump(tmp_path)])
    assert ran.returncode == 0, ran.stderr
    assert json.loads(ran.stdout)["VAULT_TOKEN"] == TOKEN
    assert not vault.exists()


def test_a_revoked_token_fails_closed_and_nothing_stands_in(tmp_path, cli):
    """FLOOR_VAULT_KEY is set in the fixture: it must not be used instead."""
    _init_and_add(cli)
    for env in ({"VAULT_TOKEN": "hvs.revoked"}, {"FV_TEST_VAULT_DOWN": "1"}):
        ran = cli(["run", "-e", "A=fv:tok", "--", *_dump(tmp_path)], extra_env=env)
        assert ran.returncode != 0
        assert "Vault Transit:" in ran.stderr
        assert VALUE not in ran.stdout + ran.stderr
        assert "hvs.revoked" not in ran.stderr and TOKEN not in ran.stderr
        listed = cli(["secrets", "list"], extra_env=env)
        assert listed.returncode == 1 and "Vault Transit:" in listed.stderr


def test_a_missing_address_or_token_is_named_and_nothing_is_created(cli, vault):
    for missing in ("VAULT_ADDR", "VAULT_TOKEN"):
        made = cli(["secrets", "init", "--custody", "vault-transit"], drop=(missing,))
        assert made.returncode == 1
        assert f"set {missing}" in made.stderr
        assert not (vault / "vault-transit").exists()
    plain = cli(
        ["secrets", "init", "--custody", "vault-transit"], extra_env={"VAULT_ADDR": "http://x"}
    )
    assert plain.returncode == 1 and "https" in plain.stderr
    assert TOKEN not in plain.stderr


def test_a_second_init_never_mints_a_second_key(cli, vault):
    _init_and_add(cli)
    wrapped = sorted((vault / "vault-transit").iterdir())
    again = cli(["secrets", "init", "--custody", "vault-transit"])
    assert again.returncode == 2 and "already exists" in again.stderr
    assert sorted((vault / "vault-transit").iterdir()) == wrapped


def test_other_custodies_are_refused_beside_a_vault_wrapped_key(cli, vault):
    # The key exists but no item yet: init's "a vault already exists" check is not
    # what stops the second key here.
    assert cli(["secrets", "init", "--custody", "vault-transit"]).returncode == 0
    assert not (vault / "vault.db").exists()
    sealed = cli(["secrets", "init", "--custody", "systemd-creds"])
    assert sealed.returncode == 2
    assert "already keeps its key in Vault Transit" in sealed.stderr
    # Passphrase init asks first (and has no terminal here); the refusal itself is
    # in create_wrapped_key, tested directly below.
    assert cli(["secrets", "init", "--custody", "passphrase"]).returncode != 0
    assert not passphrase_custody.wrapped_present(vault)
    assert not (vault / "master.key.sdcred").exists()
    added = cli(["secrets", "add", "Token", "--id", "tok", "--stdin"], stdin=f"value={VALUE}\n")
    assert added.returncode == 0, added.stderr
    for args in (["secrets", "protect"], ["secrets", "protect", "--rotate"]):
        refused = cli(args)
        assert refused.returncode == 2
        assert "kept by Vault Transit" in refused.stderr


def test_a_second_key_beside_the_vault_wrapped_one_stops_every_open(tmp_path, cli, vault):
    _init_and_add(cli)
    (vault / "master.key").write_text(os.urandom(32).hex() + "\n")
    listed = cli(["secrets", "list"])
    assert listed.returncode == 1
    assert "two keys for one store" in listed.stderr
    ran = cli(["run", "-e", "A=fv:tok", "--", *_dump(tmp_path)])
    assert ran.returncode != 0 and VALUE not in ran.stdout


def test_init_refuses_a_store_that_already_has_another_custody(cli, vault):
    vault.mkdir(mode=0o700)
    (vault / "master.key.sdcred").write_bytes(b"sealed")
    made = cli(["secrets", "init", "--custody", "vault-transit"])
    assert made.returncode == 2 and "master.key.sdcred" in made.stderr
    assert not (vault / "vault-transit").exists()


# ------------------------------------------------------- the module itself


@pytest.fixture()
def fake_transport(monkeypatch, tmp_path):
    namespace: dict = {}
    exec(compile(FAKE_VAULT, "fakevault", "exec"), namespace)  # noqa: S102 - test fixture
    monkeypatch.setattr(vault_transit, "UrllibTransport", namespace["FakeTransit"])
    monkeypatch.setenv("FV_TEST_VAULT_GOOD_TOKEN", TOKEN)
    return namespace["FakeTransit"]


ENV = {"VAULT_ADDR": ADDR, "VAULT_TOKEN": TOKEN}


@posix_only
def test_create_then_read_returns_one_key_and_the_directory_is_owner_only(tmp_path, fake_transport):
    vault = tmp_path / "v"
    path = transit_custody.create(vault, ENV, app_instance_id=APP_CONTEXT)
    assert path == vault / "vault-transit" and transit_custody.present(vault)
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o700
    first = transit_custody.read_key(vault, ENV, app_instance_id=APP_CONTEXT)
    second = transit_custody.read_key(vault, ENV, app_instance_id=APP_CONTEXT)
    assert isinstance(first, bytes) and len(first) == 32 and first == second


def test_read_key_is_none_for_a_store_without_this_custody(tmp_path, fake_transport):
    assert transit_custody.read_key(tmp_path, ENV, app_instance_id=APP_CONTEXT) is None


def test_read_key_never_creates_a_key(tmp_path, fake_transport):
    """A wrapped key that is missing is an error, not a reason to mint one over the data."""
    vault = tmp_path / "v"
    (vault / "vault-transit").mkdir(parents=True, mode=0o700)
    with pytest.raises(transit_custody.TransitCustodyError, match="Vault Transit"):
        transit_custody.read_key(vault, ENV, app_instance_id=APP_CONTEXT)
    assert sorted(p.name for p in (vault / "vault-transit").iterdir()) == []


def test_create_refuses_a_store_that_already_has_one(tmp_path, fake_transport):
    vault = tmp_path / "v"
    transit_custody.create(vault, ENV, app_instance_id=APP_CONTEXT)
    key = transit_custody.read_key(vault, ENV, app_instance_id=APP_CONTEXT)
    with pytest.raises(transit_custody.TransitCustodyError, match="never replaced"):
        transit_custody.create(vault, ENV, app_instance_id=APP_CONTEXT)
    assert transit_custody.read_key(vault, ENV, app_instance_id=APP_CONTEXT) == key


def test_the_wrapped_key_is_bound_to_its_store(tmp_path, fake_transport):
    """A blob copied into another store does not open there (Transit's derived context)."""
    import shutil

    first, second = tmp_path / "a", tmp_path / "b"
    transit_custody.create(first, ENV, app_instance_id=APP_CONTEXT)
    transit_custody.create(second, ENV, app_instance_id=APP_CONTEXT)
    for name in os.listdir(first / "vault-transit"):
        if name.startswith("g-") or name in ("active", "highest"):
            shutil.copy2(first / "vault-transit" / name, second / "vault-transit" / name)
    with pytest.raises(transit_custody.TransitCustodyError):
        transit_custody.read_key(second, ENV, app_instance_id=APP_CONTEXT)


def test_a_passphrase_wrapped_key_is_never_created_beside_a_vault_wrapped_one(
    tmp_path, fake_transport
):
    vault = tmp_path / "v"
    transit_custody.create(vault, ENV, app_instance_id=APP_CONTEXT)
    with pytest.raises(passphrase_custody.PassphraseCustodyError, match="vault-transit"):
        passphrase_custody.create_wrapped_key(vault, "correct horse battery staple")
    assert not passphrase_custody.wrapped_present(vault)


def test_import_hermes_refuses_a_vault_transit_profile_by_name():
    from floorvault.agent_cli import _hermes_custody

    with pytest.raises(ValueError, match="hermes hvault bind"):
        _hermes_custody({"custody": "vault-transit", "vault_addr": ADDR})

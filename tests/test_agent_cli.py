"""``floorvault run`` and ``floorvault secrets`` as real subprocesses.

Every test uses a throwaway store under tmp_path, a random FLOOR_VAULT_KEY and a
home directory inside tmp_path, so nothing touches the developer's own
key store or ~/.floorvault.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SECRET = "fixture-secret-value"
TOKEN = "fixture-token-value"
CUSTODY = ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY", "HERMES_VAULT_KEY")


@pytest.fixture()
def key():
    return os.urandom(32).hex()


@pytest.fixture()
def base_env(tmp_path, key):
    env = {k: v for k, v in os.environ.items() if k.upper() not in CUSTODY}
    env.pop("FLOORVAULT_DIR", None)
    home = tmp_path / "home"
    home.mkdir()
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "PYTHONPATH": str(ROOT / "src"),
            "FLOOR_VAULT_KEY": key,
            "FLOORVAULT_DIR": str(tmp_path / "vault"),
        }
    )
    return env


def fv(args, env, *, stdin=None, binary=False):
    return subprocess.run(
        [sys.executable, "-m", "floorvault.inspector", *args],
        input=stdin,
        capture_output=True,
        text=not binary,
        env=env,
        cwd=ROOT,
        timeout=120,
    )


@pytest.fixture()
def store(base_env):
    """A store with a single-value item and a two-field item."""
    added = fv(
        ["secrets", "add", "OpenAI", "--id", "openai", "--stdin"],
        base_env,
        stdin=f"value={SECRET}\n",
    )
    assert added.returncode == 0, added.stderr
    assert added.stdout.strip() == "openai"
    added = fv(
        ["secrets", "add", "Multi", "--id", "multi", "--stdin"],
        base_env,
        stdin=f"# comment\nuser=u1\ntoken={TOKEN}\n",
    )
    assert added.returncode == 0, added.stderr
    return Path(base_env["FLOORVAULT_DIR"])


def _probe(tmp_path, body):
    script = tmp_path / "probe.py"
    script.write_text("import json, os, sys\n" + body, encoding="utf-8")
    return [sys.executable, str(script)]


def _dump_env(tmp_path):
    return _probe(
        tmp_path,
        "sys.stdout.write(json.dumps(dict(os.environ)))\n",
    )


# ------------------------------------------------------------------------ run


def test_run_resolves_inherited_explicit_and_env_file_refs(tmp_path, base_env, store):
    env_file = tmp_path / ".env"
    env_file.write_text("FROM_FILE=fv:multi:user\nPLAIN=not-a-secret\n", encoding="utf-8")
    env = {**base_env, "OPENAI_API_KEY": "fv:openai"}
    result = fv(
        ["run", "--env-file", str(env_file), "-e", "TG_TOKEN=fv:multi:token", "--"]
        + _dump_env(tmp_path),
        env,
    )
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["OPENAI_API_KEY"] == SECRET
    assert child["TG_TOKEN"] == TOKEN
    assert child["FROM_FILE"] == "u1"
    assert child["PLAIN"] == "not-a-secret"
    assert result.stderr == ""


def test_hv_alias_is_accepted(tmp_path, base_env, store):
    result = fv(["run", "-e", "A=hv:openai", "--"] + _dump_env(tmp_path), base_env)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["A"] == SECRET


def test_child_never_sees_a_vault_key_variable(tmp_path, base_env, store, key):
    env = {**base_env, "VAULT_MASTER_KEY": key, "MY_KEY": key}
    result = fv(
        ["run", "--key-env", "MY_KEY", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env
    )
    assert result.returncode == 0, result.stderr
    child = {k.upper() for k in json.loads(result.stdout)}
    assert not child & {"FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "MY_KEY"}


def test_no_inherit_refs_passes_inherited_values_through(tmp_path, base_env, store):
    env = {**base_env, "A": "fv:openai"}
    result = fv(["run", "--no-inherit-refs", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["A"] == "fv:openai"


def test_one_bad_reference_stops_the_child_and_leaks_nothing(tmp_path, base_env, store):
    marker = tmp_path / "ran"
    command = _probe(tmp_path, f"open({str(marker)!r}, 'w').close()\n")
    env = {**base_env, "GOOD": "fv:openai"}
    result = fv(["run", "-e", "BAD=fv:missing", "-e", "AMBIG=fv:multi", "--"] + command, env)
    assert result.returncode == 2
    assert not marker.exists()
    assert result.stdout == ""
    assert "BAD" in result.stderr and "AMBIG" in result.stderr
    assert SECRET not in result.stderr and TOKEN not in result.stderr


def test_missing_store_is_an_error_and_is_not_created(tmp_path, base_env):
    missing = tmp_path / "nowhere"
    env = {**base_env, "FLOORVAULT_DIR": str(missing)}
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 1
    assert "no vault at" in result.stderr
    assert not missing.exists()


def test_missing_key_is_an_error_and_no_key_is_created(tmp_path, base_env, store):
    before = sorted(p.name for p in store.iterdir())
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode in (1, 2), result.stderr
    assert result.stdout == ""
    assert sorted(p.name for p in store.iterdir()) == before


def test_no_references_needs_no_store(tmp_path, base_env):
    env = {**base_env, "FLOORVAULT_DIR": str(tmp_path / "absent")}
    result = fv(["run", "--", sys.executable, "-c", "print('ok')"], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("code", [0, 3])
def test_child_exit_code_is_propagated(base_env, code):
    result = fv(["run", "--", sys.executable, "-c", f"raise SystemExit({code})"], base_env)
    assert result.returncode == code


def test_unknown_command_exits_127(base_env):
    result = fv(["run", "--", "floorvault-no-such-command-xyz"], base_env)
    assert result.returncode == 127
    assert "not found" in result.stderr


def test_missing_separator_is_a_usage_error(base_env):
    result = fv(["run", "python"], base_env)
    assert result.returncode == 2
    assert "--" in result.stderr


def test_run_writes_nothing_to_stdout_but_the_childs_bytes(tmp_path, base_env, store):
    """MCP smoke: a stdio JSON-RPC server behind `floorvault run`."""
    server = _probe(
        tmp_path,
        "request = json.loads(sys.stdin.readline())\n"
        "reply = {'jsonrpc': '2.0', 'id': request['id'],\n"
        "         'result': {'key_len': len(os.environ['OPENAI_API_KEY'])}}\n"
        "sys.stdout.buffer.write(json.dumps(reply).encode() + b'\\n')\n",
    )
    env = {**base_env, "OPENAI_API_KEY": "fv:openai", "PYTHONWARNINGS": "always"}
    request = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode() + b"\n"
    result = fv(["run", "--"] + server, env, stdin=request, binary=True)
    assert result.returncode == 0, result.stderr
    expected = {"jsonrpc": "2.0", "id": 7, "result": {"key_len": len(SECRET)}}
    assert result.stdout == json.dumps(expected).encode() + b"\n"


def test_store_written_with_the_hermes_token_env_path_opens_under_run(tmp_path, base_env, key):
    """The hermesvault plugin's token_env path: FloorVault(key, 'floor-agent')."""
    from floorvault import FloorVault, VaultStore

    hermes_store = tmp_path / "hermes-home" / "agent-vault"
    crypto = FloorVault(bytes.fromhex(key), app_instance_id="floor-agent")
    VaultStore(hermes_store, crypto=crypto).add_item(
        kind="generic", label="from hermes", secret={"value": SECRET}, item_id="vault_h"
    )
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    env["HERMES_VAULT_KEY"] = key
    result = fv(
        ["run", "--vault", str(hermes_store), "--key-env", "HERMES_VAULT_KEY"]
        + ["-e", "A=hv:vault_h", "--"]
        + _dump_env(tmp_path),
        env,
    )
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["A"] == SECRET
    assert "HERMES_VAULT_KEY" not in {k.upper() for k in child}


def test_spawn_and_wait_path_used_on_windows(tmp_path):
    """The Windows launcher, exercised on every platform."""
    from floorvault.agent_cli import _spawn_and_wait

    out = tmp_path / "out.txt"
    code = _spawn_and_wait(
        sys.executable,
        [
            "python",
            "-c",
            f"import os; open({str(out)!r}, 'w').write(os.environ['X']); raise SystemExit(4)",
        ],
        {**os.environ, "X": "seen"},
    )
    assert code == 4
    assert out.read_text() == "seen"


# -------------------------------------------------------------------- secrets


def test_secrets_round_trip_never_prints_a_value(base_env, store, monkeypatch, capsys):
    listed = fv(["secrets", "list"], base_env)
    assert listed.returncode == 0
    assert listed.stdout.splitlines() == ["multi\tgeneric\tMulti", "openai\tgeneric\tOpenAI"]

    shown = fv(["secrets", "show", "multi"], base_env)
    assert shown.returncode == 0
    assert "2 field(s): 2 set, 0 empty" in shown.stdout
    assert fv(["secrets", "show", "fv:multi:token"], base_env).stdout.strip() == "(set)"
    assert fv(["secrets", "show", "multi:nope"], base_env).returncode == 1

    ref = fv(["secrets", "ref", "multi", "--field", "token", "--env", "TG"], base_env)
    assert ref.stdout.strip() == "TG=fv:multi:token"
    assert fv(["secrets", "ref", "absent"], base_env).returncode == 1

    # put reads the value through getpass, in-process so it can be patched.
    from floorvault import agent_cli
    from floorvault.inspector import main

    for name, value in base_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(agent_cli.getpass, "getpass", lambda prompt: "rotated-value")
    assert main(["secrets", "put", "multi", "token"]) == 0
    assert main(["secrets", "put", "absent", "token"]) == 1
    run_out = capsys.readouterr().out

    result = fv(
        ["run", "-e", "T=fv:multi:token", "--"]
        + [sys.executable, "-c", "import os; print(os.environ['T'])"],
        base_env,
    )
    assert result.stdout.strip() == "rotated-value"

    removed = fv(["secrets", "rm", "multi"], base_env)
    assert removed.returncode == 0
    assert fv(["secrets", "rm", "multi"], base_env).returncode == 1

    everything = listed.stdout + shown.stdout + ref.stdout + run_out + removed.stdout
    assert SECRET not in everything and TOKEN not in everything


def test_only_secrets_add_creates_a_store(tmp_path, base_env):
    env = {**base_env, "FLOORVAULT_DIR": str(tmp_path / "fresh")}
    for args in (["list"], ["show", "x"], ["rm", "x"], ["ref", "x"]):
        result = fv(["secrets", *args], env)
        assert result.returncode == 1, args
        assert "no vault at" in result.stderr
    assert not (tmp_path / "fresh").exists()


def test_secrets_add_validates_input(base_env):
    assert fv(["secrets", "add", "L", "--id", "bad id", "a=1"], base_env).returncode == 2
    assert fv(["secrets", "add", "L"], base_env).returncode == 2
    assert fv(["secrets", "add", "L", "novalue"], base_env).returncode == 2

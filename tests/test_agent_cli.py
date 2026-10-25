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
CUSTODY = (
    "FLOOR_VAULT_KEY",
    "VAULT_MASTER_KEY",
    "APPSTATE_KEY",
    "HERMES_VAULT_KEY",
    "FLOOR_VAULT_KEY_FILE",
)


@pytest.fixture()
def key():
    return os.urandom(32).hex()


@pytest.fixture()
def base_env(tmp_path, key):
    env = {k: v for k, v in os.environ.items() if k.upper() not in CUSTODY}
    env.pop("FLOOR_VAULT_DIR", None)
    home = tmp_path / "home"
    home.mkdir()
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "PYTHONPATH": str(ROOT / "src"),
            "FLOOR_VAULT_KEY": key,
            "FLOOR_VAULT_DIR": str(tmp_path / "vault"),
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
    return Path(base_env["FLOOR_VAULT_DIR"])


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
    assert result.returncode == 125
    assert not marker.exists()
    assert result.stdout == ""
    assert "BAD" in result.stderr and "AMBIG" in result.stderr
    assert SECRET not in result.stderr and TOKEN not in result.stderr


def test_missing_store_is_an_error_and_is_not_created(tmp_path, base_env):
    missing = tmp_path / "nowhere"
    env = {**base_env, "FLOOR_VAULT_DIR": str(missing)}
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 125
    assert "no vault at" in result.stderr
    assert not missing.exists()


def test_missing_key_is_an_error_and_no_key_is_created(tmp_path, base_env, store):
    before = sorted(p.name for p in store.iterdir())
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 125, result.stderr
    assert result.stdout == ""
    assert sorted(p.name for p in store.iterdir()) == before


def test_no_references_needs_no_store(tmp_path, base_env):
    env = {**base_env, "FLOOR_VAULT_DIR": str(tmp_path / "absent")}
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
    assert result.returncode == 125
    assert "--" in result.stderr
    bad_option = fv(["run", "--no-such-option", "--", "python"], base_env)
    assert bad_option.returncode == 125


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
    env = {**base_env, "FLOOR_VAULT_DIR": str(tmp_path / "fresh")}
    for args in (["list"], ["show", "x"], ["rm", "x"], ["ref", "x"]):
        result = fv(["secrets", *args], env)
        assert result.returncode == 1, args
        assert "no vault at" in result.stderr
    assert not (tmp_path / "fresh").exists()


def test_secrets_add_validates_input(base_env):
    assert fv(["secrets", "add", "L", "--id", "bad id", "a=1"], base_env).returncode == 2
    assert fv(["secrets", "add", "L"], base_env).returncode == 2
    assert fv(["secrets", "add", "L", "novalue"], base_env).returncode == 2


# --------------------------------------------------------------------- import

OPENAI = "fixture-openai-value"
GITHUB = "fixture-github-value"


def _env_file(tmp_path, body: bytes, name=".env"):
    path = tmp_path / name
    path.write_bytes(body)
    return path


def _sample(key=None):
    lines = [
        b"\xef\xbb\xbf# app config",
        b'export OPENAI_API_KEY="' + OPENAI.encode() + b'"',
        b"  GITHUB_TOKEN=" + GITHUB.encode(),
        b"DEBUG=1",
        b"EMPTY=",
        b"REF=fv:openai_api_key",
    ]
    if key:
        lines.append(b"FLOOR_VAULT_KEY=" + key.encode())
    return b"\r\n".join(lines)  # CRLF, and no newline at the end


def _leaks(*outputs):
    return any(v in out for out in outputs for v in (OPENAI, GITHUB))


def test_import_dry_run_changes_nothing(tmp_path, base_env):
    path = _env_file(tmp_path, _sample())
    before = path.read_bytes()
    result = fv(["secrets", "import", str(path)], base_env)
    assert result.returncode == 0, result.stderr
    assert "OPENAI_API_KEY -> fv:openai_api_key (new item)" in result.stdout
    assert "GITHUB_TOKEN -> fv:github_token (new item)" in result.stdout
    assert "REF: left as is (already a reference)" in result.stdout
    assert "dry run: nothing changed" in result.stdout
    assert path.read_bytes() == before
    assert not Path(base_env["FLOOR_VAULT_DIR"]).exists()
    assert not _leaks(result.stdout, result.stderr)


def test_import_write_round_trip_keeps_layout(tmp_path, base_env, key):
    path = _env_file(tmp_path, _sample(key))
    if os.name != "nt":
        path.chmod(0o640)
    result = fv(["secrets", "import", str(path), "--skip", "DEBUG", "--write"], base_env)
    assert result.returncode == 0, result.stderr
    assert "no backup was made" in result.stderr
    assert not _leaks(result.stdout, result.stderr)

    assert path.read_bytes() == b"\r\n".join(
        [
            b"\xef\xbb\xbf# app config",
            b"export OPENAI_API_KEY=fv:openai_api_key",
            b"  GITHUB_TOKEN=fv:github_token",
            b"DEBUG=1",
            b"EMPTY=",
            b"REF=fv:openai_api_key",
            b"FLOOR_VAULT_KEY=" + key.encode(),
        ]
    )
    if os.name != "nt":
        assert stat_mode(path) == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env", "home", "vault"]  # no temp file

    # The rewritten file now drives `run`: same values, no plaintext in the file.
    probe = _probe(
        tmp_path,
        "print(os.environ['OPENAI_API_KEY'] == %r, os.environ['GITHUB_TOKEN'] == %r)"
        % (OPENAI, GITHUB),
    )
    ran = fv(["run", "--env-file", str(path), "--"] + probe, base_env)
    assert ran.returncode == 0, ran.stderr
    assert ran.stdout.strip() == "True True"
    assert not _leaks(path.read_text(encoding="utf-8-sig"))


def test_import_rerun_and_existing_same_value_are_reused(tmp_path, base_env):
    added = fv(
        ["secrets", "add", "pre", "--id", "openai_api_key", "--stdin"],
        base_env,
        stdin=f"value={OPENAI}\n",
    )
    assert added.returncode == 0, added.stderr
    path = _env_file(tmp_path, _sample())
    result = fv(["secrets", "import", str(path), "--write"], base_env)
    assert result.returncode == 0, result.stderr
    assert "OPENAI_API_KEY -> fv:openai_api_key (already in the vault)" in result.stdout
    again = fv(["secrets", "import", str(path), "--write"], base_env)
    assert again.returncode == 0, again.stderr
    assert "nothing to import" in again.stdout


def test_import_conflict_changes_nothing(tmp_path, base_env):
    fv(
        ["secrets", "add", "pre", "--id", "github_token", "--stdin"],
        base_env,
        stdin="value=other\n",
    )
    path = _env_file(tmp_path, _sample())
    before = path.read_bytes()
    result = fv(["secrets", "import", str(path), "--write"], base_env)
    assert result.returncode == 2
    assert "github_token already exists with different contents" in result.stderr
    assert path.read_bytes() == before
    listed = fv(["secrets", "list"], base_env)
    assert listed.stdout.splitlines() == ["github_token\tgeneric\tpre"]


def test_import_only_and_prefix(tmp_path, base_env):
    path = _env_file(tmp_path, _sample())
    result = fv(
        ["secrets", "import", str(path), "--only", "GITHUB_TOKEN", "--prefix", "app.", "--write"],
        base_env,
    )
    assert result.returncode == 0, result.stderr
    assert "GITHUB_TOKEN -> fv:app.github_token (new item)" in result.stdout
    assert "OPENAI_API_KEY: left as is (not selected by --only)" in result.stdout
    text = path.read_text(encoding="utf-8-sig")
    assert "GITHUB_TOKEN=fv:app.github_token" in text
    assert OPENAI in text


@pytest.mark.parametrize(
    "args, body, message",
    [
        (["--only", "NOPE"], b"A=1\n", "not set in"),
        (["--prefix", "bad prefix"], b"A=1\n", "--prefix"),
        ([], b"FOO=1\nfoo=2\n", "would both be stored as foo"),
        ([], b"A=1\nthis is not an assignment\n", ":2: expected NAME=value"),
        ([], b"A=fv:bad id\n", "malformed reference"),
    ],
)
def test_import_refuses_bad_input_and_changes_nothing(tmp_path, base_env, args, body, message):
    path = _env_file(tmp_path, body)
    result = fv(["secrets", "import", str(path), "--write", *args], base_env)
    assert result.returncode == 2
    assert message in result.stderr
    assert path.read_bytes() == body
    assert not Path(base_env["FLOOR_VAULT_DIR"]).exists()


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_import_write_refuses_a_symlink(tmp_path, base_env):
    target = _env_file(tmp_path, b"A=fixture\n", name="real.env")
    link = tmp_path / ".env"
    link.symlink_to(target)
    result = fv(["secrets", "import", str(link), "--write"], base_env)
    assert result.returncode == 2
    assert "refuses symlinks" in result.stderr
    assert target.read_bytes() == b"A=fixture\n"


def test_import_dry_run_never_creates_a_key(tmp_path, base_env, store):
    before = sorted(p.name for p in store.iterdir())
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    path = _env_file(tmp_path, b"A=fixture\n")
    result = fv(["secrets", "import", str(path)], env)
    assert result.returncode == 1
    assert sorted(p.name for p in store.iterdir()) == before


def stat_mode(path):
    import stat as _stat

    return _stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="uses POSIX shebang scripts")
def test_command_is_found_on_runs_own_path_not_the_env_files(tmp_path, base_env):
    good, evil = tmp_path / "good", tmp_path / "evil"
    for directory, word in ((good, "good"), (evil, "evil")):
        directory.mkdir()
        script = directory / "fvprobe"
        script.write_text(f'#!/bin/sh\necho {word} "$PATH"\n', encoding="utf-8")
        script.chmod(0o755)
    (evil / "fvonly").write_text("#!/bin/sh\necho evil-only\n", encoding="utf-8")
    (evil / "fvonly").chmod(0o755)
    env_file = tmp_path / ".env"
    env_file.write_text(f"PATH={evil}\n", encoding="utf-8")
    env = {**base_env, "PATH": f"{good}{os.pathsep}{base_env.get('PATH', os.defpath)}"}

    result = fv(["run", "--env-file", str(env_file), "--", "fvprobe"], env)
    assert result.returncode == 0, result.stderr
    # run's own PATH picked the binary; the child still received the file's PATH.
    assert result.stdout.strip() == f"good {evil}"

    only = fv(["run", "--env-file", str(env_file), "--", "fvonly"], env)
    assert only.returncode == 127


def _hermes_case(tmp_path, base_env, kind):
    env = dict(base_env)
    if kind == "HERMES_HOME":
        home = tmp_path / "custom-hermes"
        env["HERMES_HOME"] = str(home)
        target = home / ".env"
    elif kind == "profile":
        home = tmp_path / "custom-hermes"
        env["HERMES_HOME"] = str(home)
        target = home / "profiles" / "work" / ".env"
    elif kind == "markers":
        home = tmp_path / "unregistered-home"
        home.mkdir(parents=True)
        (home / "state.db").write_bytes(b"")
        (home / "config.yaml").write_text("{}\n", encoding="utf-8")
        target = home / ".env"
    else:  # default POSIX home
        target = Path(base_env["HOME"]) / ".hermes" / ".env"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"OPENAI_API_KEY=" + OPENAI.encode() + b"\n")
    return env, target


@pytest.mark.parametrize(
    "kind",
    [
        "HERMES_HOME",
        "profile",
        "markers",
        pytest.param(
            "default",
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows default is %LOCALAPPDATA%"),
        ),
    ],
)
def test_import_refuses_to_rewrite_a_hermes_env(tmp_path, base_env, kind):
    env, target = _hermes_case(tmp_path, base_env, kind)
    before = target.read_bytes()

    dry = fv(["secrets", "import", str(target)], env)
    assert dry.returncode == 0, dry.stderr
    assert "is a Hermes Agent .env" in dry.stderr
    assert "secrets import --hermes" in dry.stderr

    write = fv(["secrets", "import", str(target), "--write"], env)
    assert write.returncode == 2
    assert "refusing to rewrite it" in write.stderr
    assert target.read_bytes() == before
    assert not Path(env["FLOOR_VAULT_DIR"]).exists()
    assert not _leaks(dry.stdout, dry.stderr, write.stdout, write.stderr)


def test_import_says_the_rewritten_file_needs_run(tmp_path, base_env):
    path = _env_file(tmp_path, b"A=fixture\n")
    dry = fv(["secrets", "import", str(path)], base_env)
    assert "works only for programs started with `floorvault run --env-file" in dry.stderr
    assert "Hermes Agent .env" not in dry.stderr
    write = fv(["secrets", "import", str(path), "--write"], base_env)
    assert write.returncode == 0, write.stderr
    assert "works only for programs started with" in write.stderr


# ------------------------------------------------- review follow-ups (#77)


def test_hermes_key_and_copies_of_a_key_never_reach_the_child(tmp_path, base_env, store, key):
    env = {
        **base_env,
        "HERMES_VAULT_KEY": key,  # the plugin's token_env, set but not passed as --key-env
        "COPY_OF_KEY": key,  # the same key under an unrelated name
        "SHORT": "1",
    }
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert key not in child.values()
    assert not {k.upper() for k in child} & {"HERMES_VAULT_KEY", "COPY_OF_KEY", "FLOOR_VAULT_KEY"}
    assert child["SHORT"] == "1" and child["A"] == SECRET


def test_inherited_hv_values_are_not_filled_in(tmp_path, base_env, store):
    env = {**base_env, "OTHER_TOOL": "hv:openai", "MINE": "fv:openai"}
    result = fv(["run", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["OTHER_TOOL"] == "hv:openai"
    assert child["MINE"] == SECRET


def test_secrets_reject_nul_at_write_time(base_env, store, monkeypatch):
    added = fv(["secrets", "add", "L", "--stdin"], base_env, stdin="value=a\x00b\n")
    assert added.returncode == 2
    assert "NUL" in added.stderr

    from floorvault import agent_cli
    from floorvault.inspector import main

    for name, value in base_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(agent_cli.getpass, "getpass", lambda prompt: "a\x00b")
    assert main(["secrets", "put", "openai", "value"]) == 2


def test_many_runs_can_start_at_once(tmp_path, base_env, store):
    """MCP clients start all their servers together."""
    probe = _probe(tmp_path, "sys.stdout.write(os.environ['A'])\n")
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "floorvault.inspector", "run", "-e", "A=fv:openai", "--"]
            + probe,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=base_env,
            cwd=ROOT,
        )
        for _ in range(8)
    ]
    results = [proc.communicate(timeout=120) for proc in procs]
    assert [proc.returncode for proc in procs] == [0] * 8, [err for _, err in results]
    assert all(out == SECRET for out, _ in results)


@pytest.mark.skipif(os.name != "nt", reason="Windows batch-file lookup (npx.cmd)")
def test_windows_cmd_command_is_found_by_bare_name(tmp_path, base_env, store):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "fvprobe.cmd").write_text("@echo cmd-ok %A%\r\n", encoding="utf-8")
    env = {**base_env, "PATH": f"{bindir}{os.pathsep}{base_env.get('PATH', '')}"}
    result = fv(["run", "-e", "A=fv:openai", "--", "fvprobe"], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"cmd-ok {SECRET}"


# ------------------------------------------------------------------- key file


def _key_file(tmp_path, key, *, mode=0o600, text=None, name="master.key"):
    path = tmp_path / name
    path.write_text(f"{key}\n" if text is None else text, encoding="ascii")
    if os.name != "nt":
        path.chmod(mode)
    return path


def _without_key(env):
    return {k: v for k, v in env.items() if k != "FLOOR_VAULT_KEY"}


def test_key_file_opens_the_store_and_never_reaches_the_child(tmp_path, base_env, store, key):
    path = _key_file(tmp_path, key)
    env = {**_without_key(base_env), "COPY": key.upper()}
    result = fv(
        ["run", "--key-file", str(path), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env
    )
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["A"] == SECRET
    assert "COPY" not in child
    assert key not in result.stdout.lower()


def test_key_file_variable_is_the_default_and_is_removed(tmp_path, base_env, store, key):
    path = _key_file(tmp_path, key)
    env = {**_without_key(base_env), "FLOOR_VAULT_KEY_FILE": str(path)}
    result = fv(["run", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    child = json.loads(result.stdout)
    assert child["A"] == SECRET
    assert "FLOOR_VAULT_KEY_FILE" not in {k.upper() for k in child}
    # Without references the file is not read, but the variable still goes.
    result = fv(["run", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    assert "FLOOR_VAULT_KEY_FILE" not in json.loads(result.stdout)


def test_key_file_variable_is_not_a_reference_target(tmp_path, base_env, store):
    result = fv(
        ["run", "-e", "FLOOR_VAULT_KEY_FILE=fv:openai", "--"] + _dump_env(tmp_path), base_env
    )
    assert result.returncode == 125
    assert result.stdout == ""


def test_key_env_wins_over_the_key_file_variable(tmp_path, base_env, store, key):
    bad = _key_file(tmp_path, "0" * 64)
    env = {**base_env, "FLOOR_VAULT_KEY_FILE": str(bad), "MY_KEY": key}
    result = fv(
        ["run", "--key-env", "MY_KEY", "-e", "A=fv:openai", "--"] + _dump_env(tmp_path), env
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["A"] == SECRET


def test_key_env_and_key_file_together_are_refused(tmp_path, base_env, store, key):
    path = _key_file(tmp_path, key)
    env = {**base_env, "MY_KEY": key}
    result = fv(
        ["run", "--key-env", "MY_KEY", "--key-file", str(path), "-e", "A=fv:openai", "--"]
        + _dump_env(tmp_path),
        env,
    )
    assert result.returncode == 125
    assert "not both" in result.stderr
    listed = fv(["secrets", "list", "--key-env", "MY_KEY", "--key-file", str(path)], env)
    assert listed.returncode != 0
    assert "not both" in listed.stderr


@pytest.mark.parametrize(
    "text, message",
    [
        ("not-hex\n", "64 hexadecimal"),
        ("ab" * 31 + "\n", "64 hexadecimal"),
        ("ab" * 32 + " extra\n", "64 hexadecimal"),
        ("\xe9" * 10, "cannot read"),
        ("a" * 5000, "too large"),
    ],
)
def test_bad_key_file_content_is_refused_without_echoing_it(
    tmp_path, base_env, store, text, message
):
    path = tmp_path / "master.key"
    path.write_bytes(text.encode("latin-1"))
    if os.name != "nt":
        path.chmod(0o600)
    result = fv(
        ["run", "--key-file", str(path), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
        _without_key(base_env),
    )
    assert result.returncode == 125
    assert message in result.stderr
    assert result.stdout == ""
    assert "not-hex" not in result.stderr and "abab" not in result.stderr


def test_missing_key_file_and_directory_are_refused(tmp_path, base_env, store):
    for path in (tmp_path / "missing.key", tmp_path):
        result = fv(
            ["run", "--key-file", str(path), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
            _without_key(base_env),
        )
        assert result.returncode == 125, path
        assert "key file" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_replaceable_key_file_is_refused(tmp_path, base_env, store, key, mode):
    path = _key_file(tmp_path, key, mode=mode)
    result = fv(
        ["run", "--key-file", str(path), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
        _without_key(base_env),
    )
    assert result.returncode == 125
    assert "writable by group or others" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_world_readable_key_file_warns_but_works(tmp_path, base_env, store, key):
    path = _key_file(tmp_path, key, mode=0o644)
    result = fv(
        ["run", "--key-file", str(path), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
        _without_key(base_env),
    )
    assert result.returncode == 0, result.stderr
    assert "readable by other users" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_key_file_symlink_like_a_kubernetes_mount_is_followed(tmp_path, base_env, store, key):
    data = tmp_path / "secrets" / "..2026_10_24" / "master.key"
    data.parent.mkdir(parents=True)
    data.write_text(key, encoding="ascii")
    data.chmod(0o600)
    link = tmp_path / "secrets" / "master.key"
    link.symlink_to(data)
    result = fv(
        ["run", "--key-file", str(link), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
        _without_key(base_env),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["A"] == SECRET


def test_secrets_add_with_a_key_file_needs_no_os_custody(tmp_path, base_env, key):
    path = _key_file(tmp_path, key)
    env = _without_key(base_env)
    added = fv(
        ["secrets", "add", "Token", "--id", "tok", "--key-file", str(path), "--stdin"],
        env,
        stdin=f"value={SECRET}\n",
    )
    assert added.returncode == 0, added.stderr
    vault = Path(base_env["FLOOR_VAULT_DIR"])
    # No key was written next to the store and the store opens with the file alone.
    from floorvault.providers.adaptive import OS_TIER_MARKER_FILENAME, WRAPPED_KEY_FILENAME

    names = {p.name for p in vault.iterdir()}
    assert "vault.db" in names
    assert not names & {"master.key", WRAPPED_KEY_FILENAME, OS_TIER_MARKER_FILENAME}
    env = {**env, "FLOOR_VAULT_KEY_FILE": str(path)}
    listed = fv(["secrets", "list"], env)
    assert listed.returncode == 0, listed.stderr
    assert "tok" in listed.stdout
    result = fv(["run", "-e", "A=fv:tok", "--"] + _dump_env(tmp_path), env)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["A"] == SECRET
    # The same key through FLOOR_VAULT_KEY opens it too.
    result = fv(["run", "-e", "A=fv:tok", "--"] + _dump_env(tmp_path), {**base_env})
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_key_file_fifo_is_refused_without_hanging(tmp_path, base_env, store):
    fifo = tmp_path / "master.key"
    os.mkfifo(fifo, 0o600)
    result = fv(
        ["run", "--key-file", str(fifo), "-e", "A=fv:openai", "--"] + _dump_env(tmp_path),
        _without_key(base_env),
    )
    assert result.returncode == 125
    assert "not a regular file" in result.stderr


# ----------------------------------------------------------- command bindings


def _bound_env(base_env):
    """base_env without PYTHONPATH or any variable that blocks bound items."""
    from floorvault.agentenv import code_injection_variables

    drop = set(code_injection_variables(base_env)) | {"PYTHONPATH"}
    return {k: v for k, v in base_env.items() if k not in drop}


_LAUNCH = (
    f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r}); "
    "from floorvault.inspector import main; sys.exit(main())"
)


def fvb(args, env, *, stdin=None):
    """floorvault without PYTHONPATH, so bound items are not blocked by it."""
    return subprocess.run(
        [sys.executable, "-c", _LAUNCH, *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=120,
    )


def _marker_probe(tmp_path, name="probe.py"):
    marker = tmp_path / f"{name}.ran"
    script = tmp_path / name
    script.write_text(
        "import os, pathlib, sys\n"
        f"pathlib.Path({str(marker)!r}).write_text('x')\n"
        "sys.stdout.write(os.environ.get('A', ''))\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)], marker


def test_bound_item_resolves_only_for_its_exact_command_line(tmp_path, base_env, store):
    env = _bound_env(base_env)
    probe, marker = _marker_probe(tmp_path)
    allowed = fvb(["secrets", "allow", "openai", "--", *probe], env)
    assert allowed.returncode == 0, allowed.stderr
    assert "bound to 1 command line(s)" in allowed.stdout
    result = fvb(["run", "-e", "A=fv:openai", "--", *probe], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == SECRET
    marker.unlink()
    for command in ([*probe, "--extra"], [sys.executable, "-c", "print(1)"]):
        result = fvb(["run", "-e", "A=fv:openai", "--", *command], env)
        assert result.returncode == 125
        assert result.stdout == ""
        assert "A: vault item openai is not allowed for" in result.stderr
        assert SECRET not in result.stderr
        assert not marker.exists()
    # Items that are not bound still resolve for any command.
    other = fvb(["run", "-e", "B=fv:multi:token", "--", sys.executable, "-c", "print(1)"], env)
    assert other.returncode == 0, other.stderr


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlink_to_the_bound_program_does_not_match(tmp_path, base_env, store):
    env = _bound_env(base_env)
    probe, marker = _marker_probe(tmp_path)
    assert fvb(["secrets", "allow", "openai", "--", *probe], env).returncode == 0
    link = tmp_path / "bin" / "python"
    link.parent.mkdir()
    link.symlink_to(sys.executable)
    result = fvb(["run", "-e", "A=fv:openai", "--", str(link), probe[1]], env)
    assert result.returncode == 125
    assert not marker.exists()


@pytest.mark.parametrize(
    "name", ["NODE_OPTIONS", "LD_PRELOAD", "PYTHONPATH", "DYLD_INSERT_LIBRARIES"]
)
def test_code_injection_variable_blocks_bound_items_only(tmp_path, base_env, store, name):
    env = _bound_env(base_env)
    probe, marker = _marker_probe(tmp_path)
    assert fvb(["secrets", "allow", "openai", "--", *probe], env).returncode == 0
    env_file = tmp_path / ".env"
    env_file.write_text(f"{name}=whatever\n", encoding="utf-8")
    result = fvb(["run", "--env-file", str(env_file), "-e", "A=fv:openai", "--", *probe], env)
    assert result.returncode == 125
    assert f"{name} is set" in result.stderr
    assert result.stdout == "" and not marker.exists()
    if sys.platform == "darwin" and name.startswith("DYLD_"):
        # An unbound item is not blocked, but this half starts the child with the
        # variable set, and macOS's dynamic loader honours it: a bogus
        # DYLD_INSERT_LIBRARIES aborts the child before it runs.
        return
    result = fvb(["run", "--env-file", str(env_file), "-e", "A=fv:multi:token", "--", *probe], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == TOKEN


def test_allow_remove_clear_and_show(tmp_path, base_env, store):
    env = _bound_env(base_env)
    probe, _ = _marker_probe(tmp_path)
    second = [*probe, "--second"]
    assert fvb(["secrets", "allow", "openai", "--", *probe], env).returncode == 0
    # Option before the item id: argparse 3.10 and 3.13 differ here.
    assert fvb(["secrets", "allow", "--remove", "openai", "--", *second], env).returncode == 1
    assert fvb(["secrets", "allow", "openai", "--", *second], env).returncode == 0
    shown = fvb(["secrets", "show", "openai"], env)
    assert shown.returncode == 0
    assert "bound to 2 command line(s)" in shown.stdout and "--second" in shown.stdout
    assert SECRET not in shown.stdout
    assert fvb(["secrets", "allow", "--remove", "openai", "--", *second], env).returncode == 0
    last = fvb(["secrets", "allow", "openai", "--remove", "--", *probe], env)
    assert last.returncode == 1 and "Use --clear" in last.stderr
    cleared = fvb(["secrets", "allow", "openai", "--clear"], env)
    assert cleared.returncode == 0 and "not bound" in cleared.stdout
    result = fvb(["run", "-e", "A=fv:openai", "--", sys.executable, "-c", "print(1)"], env)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["secrets", "allow", "openai"],
        ["secrets", "allow", "openai", "--clear", "--", "x"],
        ["secrets", "allow", "bad id", "--", "x"],
    ],
)
def test_allow_usage_errors(base_env, store, args):
    assert fvb(args, _bound_env(base_env)).returncode == 2


def test_allow_needs_an_existing_item_and_command(tmp_path, base_env, store):
    env = _bound_env(base_env)
    assert fvb(["secrets", "allow", "missing", "--", sys.executable], env).returncode == 1
    result = fvb(["secrets", "allow", "openai", "--", "no-such-command-fv"], env)
    assert result.returncode == 1 and "not found" in result.stderr


def test_allow_warns_about_relative_paths(tmp_path, base_env, store):
    env = _bound_env(base_env)
    result = fvb(["secrets", "allow", "openai", "--", sys.executable, "pyproject.toml"], env)
    assert result.returncode == 0
    assert "pyproject.toml is a relative path" in result.stderr


def test_unreadable_binding_fails_closed(tmp_path, base_env, store):
    import sqlite3

    env = _bound_env(base_env)
    with sqlite3.connect(store / "vault.db") as conn:
        conn.execute(
            "UPDATE vault_items SET allowed_commands = ? WHERE id = 'openai'",
            ('{"commands": [["/bin/sh"]]}',),
        )
    probe, marker = _marker_probe(tmp_path)
    result = fvb(["run", "-e", "A=fv:openai", "--", *probe], env)
    assert result.returncode == 125
    assert "command binding cannot be read" in result.stderr
    assert not marker.exists()


def test_bound_item_with_a_missing_command_exits_127(tmp_path, base_env, store):
    env = _bound_env(base_env)
    probe, _ = _marker_probe(tmp_path)
    assert fvb(["secrets", "allow", "openai", "--", *probe], env).returncode == 0
    result = fvb(["run", "-e", "A=fv:openai", "--", "no-such-command-fv"], env)
    assert result.returncode == 127
    assert result.stdout == ""


# ----------------------------------------------------------- import --hermes


HERMES_ENV = (
    b"# provider keys\r\n"
    b"export OPENAI_API_KEY=sk-hermes-openai\r\n"
    b"DEBUG=1\r\n"
    b'GITHUB_TOKEN="ghp-hermes-github"\r\n'
    b"HERMES_VAULT_KEY=" + b"ab" * 32 + b"\r\n"
    b"EMPTY=\r\n"
    b"TAIL=keep-me"
)


def _hermes_home(tmp_path, *, env_bytes=HERMES_ENV, config="model: x\n"):
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "state.db").write_bytes(b"")
    (home / "config.yaml").write_text(config, encoding="utf-8")
    env_file = home / ".env"
    env_file.write_bytes(env_bytes)
    return home, env_file


MAPPING = (
    "secrets:\n"
    "  hermesvault:\n"
    "    enabled: true\n"
    "    env:\n"
    '      OPENAI_API_KEY: "hv:openai_api_key"\n'
    "      GITHUB_TOKEN: hv:github_token   # pat\n"
)


def _hermes_import(args, env):
    # The plugin takes its key from $HERMES_VAULT_KEY (its token_env) or the OS key
    # store, never $FLOOR_VAULT_KEY, and so does the import; give it the same key.
    if "FLOOR_VAULT_KEY" in env and "HERMES_VAULT_KEY" not in env:
        env = {**env, "HERMES_VAULT_KEY": env["FLOOR_VAULT_KEY"]}
    return fv(["secrets", "import", "--hermes", *args], env)


def test_hermes_dry_run_changes_nothing_and_prints_the_mapping(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    result = _hermes_import([str(env_file), "--skip", "DEBUG", "--skip", "TAIL"], base_env)
    assert result.returncode == 0, result.stderr
    assert "OPENAI_API_KEY -> hv:openai_api_key (new item)" in result.stdout
    assert "GITHUB_TOKEN -> hv:github_token (new item)" in result.stdout
    assert "HERMES_VAULT_KEY: left as is (a vault key variable" in result.stdout
    assert "EMPTY: left as is (empty)" in result.stdout
    assert '      OPENAI_API_KEY: "hv:openai_api_key"' in result.stdout
    assert "secrets:\n  hermesvault:\n    enabled: true\n    env:\n" in result.stdout
    assert f"store: {home / 'agent-vault'}" in result.stdout
    assert "dry run: nothing changed" in result.stdout
    assert "--only NAME or --skip NAME" in result.stderr
    for value in ("sk-hermes-openai", "ghp-hermes-github"):
        assert value not in result.stdout + result.stderr
    assert env_file.read_bytes() == before
    assert not (home / "agent-vault").exists()


def test_hermes_write_stores_items_and_leaves_the_env_alone(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    result = _hermes_import([str(env_file), "--only", "OPENAI_API_KEY", "--write"], base_env)
    assert result.returncode == 0, result.stderr
    assert f"stored 1 new item(s) in {home / 'agent-vault'}" in result.stdout
    assert "is unchanged" in result.stdout and "--remove-from-env" in result.stdout
    assert env_file.read_bytes() == before
    assert "sk-hermes-openai" not in result.stdout + result.stderr
    # The store opens the way the plugin opens it with $HERMES_VAULT_KEY, and so does `run`.
    probe = (
        "import os\n"
        "from floorvault import FloorVault\n"
        "from floorvault.vaultkit import VaultStore\n"
        "key = bytes.fromhex(os.environ['FLOOR_VAULT_KEY'])\n"
        f"store = VaultStore({str(home / 'agent-vault')!r}, "
        "crypto=FloorVault(key, app_instance_id='floor-agent'))\n"
        "print(store.resolve_secret('openai_api_key')['value'])\n"
    )
    opened = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, env=base_env, cwd=ROOT
    )
    assert opened.stdout.strip() == "sk-hermes-openai", opened.stderr
    ran = fv(
        ["run", "--vault", str(home / "agent-vault"), "-e", "A=hv:openai_api_key", "--"]
        + _dump_env(tmp_path),
        base_env,
    )
    assert json.loads(ran.stdout)["A"] == "sk-hermes-openai", ran.stderr
    # Re-running reuses the stored item.
    again = _hermes_import([str(env_file), "--only", "OPENAI_API_KEY", "--write"], base_env)
    assert again.returncode == 0 and "(already in the vault)" in again.stdout
    assert "stored 0 new item(s)" in again.stdout


def test_hermes_remove_is_refused_until_config_maps_every_key(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    flags = [str(env_file), "--skip", "DEBUG", "--skip", "TAIL", "--write", "--remove-from-env"]
    result = _hermes_import(flags, base_env)
    assert result.returncode == 2
    assert "secrets.hermesvault mapping" in result.stderr
    assert "nothing was removed from .env" in result.stderr
    assert env_file.read_bytes() == before
    # The items were stored, so adding the mapping and re-running is all that is left.
    assert (home / "agent-vault" / "vault.db").is_file()
    # A mapping for only one of the keys is still refused.
    (home / "config.yaml").write_text(
        "secrets:\n  hermesvault:\n    enabled: true\n    env:\n      OPENAI_API_KEY: hv:openai_api_key\n",
        encoding="utf-8",
    )
    partial = _hermes_import(flags, base_env)
    assert partial.returncode == 2 and "does not map GITHUB_TOKEN" in partial.stderr
    assert env_file.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_hermes_remove_deletes_only_the_mapped_lines_and_keeps_layout(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path, config="model: x\n" + MAPPING)
    base_env["FLOOR_VAULT_KEY"] = "ab" * 32
    env_file.chmod(0o640)
    flags = [str(env_file), "--skip", "DEBUG", "--skip", "TAIL", "--write", "--remove-from-env"]
    result = _hermes_import(flags, base_env)
    assert result.returncode == 0, result.stderr
    assert "removed 2 line(s)" in result.stdout
    assert env_file.read_bytes() == (
        b"# provider keys\r\n"
        b"DEBUG=1\r\n"
        b"HERMES_VAULT_KEY=" + b"ab" * 32 + b"\r\n"
        b"EMPTY=\r\n"
        b"TAIL=keep-me"
    )
    assert stat_mode(env_file) == 0o640
    assert "no backup was made" in result.stderr
    assert "checked enabled YAML mappings" in result.stderr
    assert "`hermes doctor` warns that no API key is in .env" in result.stderr
    assert "fails at its first API call, not at startup" in result.stderr
    assert "HERMES_VAULT_KEY is still in .env" in result.stderr
    for value in ("sk-hermes-openai", "ghp-hermes-github"):
        assert value not in result.stdout + result.stderr
    ran = fv(
        ["run", "--vault", str(home / "agent-vault"), "-e", "G=hv:github_token", "--"]
        + _dump_env(tmp_path),
        base_env,
    )
    assert json.loads(ran.stdout)["G"] == "ghp-hermes-github", ran.stderr
    # Nothing is left to import once the lines are gone.
    done = _hermes_import(flags, base_env)
    assert done.returncode == 0, done.stderr
    assert "nothing to import" in done.stdout


def test_hermes_remove_needs_a_readable_config(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    (home / "config.yaml").unlink()
    flags = [str(env_file), "--vault", str(home / "agent-vault"), "--only", "OPENAI_API_KEY"]
    result = _hermes_import([*flags, "--write", "--remove-from-env"], base_env)
    assert result.returncode == 2
    assert f"cannot read {home / 'config.yaml'}" in result.stderr
    assert "nothing was removed from .env" in result.stderr
    assert env_file.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_hermes_remove_refuses_a_symlinked_env(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path, config=MAPPING)
    link = home / "link.env"
    link.symlink_to(env_file)
    result = _hermes_import(
        [str(link), "--vault", str(home / "agent-vault"), "--write", "--remove-from-env"],
        base_env,
    )
    assert result.returncode == 2 and "refuses symlinks" in result.stderr
    assert not (home / "agent-vault").exists()


def test_hermes_usage_errors(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    # --remove-from-env needs --write, and belongs to --hermes.
    assert _hermes_import([str(env_file), "--remove-from-env"], base_env).returncode == 2
    plain = fv(["secrets", "import", str(env_file), "--remove-from-env", "--write"], base_env)
    assert plain.returncode == 2 and "--remove-from-env is for --hermes" in plain.stderr
    # A file is required without --hermes.
    assert fv(["secrets", "import"], base_env).returncode == 2
    # A directory that is not a Hermes home needs an explicit --vault.
    other = tmp_path / "other"
    other.mkdir()
    (other / ".env").write_bytes(b"A=1\n")
    result = _hermes_import([str(other / ".env"), "--write"], base_env)
    assert result.returncode == 2 and "give --vault DIR" in result.stderr
    assert not (other / "agent-vault").exists()
    explicit = _hermes_import([str(other / ".env"), "--vault", str(tmp_path / "vv")], base_env)
    assert explicit.returncode == 0, explicit.stderr
    assert "A -> hv:a (new item)" in explicit.stdout
    assert env_file.read_bytes() == before
    bad_prefix = _hermes_import([str(env_file), "--prefix", "a b"], base_env)
    assert bad_prefix.returncode == 2


def test_hermes_default_file_comes_from_hermes_home(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    env = {**base_env, "HERMES_HOME": str(home)}
    result = _hermes_import(["--only", "OPENAI_API_KEY"], env)
    assert result.returncode == 0, result.stderr
    assert "OPENAI_API_KEY -> hv:openai_api_key" in result.stdout
    nothing = {**base_env, "HERMES_HOME": str(tmp_path / "nowhere")}
    missing = _hermes_import([], nothing)
    assert missing.returncode == 2 and "no Hermes .env found" in missing.stderr


def test_hermes_conflicting_item_stops_the_import(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    assert (
        _hermes_import([str(env_file), "--only", "OPENAI_API_KEY", "--write"], base_env).returncode
        == 0
    )
    env_file.write_bytes(HERMES_ENV.replace(b"sk-hermes-openai", b"sk-rotated"))
    result = _hermes_import([str(env_file), "--only", "OPENAI_API_KEY", "--write"], base_env)
    assert result.returncode == 2
    assert "already exists with different contents" in result.stderr


def test_hermes_uses_the_plugins_token_env_key_when_it_is_set(tmp_path, base_env):
    home, env_file = _hermes_home(tmp_path)
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    # A key of its own, not the one base_env holds in FLOOR_VAULT_KEY.
    env["HERMES_VAULT_KEY"] = os.urandom(32).hex()
    result = _hermes_import([str(env_file), "--only", "OPENAI_API_KEY", "--write"], env)
    assert result.returncode == 0, result.stderr
    assert "using the key in $HERMES_VAULT_KEY, as the hermesvault plugin does" in result.stderr
    ran = fv(
        ["run", "--vault", str(home / "agent-vault"), "--key-env", "HERMES_VAULT_KEY"]
        + ["-e", "A=hv:openai_api_key", "--"]
        + _dump_env(tmp_path),
        env,
    )
    assert json.loads(ran.stdout)["A"] == "sk-hermes-openai", ran.stderr
    # Without that key variable the store does not open under a different key.
    wrong = fv(
        ["run", "--vault", str(home / "agent-vault"), "-e", "A=hv:openai_api_key", "--"]
        + _dump_env(tmp_path),
        base_env,
    )
    assert wrong.returncode == 125


@pytest.mark.parametrize(
    "line, name, item_id, expected",
    [
        ('      K: "hv:a"', "K", "a", True),
        ("      K: 'hv:a'", "K", "a", True),
        ("      K: hv:a", "K", "a", True),
        ("      K: hv:a   # note", "K", "a", True),
        ('      K: "hv:a:value"', "K", "a", True),
        ("\tK: hv:a", "K", "a", False),
        ("      K: \"hv:a'", "K", "a", False),
        ("      K: hv:ab", "K", "a", False),
        ("      K: hv:a:token", "K", "a", False),
        ("      K: hv:b", "K", "a", False),
        ("      # K: hv:a", "K", "a", False),
        ("K: hv:a", "K", "a", False),
        ("      OTHER_K: hv:a", "K", "a", False),
        ("      K: fv:a", "K", "a", False),
        ("      K.X: hv:a", "K", "a", False),
    ],
)
def test_config_mapping_check(line, name, item_id, expected):
    from floorvault.agent_cli import _config_maps

    assert (
        _config_maps(
            "secrets:\n  hermesvault:\n    enabled: true\n    env:\n" + line + "\n", name, item_id
        )
        is expected
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_hermes_remove_notes_omit_the_master_key_warning_when_it_is_not_in_env(tmp_path, base_env):
    env_bytes = b"OPENAI_API_KEY=sk-hermes-openai\nDEBUG=1\n"
    home, env_file = _hermes_home(tmp_path, env_bytes=env_bytes, config=MAPPING)
    result = _hermes_import(
        [str(env_file), "--only", "OPENAI_API_KEY", "--write", "--remove-from-env"], base_env
    )
    assert result.returncode == 0, result.stderr
    assert env_file.read_bytes() == b"DEBUG=1\n"
    assert "`hermes doctor` warns" in result.stderr
    assert "HERMES_VAULT_KEY is still in" not in result.stderr


@pytest.mark.parametrize(
    "config",
    [
        MAPPING.replace("enabled: true", "enabled: false"),
        MAPPING.replace("enabled: true", 'enabled: "true"'),
        MAPPING.replace("secrets:", "unrelated:"),
        "notes: |\n" + "\n".join("  " + line for line in MAPPING.splitlines()),
        MAPPING + "secrets: {}\n",
        MAPPING.replace("    env:", "    env: {}\n    env:"),
        MAPPING.replace("    env:", "    dir: another-store\n    env:"),
        MAPPING + "invalid: [\n",
    ],
)
def test_hermes_remove_requires_nested_plugin_config(tmp_path, base_env, config):
    _, env_file = _hermes_home(tmp_path, config=config, env_bytes=b"OPENAI_API_KEY=fixture\n")
    before = env_file.read_bytes()
    result = _hermes_import([str(env_file), "--write", "--remove-from-env"], base_env)
    assert result.returncode == 2, result.stderr
    assert "nothing was removed from .env" in result.stderr
    assert env_file.read_bytes() == before


def test_hermes_remove_rejects_different_dotenv_bootstrap_key(tmp_path, base_env):
    _, env_file = _hermes_home(tmp_path, config=MAPPING)
    result = _hermes_import(
        [str(env_file), "--only", "OPENAI_API_KEY", "--write", "--remove-from-env"], base_env
    )
    assert result.returncode == 2
    assert "plugin key" in result.stderr
    assert env_file.read_bytes() == HERMES_ENV
    assert "sk-hermes-openai" not in result.stdout + result.stderr


def test_hermes_remove_accepts_flow_yaml_and_custom_key(tmp_path, base_env):
    config = 'secrets: {hermesvault: {enabled: true, token_env: CUSTOM_KEY, env: {"OPENAI_API_KEY": "hv:openai_api_key:value"}}}\n'
    _, env_file = _hermes_home(tmp_path, config=config, env_bytes=b"OPENAI_API_KEY=fixture\n")
    env = {**base_env, "CUSTOM_KEY": base_env["FLOOR_VAULT_KEY"]}
    result = _hermes_import(
        [str(env_file), "--key-env", "CUSTOM_KEY", "--write", "--remove-from-env"], env
    )
    assert result.returncode == 0, result.stderr
    assert env_file.read_bytes() == b""


@pytest.mark.parametrize("setting", ['token_env: ""', 'override_existing: "false"'])
def test_hermes_remove_rejects_malformed_plugin_settings(tmp_path, base_env, setting):
    config = MAPPING.replace("    env:", f"    {setting}\n    env:")
    _, env_file = _hermes_home(tmp_path, config=config, env_bytes=b"OPENAI_API_KEY=fixture\n")
    result = _hermes_import([str(env_file), "--write", "--remove-from-env"], base_env)
    assert result.returncode == 2
    assert env_file.read_bytes() == b"OPENAI_API_KEY=fixture\n"


def test_hermes_yaml_dependency_is_optional_but_required_for_removal(monkeypatch):
    import builtins

    from floorvault.hermes_config import load_hermes_config

    original = builtins.__import__

    def without_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("not installed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_yaml)
    with pytest.raises(ValueError, match=r"floorvault\[hermes\]"):
        load_hermes_config(MAPPING)


@pytest.mark.parametrize(
    "text",
    [
        "!!python/object/apply:os.system ['sensitive-input']",
        MAPPING + "\n---\n" + MAPPING,
        "",
        "17",
        "secrets: {hermesvault: {enabled: true, env: {}}}\nsecrets: {}",
    ],
)
def test_hermes_yaml_errors_do_not_disclose_document(text):
    from floorvault.hermes_config import load_hermes_config

    with pytest.raises(ValueError) as error:
        load_hermes_config(text)
    assert "sensitive-input" not in str(error.value)


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="the plugin's fallback is the real OS key store (macOS Keychain, Windows "
    "DPAPI); on Linux the stripped environment has no Secret Service",
)
def test_hermes_remove_refuses_when_the_profile_env_clears_the_plugin_key(tmp_path, base_env):
    # Hermes loads .env with override, so `HERMES_VAULT_KEY=` leaves the plugin
    # without its key; the import's own key must not certify the removal.
    original = b"OPENAI_API_KEY=fixture\nHERMES_VAULT_KEY=\n"
    _, env_file = _hermes_home(tmp_path, config=MAPPING, env_bytes=original)
    env = {k: v for k, v in base_env.items() if not k.startswith(("DISPLAY", "WAYLAND", "DBUS"))}
    result = _hermes_import(
        [str(env_file), "--only", "OPENAI_API_KEY", "--write", "--remove-from-env"], env
    )
    assert result.returncode == 2, result.stderr
    assert env_file.read_bytes() == original
    assert "plugin key cannot decrypt the imported values" in result.stderr


def test_hermes_remove_is_not_certified_by_floor_vault_key(tmp_path, monkeypatch):
    """Unit-level: a FLOOR_VAULT_KEY the plugin ignores never stands in for its key."""
    import floorvault.providers.adaptive as adaptive
    from floorvault import agent_cli
    from floorvault.agentenv import read_env_file
    from floorvault.providers.base import KeyProviderError

    seen = []

    class Provider:
        def __init__(self, **kwargs):
            seen.append(kwargs)

        def resolve_key(self, *, allow_create):
            assert allow_create is False
            raise KeyProviderError("no OS key here")

    monkeypatch.setattr(adaptive, "AdaptiveKeyProvider", Provider)
    monkeypatch.setenv("FLOOR_VAULT_KEY", "ab" * 32)
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    home = tmp_path / "h"
    (home / "agent-vault").mkdir(parents=True)
    (home / ".env").write_text("OPENAI_API_KEY=x\n", encoding="utf-8")
    env_file = read_env_file(home / ".env")
    (line,) = list(env_file.assignments())
    with pytest.raises(ValueError, match="plugin key cannot decrypt"):
        agent_cli._verify_hermes_removal(
            MAPPING, home, home / "agent-vault", env_file, [(line, "openai_api_key")]
        )
    assert seen and seen[0]["environ"] == {} and seen[0]["interactive"] is False


def test_hermes_remove_refuses_known_host_config_fallback(tmp_path, base_env):
    config = MAPPING + "max_turns: 4\nagent: broken\n"
    original = b"OPENAI_API_KEY=fixture\n"
    _, env_file = _hermes_home(tmp_path, config=config, env_bytes=original)
    result = _hermes_import([str(env_file), "--write", "--remove-from-env"], base_env)
    assert result.returncode == 2
    assert env_file.read_bytes() == original
    assert "agent must be a mapping" in result.stderr


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="falls through to the real OS key store: the macOS Keychain (which can block "
    "on a CI runner) or Windows DPAPI; on Linux the stripped environment has no "
    "Secret Service",
)
def test_hermes_import_does_not_use_floor_vault_key(tmp_path, base_env):
    """The plugin ignores $FLOOR_VAULT_KEY, so the import must not store under it."""
    home, env_file = _hermes_home(tmp_path, config="model: x\n" + MAPPING)
    before = env_file.read_bytes()
    env = {k: v for k, v in base_env.items() if not k.startswith(("DISPLAY", "WAYLAND", "DBUS"))}
    flags = [str(env_file), "--only", "OPENAI_API_KEY"]
    dry = fv(["secrets", "import", "--hermes", *flags], env)
    assert dry.returncode == 0, dry.stderr
    assert "$FLOOR_VAULT_KEY is ignored here" in dry.stderr
    written = fv(["secrets", "import", "--hermes", *flags, "--write", "--remove-from-env"], env)
    assert written.returncode != 0
    assert env_file.read_bytes() == before
    assert not (home / "agent-vault" / "vault.db").exists()
    assert "sk-hermes-openai" not in written.stdout + written.stderr


def test_hermes_import_refuses_a_key_file(tmp_path, base_env, key):
    home, env_file = _hermes_home(tmp_path)
    before = env_file.read_bytes()
    key_file = tmp_path / "master.hex"
    key_file.write_text(key + "\n", encoding="utf-8")
    if os.name != "nt":
        key_file.chmod(0o600)
    result = _hermes_import([str(env_file), "--write", "--key-file", str(key_file)], base_env)
    assert result.returncode == 2 and "cannot read a key file" in result.stderr
    assert env_file.read_bytes() == before
    assert not (home / "agent-vault").exists()

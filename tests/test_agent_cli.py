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
    assert "hermes hvault add" in dry.stderr

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

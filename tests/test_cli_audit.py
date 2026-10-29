"""Regression tests for the fixes from the CLI audit (docs/CLI-AUDIT-2026-10-26.md).

Each test names the audit finding it pins (RUN-n, SEC-n, INS-n). Every test
uses a throwaway store and key under tmp_path; nothing touches the
developer's key store or ~/.floorvault.
"""

from __future__ import annotations

import contextlib
import getpass
import io
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from floorvault.agentenv import AgentEnvError, code_injection_variables, read_env_file
from floorvault.inspector import main

ROOT = Path(__file__).resolve().parents[1]
SECRET = "fixture-secret-value"
CUSTODY = (
    "FLOOR_VAULT_KEY",
    "VAULT_MASTER_KEY",
    "APPSTATE_KEY",
    "HERMES_VAULT_KEY",
    "FLOOR_VAULT_KEY_FILE",
)
POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX paths and symlinks")


@pytest.fixture()
def key():
    return os.urandom(32).hex()


@pytest.fixture()
def base_env(tmp_path, key):
    # Drop custody variables, and every variable the code-injection guard
    # flags (CI images and developer shells set some), so tests about bound
    # items are not refused for an unrelated reason (fv() puts src on sys.path).
    flagged = set(code_injection_variables(os.environ))
    env = {k: v for k, v in os.environ.items() if k.upper() not in CUSTODY and k not in flagged}
    home = tmp_path / "home"
    home.mkdir()
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "FLOOR_VAULT_KEY": key,
            "FLOOR_VAULT_DIR": str(tmp_path / "vault"),
        }
    )
    return env


# Import floorvault from this checkout's src without PYTHONPATH (a code-loading
# variable the bound-item guard refuses). The mutation harness runs the suite
# against a mutated copy of the repository, so the subprocess must load that
# copy's source rather than the installed package.
_LAUNCH = (
    f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r}); "
    "from floorvault.inspector import main; sys.exit(main())"
)


def _prompted(*_args, **_kwargs):
    raise AssertionError("the command prompted for a value")


def fv(args, env, *, stdin=None):
    """Run the CLI with ``env`` as its whole environment.

    Only ``run`` needs a process of its own (it execs the command on POSIX).
    Everything else runs in this process, which keeps this file cheap for the
    mutation harness: it runs the whole suite once per curated mutant.
    """
    if args[0] == "run":
        return subprocess.run(
            [sys.executable, "-c", _LAUNCH, *args],
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            timeout=120,
        )
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", *args]),
        mock.patch.object(sys, "stdin", io.StringIO(stdin or "")),
        mock.patch.object(getpass, "getpass", _prompted),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            code = main()
        except SystemExit as exc:  # argparse exits for usage errors and --help
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return subprocess.CompletedProcess(args, code, out.getvalue(), err.getvalue())


@pytest.fixture()
def store(base_env):
    for item_id, fields in (("one", f"value={SECRET}\n"), ("multi", "user=u\ntoken=t0k3n\n")):
        added = fv(["secrets", "add", item_id, "--id", item_id, "--stdin"], base_env, stdin=fields)
        assert added.returncode == 0, added.stderr
    return Path(base_env["FLOOR_VAULT_DIR"])


def _printenv(tmp_path, *names):
    script = tmp_path / "printenv.py"
    script.write_text(
        "import os, sys\nfor n in sys.argv[1:]:\n    print(f'{n}={os.environ.get(n, \"\")}')\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script), *names]


# ------------------------------------------------------------------------ run


def test_run_1_code_loading_variable_set_by_a_reference_blocks_bound_items(
    tmp_path, base_env, store
):
    command = _printenv(tmp_path, "X")
    allowed = fv(["secrets", "allow", "one", "--", *command], base_env)
    assert allowed.returncode == 0, allowed.stderr
    result = fv(
        ["run", "-e", "X=fv:one", "-e", "LD_PRELOAD=fv:multi:user", "--", *command], base_env
    )
    assert result.returncode == 125
    assert "LD_PRELOAD is set" in result.stderr
    assert SECRET not in result.stdout


@POSIX
def test_run_2_starts_exactly_the_path_its_binding_was_checked_against(tmp_path, base_env, store):
    real = tmp_path / "real" / "bin"
    evil = tmp_path / "evil" / "x" / "bin"
    real.mkdir(parents=True)
    evil.mkdir(parents=True)
    for directory, word in ((real, "real"), (evil, "EVIL")):
        prog = directory / "prog"
        prog.write_text(f"#!/bin/sh\necho {word}\n", encoding="utf-8")
        prog.chmod(0o755)
    (tmp_path / "evil" / "x" / "y").mkdir()
    # real/sub -> evil/x/y, so the kernel resolves real/sub/../bin to evil/x/bin.
    (tmp_path / "real" / "sub").symlink_to(tmp_path / "evil" / "x" / "y")
    allowed = fv(["secrets", "allow", "one", "--", str(real / "prog")], base_env)
    assert allowed.returncode == 0, allowed.stderr
    result = fv(
        ["run", "-e", "X=fv:one", "--", str(tmp_path / "real" / "sub" / ".." / "bin" / "prog")],
        base_env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "real"


def test_run_3_strips_a_key_file_copy_even_without_references(tmp_path, base_env, store, key):
    key_file = tmp_path / "fv.key"
    key_file.write_text(key, encoding="utf-8")
    key_file.chmod(0o600)
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    env["COPY"] = key
    result = fv(["run", "--key-file", str(key_file), "--", *_printenv(tmp_path, "COPY")], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "COPY="


def test_run_4_uv_python_blocks_bound_items(tmp_path, base_env, store):
    command = _printenv(tmp_path, "X")
    assert fv(["secrets", "allow", "one", "--", *command], base_env).returncode == 0
    result = fv(["run", "-e", "X=fv:one", "--", *command], {**base_env, "UV_PYTHON": "/tmp/x"})
    assert result.returncode == 125
    assert "UV_PYTHON is set" in result.stderr


@pytest.mark.parametrize("separator", [" ", " ", "\x0c", "\x0b", "\x1d", "\x85"])
def test_run_5_env_file_refuses_hidden_line_breaks(tmp_path, separator):
    env_file = tmp_path / "e.env"
    env_file.write_text(f"GREETING=hello{separator}STOLEN=fv:one\n", encoding="utf-8")
    with pytest.raises(AgentEnvError) as info:
        read_env_file(env_file)
    assert f"U+{ord(separator):04X}" in str(info.value)
    assert "hello" not in str(info.value)


def test_run_5_env_file_line_endings_still_work(tmp_path):
    env_file = tmp_path / "e.env"
    env_file.write_bytes(b"A=1\r\nB=2\rC=3\nD=4")
    parsed = {line.name: line.value for line in read_env_file(env_file).assignments()}
    assert parsed == {"A": "1", "B": "2", "C": "3", "D": "4"}


def test_run_6_unusable_command_path_is_127_not_a_traceback(base_env):
    result = fv(["run", "--", "/" + "a" * 300 + "/x"], base_env)
    assert result.returncode == 127
    assert "Traceback" not in result.stderr


def test_run_7_key_copy_in_another_hex_case_is_stripped(tmp_path, base_env, store, key):
    env = {**base_env, "COPY": key.upper()}
    result = fv(["run", "-e", "X=fv:one", "--", *_printenv(tmp_path, "COPY")], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "COPY="


def test_run_8_help_goes_to_stderr(base_env):
    result = fv(["run", "--help"], base_env)
    assert result.returncode == 0
    assert result.stdout == ""
    assert "floorvault run" in result.stderr


WINDOWS = pytest.mark.skipif(os.name != "nt", reason="Windows-only behaviour")


def _exe(directory: Path, name: str) -> Path:
    """An empty file standing in for an executable.

    Fixtures carry PATHEXT's upper-case extensions: Windows matches names
    case-insensitively, the Linux and macOS runners of these tests do not.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"")
    return path


def test_run_10_windows_lookup_never_searches_the_current_directory(tmp_path, monkeypatch):
    from floorvault.agent_cli import _windows_which

    cwd, bin_dir = tmp_path / "cwd", tmp_path / "bin"
    _exe(cwd, "node.EXE")
    bin_dir.mkdir()
    monkeypatch.chdir(cwd)
    # Not on PATH: not found, even though the working directory holds one.
    assert _windows_which("node", str(bin_dir), ".COM;.EXE") is None
    # Empty entries (a trailing ';') do not stand for the working directory either.
    assert _windows_which("node", f";{bin_dir};", ".COM;.EXE") is None
    found = _exe(bin_dir, "node.EXE")
    assert _windows_which("node", f";{bin_dir};", ".COM;.EXE") == str(found)


def test_run_10_windows_lookup_follows_path_order_and_pathext(tmp_path):
    from floorvault.agent_cli import _windows_which

    first, second = tmp_path / "first", tmp_path / "second"
    _exe(second, "tool.EXE")
    cmd = _exe(first, "tool.CMD")
    path = f"{first};{second}"
    # PATH order wins over PATHEXT order, as in Windows' own search.
    assert _windows_which("tool", path, ".EXE;.CMD") == str(cmd)
    # A name that already carries a PATHEXT extension is tried as given.
    assert _windows_which("tool.EXE", path, ".EXE;.CMD") == str(second / "tool.EXE")
    # Without PATHEXT, the Windows default list applies.
    assert _windows_which("tool", str(second), None) == str(second / "tool.EXE")
    # An extension outside PATHEXT is not run directly.
    _exe(first, "tool.py")
    assert _windows_which("tool.py", str(first), ".EXE") is None


@WINDOWS
def test_run_10_working_directory_executable_is_not_found_on_windows(tmp_path, monkeypatch):
    from floorvault.agent_cli import _find_command

    _exe(tmp_path, "fvcwdprobe.exe")
    monkeypatch.chdir(tmp_path)
    environ = {"PATH": os.environ.get("SystemRoot", r"C:\Windows"), "PATHEXT": ".EXE"}
    assert _find_command("fvcwdprobe", environ) == (None, 127)
    # Naming it as a path is the operator's explicit choice.
    path, code = _find_command(r".\fvcwdprobe.exe", environ)
    assert code == 0 and Path(path).name == "fvcwdprobe.exe"


@WINDOWS
def test_run_10_drive_relative_command_is_a_path_on_windows(tmp_path, monkeypatch):
    from floorvault.agent_cli import _find_command

    _exe(tmp_path, "fvdriveprobe.exe")
    monkeypatch.chdir(tmp_path)
    drive = os.path.splitdrive(str(tmp_path))[0]
    environ = {"PATH": os.environ.get("SystemRoot", r"C:\Windows"), "PATHEXT": ".EXE"}
    # "C:fvdriveprobe.exe" names a file in the drive's working directory: it is
    # looked up as a path, never joined onto PATH entries.
    path, code = _find_command(f"{drive}fvdriveprobe.exe", environ)
    assert code == 0 and Path(path).name == "fvdriveprobe.exe"
    assert _find_command(f"{drive}fvdriveprobe", environ) == (None, 127)


@pytest.mark.skipif(not hasattr(__import__("signal"), "SIGBREAK"), reason="Windows SIGBREAK")
def test_run_11_ctrl_break_is_ignored_while_waiting(monkeypatch):
    import signal

    from floorvault import agent_cli

    seen = []

    class Child:
        def wait(self):
            seen.append(signal.getsignal(signal.SIGBREAK))
            return 3

    before = signal.getsignal(signal.SIGBREAK)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: Child())
    assert agent_cli._spawn_and_wait("x", ["x"], {}) == 3
    assert seen == [signal.SIG_IGN]
    assert signal.getsignal(signal.SIGBREAK) == before


@WINDOWS
def test_run_11_ctrl_break_does_not_end_run_before_its_child(tmp_path, base_env):
    import signal
    import time

    go = tmp_path / "go"
    child = (
        "import os, signal, sys, time\n"
        "signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
        "print('ready', flush=True)\n"
        "deadline = time.monotonic() + 60\n"
        f"while not os.path.exists({str(go)!r}) and time.monotonic() < deadline:\n"
        "    time.sleep(0.05)\n"
        "sys.exit(7)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", _LAUNCH, "run", "--", sys.executable, "-c", child],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=base_env,
        cwd=ROOT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
        time.sleep(1)
        assert proc.poll() is None, "Ctrl+Break ended run while its child kept running"
        go.write_text("")
        assert proc.wait(timeout=60) == 7
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_run_12_names_fold_to_one_variable_on_windows():
    from floorvault.agentenv import collect

    inherited = {"PATH": "inherited", "API_KEY": "plain"}
    env, refs = collect(inherited, [{"Path": "from-file"}], ["Api_Key=fv:item"], fold_case=True)
    assert env == {"PATH": "from-file"}
    assert set(refs) == {"API_KEY"}
    # POSIX names are case-sensitive: both spellings stay.
    env, refs = collect(inherited, [{"Path": "from-file"}], ["Api_Key=fv:item"], fold_case=False)
    assert env == {"PATH": "inherited", "Path": "from-file", "API_KEY": "plain"}
    assert set(refs) == {"Api_Key"}


@WINDOWS
def test_run_12_later_env_file_wins_whatever_the_spelling(tmp_path, base_env):
    # Python 3.11+ keeps the last-inserted of names that differ only in case;
    # the second file updates the inherited name in place, so without folding
    # the first file's spelling (inserted later) reached the child instead.
    first, second = tmp_path / "first.env", tmp_path / "second.env"
    first.write_text("Fv_Case_Probe=first\n")
    second.write_text("FV_CASE_PROBE=second\n")
    env = {**base_env, "FV_CASE_PROBE": "inherited"}
    probe = "import os; print(os.environ['FV_CASE_PROBE'])"
    files = ["--env-file", str(first), "--env-file", str(second)]
    result = fv(["run", *files, "--", sys.executable, "-c", probe], env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "second"


# -------------------------------------------------------------------- secrets


def test_sec_1_import_refuses_the_key_file_pointer(tmp_path, base_env):
    env_file = tmp_path / ".env"
    env_file.write_text("FLOOR_VAULT_KEY_FILE=/run/secrets/fv\nX=1\n", encoding="utf-8")
    result = fv(["secrets", "import", str(env_file)], base_env)
    assert result.returncode == 0, result.stderr
    assert "FLOOR_VAULT_KEY_FILE: left as is (a vault key variable" in result.stdout
    assert "X -> fv:x" in result.stdout


def test_sec_2_allow_change_is_one_transaction(tmp_path, key):
    from floorvault import FloorVault
    from floorvault.vaultkit.vault import VaultStore

    store = VaultStore(
        tmp_path / "v", crypto=FloorVault(bytes.fromhex(key), memory_mode="disabled")
    )
    prog = os.path.abspath("/opt/tool/bin/server")
    store.add_item("generic", "Token", {"value": SECRET}, item_id="tok")
    seen = []

    def change(current):
        # A second writer cannot get in while the change is being decided.
        other = sqlite3.connect(tmp_path / "v" / "vault.db", timeout=0.1)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("UPDATE vault_items SET allowed_commands = NULL")
        finally:
            other.close()
        seen.append(current)
        return [[prog]]

    assert store.update_allowed_commands("tok", change) == [[prog]]
    assert seen == [None]

    def refuse(current):
        raise RuntimeError("refused")

    with pytest.raises(RuntimeError):
        store.update_allowed_commands("tok", refuse)
    assert store.get_allowed_commands("tok") == [[prog]]


def test_sec_2_allow_remove_last_line_is_still_refused(tmp_path, base_env, store):
    command = _printenv(tmp_path)
    assert fv(["secrets", "allow", "one", "--", *command], base_env).returncode == 0
    refused = fv(["secrets", "allow", "one", "--remove", "--", *command], base_env)
    assert refused.returncode == 1
    assert "last command line" in refused.stderr
    assert "bound to 1 command line" in fv(["secrets", "show", "one"], base_env).stdout


def test_sec_3_hermes_import_refuses_floor_vault_key_file(tmp_path, base_env, key):
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "state.db").write_bytes(b"")
    (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
    env_file = home / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-test\n", encoding="utf-8")
    key_file = tmp_path / "fv.key"
    key_file.write_text(key, encoding="utf-8")
    key_file.chmod(0o600)
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    env.update({"HERMES_HOME": str(home), "FLOOR_VAULT_KEY_FILE": str(key_file)})
    result = fv(["secrets", "import", "--hermes", str(env_file), "--write"], env)
    assert result.returncode == 2
    assert "$FLOOR_VAULT_KEY_FILE" in result.stderr
    assert not (home / "agent-vault").exists()
    assert env_file.read_text(encoding="utf-8") == "OPENAI_API_KEY=sk-test\n"


def test_sec_4_import_leaves_a_copy_of_the_master_key(tmp_path, base_env, key):
    env_file = tmp_path / ".env"
    env_file.write_text(f"BACKUP={key.upper()}\nX=1\n", encoding="utf-8")
    result = fv(["secrets", "import", str(env_file), "--write"], base_env)
    assert result.returncode == 0, result.stderr
    assert "BACKUP: left as is (a copy of a vault key" in result.stdout
    assert f"BACKUP={key.upper()}" in env_file.read_text(encoding="utf-8")


def test_sec_5_whitespace_values_are_refused_or_left(tmp_path, base_env):
    added = fv(["secrets", "add", "Label", "a=   "], base_env)
    assert added.returncode == 2
    assert "has no value" in added.stderr
    env_file = tmp_path / ".env"
    env_file.write_text('A="   "\nB=real\n', encoding="utf-8")
    result = fv(["secrets", "import", str(env_file), "--write"], base_env)
    assert result.returncode == 0, result.stderr
    assert "A: left as is (empty)" in result.stdout
    assert env_file.read_text(encoding="utf-8") == 'A="   "\nB=fv:b\n'


def test_sec_6_add_with_another_key_is_refused_and_changes_nothing(base_env, store):
    other = {**base_env, "FLOOR_VAULT_KEY": os.urandom(32).hex()}
    refused = fv(["secrets", "add", "Two", "value=two", "--id", "two"], other)
    assert refused.returncode == 1
    assert "this key does not open the vault" in refused.stderr
    listed = fv(["secrets", "list"], base_env)
    assert listed.returncode == 0, listed.stderr
    assert [line.split("\t")[0] for line in listed.stdout.splitlines()] == ["multi", "one"]


@pytest.mark.parametrize(
    "item_id,field", [("one", ":lead"), ("one", "nl\nx"), ("one", " "), ("bad id", "f")]
)
def test_sec_7_put_validates_before_prompting(base_env, store, item_id, field):
    # stdin is empty: a prompt would fail differently from the usage error.
    result = fv(["secrets", "put", item_id, field], base_env, stdin="")
    assert result.returncode == 2, result.stderr


def test_sec_8_labels_stay_one_line(tmp_path, base_env, store, key):
    refused = fv(["secrets", "add", "evil\nroot\tgeneric\tProd", "value=y"], base_env)
    assert refused.returncode == 2
    assert "control character" in refused.stderr
    # A label already stored with a newline (by the library) is escaped in list.
    from floorvault import FloorVault
    from floorvault.agent_cli import APP_CONTEXT
    from floorvault.vaultkit.vault import VaultStore

    lib = VaultStore(store, crypto=FloorVault(bytes.fromhex(key), app_instance_id=APP_CONTEXT))
    lib.add_item("generic", "evil\nroot", {"value": "y"}, item_id="old")
    listed = fv(["secrets", "list"], base_env)
    assert "old\tgeneric\tevil\\x0aroot" in listed.stdout.splitlines()


def test_sec_9_ref_prints_only_resolvable_references(base_env, store):
    several = fv(["secrets", "ref", "multi"], base_env)
    assert several.returncode == 1
    assert "several fields (user, token)" in several.stderr
    assert fv(["secrets", "ref", "multi", "--field", "nope"], base_env).returncode == 1
    assert fv(["secrets", "ref", "one", "--field", ""], base_env).returncode == 2
    assert fv(["secrets", "ref", "multi", "--field", "token"], base_env).stdout == (
        "fv:multi:token\n"
    )
    assert fv(["secrets", "ref", "one"], base_env).stdout == "fv:one\n"


def test_sec_10_init_help_does_not_offer_key_options(base_env):
    help_text = fv(["secrets", "init", "--help"], base_env).stdout
    assert "--key-env" not in help_text and "--key-file" not in help_text
    assert "--vault" in help_text


def test_sec_11_conflicting_key_options_are_a_usage_error(tmp_path, base_env, store):
    result = fv(["secrets", "list", "--key-env", "X", "--key-file", str(tmp_path / "k")], base_env)
    assert result.returncode == 2
    assert "not both" in result.stderr


def test_sec_12_duplicate_id_gets_a_clear_message(base_env, store):
    result = fv(["secrets", "add", "Again", "value=v", "--id", "one"], base_env)
    assert result.returncode == 1
    assert "item one already exists" in result.stderr


def _no_key_env(base_env, tmp_path, vault):
    env = {k: v for k, v in base_env.items() if k != "FLOOR_VAULT_KEY"}
    env = {k: v for k, v in env.items() if not k.startswith(("DISPLAY", "WAYLAND", "DBUS"))}
    env["FLOOR_VAULT_DIR"] = str(vault)
    return env


def test_sec_17_no_custody_names_cli_options_and_leaves_no_directory(tmp_path, base_env):
    from floorvault.providers import adaptive
    from floorvault.providers.base import NoCustodyError

    vault = tmp_path / "a" / "b" / "vault"
    env = _no_key_env(base_env, tmp_path, vault)

    def no_custody(self, *, allow_create=True):
        raise NoCustodyError("Refusing headless fallback (library wording)")

    with mock.patch.object(adaptive.AdaptiveKeyProvider, "resolve_key", no_custody):
        result = fv(["secrets", "add", "T", "--id", "t", "--stdin"], env, stdin="value=v\n")
    assert result.returncode == 1
    for hint in ("--key-file", "$FLOOR_VAULT_KEY_FILE", "--key-env", "--custody systemd-creds"):
        assert hint in result.stderr
    assert "AdaptiveKeyProvider(" not in result.stderr
    assert not (tmp_path / "a").exists()


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="needs a host without OS custody: the stripped environment has no Secret "
    "Service on Linux, while macOS and Windows have a key store",
)
def test_sec_17_on_a_host_without_os_custody(tmp_path, base_env):
    vault = tmp_path / "vault"
    env = _no_key_env(base_env, tmp_path, vault)
    result = fv(["secrets", "add", "T", "--id", "t", "--stdin"], env, stdin="value=v\n")
    assert result.returncode == 1
    assert "no key is available here" in result.stderr
    assert "AdaptiveKeyProvider(" not in result.stderr
    assert not vault.exists()


# -------------------------------------------------------------------- inspect


def _inspect(args, env):
    return fv(["inspect", *args], env)


@pytest.fixture()
def table_db(tmp_path, key):
    """A table written by EncryptedSQLiteTable (folded names) plus extra rows."""
    from floorvault import FloorVault
    from floorvault.sqlite_adapter import EncryptedSQLiteTable

    path = tmp_path / "a.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE Users (id TEXT, uid TEXT, secret BLOB, bin BLOB)")
    crypto = FloorVault(bytes.fromhex(key))
    conn.execute("INSERT INTO Users (id) VALUES ('1')")
    EncryptedSQLiteTable(conn, crypto, "Users").store("1", "secret", SECRET)
    # Binary, revision-bound and duplicate-id rows written through the core API.
    conn.execute(
        "INSERT INTO Users (id, uid, bin) VALUES (?, ?, ?)",
        ("2", "u2", crypto.encrypt(b"\xff\x00", table="Users", record_id="2", column="bin")),
    )
    conn.execute(
        "INSERT INTO Users (id, uid, secret) VALUES (?, ?, ?)",
        (
            "3",
            "u3",
            crypto.encrypt("rev", table="Users", record_id="3", column="secret", revision=4),
        ),
    )
    conn.execute(
        "INSERT INTO Users (id, uid, secret) VALUES (?, ?, ?)",
        ("u9", "u9", crypto.encrypt("by-uid", table="Users", record_id="u9", column="secret")),
    )
    conn.execute("INSERT INTO Users (id) VALUES ('dup')")
    conn.execute("INSERT INTO Users (id) VALUES ('dup')")
    conn.commit()
    conn.close()
    return path


def test_ins_1_corrupt_database_is_a_clean_error(tmp_path, base_env):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"SQLite format 3\x00" + os.urandom(200))
    result = _inspect([str(bad), "t", "1", "c"], base_env)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr and result.stderr.startswith("Error:")


def test_ins_2_and_3_bad_arguments_are_clean_errors(base_env, table_db):
    empty_app = _inspect([str(table_db), "Users", "1", "secret", "--app-instance", ""], base_env)
    assert empty_app.returncode == 1 and "Traceback" not in empty_app.stderr
    dotted = _inspect([str(table_db), "Users", "1", "Users.secret"], base_env)
    assert dotted.returncode == 1 and "bare column name" in dotted.stderr


def test_ins_4_folded_names_authenticate(base_env, table_db):
    result = _inspect([str(table_db), "Users", "1", "secret", "--reveal"], base_env)
    assert result.returncode == 0, result.stderr
    assert f"Decrypted value: {SECRET}" in result.stdout
    assert "Authenticated as users.secret" in result.stdout


def test_ins_5_duplicate_ids_are_refused(base_env, table_db):
    result = _inspect([str(table_db), "Users", "dup", "secret"], base_env)
    assert result.returncode == 1
    assert "more than one row" in result.stderr


def test_ins_6_binary_values_authenticate(base_env, table_db):
    redacted = _inspect([str(table_db), "Users", "2", "bin"], base_env)
    assert redacted.returncode == 0, redacted.stderr
    assert "Decrypted binary value: <redacted>" in redacted.stdout
    revealed = _inspect([str(table_db), "Users", "2", "bin", "--reveal"], base_env)
    assert "ff00" in revealed.stdout


def test_ins_7_id_column_and_revision(base_env, table_db):
    by_revision = _inspect([str(table_db), "Users", "3", "secret", "--revision", "4"], base_env)
    assert by_revision.returncode == 0, by_revision.stderr
    assert _inspect([str(table_db), "Users", "3", "secret"], base_env).returncode == 1
    by_uid = _inspect(
        [str(table_db), "Users", "u9", "secret", "--id-column", "uid", "--reveal"], base_env
    )
    assert by_uid.returncode == 0, by_uid.stderr
    assert "by-uid" in by_uid.stdout


# --------------------------------------------- inspect: key options, schema (#100)


def _no_default_key(base_env):
    return {k: v for k, v in base_env.items() if k.upper() not in CUSTODY}


def test_ins_8_inspect_takes_the_same_key_options_as_run(tmp_path, base_env, table_db, key):
    env = {**_no_default_key(base_env), "MY_KEY": key}
    row = [str(table_db), "Users", "1", "secret", "--reveal"]
    by_env = _inspect([*row, "--key-env", "MY_KEY"], env)
    assert by_env.returncode == 0, by_env.stderr
    assert f"Decrypted value: {SECRET}" in by_env.stdout

    key_file = tmp_path / "key.hex"
    key_file.write_text(key + "\n")
    os.chmod(key_file, 0o600)
    by_file = _inspect([*row, "--key-file", str(key_file)], env)
    assert by_file.returncode == 0, by_file.stderr
    by_variable = _inspect(row, {**env, "FLOOR_VAULT_KEY_FILE": str(key_file)})
    assert by_variable.returncode == 0, by_variable.stderr
    assert f"Decrypted value: {SECRET}" in by_variable.stdout

    wrong = _inspect([*row, "--key-env", "OTHER"], {**env, "OTHER": "ab" * 32})
    assert wrong.returncode == 1
    assert SECRET not in wrong.stdout + wrong.stderr


def test_ins_8_inspect_key_option_errors(tmp_path, base_env, table_db, key):
    env = _no_default_key(base_env)
    row = [str(table_db), "Users", "1", "secret"]
    both = _inspect([*row, "--key-env", "K", "--key-file", str(tmp_path / "k")], env)
    assert both.returncode == 2
    assert "not both" in both.stderr
    unset = _inspect([*row, "--key-env", "NOT_SET_ANYWHERE"], env)
    assert unset.returncode == 1
    assert "--key-env NOT_SET_ANYWHERE is not set" in unset.stderr
    missing = _inspect([*row, "--key-file", str(tmp_path / "absent")], env)
    assert missing.returncode == 1
    assert "Traceback" not in missing.stderr


def test_ins_8_inspect_never_creates_a_key(tmp_path, base_env, table_db):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    home = Path(base_env["HOME"])
    before = sorted(home.rglob("*"))
    result = _inspect(
        [
            str(table_db),
            "Users",
            "1",
            "secret",
            "--key-dir",
            str(key_dir),
            "--service-name",
            f"fv-test-{os.urandom(4).hex()}",
        ],
        _no_default_key(base_env),
    )
    assert result.returncode == 1
    assert list(key_dir.iterdir()) == []
    assert sorted(home.rglob("*")) == before


def test_ins_7_schema_id_and_version_select_the_record_identity(tmp_path, base_env, key):
    from floorvault import FloorVault

    path = tmp_path / "s.db"
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE t (id TEXT, c BLOB)")
        cipher = FloorVault(bytes.fromhex(key)).encrypt(
            SECRET, table="t", record_id="1", column="c", schema_id="app.v2", schema_version=3
        )
        conn.execute("INSERT INTO t VALUES ('1', ?)", (cipher,))
        conn.commit()
    row = [str(path), "t", "1", "c", "--reveal"]
    assert _inspect(row, base_env).returncode == 1
    assert _inspect([*row, "--schema-id", "app.v2"], base_env).returncode == 1
    assert _inspect([*row, "--schema-version", "3"], base_env).returncode == 1
    both = _inspect([*row, "--schema-id", "app.v2", "--schema-version", "3"], base_env)
    assert both.returncode == 0, both.stderr
    assert f"Decrypted value: {SECRET}" in both.stdout
    empty = _inspect([*row, "--schema-id", " "], base_env)
    assert empty.returncode == 1
    assert "--schema-id must not be empty" in empty.stderr

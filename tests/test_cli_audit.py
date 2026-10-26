"""Regression tests for the fixes from the CLI audit (docs/CLI-AUDIT-2026-10-26.md).

Each test names the audit finding it pins (RUN-n, SEC-n, INS-n). Every test
uses a throwaway store and key under tmp_path; nothing touches the
developer's key store or ~/.floorvault.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from floorvault.agentenv import AgentEnvError, code_injection_variables, read_env_file

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


def fv(args, env, *, stdin=None):
    return subprocess.run(
        [sys.executable, "-c", _LAUNCH, *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=120,
    )


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

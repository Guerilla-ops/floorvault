"""The hermesvault plugin's command-binding checks, without a Hermes checkout.

tests/test_hermes_plugin.py drives the whole secret source but needs Hermes' own
``agent`` package, so it skips in CI. The binding logic lives in
``plugins/hermesvault/binding_guard.py``, which imports nothing from Hermes, so
these tests run everywhere and the curated mutants for it are killed in CI.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "hermesvault"))

from binding_guard import (  # noqa: E402
    binding_problem,
    binding_record_problems,
    gateway_command_line,
    hermes_command_lines,
    started_as,
)

from floorvault import FloorVault  # noqa: E402
from floorvault.binding_record import BindingRecord  # noqa: E402
from floorvault.vaultkit.vault import VaultStore  # noqa: E402

HERMES = os.path.abspath("/opt/hermes/bin/hermes")
PYTHON = os.path.abspath("/opt/hermes/venv/bin/python")
ITEM = "vault_testopenai"


@pytest.fixture()
def store(tmp_path):
    vault = VaultStore(
        tmp_path / "vault", crypto=FloorVault(os.urandom(32), memory_mode="disabled")
    )
    vault.add_item("generic", "openai", {"value": "sk-test-123"}, item_id=ITEM)
    vault.add_item("generic", "other", {"value": "x"}, item_id="vault_other")
    vault.database = tmp_path / "vault" / "vault.db"  # for tests that write the file directly
    return vault


def _as_started(monkeypatch, argv, orig_argv=None, executable=PYTHON):
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "orig_argv", orig_argv or [executable, *argv], raising=False)
    monkeypatch.setattr(sys, "executable", executable)


def _write_binding(store, item_id, value):
    with contextlib.closing(sqlite3.connect(store.database)) as db:
        db.execute("UPDATE vault_items SET allowed_commands = ? WHERE id = ?", (value, item_id))
        db.commit()


def _sealed(store, item_id):
    with contextlib.closing(sqlite3.connect(store.database)) as db:
        return db.execute(
            "SELECT allowed_commands FROM vault_items WHERE id = ?", (item_id,)
        ).fetchone()[0]


# ----------------------------------------------------------- what Hermes started as


def test_a_script_launch_is_its_argv_with_the_absolute_program(monkeypatch):
    _as_started(monkeypatch, [HERMES, "gateway", "run"])
    assert [HERMES, "gateway", "run"] in hermes_command_lines()


def test_an_interpreter_launch_is_the_interpreter_and_its_arguments(monkeypatch):
    module = os.path.abspath("/opt/hermes/lib/hermes_cli/__main__.py")
    original = [PYTHON, "-m", "hermes_cli", "gateway", "run"]
    _as_started(monkeypatch, [module, "gateway", "run"], orig_argv=original)
    lines = hermes_command_lines()
    assert original in lines and [module, "gateway", "run"] in lines


def test_a_relative_program_path_is_never_resolved_against_the_current_directory(
    monkeypatch, tmp_path
):
    # Hermes started as ./hermes, then the process moved to another directory: the
    # path can no longer be turned back into the program that started, so it is
    # not offered at all (and a binding for whatever the cwd now names must not match).
    _as_started(monkeypatch, ["./hermes", "chat"], orig_argv=["python3", "./hermes", "chat"])
    monkeypatch.setattr(sys, "executable", "python3")
    monkeypatch.chdir(tmp_path)
    assert hermes_command_lines() == []
    assert "relative program path cannot be matched" in started_as()


def _executable(path):
    path.write_text("")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows decides what is executable by extension"
)
def test_the_warning_names_the_line_that_can_be_bound_not_a_script_that_cannot(
    monkeypatch, tmp_path
):
    # `python main.py gateway run`: sys.argv[0] is a script, which `secrets allow` refuses
    # ("not executable"); the interpreter line is the one an operator can bind.
    script = tmp_path / "main.py"
    script.write_text("")
    interpreter = _executable(tmp_path / "python3")
    original = [str(interpreter), "-m", "hermes_cli.main", "gateway", "run"]
    _as_started(
        monkeypatch,
        [str(script), "gateway", "run"],
        orig_argv=original,
        executable=str(interpreter),
    )
    text = started_as()
    assert text == shlex.join(original)
    assert str(script) not in text


def test_the_warning_names_every_spelling_that_can_be_bound(monkeypatch, tmp_path):
    runner = _executable(tmp_path / "hermes.bat")
    interpreter = _executable(tmp_path / "python3.bat")
    _as_started(
        monkeypatch,
        [str(runner), "chat"],
        orig_argv=[str(interpreter), str(runner), "chat"],
        executable=str(interpreter),
    )
    text = started_as()
    assert shlex.join([str(runner), "chat"]) in text
    assert shlex.join([str(interpreter), str(runner), "chat"]) in text


def test_there_may_be_no_command_line_at_all(monkeypatch):
    _as_started(monkeypatch, [], orig_argv=[], executable="")
    assert hermes_command_lines() == []
    assert started_as() == "an unknown command line"


# ------------------------------------------------------------------ the check itself


def test_a_bound_item_may_be_resolved_for_the_command_it_is_bound_to(store):
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    assert binding_problem(store, ITEM, [[HERMES, "gateway", "run"]], False) is None


def test_a_bound_item_may_not_be_resolved_for_another_command(store, monkeypatch):
    _as_started(monkeypatch, [HERMES, "chat"])
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    lines = hermes_command_lines()
    problem = binding_problem(store, ITEM, lines, False)
    assert problem is not None and "bound to other command lines" in problem
    # shlex.join quotes a Windows path, as `floorvault run` does when it names a command.
    assert shlex.join([HERMES, "chat"]) in problem and "hermes hvault allow" in problem
    assert "sk-test-123" not in problem
    for argv in ([HERMES], [HERMES, "gateway"], [HERMES, "gateway", "run", "--debug"]):
        assert binding_problem(store, ITEM, [argv], False) is not None, argv


def test_any_of_several_bound_lines_will_do(store):
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"], [HERMES, "chat"]])
    for line in ([HERMES, "gateway", "run"], [HERMES, "chat"]):
        assert binding_problem(store, ITEM, [line], False) is None
    assert binding_problem(store, ITEM, [[HERMES, "doctor"]], False) is not None


def test_either_description_of_the_process_may_be_the_bound_one(store):
    store.set_allowed_commands(ITEM, [[PYTHON, "-m", "hermes_cli", "run"]])
    lines = [[HERMES, "run"], [PYTHON, "-m", "hermes_cli", "run"]]
    assert binding_problem(store, ITEM, lines, False) is None


def test_with_no_command_line_a_bound_item_is_refused(store):
    store.set_allowed_commands(ITEM, [[HERMES, "chat"]])
    problem = binding_problem(store, ITEM, [], False)
    assert problem is not None and "bound to other command lines" in problem


def test_an_unbound_item_is_allowed_unless_a_binding_is_required(store):
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], False) is None
    problem = binding_problem(store, ITEM, [[HERMES, "chat"]], True)
    assert problem is not None
    assert "require_binding" in problem and f"hermes hvault allow {ITEM}" in problem


def test_a_binding_cleared_in_vault_db_blocks_the_item_only_when_required(store):
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], False) is not None
    _write_binding(store, ITEM, None)  # whoever can write vault.db, with no key (#97)
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], False) is None
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], True) is not None


def test_a_binding_that_does_not_authenticate_blocks_the_item(store):
    store.set_allowed_commands(ITEM, [[HERMES, "chat"]])
    _write_binding(store, ITEM, b"not a sealed value")
    assert "cannot be read" in binding_problem(store, ITEM, [[HERMES, "chat"]], False)
    assert "cannot be read" in binding_problem(store, ITEM, [[HERMES, "chat"]], True)


def test_a_binding_copied_from_another_item_does_not_authenticate(store):
    store.set_allowed_commands("vault_other", [[HERMES, "chat"]])
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    _write_binding(store, ITEM, _sealed(store, "vault_other"))
    assert "cannot be read" in binding_problem(store, ITEM, [[HERMES, "chat"]], False)


def test_a_floorvault_that_cannot_read_bindings_is_flagged_when_they_are_required():
    class Old:  # floorvault before 0.2.8: no get_allowed_commands
        pass

    assert binding_problem(Old(), ITEM, [[HERMES, "chat"]], False) is None
    problem = binding_problem(Old(), ITEM, [[HERMES, "chat"]], True)
    assert problem is not None and "older than 0.2.8" in problem


class _Without:
    """A store that lacks one attribute, as an older floorvault would."""

    def __init__(self, store, missing):
        self._store, self._missing = store, missing

    def __getattr__(self, name):
        if name == self._missing:
            raise AttributeError(name)
        return getattr(self._store, name)


def test_the_hint_names_the_command_that_works_with_the_installed_floorvault(store, monkeypatch):
    """`hermes hvault allow` needs the sealed record of floorvault 0.3.0; 0.2.x binds with `floorvault secrets allow`."""
    _as_started(monkeypatch, [HERMES, "chat"])
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    lines = hermes_command_lines()
    new = binding_problem(store, ITEM, lines, False)
    assert new is not None and f"`hermes hvault allow {ITEM}" in new
    old = binding_problem(_Without(store, "binding_fingerprint"), ITEM, lines, False)
    assert old is not None and f"`floorvault secrets allow {ITEM}" in old
    assert "hermes hvault allow" not in old
    # An unbound item under require_binding gets the same capability-dependent hint.
    unbound = binding_problem(_Without(store, "binding_fingerprint"), "vault_other", lines, True)
    assert unbound is not None and "floorvault secrets allow vault_other" in unbound
    assert "hermes hvault allow" in binding_problem(store, "vault_other", lines, True)
    # Reading bindings does not need 0.3.0: a store with get_allowed_commands but no
    # fingerprint still enforces.
    assert binding_problem(_Without(store, "binding_fingerprint"), ITEM, [[HERMES, "x"]], False)


def test_the_gateway_line_follows_hermes_profile_selection(tmp_path, monkeypatch):
    """Hermes passes --profile default unless the home is a profiles/<name> directory."""
    monkeypatch.setattr(sys, "executable", PYTHON)
    monkeypatch.setattr(sys, "platform", "linux")
    tail = ["-m", "hermes_cli.main", "gateway", "run", "--quiet", "--idle-exit"]
    root_home = tmp_path / "hermes"
    root_home.mkdir()
    assert gateway_command_line(root_home) == [
        PYTHON,
        "-m",
        "hermes_cli.main",
        "--profile",
        "default",
        *tail[2:],
    ]
    named = tmp_path / "hermes" / "profiles" / "work"
    named.mkdir(parents=True)
    assert gateway_command_line(named) == [PYTHON, *tail]


def test_the_gateway_line_is_unknown_on_windows_or_without_an_absolute_interpreter(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(sys, "executable", PYTHON)
    monkeypatch.setattr(sys, "platform", "win32")
    assert gateway_command_line(tmp_path) is None
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "executable", "python3")
    assert gateway_command_line(tmp_path) is None


# ------------------------------------------------- the record kept outside the store


@pytest.fixture()
def recorded(store, tmp_path):
    """The store, its directory, and the record `allow` would keep for it."""
    base = tmp_path / "vault"
    environ = {"FLOOR_VAULT_STATE_DIR": str(tmp_path / "state")}
    return store, base, environ, BindingRecord(base, tmp_path / "state")


def _problems(recorded, items=(ITEM, "vault_other")):
    store, base, environ, _ = recorded
    return binding_record_problems(store, base, items, environ)


def test_a_store_that_never_had_a_record_is_judged_as_before(recorded, tmp_path):
    assert _problems(recorded) == ({}, [])
    assert not (tmp_path / "state").exists(), "resolving must create nothing"


def test_a_recorded_binding_that_is_unchanged_has_no_problem(recorded):
    store, _, _, record = recorded
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    record.record(ITEM, store.binding_fingerprint(ITEM))
    before = record.path.read_bytes()
    assert _problems(recorded) == ({}, [])
    assert record.path.read_bytes() == before, "an unrecorded item must not be added"


def test_a_binding_cleared_in_vault_db_is_refused_without_require_binding(recorded):
    store, _, _, record = recorded
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    record.record(ITEM, store.binding_fingerprint(ITEM))
    _write_binding(store, ITEM, None)  # whoever can write vault.db, with no key (#97)
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], False) is None  # the store alone
    problems, notes = _problems(recorded)
    assert list(problems) == [ITEM] and notes == []
    assert "changed since it was last recorded" in problems[ITEM]
    assert f"hermes hvault allow {ITEM} --accept" in problems[ITEM]


def test_an_older_wider_binding_written_back_is_refused(recorded):
    store, _, _, record = recorded
    store.set_allowed_commands(ITEM, [[HERMES, "chat"], [HERMES, "gateway", "run"]])
    older = _sealed(store, ITEM)
    store.set_allowed_commands(ITEM, [[HERMES, "gateway", "run"]])
    record.record(ITEM, store.binding_fingerprint(ITEM))
    _write_binding(store, ITEM, older)
    # It authenticates and allows the command, so only the record can refuse it.
    assert binding_problem(store, ITEM, [[HERMES, "chat"]], True) is None
    assert list(_problems(recorded)[0]) == [ITEM]


def test_a_record_that_exists_and_cannot_be_read_refuses_every_item(recorded):
    store, _, _, record = recorded
    record.record(ITEM, store.binding_fingerprint(ITEM))
    record.path.write_bytes(b"not a record")
    problems, notes = _problems(recorded)
    assert sorted(problems) == sorted([ITEM, "vault_other"]) and notes == []
    assert all("cannot be checked against the binding record" in p for p in problems.values())


def test_a_lost_record_is_said_and_refuses_nothing(recorded):
    store, _, _, record = recorded
    record.record(ITEM, store.binding_fingerprint(ITEM))
    record.path.unlink()  # the marker in the store directory stays
    problems, notes = _problems(recorded)
    assert problems == {} and len(notes) == 1
    assert "is missing" in notes[0] and "not noticed here" in notes[0]
    assert not record.path.exists(), "resolving must not start a new record"


def test_a_state_directory_inside_the_store_is_said_and_refuses_nothing(store, tmp_path):
    base = tmp_path / "vault"
    problems, notes = binding_record_problems(
        store, base, [ITEM], {"FLOOR_VAULT_STATE_DIR": str(base / "state")}
    )
    assert problems == {} and len(notes) == 1 and "no binding record can be kept" in notes[0]


def test_a_missing_item_is_left_to_resolution_to_report(recorded):
    store, _, _, record = recorded
    record.record(ITEM, "0" * 64)
    assert _problems(recorded, items=["vault_gone"]) == ({}, [])


def test_a_floorvault_that_cannot_read_the_record_checks_nothing(recorded, monkeypatch):
    store, base, environ, record = recorded
    record.record(ITEM, "0" * 64)  # differs from the stored "none"
    assert list(_problems(recorded)[0]) == [ITEM]
    monkeypatch.delattr(BindingRecord, "compare")  # floorvault 0.3.0 to 0.4.0
    problems, notes = _problems(recorded)
    assert problems == {}
    # Silence would read as "checked and fine": the operator is told it is not checked.
    assert len(notes) == 1 and "cannot check the binding record" in notes[0]
    assert "upgrade floorvault" in notes[0]
    problems, notes = binding_record_problems(
        _Without(store, "binding_fingerprint"), base, [ITEM], environ
    )
    assert problems == {} and len(notes) == 1 and "cannot check the binding record" in notes[0]

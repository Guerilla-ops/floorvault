"""The hermesvault plugin's command-binding checks, without a Hermes checkout.

tests/test_hermes_plugin.py drives the whole secret source but needs Hermes' own
``agent`` package, so it skips in CI. The binding logic lives in
``plugins/hermesvault/binding_guard.py``, which imports nothing from Hermes, so
these tests run everywhere and the curated mutants for it are killed in CI.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "hermesvault"))

from binding_guard import binding_problem, hermes_command_lines, started_as  # noqa: E402

from floorvault import FloorVault  # noqa: E402
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
    assert f"{HERMES} chat" in problem and "floorvault secrets allow" in problem
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
    assert "require_binding" in problem and f"floorvault secrets allow {ITEM}" in problem


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

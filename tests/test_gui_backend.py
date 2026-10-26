"""``floorvault.gui.backend``: the Qt-free logic behind ``floorvault-gui``.

Every test uses a throwaway store under tmp_path and a random key passed
through an explicit environment mapping, so nothing touches the developer's
key store, ~/.floorvault or os.environ.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

import pytest

from floorvault.gui.backend import (
    GuiError,
    VaultSession,
    describe_argv,
    key_source_hint,
    split_command_line,
    suggested_env_name,
)

SECRET = "fixture-secret-value"
OTHER = "fixture-other-value"


@pytest.fixture()
def environ(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PATH": os.environ.get("PATH", os.defpath),
        "FLOOR_VAULT_KEY": os.urandom(32).hex(),
    }


@pytest.fixture()
def session(tmp_path, environ):
    return VaultSession(tmp_path / "vault", key_source="env", environ=environ)


def _no_secret_in(obj) -> None:
    assert SECRET not in repr(obj)
    assert OTHER not in repr(obj)


# --------------------------------------------------------------- open / lock


def test_unlock_never_creates_a_store(session):
    assert not session.store_exists()
    with pytest.raises(GuiError, match="no vault at"):
        session.unlock()
    assert not session.store_exists()
    assert not session.unlocked


def test_first_add_creates_the_store_then_unlock_reopens_it(session, tmp_path, environ):
    item_id = session.add_generic("Token", {"value": SECRET}, item_id="tok")
    assert item_id == "tok"
    assert session.store_exists()

    again = VaultSession(tmp_path / "vault", key_source="env", environ=environ)
    again.unlock()
    assert [row.id for row in again.items()] == ["tok"]


def test_wrong_key_fails_to_unlock_with_a_safe_message(session, tmp_path, environ):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    wrong = dict(environ, FLOOR_VAULT_KEY=os.urandom(32).hex())
    other = VaultSession(tmp_path / "vault", key_source="env", environ=wrong)
    with pytest.raises(GuiError, match="this key does not open the vault") as info:
        other.unlock()
    _no_secret_in(str(info.value))
    assert wrong["FLOOR_VAULT_KEY"] not in str(info.value)
    assert not other.unlocked


def test_lock_drops_the_store(session):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    session.lock()
    assert not session.unlocked
    with pytest.raises(GuiError, match="locked"):
        session.items()


def test_adding_while_locked_with_a_store_present_is_refused(session, tmp_path, environ):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    fresh = VaultSession(tmp_path / "vault", key_source="env", environ=environ)
    with pytest.raises(GuiError, match="unlock the vault first"):
        fresh.add_generic("Other", {"value": OTHER})


def test_key_file_source(tmp_path, environ):
    key_file = tmp_path / "fv.key"
    key_file.write_text(os.urandom(32).hex())
    if os.name == "posix":
        key_file.chmod(0o600)
    env = {k: v for k, v in environ.items() if k != "FLOOR_VAULT_KEY"}
    first = VaultSession(tmp_path / "vault", key_source="file", key_file=key_file, environ=env)
    first.add_generic("Token", {"value": SECRET}, item_id="tok")
    second = VaultSession(tmp_path / "vault", key_source="file", key_file=key_file, environ=env)
    second.unlock()
    assert second.detail("tok").fields[0].is_set


def test_key_file_source_without_a_path_says_so(tmp_path, environ):
    s = VaultSession(tmp_path / "vault", key_source="file", environ=environ)
    with pytest.raises(GuiError, match="choose a key file"):
        s.add_generic("Token", {"value": SECRET})


def test_unknown_key_source_is_rejected(tmp_path, environ):
    with pytest.raises(GuiError):
        VaultSession(tmp_path / "vault", key_source="paper", environ=environ)


def test_os_only_refuses_both_environment_keys_when_creating(tmp_path, environ, monkeypatch):
    """Selecting the OS key store must not silently adopt an environment key."""
    monkeypatch.setenv("FLOOR_VAULT_KEY", os.urandom(32).hex())
    monkeypatch.setenv("VAULT_MASTER_KEY", os.urandom(32).hex())
    s = VaultSession(tmp_path / "vault", key_source="os", environ=environ)
    assert s.key_description == "OS key store only"
    with pytest.raises(GuiError, match="refuses environment-variable key custody") as info:
        s.add_generic("Token", {"value": SECRET})
    assert os.environ["FLOOR_VAULT_KEY"] not in str(info.value)
    assert not s.store_exists(), "no store may be created under the refused key"


def test_os_only_refuses_environment_keys_when_unlocking(session, tmp_path, environ, monkeypatch):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")  # store under an env key
    monkeypatch.setenv("FLOOR_VAULT_KEY", environ["FLOOR_VAULT_KEY"])
    monkeypatch.setenv("VAULT_MASTER_KEY", environ["FLOOR_VAULT_KEY"])
    s = VaultSession(tmp_path / "vault", key_source="os", environ=environ)
    with pytest.raises(GuiError, match="refuses environment-variable key custody"):
        s.unlock()
    assert not s.unlocked


def test_key_description_names_the_real_source(tmp_path, environ):
    assert VaultSession(tmp_path, key_source="env", environ=environ).key_description == (
        "environment variable FLOOR_VAULT_KEY"
    )
    key_file = tmp_path / "k"
    assert (
        VaultSession(
            tmp_path, key_source="file", key_file=key_file, environ=environ
        ).key_description
        == f"key file {key_file}"
    )


def test_key_source_hint_never_shows_key_material(environ):
    hint = key_source_hint("env", environ)
    assert hint == "FLOOR_VAULT_KEY is set"
    assert environ["FLOOR_VAULT_KEY"] not in hint
    assert "not set" in key_source_hint("file", environ)


# --------------------------------------------------------------- reading


def test_detail_reports_fields_but_never_values(session):
    session.add_generic("Bot", {"token": SECRET, "chat_id": OTHER}, item_id="bot")
    detail = session.detail("bot")
    assert [(f.name, f.is_set) for f in detail.fields] == [("token", True), ("chat_id", True)]
    assert detail.reference == "fv:bot:token"
    assert detail.commands is None
    assert detail.editable
    _no_secret_in(detail)
    _no_secret_in(session.items())


def test_single_field_reference_has_no_field(session):
    session.add_generic("Key", {"api_key": SECRET}, item_id="openai-prod")
    detail = session.detail("openai-prod")
    assert detail.reference == "fv:openai-prod"
    assert detail.env_name == "OPENAI_PROD"


def test_suggested_env_name():
    assert suggested_env_name("github.token") == "GITHUB_TOKEN"
    assert suggested_env_name("9lives") is None


def test_detail_of_a_missing_item(session):
    session.add_generic("Key", {"v": SECRET}, item_id="a")
    with pytest.raises(GuiError, match="not found"):
        session.detail("missing")


# --------------------------------------------------------------- writing


@pytest.mark.parametrize(
    "label,fields,item_id,match",
    [
        ("", {"v": SECRET}, None, "label"),
        ("L", {}, None, "at least one field"),
        ("L", {"v": SECRET}, "bad id!", "the id may use only"),
        ("L", {" ": SECRET}, None, "needs a name"),
        ("L", {"a\nb": SECRET}, None, "NUL or newline"),
        ("L", {"v": "  "}, None, "has no value"),
    ],
)
def test_add_validates_input(session, label, fields, item_id, match):
    with pytest.raises(GuiError, match=match) as info:
        session.add_generic(label, fields, item_id=item_id)
    _no_secret_in(str(info.value))


def test_add_refuses_an_existing_id(session):
    session.add_generic("A", {"v": SECRET}, item_id="dup")
    with pytest.raises(GuiError, match="already exists"):
        session.add_generic("B", {"v": OTHER}, item_id="dup")


def test_set_field_replaces_and_adds_fields(session):
    session.add_generic("Bot", {"token": SECRET}, item_id="bot")
    session.set_field("bot", "token", OTHER)
    session.set_field("bot", "chat_id", OTHER)
    names = [f.name for f in session.detail("bot").fields]
    assert names == ["token", "chat_id"]


def test_set_field_refuses_empty(session):
    session.add_generic("Bot", {"token": SECRET}, item_id="bot")
    with pytest.raises(GuiError, match="empty value"):
        session.set_field("bot", "token", "")


def test_remove(session):
    session.add_generic("A", {"v": SECRET}, item_id="a")
    session.remove("a")
    assert session.items() == []
    with pytest.raises(GuiError, match="not found"):
        session.remove("a")


# --------------------------------------------------------------- bindings


def test_resolve_command_line_pins_an_absolute_program(session):
    argv, warnings = session.resolve_command_line(f'"{sys.executable}" -m http.server')
    assert os.path.isabs(argv[0])
    assert argv[1:] == ["-m", "http.server"]
    assert warnings == []


@pytest.mark.parametrize(
    "text,expected",
    [
        # The review's case: a quoted value after '=' stays one argument.
        (r'python.exe --name="two words"', ["python.exe", "--name=two words"]),
        # A quoted program path keeps its backslashes.
        (
            r'"C:\Program Files\Python\python.exe" -m one',
            [r"C:\Program Files\Python\python.exe", "-m", "one"],
        ),
        # Escaped quotes, outside and inside quotes.
        (r'prog a\"b "c\"d"', ["prog", 'a"b', 'c"d']),
        # 2n backslashes before a quote: n backslashes, and the quote toggles.
        (r'prog e\\"f g" h', ["prog", "e\\f g", "h"]),
        # A trailing backslash in a quoted argument is written doubled.
        (r'prog "C:\dir\\" next', ["prog", "C:\\dir\\", "next"]),
        # Backslashes not before a quote are literal.
        (r"prog a\\b c\d", ["prog", "a\\\\b", "c\\d"]),
        # "" inside quotes is a literal quote; an empty quoted argument survives.
        (r'prog "say ""hi""" ""', ["prog", 'say "hi"', ""]),
        # The program name: backslashes are literal even before a quote.
        (r'"C:\dir\" x', ["C:\\dir\\", "x"]),
        ("  prog\t a  ", ["prog", "a"]),
    ],
)
def test_windows_command_lines_follow_the_c_runtime(text, expected):
    assert split_command_line(text, windows=True) == expected


def test_describe_argv_shows_argument_boundaries():
    assert describe_argv(["prog", "--name=two words", ""]) == (
        "  [0] prog\n  [1] --name=two words\n  [2] "
    )


def test_split_command_line_strips_windows_quotes():
    text = r'"C:\Program Files\Python\python.exe" -m one "two words"'
    assert split_command_line(text, windows=True) == [
        r"C:\Program Files\Python\python.exe",
        "-m",
        "one",
        "two words",
    ]
    assert split_command_line("npx -y '@scope/server'", windows=False) == [
        "npx",
        "-y",
        "@scope/server",
    ]
    for windows in (True, False):
        with pytest.raises(ValueError):
            split_command_line('"unterminated', windows=windows)


def test_resolve_command_line_rejects_unknown_programs(session):
    with pytest.raises(GuiError, match="not found"):
        session.resolve_command_line("definitely-not-a-real-program-xyz --flag")
    with pytest.raises(GuiError, match="give a command line"):
        session.resolve_command_line("   ")


def test_bind_at_add_then_add_and_remove_lines(session):
    first, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    second, _ = session.resolve_command_line(f'"{sys.executable}" -m two')
    session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=first)
    assert session.detail("a").commands == (tuple(first),)
    assert session.items()[0].unbound is False

    session.bind("a", second)
    assert len(session.detail("a").commands) == 2
    session.unbind_line("a", first)
    assert session.detail("a").commands == (tuple(second),)


def test_bind_at_add_never_uses_a_second_write(session, monkeypatch):
    """The binding is written with the item, not by a later set_allowed_commands."""
    from floorvault.vaultkit.vault import VaultStore

    def refuse(*_a, **_k):
        raise AssertionError("binding must be part of add_item's transaction")

    monkeypatch.setattr(VaultStore, "set_allowed_commands", refuse)
    argv, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=argv)
    assert session.detail("a").commands == (tuple(argv),)


def test_a_failed_binding_at_add_leaves_no_unbound_item(session, monkeypatch):
    from floorvault.vaultkit.vault import VaultStore

    session.add_generic("Seed", {"v": OTHER}, item_id="seed")  # creates the store
    real = VaultStore._encrypt_metadata

    def fail_on_binding(self, item_id, column, value):
        if column == "allowed_commands":
            raise RuntimeError("injected failure")
        return real(self, item_id, column, value)

    monkeypatch.setattr(VaultStore, "_encrypt_metadata", fail_on_binding)
    argv, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    with pytest.raises(GuiError, match="adding the item failed"):
        session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=argv)
    monkeypatch.undo()
    assert [row.id for row in session.items()] == ["seed"]


def test_removing_the_last_line_is_refused_clearing_is_explicit(session):
    argv, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=argv)
    with pytest.raises(GuiError, match="last command line"):
        session.unbind_line("a", argv)
    assert session.detail("a").commands is not None

    session.clear_binding("a")
    assert session.detail("a").commands is None
    assert session.items()[0].unbound is True


def test_unbinding_a_line_that_is_not_bound(session):
    argv, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    other, _ = session.resolve_command_line(f'"{sys.executable}" -m two')
    session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=argv)
    with pytest.raises(GuiError, match="is not bound to"):
        session.unbind_line("a", other)


def test_binding_changes_are_one_transaction(session, monkeypatch):
    """bind and unbind_line go through update_allowed_commands (audit SEC-2): a
    separate read then write could restore a line another change removed."""
    from floorvault.vaultkit.vault import VaultStore

    first, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    second, _ = session.resolve_command_line(f'"{sys.executable}" -m two')
    session.add_generic("A", {"v": SECRET}, item_id="a", bind_to=first)

    def refuse(*_a, **_k):
        raise AssertionError("binding changes must read and write in one transaction")

    monkeypatch.setattr(VaultStore, "set_allowed_commands", refuse)
    monkeypatch.setattr(VaultStore, "get_allowed_commands", refuse)
    session.bind("a", second)
    session.unbind_line("a", first)
    with pytest.raises(GuiError, match="last command line"):
        session.unbind_line("a", second)
    monkeypatch.undo()
    assert session.detail("a").commands == (tuple(second),)


# --------------------------------------------------------------- import


def _env(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "project.env"
    path.write_text(text, encoding="utf-8")
    return path


def test_import_preview_then_write(session, tmp_path):
    path = _env(
        tmp_path,
        f"OPENAI_API_KEY={SECRET}\n"
        "ANTHROPIC_API_KEY=fv:anthropic\n"
        "FLOOR_VAULT_KEY=00\n"
        "EMPTY=\n"
        f"LOG_LEVEL={OTHER}\n",
    )
    preview = session.preview_import(path, skip=["LOG_LEVEL"])
    _no_secret_in(preview)
    statuses = {row.name: row.status for row in preview.rows}
    assert statuses == {
        "OPENAI_API_KEY": "new",
        "ANTHROPIC_API_KEY": "left",
        "FLOOR_VAULT_KEY": "left",
        "EMPTY": "left",
        "LOG_LEVEL": "skipped",
    }
    assert [row.name for row in preview.rows][0] == "OPENAI_API_KEY"
    assert not preview.vault_exists and preview.can_write
    assert not session.store_exists(), "a preview must change nothing"

    assert preview.skip == ("LOG_LEVEL",)
    result = session.run_import(preview)
    assert (result.stored, result.rewritten) == (1, 1)
    text = path.read_text(encoding="utf-8")
    assert SECRET not in text
    assert "OPENAI_API_KEY=fv:openai_api_key" in text
    assert f"LOG_LEVEL={OTHER}" in text
    assert session.detail("openai_api_key").fields[0].is_set


def test_import_leaves_key_copies_and_the_key_file_pointer(session, tmp_path, environ):
    """Audit SEC-1 and SEC-4, through the GUI's own key settings."""
    path = _env(
        tmp_path,
        f"BACKUP_KEY={environ['FLOOR_VAULT_KEY'].upper()}\n"
        f"FLOOR_VAULT_KEY_FILE={tmp_path / 'k'}\n"
        f"OPENAI_API_KEY={SECRET}\n",
    )
    statuses = {row.name: row.status for row in session.preview_import(path).rows}
    assert statuses == {
        "BACKUP_KEY": "left",
        "FLOOR_VAULT_KEY_FILE": "left",
        "OPENAI_API_KEY": "new",
    }


def test_import_same_value_is_reused_and_a_different_one_blocks(session, tmp_path):
    session.add_generic("Old", {"value": SECRET}, item_id="token")
    session.add_generic("Old db", {"value": "something-else"}, item_id="database_url")

    same = _env(tmp_path, f"TOKEN={SECRET}\n")
    preview = session.preview_import(same)
    assert preview.rows[0].status == "same" and preview.can_write
    assert session.run_import(preview).stored == 0
    assert same.read_text(encoding="utf-8") == "TOKEN=fv:token\n"

    clash = tmp_path / "clash.env"
    clash.write_text(f"DATABASE_URL={OTHER}\n", encoding="utf-8")
    preview = session.preview_import(clash)
    assert preview.rows[0].status == "conflict"
    assert not preview.can_write
    with pytest.raises(GuiError, match="different contents"):
        session.run_import(preview)
    assert OTHER in clash.read_text(encoding="utf-8"), "a blocked import must not rewrite"

    with_prefix = session.preview_import(clash, prefix="app.")
    assert with_prefix.rows[0].status == "new" and with_prefix.can_write


def test_import_executes_the_previewed_prefix_only(session, tmp_path):
    path = _env(tmp_path, f"TOKEN={SECRET}\n")
    preview = session.preview_import(path, prefix="app.")
    assert preview.references == (("TOKEN", "app.token"),)
    session.run_import(preview)
    assert path.read_text(encoding="utf-8") == "TOKEN=fv:app.token\n"


def test_import_refuses_a_plan_that_differs_from_its_preview(session, tmp_path):
    path = _env(tmp_path, f"TOKEN={SECRET}\n")
    preview = session.preview_import(path, prefix="app.")
    tampered = dataclasses.replace(preview, prefix="prod.")
    with pytest.raises(GuiError, match="no longer matches its preview"):
        session.run_import(tampered)
    assert SECRET in path.read_text(encoding="utf-8")
    assert not session.store_exists()


def test_import_refuses_a_file_changed_since_preview(session, tmp_path):
    path = _env(tmp_path, f"TOKEN={SECRET}\n")
    preview = session.preview_import(path)
    path.write_text(f"TOKEN={SECRET}\nNEW={OTHER}\n", encoding="utf-8")
    with pytest.raises(GuiError, match="changed since the preview"):
        session.run_import(preview)
    assert not session.store_exists()


def test_import_needs_unlock_when_a_store_exists(session, tmp_path, environ):
    session.add_generic("A", {"value": SECRET}, item_id="a")
    locked = VaultSession(tmp_path / "vault", key_source="env", environ=environ)
    with pytest.raises(GuiError, match="unlock the vault first"):
        locked.preview_import(_env(tmp_path, f"TOKEN={OTHER}\n"))


def test_import_refuses_a_hermes_env(tmp_path, environ):
    hermes = tmp_path / "hermes-home"
    hermes.mkdir()
    env = dict(environ, HERMES_HOME=str(hermes))
    s = VaultSession(tmp_path / "vault", key_source="env", environ=env)
    path = hermes / ".env"
    path.write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    with pytest.raises(GuiError, match="--hermes"):
        s.preview_import(path)


def test_import_rejects_a_bad_prefix(session, tmp_path):
    with pytest.raises(GuiError, match="prefix"):
        session.preview_import(_env(tmp_path, f"TOKEN={SECRET}\n"), prefix="bad prefix")


@pytest.mark.skipif(os.name != "posix", reason="symlink creation needs privileges on Windows")
def test_import_write_refuses_a_symlink(session, tmp_path):
    real = _env(tmp_path, f"TOKEN={SECRET}\n")
    link = tmp_path / "link.env"
    link.symlink_to(real)
    preview = session.preview_import(link)
    with pytest.raises(GuiError, match="not a regular file"):
        session.run_import(preview)
    assert SECRET in real.read_text(encoding="utf-8")


# --------------------------------------------------------------- entry point


def test_gui_help_works_without_importing_qt(capsys, monkeypatch):
    from floorvault.gui import app

    monkeypatch.setitem(sys.modules, "PySide6", None)
    with pytest.raises(SystemExit) as info:
        app.main(["--help"])
    assert info.value.code == 0
    assert "floorvault-gui" in capsys.readouterr().out


def test_gui_without_pyside6_prints_the_install_hint(capsys, monkeypatch):
    from floorvault.gui import app

    monkeypatch.setitem(sys.modules, "PySide6", None)
    assert app.main([]) == 1
    assert 'pip install "floorvault[gui]"' in capsys.readouterr().err


def test_core_package_never_imports_the_gui():
    import subprocess

    code = (
        "import sys, floorvault, floorvault.agent_cli, floorvault.inspector;"
        "assert not any(m.startswith(('floorvault.gui', 'PySide6')) for m in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)

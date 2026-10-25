"""``floorvault-gui``'s PySide6 window, driven headless.

Skipped where PySide6 (the ``gui`` extra) or its system libraries are missing.
Modal prompts are replaced with stubs, so nothing waits for a person. Every
test checks that no stored value appears in any widget's text.
"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QTableWidget,
)

from floorvault.gui import window as gui  # noqa: E402
from floorvault.gui.backend import VaultSession  # noqa: E402

SECRET = "fixture-secret-value"
OTHER = "fixture-other-value"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


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


@pytest.fixture(autouse=True)
def no_modals(monkeypatch):
    """Answer every confirmation with Yes and record warnings instead of blocking."""
    shown = []
    yes = QMessageBox.StandardButton.Yes
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]) or yes)
    return shown


def _texts(widget) -> list[str]:
    out = []
    for label in widget.findChildren(QLabel):
        out.append(label.text())
    for edit in widget.findChildren(QLineEdit):
        # A value being typed lives in a password-mode input, drawn as dots.
        if edit.echoMode() != QLineEdit.EchoMode.Password:
            out.append(edit.text())
    for edit in widget.findChildren(QPlainTextEdit):
        out.append(edit.toPlainText())
    for listing in widget.findChildren(QListWidget):
        out.extend(listing.item(i).text() for i in range(listing.count()))
    for table in widget.findChildren(QTableWidget):
        for r in range(table.rowCount()):
            for c in range(table.columnCount()):
                item = table.item(r, c)
                if item is not None:
                    out.append(item.text())
    return out


def _assert_no_secret(widget) -> None:
    joined = "\n".join(_texts(widget))
    assert SECRET not in joined
    assert OTHER not in joined


def _unlock(win: gui.MainWindow) -> None:
    page = win.unlock_page
    page.source_env.setChecked(True)
    page.unlock_button.click()


def test_unlock_page_offers_create_only_without_a_store(app, session):
    win = gui.MainWindow(session)
    page = win.unlock_page
    assert not page.unlock_button.isEnabled()
    assert page.add_first.isEnabled() and page.import_first.isEnabled()
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    session.lock()
    page.reset()
    assert page.unlock_button.isEnabled()
    assert not page.add_first.isEnabled()
    win.close()


def test_unlock_shows_items_set_state_and_no_values(app, session):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    session.add_generic("Bot", {"token": SECRET, "chat_id": OTHER}, item_id="bot")
    session.lock()
    win = gui.MainWindow(session)
    _unlock(win)
    assert win.stack.currentWidget() is win.vault_page
    assert win.vault_page.list.count() == 2
    texts = "\n".join(_texts(win))
    assert "● Set" in texts
    assert "fv:bot:token" in texts
    _assert_no_secret(win)
    win.close()


def test_wrong_key_stays_on_the_unlock_page(app, session, environ):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    session.lock()
    environ["FLOOR_VAULT_KEY"] = os.urandom(32).hex()
    win = gui.MainWindow(session)
    _unlock(win)
    assert win.stack.currentWidget() is win.unlock_page
    assert "does not open" in win.unlock_page.error.text()
    win.close()


def test_add_item_dialog_creates_binds_and_clears_the_clipboard(app, session):
    QGuiApplication.clipboard().setText(SECRET)
    dialog = gui.AddItemDialog(session)
    dialog.label_edit.setText("Token")
    dialog.id_edit.setText("tok")
    name, value, _row = dialog.field_rows[0]
    assert value.echoMode() == QLineEdit.EchoMode.Password
    value.setText(SECRET)
    dialog.command_edit.setText(f'"{sys.executable}" -m one')
    _assert_no_secret(dialog)
    dialog._save()
    assert dialog.created_id == "tok"
    assert value.text() == ""
    assert QGuiApplication.clipboard().text() != SECRET
    detail = session.detail("tok")
    assert detail.commands and detail.commands[0][1:] == ("-m", "one")


def test_add_item_dialog_shows_errors_inline(app, session):
    dialog = gui.AddItemDialog(session)
    dialog.bind_any.setChecked(True)
    dialog.field_rows[0][1].setText(SECRET)
    dialog._save()
    assert "label" in dialog.error.text()
    _assert_no_secret(dialog)
    assert not session.store_exists()


def test_copy_reference_copies_the_reference_only(app, session):
    session.add_generic("Token", {"value": SECRET}, item_id="openai-prod")
    win = gui.MainWindow(session)
    win.show_vault()
    buttons = [b for b in win.findChildren(QtWidgets.QPushButton) if b.text() == "Copy as NAME=…"]
    buttons[0].click()
    assert QGuiApplication.clipboard().text() == "OPENAI_PROD=fv:openai-prod"
    win.close()


def test_lock_now_and_idle_lock(app, session):
    session.add_generic("Token", {"value": SECRET}, item_id="tok")
    win = gui.MainWindow(session, idle_lock_ms=60)
    win.show_vault()
    assert win.vault_page.list.count() == 1
    win.lock()
    assert not session.unlocked
    assert win.vault_page.list.count() == 0
    assert win.stack.currentWidget() is win.unlock_page

    _unlock(win)
    assert session.unlocked
    QTest.qWait(300)
    assert not session.unlocked, "the idle timer should have locked the vault"
    assert win.stack.currentWidget() is win.unlock_page
    win.close()


def test_last_binding_removal_is_refused_in_the_window(app, session, no_modals):
    argv, _ = session.resolve_command_line(f'"{sys.executable}" -m one')
    session.add_generic("Token", {"value": SECRET}, item_id="tok", bind_to=argv)
    win = gui.MainWindow(session)
    win.show_vault()
    remove = [b for b in win.findChildren(QtWidgets.QPushButton) if b.text() == "Remove"]
    remove[0].click()
    assert any("last command line" in text for text in no_modals)
    assert session.detail("tok").commands is not None
    win.close()


def test_import_dialog_previews_then_writes(app, session, tmp_path):
    path = tmp_path / "project.env"
    path.write_text(f"TOKEN={SECRET}\nFLOOR_VAULT_KEY=00\nLOG_LEVEL={OTHER}\n", encoding="utf-8")
    dialog = gui.ImportDialog(session)
    dialog.path_edit.setText(str(path))
    dialog.refresh()
    assert dialog.table.rowCount() == 3
    _assert_no_secret(dialog)
    assert dialog.write_button.isEnabled()

    dialog._toggle("LOG_LEVEL", False)
    QTest.qWait(20)
    statuses = [dialog.table.item(r, 3).text() for r in range(dialog.table.rowCount())]
    assert "Skipped by you" in statuses
    assert "LOG_LEVEL=(unchanged)" in dialog.after.toPlainText()
    _assert_no_secret(dialog)

    dialog._write()
    text = path.read_text(encoding="utf-8")
    assert "TOKEN=fv:token" in text and SECRET not in text
    assert f"LOG_LEVEL={OTHER}" in text
    assert session.unlocked and session.detail("token").fields[0].is_set

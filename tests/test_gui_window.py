"""``floorvault-gui``'s PySide6 window, driven headless.

Skipped where PySide6 (the ``gui`` extra) or its system libraries are missing,
unless FLOORVAULT_REQUIRE_GUI_TESTS=1 is set: then a missing Qt is a failure,
so the CI job that exists to run these tests cannot pass by skipping them.
Modal prompts are replaced with stubs, so nothing waits for a person. Every
test checks that no stored value appears in any widget's text.
"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if os.environ.get("FLOORVAULT_REQUIRE_GUI_TESTS") == "1":
    from PySide6 import QtWidgets
else:
    QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QInputDialog,
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
# The real confirmation, kept before the autouse stub replaces it.
REAL_QUESTION = QMessageBox.question


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


# Every dialog a test creates gets this parent, which lives for the whole run.
# A parentless dialog whose signal lambdas form a reference cycle would be freed
# by Python's cycle collector at an arbitrary moment - possibly inside a later
# test's nested event loop - and Qt crashes when that happens. In the app every
# dialog has a parent, so this only affects tests.
_KEEP: list = []


def _parent():
    if not _KEEP:
        _KEEP.append(QtWidgets.QWidget())
    return _KEEP[0]


@pytest.fixture(autouse=True)
def close_dialogs(app):
    yield
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, QDialog) and widget.isVisible():
            widget.reject()


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
    dialog = gui.AddItemDialog(session, _parent())
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
    dialog = gui.AddItemDialog(session, _parent())
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
    dialog = gui.ImportDialog(session, _parent())
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


# --------------------------------------------------------------- stale previews


def _previewed(session, tmp_path):
    path = tmp_path / "project.env"
    path.write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    dialog = gui.ImportDialog(session, _parent())
    dialog.path_edit.setText(str(path))
    dialog.prefix_edit.setText("app.")
    dialog.refresh()
    assert dialog.preview is not None and dialog.write_button.isEnabled()
    assert dialog.preview.references == (("TOKEN", "app.token"),)
    return dialog, path


def test_changing_the_prefix_after_preview_withdraws_it(app, session, tmp_path):
    dialog, path = _previewed(session, tmp_path)
    dialog.prefix_edit.setText("prod.")
    assert dialog.preview is None
    assert not dialog.write_button.isEnabled()
    assert dialog.table.rowCount() == 0
    dialog._write()
    assert SECRET in path.read_text(encoding="utf-8"), "a stale preview must not write"

    dialog.refresh()
    assert dialog.preview.references == (("TOKEN", "prod.token"),)
    dialog._write()
    assert path.read_text(encoding="utf-8") == "TOKEN=fv:prod.token\n"


def test_changing_the_path_after_preview_withdraws_it(app, session, tmp_path):
    dialog, path = _previewed(session, tmp_path)
    other = tmp_path / "other.env"
    other.write_text(f"OTHER={OTHER}\n", encoding="utf-8")
    dialog.path_edit.setText(str(other))
    assert dialog.preview is None and not dialog.write_button.isEnabled()
    dialog._write()
    assert SECRET in path.read_text(encoding="utf-8")
    assert OTHER in other.read_text(encoding="utf-8")


# --------------------------------------------------------------- locking over dialogs


def _visible_dialogs():
    return [w for w in QApplication.topLevelWidgets() if isinstance(w, QDialog) and w.isVisible()]


def _lock_while(win, open_modal, fill):
    """Run ``open_modal`` (it blocks in exec) and let the idle lock end it.

    ``fill`` runs inside the modal's event loop, before the lock. A safety
    timer rejects anything still open after 3 s so a regression fails instead
    of hanging; it records what it had to close.
    """
    left_open: list[str] = []

    def safety():
        for dialog in _visible_dialogs():
            left_open.append(type(dialog).__name__)
            dialog.reject()

    guard = QTimer()
    guard.setSingleShot(True)
    guard.timeout.connect(safety)
    guard.start(3000)
    QTimer.singleShot(20, fill)
    win.idle_timer.start()
    try:
        result = open_modal()
    finally:
        guard.stop()
    assert left_open == [], f"the lock left these dialogs open: {left_open}"
    assert not win.session.unlocked
    assert win.stack.currentWidget() is win.unlock_page
    assert _visible_dialogs() == []
    return result


@pytest.fixture()
def locking_window(app, session):
    session.add_generic("Token", {"value": OTHER}, item_id="tok")
    win = gui.MainWindow(session, idle_lock_ms=150)
    win.show_vault()
    win.idle_timer.stop()
    yield win
    win.close()


def test_lock_clears_and_closes_the_add_item_dialog(locking_window):
    win = locking_window
    seen = {}

    def fill():
        dialog = next(d for d in _visible_dialogs() if isinstance(d, gui.AddItemDialog))
        seen["dialog"] = dialog
        dialog.label_edit.setText("Typed label")
        dialog.field_rows[0][1].setText(SECRET)

    _lock_while(win, win.vault_page._add, fill)
    dialog = seen["dialog"]
    assert dialog.field_rows[0][1].text() == ""
    assert dialog.label_edit.text() == ""
    assert dialog.created_id is None


def test_lock_clears_the_import_preview(locking_window, tmp_path):
    win = locking_window
    path = tmp_path / "project.env"
    path.write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    seen = {}

    def fill():
        dialog = next(d for d in _visible_dialogs() if isinstance(d, gui.ImportDialog))
        seen["dialog"] = dialog
        dialog.path_edit.setText(str(path))
        dialog.refresh()
        assert dialog.table.rowCount() == 1

    _lock_while(win, win.vault_page._import, fill)
    dialog = seen["dialog"]
    assert dialog.preview is None
    assert dialog.table.rowCount() == 0
    assert dialog.path_edit.text() == "" and dialog.after.toPlainText() == ""
    assert SECRET in path.read_text(encoding="utf-8")


def test_lock_ends_a_value_prompt_without_saving(locking_window, environ):
    win = locking_window

    def fill():
        prompt = next(d for d in _visible_dialogs() if isinstance(d, QInputDialog))
        prompt.setTextValue(OTHER + "-replacement")

    _lock_while(win, lambda: win.vault_page.detail._set_field("value"), fill)
    win.session.unlock()
    assert win.session.detail("tok").fields[0].is_set


def test_lock_answers_a_pending_import_confirmation_with_no(locking_window, tmp_path, monkeypatch):
    win = locking_window
    path = tmp_path / "project.env"
    path.write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    dialog = gui.ImportDialog(win.session, _parent())
    dialog.path_edit.setText(str(path))
    dialog.refresh()
    monkeypatch.setattr(QMessageBox, "question", REAL_QUESTION)

    _lock_while(win, dialog._write, lambda: None)
    assert SECRET in path.read_text(encoding="utf-8"), "a dismissed confirmation must not write"
    dialog.close()

"""The PySide6 front end of ``floorvault-gui``. All vault logic lives in ``backend``.

What this layer adds on top of the backend's rules:

* Secret inputs use password echo, which also disables copying out of them.
* After a value is saved, the clipboard is cleared if it still holds that value
  (the usual way a secret arrives is a paste).
* The window locks itself after a period with no keyboard or mouse input.
* Copy buttons copy ``fv:`` references only. There is no way to copy or reveal
  a stored value.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .backend import (
    DEFAULT_KEY_ENV,
    GuiError,
    ImportPreview,
    ItemDetail,
    VaultSession,
    key_source_hint,
)

IDLE_LOCK_MS = 5 * 60 * 1000

INK = "#080808"
MUTED = "#5E5E5E"
GREEN = "#2F5E38"
WARN = "#B4501F"

STYLE = f"""
QWidget {{ font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; font-size: 14px;
          color: {INK}; background: #FFFFFF; }}
QLineEdit, QComboBox, QPlainTextEdit {{ border: 1px solid #BDBDB8; border-radius: 4px;
          padding: 7px 10px; }}
QLineEdit:focus, QPlainTextEdit:focus {{ border-color: #477D50; }}
QLineEdit:read-only {{ background: #F6F6F4; }}
QPushButton {{ border: 1px solid #BDBDB8; border-radius: 4px; padding: 8px 14px;
          background: #FFFFFF; }}
QPushButton:hover {{ border-color: {INK}; }}
QPushButton[primary="true"] {{ background: {INK}; color: #FFFFFF; border-color: {INK};
          font-weight: 600; }}
QPushButton[danger="true"] {{ color: {WARN}; border-color: {WARN}; }}
QPushButton:disabled {{ color: #8A8A85; background: #F6F6F4; border-color: #DADAD6; }}
*[mono="true"] {{ font-family: "IBM Plex Mono", "SF Mono", Menlo, Consolas,
          "DejaVu Sans Mono", monospace; }}
QLabel[role="eyebrow"] {{ font-size: 11px; letter-spacing: 1px; color: {MUTED}; }}
QLabel[role="muted"] {{ color: {MUTED}; font-size: 13px; }}
QLabel[role="error"] {{ color: {WARN}; }}
QLabel[role="title"] {{ font-size: 28px; font-weight: 700; }}
QLabel[role="brand"] {{ font-size: 22px; font-weight: 700; }}
QFrame[role="warning"] {{ border: 1px solid {WARN}; background: #FDF3EE; border-radius: 4px; }}
QFrame[role="warning"] QLabel {{ background: #FDF3EE; }}
QFrame[role="card"] {{ border: 1px solid {INK}; border-radius: 4px; }}
QListWidget {{ border: 0; border-right: 1px solid #DADAD6; }}
QListWidget::item {{ padding: 10px 12px; border-bottom: 1px solid #ECECE8; }}
QListWidget::item:selected {{ background: #EEF3EE; color: {INK}; }}
QTableWidget {{ border: 1px solid #DADAD6; gridline-color: #ECECE8; }}
QHeaderView::section {{ background: #F6F6F4; border: 0; padding: 6px; color: {MUTED}; }}
"""

BRAND = 'FloorVault<span style="color:#DD6C39">.</span>'


# ------------------------------------------------------------------ helpers


def _label(text: str = "", role: Optional[str] = None, *, mono: bool = False) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if role:
        label.setProperty("role", role)
    if mono:
        label.setProperty("mono", True)
    return label


def _button(text: str, *, primary: bool = False, danger: bool = False) -> QPushButton:
    button = QPushButton(text)
    if primary:
        button.setProperty("primary", True)
    if danger:
        button.setProperty("danger", True)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def _secret_input(placeholder: str = "value") -> QLineEdit:
    edit = QLineEdit()
    edit.setEchoMode(QLineEdit.EchoMode.Password)
    edit.setPlaceholderText(placeholder)
    edit.setInputMethodHints(
        Qt.InputMethodHint.ImhHiddenText
        | Qt.InputMethodHint.ImhSensitiveData
        | Qt.InputMethodHint.ImhNoPredictiveText
    )
    return edit


def _error(parent: QWidget, exc: Exception) -> None:
    # GuiError messages are written to be shown; anything else by type only.
    text = str(exc) if isinstance(exc, GuiError) else f"Unexpected error ({type(exc).__name__})"
    QMessageBox.warning(parent, "FloorVault", text)


def forget_clipboard_if(values: Iterable[str]) -> None:
    """Clear the clipboard when it still holds one of ``values``."""
    clipboard = QGuiApplication.clipboard()
    current = clipboard.text()
    if current and any(current == value for value in values if value):
        clipboard.clear()


def copy_reference(text: str) -> None:
    QGuiApplication.clipboard().setText(text)


def _clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            # Detach now: deleteLater alone leaves the old widget painted until
            # the event loop gets round to deleting it.
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            _clear_layout(item.layout())


def ask_secret(parent: QWidget, title: str, prompt: str) -> Optional[str]:
    value, ok = QInputDialog.getText(parent, title, prompt, QLineEdit.EchoMode.Password)
    return value if ok else None


def ask_command(parent: QWidget, session: VaultSession) -> Optional[list[str]]:
    """Ask for a command line, pin its program to a path, and confirm it."""
    text, ok = QInputDialog.getText(
        parent,
        "Bind to a command",
        "Command line allowed to receive this item\n(for example: npx -y @scope/server)",
    )
    if not ok or not text.strip():
        return None
    try:
        argv, warnings = session.resolve_command_line(text)
    except GuiError as exc:
        _error(parent, exc)
        return None
    shown = " ".join(argv)
    note = ("\n\nWarning: " + "\nWarning: ".join(warnings)) if warnings else ""
    answer = QMessageBox.question(
        parent,
        "Bind to a command",
        f"Allow exactly this command line?\n\n{shown}{note}",
    )
    return argv if answer == QMessageBox.StandardButton.Yes else None


# ------------------------------------------------------------------ unlock


class UnlockPage(QWidget):
    unlocked = Signal()

    def __init__(self, session: VaultSession, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.session = session

        title = QLabel(BRAND)
        title.setStyleSheet("font-size: 56px; font-weight: 700;")
        tagline = _label("Secrets go in. References come out. Values never show on screen.")
        tagline.setStyleSheet("font-size: 18px; font-weight: 500;")
        intro = _label(
            "This window manages the same store as `floorvault secrets`. Programs get "
            "values only through `floorvault run`.",
            "muted",
        )

        self.store_edit = QLineEdit(str(session.vault_dir))
        self.store_edit.setProperty("mono", True)
        self.store_edit.setAccessibleName("Store directory")
        self.store_edit.textChanged.connect(self._update_state)
        browse = _button("Browse…")
        browse.clicked.connect(self._browse_store)
        self.store_status = _label("", "muted")

        self.source_os = QRadioButton("OS key store")
        self.source_file = QRadioButton("Key file")
        self.source_env = QRadioButton("Environment variable")
        group = QButtonGroup(self)
        for button in (self.source_os, self.source_file, self.source_env):
            group.addButton(button)
        {"os": self.source_os, "file": self.source_file, "env": self.source_env}[
            session.key_source
        ].setChecked(True)

        self.key_file_edit = QLineEdit(str(session.key_file) if session.key_file else "")
        self.key_file_edit.setPlaceholderText(key_source_hint("file"))
        self.key_file_edit.setAccessibleName("Key file path")
        key_browse = _button("Browse…")
        key_browse.clicked.connect(self._browse_key_file)
        self.key_env_edit = QLineEdit(session.key_env or DEFAULT_KEY_ENV)
        self.key_env_edit.setProperty("mono", True)
        self.key_env_edit.setAccessibleName("Key variable name")
        for button in (self.source_os, self.source_file, self.source_env):
            button.toggled.connect(self._update_state)

        self.unlock_button = _button("Unlock", primary=True)
        self.unlock_button.clicked.connect(self._unlock)
        self.error = _label("", "error")
        self.add_first = _button("Add your first item…")
        self.add_first.clicked.connect(self._add_first)
        self.import_first = _button("Import a .env file…")
        self.import_first.clicked.connect(self._import_first)

        card = QFrame()
        card.setProperty("role", "card")
        form = QVBoxLayout(card)
        form.setContentsMargins(24, 24, 24, 24)
        form.setSpacing(10)
        heading = _label("Open vault")
        heading.setStyleSheet("font-size: 20px; font-weight: 700;")
        form.addWidget(heading)
        form.addWidget(_label("STORE", "eyebrow"))
        row = QHBoxLayout()
        row.addWidget(self.store_edit, 1)
        row.addWidget(browse)
        form.addLayout(row)
        form.addWidget(self.store_status)
        form.addSpacing(8)
        form.addWidget(_label("MASTER KEY FROM", "eyebrow"))
        form.addWidget(self.source_os)
        form.addWidget(_label("   " + key_source_hint("os"), "muted"))
        form.addWidget(self.source_file)
        row = QHBoxLayout()
        row.addSpacing(24)
        row.addWidget(self.key_file_edit, 1)
        row.addWidget(key_browse)
        form.addLayout(row)
        form.addWidget(self.source_env)
        row = QHBoxLayout()
        row.addSpacing(24)
        row.addWidget(self.key_env_edit, 1)
        form.addLayout(row)
        form.addSpacing(8)
        row = QHBoxLayout()
        row.addWidget(self.unlock_button)
        row.addWidget(_label("Opening never creates a store or a key.", "muted"), 1)
        form.addLayout(row)
        form.addWidget(self.error)
        form.addSpacing(8)
        form.addWidget(_label("No vault here yet?", "muted"))
        row = QHBoxLayout()
        row.addWidget(self.add_first)
        row.addWidget(self.import_first)
        row.addStretch(1)
        form.addLayout(row)

        left = QVBoxLayout()
        left.addWidget(title)
        left.addWidget(tagline)
        left.addWidget(intro)
        left.addStretch(1)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(48, 48, 48, 48)
        outer.setSpacing(40)
        outer.addLayout(left, 1)
        outer.addWidget(card, 1)
        self._update_state()

    def _source(self) -> str:
        if self.source_file.isChecked():
            return "file"
        if self.source_env.isChecked():
            return "env"
        return "os"

    def _apply(self) -> None:
        """Copy the form into the session."""
        self.session.lock()
        self.session.vault_dir = Path(self.store_edit.text().strip() or ".").expanduser()
        key_file = self.key_file_edit.text().strip()
        self.session.configure_key(
            self._source(),
            key_file=Path(key_file) if key_file else None,
            key_env=self.key_env_edit.text().strip() or None,
        )

    def _update_state(self) -> None:
        self.key_file_edit.setEnabled(self.source_file.isChecked())
        self.key_env_edit.setEnabled(self.source_env.isChecked())
        path = Path(self.store_edit.text().strip() or ".").expanduser()
        exists = (path / "vault.db").is_file()
        self.store_status.setText("vault.db found" if exists else "No vault here yet")
        self.unlock_button.setEnabled(exists)
        self.add_first.setEnabled(not exists)
        self.import_first.setEnabled(not exists)

    def _browse_store(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Store directory", self.store_edit.text())
        if chosen:
            self.store_edit.setText(chosen)

    def _browse_key_file(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Key file")
        if chosen:
            self.key_file_edit.setText(chosen)
            self.source_file.setChecked(True)

    def _unlock(self) -> None:
        self.error.setText("")
        try:
            self._apply()
            self.session.unlock()
        except GuiError as exc:
            self.error.setText(str(exc))
            return
        self.unlocked.emit()

    def _add_first(self) -> None:
        self.error.setText("")
        try:
            self._apply()
        except GuiError as exc:
            self.error.setText(str(exc))
            return
        if AddItemDialog(self.session, self).exec() == QDialog.DialogCode.Accepted:
            self.unlocked.emit()

    def _import_first(self) -> None:
        self.error.setText("")
        try:
            self._apply()
        except GuiError as exc:
            self.error.setText(str(exc))
            return
        dialog = ImportDialog(self.session, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and self.session.unlocked:
            self.unlocked.emit()

    def reset(self) -> None:
        self.error.setText("")
        self._update_state()


# ------------------------------------------------------------------ add item


class AddItemDialog(QDialog):
    """Create a generic item. Login, payment and address items come later."""

    def __init__(self, session: VaultSession, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.session = session
        self.created_id: Optional[str] = None
        self.setWindowTitle("New item")
        self.setMinimumWidth(620)

        self.label_edit = QLineEdit()
        self.label_edit.setPlaceholderText("Anthropic API key")
        self.label_edit.setAccessibleName("Label")
        self.id_edit = QLineEdit()
        self.id_edit.setProperty("mono", True)
        self.id_edit.setPlaceholderText("random if blank")
        self.id_edit.setAccessibleName("Item id")
        self.id_edit.textChanged.connect(self._update_reference)

        self.fields_box = QVBoxLayout()
        self.field_rows: list[tuple[QLineEdit, QLineEdit, QWidget]] = []
        add_field = _button("+ Add field")
        add_field.clicked.connect(lambda: self._add_field_row())

        self.bind_only = QRadioButton("Only this command line (recommended for agents)")
        self.bind_any = QRadioButton("Any command that names it")
        self.bind_only.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.bind_only)
        group.addButton(self.bind_any)
        self.command_edit = QLineEdit()
        self.command_edit.setProperty("mono", True)
        self.command_edit.setPlaceholderText("npx -y @scope/server")
        self.command_edit.setAccessibleName("Allowed command line")
        self.bind_only.toggled.connect(self.command_edit.setEnabled)

        self.reference = _label("", mono=True)
        self.error = _label("", "error")
        save = _button("Save to vault", primary=True)
        save.clicked.connect(self._save)
        cancel = _button("Cancel")
        cancel.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(8)
        title = _label("New item", "title")
        layout.addWidget(title)
        grid = QGridLayout()
        grid.addWidget(_label("LABEL", "eyebrow"), 0, 0)
        grid.addWidget(_label("ID (OPTIONAL)", "eyebrow"), 0, 1)
        grid.addWidget(self.label_edit, 1, 0)
        grid.addWidget(self.id_edit, 1, 1)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addWidget(
            _label(
                "Kind: generic (API keys, tokens). Login, payment and address come later.", "muted"
            )
        )
        layout.addSpacing(6)
        layout.addWidget(_label("FIELDS", "eyebrow"))
        layout.addLayout(self.fields_box)
        row = QHBoxLayout()
        row.addWidget(add_field)
        row.addWidget(
            _label(
                "Values are hidden. A pasted value is cleared from the clipboard on save.", "muted"
            ),
            1,
        )
        layout.addLayout(row)
        layout.addSpacing(6)
        layout.addWidget(_label("WHO MAY RECEIVE IT", "eyebrow"))
        layout.addWidget(self.bind_only)
        layout.addWidget(self.command_edit)
        layout.addWidget(self.bind_any)
        layout.addSpacing(6)
        layout.addWidget(_label("REFERENCE", "eyebrow"))
        layout.addWidget(self.reference)
        if not session.store_exists():
            layout.addWidget(
                _label(
                    "This is the first item: saving also creates the store and a master key.",
                    "muted",
                )
            )
        layout.addWidget(self.error)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)

        self._add_field_row("value")
        self._update_reference()

    def _add_field_row(self, name: str = "") -> None:
        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        name_edit = QLineEdit(name)
        name_edit.setProperty("mono", True)
        name_edit.setPlaceholderText("field name")
        name_edit.setAccessibleName("Field name")
        name_edit.textChanged.connect(self._update_reference)
        value_edit = _secret_input()
        value_edit.setAccessibleName("Field value")
        remove = _button("Remove")
        line.addWidget(name_edit, 1)
        line.addWidget(value_edit, 2)
        line.addWidget(remove)
        entry = (name_edit, value_edit, row)
        self.field_rows.append(entry)
        remove.clicked.connect(lambda: self._remove_field_row(entry))
        self.fields_box.addWidget(row)
        self._update_reference()

    def _remove_field_row(self, entry) -> None:
        if len(self.field_rows) == 1:
            return
        self.field_rows.remove(entry)
        entry[1].clear()
        entry[2].deleteLater()
        self._update_reference()

    def _update_reference(self) -> None:
        item_id = self.id_edit.text().strip() or "<random id>"
        names = [n.text().strip() for n, _v, _r in self.field_rows if n.text().strip()]
        ref = f"fv:{item_id}" + (f":{names[0]}" if len(names) > 1 else "")
        self.reference.setText(ref)

    def values(self) -> dict[str, str]:
        return {n.text().strip(): v.text() for n, v, _r in self.field_rows}

    def _save(self) -> None:
        self.error.setText("")
        fields = self.values()
        if len(fields) != len(self.field_rows):
            self.error.setText("two fields have the same name")
            return
        bind_to = None
        try:
            if self.bind_only.isChecked():
                if not self.command_edit.text().strip():
                    raise GuiError("give the command line, or choose “Any command”")
                bind_to, _warnings = self.session.resolve_command_line(self.command_edit.text())
            self.created_id = self.session.add_generic(
                self.label_edit.text(),
                fields,
                item_id=self.id_edit.text().strip() or None,
                bind_to=bind_to,
            )
        except GuiError as exc:
            self.error.setText(str(exc))
            return
        forget_clipboard_if(fields.values())
        for _n, value_edit, _r in self.field_rows:
            value_edit.clear()
        self.accept()


# ------------------------------------------------------------------ import


class ImportDialog(QDialog):
    """Preview, then store a project .env's values and rewrite it to references."""

    STATUS_TEXT = {
        "new": "New item",
        "same": "Already in vault · same value",
        "conflict": "Conflict · vault holds a different value",
        "skipped": "Skipped by you",
    }

    def __init__(self, session: VaultSession, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.session = session
        self.preview: Optional[ImportPreview] = None
        self.skip: set[str] = set()
        self.setWindowTitle("Import a .env file")
        self.resize(900, 640)

        self.path_edit = QLineEdit()
        self.path_edit.setProperty("mono", True)
        self.path_edit.setPlaceholderText("path to a project .env")
        self.path_edit.setAccessibleName("Env file path")
        browse = _button("Browse…")
        browse.clicked.connect(self._browse)
        self.prefix_edit = QLineEdit()
        self.prefix_edit.setProperty("mono", True)
        self.prefix_edit.setPlaceholderText("myapp.")
        self.prefix_edit.setAccessibleName("Item id prefix")
        self.prefix_edit.setMaximumWidth(180)
        preview = _button("Preview")
        preview.clicked.connect(self.refresh)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Import", "Variable", "Becomes", "Status"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        self.problems = _label("", "error")
        self.after = QPlainTextEdit()
        self.after.setReadOnly(True)
        self.after.setProperty("mono", True)
        self.after.setAccessibleName("File after import")
        self.after.setMaximumHeight(160)

        self.write_button = _button("Store and rewrite file", primary=True)
        self.write_button.setEnabled(False)
        self.write_button.clicked.connect(self._write)
        cancel = _button("Cancel")
        cancel.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(_label("Import a .env file", "title"))
        layout.addWidget(
            _label(
                "Each plaintext value becomes a vault item and its line becomes an fv: "
                "reference. For a Hermes Agent .env use `floorvault secrets import --hermes`.",
                "muted",
            )
        )
        row = QHBoxLayout()
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse)
        row.addWidget(_label("ID PREFIX", "eyebrow"))
        row.addWidget(self.prefix_edit)
        row.addWidget(preview)
        layout.addLayout(row)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.problems)
        layout.addWidget(_label("FILE AFTER IMPORT (values are never shown)", "eyebrow"))
        layout.addWidget(self.after)
        layout.addWidget(
            _label(
                "The file is rewritten in place with no backup. Older plaintext may remain in "
                "git history, swap files or backups — rotate any key that was ever committed.",
                "muted",
            )
        )
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self.write_button)
        layout.addLayout(buttons)

    def _browse(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Env file", "", "Env files (*.env .env*);;All files (*)"
        )
        if chosen:
            self.path_edit.setText(chosen)
            self.skip.clear()
            self.refresh()

    def refresh(self) -> None:
        self.preview = None
        self.write_button.setEnabled(False)
        text = self.path_edit.text().strip()
        if not text:
            return
        try:
            self.preview = self.session.preview_import(
                Path(text), skip=sorted(self.skip), prefix=self.prefix_edit.text().strip()
            )
        except GuiError as exc:
            self.table.setRowCount(0)
            self.after.setPlainText("")
            self.problems.setText(str(exc))
            return
        self._show(self.preview)

    def _show(self, preview: ImportPreview) -> None:
        self.table.setRowCount(len(preview.rows))
        lines = []
        for index, row in enumerate(preview.rows):
            box = QCheckBox()
            box.setAccessibleName(f"Import {row.name}")
            choosable = row.status in ("new", "same", "conflict", "skipped")
            box.setEnabled(choosable)
            box.setChecked(row.status in ("new", "same", "conflict"))
            box.toggled.connect(lambda checked, name=row.name: self._toggle(name, checked))
            holder = QWidget()
            holder_layout = QHBoxLayout(holder)
            holder_layout.setContentsMargins(8, 0, 8, 0)
            holder_layout.addWidget(box)
            self.table.setCellWidget(index, 0, holder)
            self.table.setItem(index, 1, QTableWidgetItem(row.name))
            self.table.setItem(
                index, 2, QTableWidgetItem(f"fv:{row.item_id}" if row.item_id else "—")
            )
            status = QTableWidgetItem(self.STATUS_TEXT.get(row.status, f"Left as is · {row.note}"))
            if row.status == "conflict":
                status.setForeground(Qt.GlobalColor.darkRed)
            self.table.setItem(index, 3, status)
            if row.status in ("new", "same", "conflict"):
                lines.append(f"{row.name}=fv:{row.item_id}")
            else:
                lines.append(f"{row.name}=(unchanged)")
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.after.setPlainText("\n".join(lines))
        self.problems.setText("\n".join(preview.problems))
        count = preview.to_store
        self.write_button.setText(
            f"Store {count} and rewrite file" if count else "Rewrite file to references"
        )
        self.write_button.setEnabled(preview.can_write)

    def _toggle(self, name: str, checked: bool) -> None:
        if checked:
            self.skip.discard(name)
        else:
            self.skip.add(name)
        # Rebuilding the table deletes this checkbox; let its signal finish first.
        QTimer.singleShot(0, self.refresh)

    def _write(self) -> None:
        preview = self.preview
        if preview is None or not preview.can_write:
            return
        answer = QMessageBox.question(
            self,
            "Import",
            f"Store {preview.to_store} new item(s) and rewrite {preview.path.name} "
            f"with {preview.to_rewrite} reference(s)? No backup is made.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self.session.run_import(
                preview, skip=sorted(self.skip), prefix=self.prefix_edit.text().strip()
            )
        except GuiError as exc:
            self.problems.setText(str(exc))
            self.refresh()
            return
        QMessageBox.information(
            self,
            "Import",
            f"Stored {result.stored} new item(s); rewrote {preview.path.name} with "
            f"{result.rewritten} reference(s).",
        )
        self.accept()


# ------------------------------------------------------------------ vault


class DetailPanel(QWidget):
    changed = Signal(str)  # an item id to reselect, or "" after a delete

    def __init__(self, session: VaultSession, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.session = session
        self.detail: Optional[ItemDetail] = None
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(32, 24, 32, 24)
        self.box.setSpacing(8)
        self.show_empty()

    def show_empty(self) -> None:
        self.detail = None
        _clear_layout(self.box)
        self.box.addWidget(_label("Select an item, or add one.", "muted"))
        self.box.addStretch(1)

    def show_item(self, detail: ItemDetail) -> None:
        self.detail = detail
        _clear_layout(self.box)
        box = self.box

        box.addWidget(_label(f"{detail.kind.upper()} ITEM", "eyebrow"))
        box.addWidget(_label(detail.label, "title"))
        box.addWidget(_label(f"id {detail.id}", "muted", mono=True))
        box.addSpacing(12)

        box.addWidget(_label("REFERENCE — PASTE THIS INTO CONFIG, NOT THE SECRET", "eyebrow"))
        ref_line = f"{detail.env_name}={detail.reference}" if detail.env_name else detail.reference
        ref = QLineEdit(ref_line)
        ref.setReadOnly(True)
        ref.setProperty("mono", True)
        ref.setAccessibleName("Reference")
        copy_plain = _button("Copy reference", primary=True)
        copy_plain.clicked.connect(lambda: copy_reference(detail.reference))
        row = QHBoxLayout()
        row.addWidget(ref, 1)
        row.addWidget(copy_plain)
        if detail.env_name:
            copy_env = _button("Copy as NAME=…")
            copy_env.clicked.connect(lambda: copy_reference(ref_line))
            row.addWidget(copy_env)
        box.addLayout(row)
        box.addWidget(_label("Use with: floorvault run --env-file .env -- your-command", "muted"))
        box.addSpacing(12)

        box.addWidget(_label("FIELDS", "eyebrow"))
        grid = QGridLayout()
        for index, field in enumerate(detail.fields):
            name = _label(field.name, mono=True)
            state = _label("● Set" if field.is_set else "○ Empty")
            state.setStyleSheet(f"color: {GREEN if field.is_set else MUTED};")
            dots = _label("••••••••", "muted")
            dots.setAccessibleName("hidden value")
            replace = _button("Replace…" if field.is_set else "Set value…")
            replace.setEnabled(detail.editable)
            replace.clicked.connect(lambda _=False, f=field.name: self._set_field(f))
            grid.addWidget(name, index, 0)
            grid.addWidget(state, index, 1)
            grid.addWidget(dots, index, 2)
            grid.addWidget(replace, index, 3)
        grid.setColumnStretch(0, 1)
        box.addLayout(grid)
        if detail.editable:
            add = _button("+ Add field")
            add.clicked.connect(self._add_field)
            row = QHBoxLayout()
            row.addWidget(add)
            row.addWidget(
                _label("Values are write-only here. There is no reveal button.", "muted"), 1
            )
            box.addLayout(row)
        else:
            box.addWidget(
                _label("Editing login, payment and address items is not supported yet.", "muted")
            )
        box.addSpacing(12)

        box.addWidget(_label("ALLOWED COMMANDS", "eyebrow"))
        if detail.commands is None:
            warn = QFrame()
            warn.setProperty("role", "warning")
            line = QHBoxLayout(warn)
            line.addWidget(
                _label(
                    "Not bound. `floorvault run` will hand this item to any command that names it."
                ),
                1,
            )
            bind = _button("Bind to a command…", primary=True)
            bind.clicked.connect(self._bind)
            line.addWidget(bind)
            box.addWidget(warn)
        else:
            for argv in detail.commands:
                row = QHBoxLayout()
                row.addWidget(_label(" ".join(argv), mono=True), 1)
                remove = _button("Remove")
                remove.clicked.connect(lambda _=False, a=argv: self._unbind_line(a))
                row.addWidget(remove)
                box.addLayout(row)
            row = QHBoxLayout()
            add_line = _button("Add command line…")
            add_line.clicked.connect(self._bind)
            clear = _button("Allow any command…", danger=True)
            clear.clicked.connect(self._clear_binding)
            row.addWidget(add_line)
            row.addWidget(clear)
            row.addStretch(1)
            box.addLayout(row)
            box.addWidget(
                _label(
                    "Resolves only for these exact command lines, and never while LD_PRELOAD "
                    "or a similar variable is set.",
                    "muted",
                )
            )
        box.addStretch(1)

        footer = QHBoxLayout()
        footer.addWidget(
            _label(
                "Deleting removes the row. Old copies may remain in WAL pages and backups.", "muted"
            ),
            1,
        )
        delete = _button("Delete item…", danger=True)
        delete.clicked.connect(self._delete)
        footer.addWidget(delete)
        box.addLayout(footer)

    def _run(self, action) -> None:
        detail = self.detail
        if detail is None:
            return
        try:
            action(detail)
        except GuiError as exc:
            _error(self, exc)
            return
        self.changed.emit(detail.id)

    def _set_field(self, field: str) -> None:
        detail = self.detail
        if detail is None:
            return
        value = ask_secret(self, "Set value", f"New value for {detail.id}.{field}")
        if not value:
            return
        self._run(lambda d: self.session.set_field(d.id, field, value))
        forget_clipboard_if([value])

    def _add_field(self) -> None:
        detail = self.detail
        if detail is None:
            return
        name, ok = QInputDialog.getText(self, "Add field", f"Field name for {detail.id}")
        name = name.strip()
        if not ok or not name:
            return
        if any(f.name == name for f in detail.fields):
            _error(self, GuiError(f"{detail.id} already has a field {name!r}; use Replace…"))
            return
        self._set_field(name)

    def _bind(self) -> None:
        argv = ask_command(self, self.session)
        if argv:
            self._run(lambda d: self.session.bind(d.id, argv))

    def _unbind_line(self, argv: Sequence[str]) -> None:
        self._run(lambda d: self.session.unbind_line(d.id, argv))

    def _clear_binding(self) -> None:
        detail = self.detail
        if detail is None:
            return
        answer = QMessageBox.warning(
            self,
            "Allow any command",
            f"Remove every binding from {detail.id}? `floorvault run` will then resolve it "
            "for any command that names it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._run(lambda d: self.session.clear_binding(d.id))

    def _delete(self) -> None:
        detail = self.detail
        if detail is None:
            return
        answer = QMessageBox.warning(
            self,
            "Delete item",
            f"Delete {detail.label} ({detail.id})? Programs that reference fv:{detail.id} "
            "will stop starting.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.session.remove(detail.id)
        except GuiError as exc:
            _error(self, exc)
            return
        self.changed.emit("")


class VaultPage(QWidget):
    lock_requested = Signal()

    KIND_FILTERS = ("All kinds", "generic", "login", "payment", "address")

    def __init__(self, session: VaultSession, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.session = session
        self.rows = []

        brand = QLabel(BRAND)
        brand.setProperty("role", "brand")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search id or label")
        self.search.setAccessibleName("Search items")
        self.search.textChanged.connect(self._fill_list)
        self.kind = QComboBox()
        self.kind.addItems(self.KIND_FILTERS)
        self.kind.setAccessibleName("Filter by kind")
        self.kind.currentIndexChanged.connect(self._fill_list)
        add = _button("Add item…", primary=True)
        add.clicked.connect(self._add)
        imp = _button("Import .env…")
        imp.clicked.connect(self._import)
        lock = _button("Lock now")
        lock.clicked.connect(self.lock_requested.emit)
        self.store_label = _label("", "muted", mono=True)

        top = QHBoxLayout()
        top.setContentsMargins(20, 14, 20, 14)
        top.addWidget(brand)
        top.addSpacing(16)
        top.addWidget(self.search, 1)
        top.addWidget(self.kind)
        top.addWidget(add)
        top.addWidget(imp)
        top.addWidget(lock)

        self.list = QListWidget()
        self.list.setAccessibleName("Items")
        self.list.currentItemChanged.connect(self._selected)
        self.detail = DetailPanel(session)
        self.detail.changed.connect(self.refresh)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.detail)

        splitter = QSplitter()
        splitter.addWidget(self.list)
        splitter.addWidget(scroll)
        splitter.setSizes([340, 760])

        rule = QFrame()
        rule.setFrameShape(QFrame.Shape.HLine)
        rule.setStyleSheet(f"color: {INK};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(top)
        layout.addWidget(rule)
        layout.addWidget(splitter, 1)
        status = QHBoxLayout()
        status.setContentsMargins(20, 6, 20, 6)
        status.addWidget(self.store_label, 1)
        layout.addLayout(status)

    def refresh(self, select: str = "") -> None:
        current = select or self._current_id()
        try:
            self.rows = self.session.items()
        except GuiError as exc:
            _error(self, exc)
            self.rows = []
        self.store_label.setText(
            f"{self.session.vault_dir} · unlocked · key from {self.session.key_source}"
        )
        self._fill_list(select=current)

    def clear(self) -> None:
        self.rows = []
        self.list.clear()
        self.detail.show_empty()

    def _current_id(self) -> str:
        item = self.list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def _fill_list(self, *_args, select: str = "") -> None:
        select = select or self._current_id()
        needle = self.search.text().strip().lower()
        kind = self.kind.currentText()
        self.list.blockSignals(True)
        self.list.clear()
        chosen = None
        for row in self.rows:
            if kind != self.KIND_FILTERS[0] and row.kind != kind:
                continue
            if needle and needle not in row.id.lower() and needle not in row.label.lower():
                continue
            flag = {True: "   · ANY CMD", None: "   · binding unreadable", False: ""}[row.unbound]
            item = QListWidgetItem(f"{row.label}\n{row.id} · {row.kind}{flag}")
            item.setData(Qt.ItemDataRole.UserRole, row.id)
            self.list.addItem(item)
            if row.id == select:
                chosen = item
        self.list.blockSignals(False)
        if chosen is None and self.list.count():
            chosen = self.list.item(0)
        if chosen is not None:
            self.list.setCurrentItem(chosen)
            self._selected(chosen)
        else:
            self.detail.show_empty()

    def _selected(self, item, _previous=None) -> None:
        if item is None:
            self.detail.show_empty()
            return
        try:
            self.detail.show_item(self.session.detail(item.data(Qt.ItemDataRole.UserRole)))
        except GuiError as exc:
            self.detail.show_empty()
            _error(self, exc)

    def _add(self) -> None:
        dialog = AddItemDialog(self.session, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.refresh(select=dialog.created_id or "")

    def _import(self) -> None:
        if ImportDialog(self.session, self).exec() == QDialog.DialogCode.Accepted:
            self.refresh()


# ------------------------------------------------------------------ window


class _IdleWatcher(QObject):
    """Restarts the lock timer on any keyboard or mouse input."""

    EVENTS = {
        QEvent.Type.KeyPress,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.MouseMove,
        QEvent.Type.Wheel,
    }

    def __init__(self, timer: QTimer) -> None:
        super().__init__()
        self.timer = timer

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt's name
        if event.type() in self.EVENTS and self.timer.isActive():
            self.timer.start()
        return False


class MainWindow(QMainWindow):
    def __init__(self, session: VaultSession, *, idle_lock_ms: int = IDLE_LOCK_MS) -> None:
        super().__init__()
        self.session = session
        self.setWindowTitle("FloorVault")
        self.resize(1180, 760)
        self.setStyleSheet(STYLE)

        self.unlock_page = UnlockPage(session)
        self.vault_page = VaultPage(session)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.unlock_page)
        self.stack.addWidget(self.vault_page)
        self.setCentralWidget(self.stack)

        self.unlock_page.unlocked.connect(self.show_vault)
        self.vault_page.lock_requested.connect(self.lock)

        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.setInterval(idle_lock_ms)
        self.idle_timer.timeout.connect(self.lock)
        self._watcher = _IdleWatcher(self.idle_timer)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._watcher)

    def show_vault(self) -> None:
        self.vault_page.refresh()
        self.stack.setCurrentWidget(self.vault_page)
        self.idle_timer.start()

    def lock(self) -> None:
        self.idle_timer.stop()
        self.session.lock()
        self.vault_page.clear()
        self.unlock_page.reset()
        self.stack.setCurrentWidget(self.unlock_page)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt's name
        self.lock()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self._watcher)
        super().closeEvent(event)


def run(session: VaultSession) -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("FloorVault")
    # On the application, not just the window, so dialogs and message boxes match.
    app.setStyleSheet(STYLE)
    window = MainWindow(session)
    window.show()
    return app.exec()

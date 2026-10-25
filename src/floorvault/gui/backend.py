"""The logic behind ``floorvault-gui``, kept free of Qt so it can be tested alone.

It drives the same store, key custody and import rules as ``floorvault
secrets`` (``agent_cli``), and keeps the CLI's rules:

* Nothing here returns a stored value. Fields are reported as set or empty.
* Opening never creates a store or key. Only ``add_generic`` and
  ``run_import`` may, and only when no store exists yet.
* Removing an item's last allowed command line is refused; ``clear_binding``
  is the separate, explicit way to let any command resolve the item.
* Error messages name items, variables and error types, never values.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ..agent_cli import (
    _ITEM_ID,
    KEY_FILE_ENV,
    ImportFileChanged,
    StoreUnavailable,
    _find_command,
    _format_command,
    _is_hermes_env_file,
    _is_regular_file,
    _replace_file,
    find_import_conflicts,
    open_store,
    plan_env_import,
    read_key_file,
    store_imported_items,
)
from ..agentenv import (
    AgentEnvError,
    command_allowed,
    default_vault_dir,
    is_valid_env_name,
    read_env_file,
    render_env_file,
)
from ..core import DecryptionVerificationError

#: Where the master key comes from: the OS key store (the CLI's default), a
#: key file such as an orchestrator secret mount, or an environment variable.
KEY_SOURCES = ("os", "file", "env")
DEFAULT_KEY_ENV = "FLOOR_VAULT_KEY"


class GuiError(Exception):
    """An operation failed. The message is safe to show: it holds no value."""


@dataclass(frozen=True)
class ItemRow:
    id: str
    kind: str
    label: str
    #: True when ``run`` resolves the item for any command. None when the
    #: binding could not be read (it fails authentication or does not decode).
    unbound: Optional[bool]


@dataclass(frozen=True)
class FieldState:
    name: str
    is_set: bool


@dataclass(frozen=True)
class ItemDetail:
    id: str
    kind: str
    label: str
    fields: tuple[FieldState, ...]
    #: The bound command lines, or None when the item is not bound.
    commands: Optional[tuple[tuple[str, ...], ...]]
    #: ``fv:<id>``, or ``fv:<id>:<field>`` when the item has several fields.
    reference: str
    #: A suggested variable name for ``NAME=fv:...``, or None.
    env_name: Optional[str]

    @property
    def editable(self) -> bool:
        """Only generic items support field updates in the store."""
        return self.kind == "generic"


@dataclass(frozen=True)
class ImportRow:
    name: str
    item_id: Optional[str]
    #: ``new``, ``same`` (already in the vault), ``conflict``, ``left`` or ``skipped``.
    status: str
    note: str


@dataclass(frozen=True)
class ImportPreview:
    path: Path
    digest: str
    rows: tuple[ImportRow, ...]
    problems: tuple[str, ...]
    vault_exists: bool

    @property
    def to_store(self) -> int:
        return sum(1 for row in self.rows if row.status == "new")

    @property
    def to_rewrite(self) -> int:
        return sum(1 for row in self.rows if row.status in ("new", "same"))

    @property
    def can_write(self) -> bool:
        return not self.problems and self.to_rewrite > 0


@dataclass(frozen=True)
class ImportResult:
    stored: int
    rewritten: int


def suggested_env_name(item_id: str) -> Optional[str]:
    """``openai-prod`` -> ``OPENAI_PROD``; None when no valid name results."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", item_id).upper()
    return name if is_valid_env_name(name) else None


def key_source_hint(source: str, environ: Optional[Mapping[str, str]] = None) -> str:
    """A short status line for the unlock screen. Never includes key material."""
    environ = os.environ if environ is None else environ
    if source == "file":
        raw = (environ.get(KEY_FILE_ENV) or "").strip()
        return f"${KEY_FILE_ENV} = {raw}" if raw else f"${KEY_FILE_ENV} is not set"
    if source == "env":
        return (
            f"{DEFAULT_KEY_ENV} is set"
            if (environ.get(DEFAULT_KEY_ENV) or "").strip()
            else f"{DEFAULT_KEY_ENV} is not set"
        )
    return "OS key store (Keychain, Secret Service or DPAPI)"


def _failed(action: str, exc: BaseException) -> GuiError:
    # StoreUnavailable messages are written to be printable; any other message
    # might quote data, so only its type is shown.
    if isinstance(exc, (StoreUnavailable, GuiError)):
        return GuiError(str(exc))
    return GuiError(f"{action} failed ({type(exc).__name__})")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class VaultSession:
    """One store directory and how to get its key; holds the open store while unlocked."""

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        *,
        key_source: str = "os",
        key_file: Optional[Path] = None,
        key_env: Optional[str] = None,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._environ = os.environ if environ is None else environ
        self.vault_dir = (
            Path(vault_dir).expanduser() if vault_dir else default_vault_dir(self._environ)
        )
        self.configure_key(key_source, key_file=key_file, key_env=key_env)
        self._store = None

    # ------------------------------------------------------------ open/lock

    def configure_key(
        self, source: str, *, key_file: Optional[Path] = None, key_env: Optional[str] = None
    ) -> None:
        if source not in KEY_SOURCES:
            raise GuiError(f"unknown key source {source!r}")
        self.key_source = source
        self.key_file = Path(key_file).expanduser() if key_file else None
        self.key_env = key_env or None

    def store_exists(self) -> bool:
        return _is_regular_file(self.vault_dir / "vault.db")

    @property
    def unlocked(self) -> bool:
        return self._store is not None

    def _open(self, *, create: bool):
        key_bytes = None
        key_env = None
        if self.key_source == "file":
            path = self.key_file
            if path is None:
                raw = (self._environ.get(KEY_FILE_ENV) or "").strip()
                path = Path(raw) if raw else None
            if path is None:
                raise GuiError(f"choose a key file, or set ${KEY_FILE_ENV}")
            key_bytes = read_key_file(path)
        elif self.key_source == "env":
            key_env = self.key_env or DEFAULT_KEY_ENV
        return open_store(
            self.vault_dir,
            key_env=key_env,
            key_bytes=key_bytes,
            create=create,
            environ=self._environ,
        )

    def unlock(self) -> None:
        """Open an existing store and check the key reads it. Never creates either."""
        self._store = None
        try:
            store = self._open(create=False)
        except Exception as exc:  # noqa: BLE001 - reported by type or safe message
            raise _failed("unlocking", exc) from None
        try:
            # Opening does not authenticate anything; reading the sealed
            # listing does, so a wrong key is reported here, not on first use.
            store.list_items()
        except DecryptionVerificationError:
            raise GuiError(f"this key does not open the vault at {self.vault_dir}") from None
        except Exception as exc:  # noqa: BLE001
            raise _failed("unlocking", exc) from None
        self._store = store

    def lock(self) -> None:
        """Drop the open store and its key handle."""
        self._store = None

    def _require(self):
        if self._store is None:
            raise GuiError("the vault is locked")
        return self._store

    @staticmethod
    def _meta(store, item_id: str):
        try:
            return store.get_meta(item_id)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"reading item {item_id}", exc) from None

    def _store_or_create(self):
        """The open store; with no store on disk yet, create it (and a key)."""
        if self._store is not None:
            return self._store
        if self.store_exists():
            raise GuiError("unlock the vault first")
        try:
            self._store = self._open(create=True)
        except Exception as exc:  # noqa: BLE001
            raise _failed("creating the vault", exc) from None
        return self._store

    # ------------------------------------------------------------ reading

    def items(self) -> list[ItemRow]:
        store = self._require()
        rows = []
        try:
            metas = sorted(store.list_items(), key=lambda m: m.id)
        except Exception as exc:  # noqa: BLE001
            raise _failed("listing items", exc) from None
        for meta in metas:
            try:
                unbound: Optional[bool] = not store.get_allowed_commands(meta.id)
            except Exception:  # noqa: BLE001 - shown as "unknown", never as unbound
                unbound = None
            rows.append(ItemRow(meta.id, meta.kind, meta.label, unbound))
        return rows

    def detail(self, item_id: str) -> ItemDetail:
        store = self._require()
        meta = self._meta(store, item_id)
        if meta is None:
            raise GuiError(f"item {item_id} not found")
        try:
            secret = store.resolve_secret(item_id)
            fields = tuple(FieldState(str(name), bool(value)) for name, value in secret.items())
            del secret
            allowed = store.get_allowed_commands(item_id)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"reading item {item_id}", exc) from None
        reference = f"fv:{item_id}"
        if len(fields) > 1:
            reference += f":{fields[0].name}"
        return ItemDetail(
            id=meta.id,
            kind=meta.kind,
            label=meta.label,
            fields=fields,
            commands=tuple(tuple(line) for line in allowed) if allowed else None,
            reference=reference,
            env_name=suggested_env_name(item_id),
        )

    # ------------------------------------------------------------ writing

    def resolve_command_line(self, text: str) -> tuple[list[str], list[str]]:
        """Parse a command line and pin its program to an absolute path.

        Returns ``(argv, warnings)``. The program is looked up on this
        process's own PATH, as ``secrets allow`` does.
        """
        try:
            argv = shlex.split(text, posix=os.name != "nt")
        except ValueError as exc:
            raise GuiError(f"cannot parse the command line ({exc})") from None
        if not argv:
            raise GuiError("give a command line, for example: npx -y @scope/server")
        path, code = _find_command(argv[0], self._environ)
        if path is None:
            reason = "not found" if code == 127 else "not executable"
            raise GuiError(f"{argv[0]}: command {reason} on PATH")
        warnings = [
            f"{arg} is a relative path; it is resolved against the directory the "
            "command starts in. Prefer an absolute path."
            for arg in argv[1:]
            if not arg.startswith("-") and not os.path.isabs(arg) and os.path.exists(arg)
        ]
        return [os.path.abspath(path), *argv[1:]], warnings

    def add_generic(
        self,
        label: str,
        fields: Mapping[str, str],
        *,
        item_id: Optional[str] = None,
        bind_to: Optional[Sequence[str]] = None,
    ) -> str:
        """Create a generic item and return its id; creates the store if there is none.

        ``bind_to`` is an argv from ``resolve_command_line``.
        """
        label = (label or "").strip()
        if not label:
            raise GuiError("give the item a label")
        item_id = (item_id or "").strip() or None
        if item_id is not None and not _ITEM_ID.fullmatch(item_id):
            raise GuiError("the id may use only A-Z a-z 0-9 . _ - (up to 128 characters)")
        if not fields:
            raise GuiError("add at least one field")
        for name, value in fields.items():
            if not name or not name.strip():
                raise GuiError("every field needs a name")
            if any(ch in name for ch in "\x00\r\n") or "\x00" in value:
                raise GuiError(f"field {name!r} contains a NUL or newline")
            if not value.strip():
                # The store drops empty generic fields; say so instead of losing one.
                raise GuiError(f"field {name!r} has no value")
        store = self._store_or_create()
        if item_id is not None and self._meta(store, item_id) is not None:
            raise GuiError(f"an item with id {item_id} already exists")
        try:
            meta = store.add_item(kind="generic", label=label, secret=dict(fields), item_id=item_id)
        except Exception as exc:  # noqa: BLE001
            raise _failed("adding the item", exc) from None
        if bind_to:
            try:
                store.set_allowed_commands(meta.id, [list(bind_to)])
            except Exception as exc:  # noqa: BLE001
                raise GuiError(
                    f"item {meta.id} was added but binding it failed "
                    f"({type(exc).__name__}); it is not bound"
                ) from None
        return meta.id

    def set_field(self, item_id: str, field: str, value: str) -> None:
        store = self._require()
        if not value:
            raise GuiError("empty value; nothing changed")
        if "\x00" in value:
            raise GuiError("the value may not contain a NUL byte; nothing changed")
        try:
            updated = store.update_generic_field(item_id, field, value)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"updating {item_id}.{field}", exc) from None
        if not updated:
            raise GuiError(f"item {item_id} not found")

    def remove(self, item_id: str) -> None:
        store = self._require()
        try:
            removed = store.remove_item(item_id)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"removing {item_id}", exc) from None
        if not removed:
            raise GuiError(f"item {item_id} not found")

    def bind(self, item_id: str, argv: Sequence[str]) -> None:
        """Add one command line ``item_id`` may be resolved for."""
        store = self._require()
        try:
            current = store.get_allowed_commands(item_id) or []
            store.set_allowed_commands(item_id, [*current, list(argv)])
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"binding {item_id}", exc) from None

    def unbind_line(self, item_id: str, argv: Sequence[str]) -> None:
        """Remove one command line. Refuses the last one: see ``clear_binding``."""
        store = self._require()
        try:
            current = store.get_allowed_commands(item_id) or []
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"reading {item_id}'s bindings", exc) from None
        remaining = [entry for entry in current if not command_allowed(list(argv), [entry])]
        if len(remaining) == len(current):
            raise GuiError(f"item {item_id} is not bound to {_format_command(argv)}")
        if not remaining:
            raise GuiError(
                f"that is the last command line {item_id} is bound to; removing it would "
                "let any command resolve the item. Use “Allow any command” for that."
            )
        try:
            store.set_allowed_commands(item_id, remaining)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"unbinding {item_id}", exc) from None

    def clear_binding(self, item_id: str) -> None:
        """Remove every binding: ``run`` will resolve the item for any command."""
        store = self._require()
        try:
            store.set_allowed_commands(item_id, None)
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"unbinding {item_id}", exc) from None

    # ------------------------------------------------------------ import

    def _read_import_file(self, path: Path):
        if _is_hermes_env_file(path, self._environ):
            raise GuiError(
                f"{path} is a Hermes Agent .env. Hermes reads that file itself; import it "
                "with `floorvault secrets import --hermes` instead."
            )
        try:
            return read_env_file(path)
        except AgentEnvError as exc:
            raise GuiError("; ".join(exc.problems) or f"cannot read {path}") from None
        except OSError as exc:
            raise GuiError(f"{path}: cannot read env file ({type(exc).__name__})") from None

    def preview_import(
        self, path: Path, *, skip: Sequence[str] = (), prefix: str = ""
    ) -> ImportPreview:
        """What ``run_import`` would do. Changes nothing."""
        path = Path(path).expanduser()
        if not re.fullmatch(r"[A-Za-z0-9._-]*", prefix):
            raise GuiError("the prefix may contain only A-Z a-z 0-9 . _ -")
        vault_exists = self.store_exists()
        if vault_exists and self._store is None:
            raise GuiError("unlock the vault first")
        env_file = self._read_import_file(path)
        to_store, left, problems = plan_env_import(
            env_file, skip=skip, prefix=prefix, key_env=self.key_env
        )
        already: set[str] = set()
        conflicts: dict[str, str] = {}
        if self._store is not None and not problems:
            try:
                already, conflicts = find_import_conflicts(self._store, to_store)
            except Exception as exc:  # noqa: BLE001
                raise _failed("comparing with the vault", exc) from None
        rows: list[ImportRow] = []
        for line, item_id in to_store:
            if item_id in conflicts:
                rows.append(
                    ImportRow(line.name, item_id, "conflict", "vault holds a different value")
                )
            elif item_id in already:
                rows.append(ImportRow(line.name, item_id, "same", "already in the vault"))
            else:
                rows.append(ImportRow(line.name, item_id, "new", "new item"))
        for name, reason in left:
            if reason == "--skip":
                rows.append(ImportRow(name, None, "skipped", "skipped by you"))
            else:
                rows.append(ImportRow(name, None, "left", reason))
        order = {line.name: line.number for line in env_file.assignments()}
        rows.sort(key=lambda row: order.get(row.name, 0))
        return ImportPreview(
            path=path,
            digest=_digest(env_file.raw),
            rows=tuple(rows),
            problems=tuple([*problems, *conflicts.values()]),
            vault_exists=vault_exists,
        )

    def run_import(
        self, preview: ImportPreview, *, skip: Sequence[str] = (), prefix: str = ""
    ) -> ImportResult:
        """Store the previewed values and rewrite the file to ``fv:`` references.

        Refuses when the file changed since ``preview``. No backup is made.
        """
        path = preview.path
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise GuiError(f"{path} is not a regular file; symlinks are not rewritten")
        except OSError as exc:
            raise GuiError(f"{path}: cannot read env file ({type(exc).__name__})") from None
        env_file = self._read_import_file(path)
        if _digest(env_file.raw) != preview.digest:
            raise GuiError(f"{path} changed since the preview; preview it again")
        to_store, _left, problems = plan_env_import(
            env_file, skip=skip, prefix=prefix, key_env=self.key_env
        )
        if problems:
            raise GuiError("; ".join(problems))
        if not to_store:
            raise GuiError("nothing to import")
        store = self._store_or_create()
        already, conflicts = find_import_conflicts(store, to_store)
        if conflicts:
            raise GuiError("; ".join(conflicts.values()))
        stored, failure = store_imported_items(store, to_store, already, path)
        if failure is not None:
            raise GuiError(
                f"{failure}; {path} is unchanged. Items stored so far are kept; "
                "importing again reuses them."
            )
        data = render_env_file(
            env_file, {line.number: f"fv:{item_id}" for line, item_id in to_store}
        )
        try:
            _replace_file(path, env_file.raw, data)
        except (ImportFileChanged, OSError) as exc:
            raise GuiError(
                f"{path} was not rewritten ({type(exc).__name__}); the items are stored "
                "and importing again reuses them"
            ) from None
        return ImportResult(stored=stored, rewritten=len(to_store))

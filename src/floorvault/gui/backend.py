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
    APP_CONTEXT,
    KEY_FILE_ENV,
    SERVICE_NAME,
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
from ..core import DecryptionVerificationError, FloorVault
from ..providers.adaptive import AdaptiveKeyProvider
from ..providers.base import KeyProviderError
from ..vaultkit.vault import VaultStore

#: Where the master key comes from, each enforced as chosen:
#:
#: ``os``   the OS key store only (Keychain, Secret Service or DPAPI). Unlike
#:          the CLI's default, it never adopts FLOOR_VAULT_KEY or
#:          VAULT_MASTER_KEY: it refuses to open while either is set.
#: ``file`` a key file, such as an orchestrator secret mount.
#: ``env``  a named environment variable.
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
    """An immutable import plan. ``run_import`` executes exactly this plan.

    The settings that shape the plan (path, prefix, skipped names) live here
    rather than being passed again at execution, so a field edited after the
    preview cannot change what is written.
    """

    path: Path
    digest: str
    prefix: str
    skip: tuple[str, ...]
    rows: tuple[ImportRow, ...]
    problems: tuple[str, ...]
    vault_exists: bool

    @property
    def references(self) -> tuple[tuple[str, str], ...]:
        """``(variable, item id)`` for every line the import rewrites."""
        return tuple(
            (row.name, row.item_id or "")
            for row in self.rows
            if row.status in ("new", "same", "conflict")
        )

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
    return "Keychain, Secret Service or DPAPI. Refuses to open while FLOOR_VAULT_KEY or VAULT_MASTER_KEY is set."


def _failed(action: str, exc: BaseException) -> GuiError:
    # StoreUnavailable messages are written to be printable; any other message
    # might quote data, so only its type is shown.
    if isinstance(exc, (StoreUnavailable, GuiError)):
        return GuiError(str(exc))
    return GuiError(f"{action} failed ({type(exc).__name__})")


def split_command_line(text: str, *, windows: bool) -> list[str]:
    """Split a typed command line into argv. Raises ValueError on an open quote.

    POSIX: shell rules (``shlex.split``). Windows: the rules the Microsoft C
    runtime uses to build ``sys.argv``, so a binding matches the argv that
    ``floorvault run`` itself receives there (see ``_split_windows``).
    """
    return _split_windows(text) if windows else shlex.split(text)


def _split_windows(text: str) -> list[str]:
    """Windows command-line splitting, following the Microsoft C runtime.

    * Arguments are separated by spaces or tabs outside double quotes.
    * The program name (first argument) is special: a double quote only
      toggles quoting and backslashes are literal, so ``"C:\\dir\\"`` works.
    * Elsewhere, ``2n`` backslashes before a double quote give ``n`` backslashes
      and the quote toggles quoting; ``2n+1`` give ``n`` backslashes and a
      literal quote. Backslashes not before a quote are literal.
    * Inside quotes, ``""`` is a literal quote.

    Unlike the runtime, an unclosed quote is an error rather than running to
    the end of the line, so a typo cannot silently become a different binding.
    """
    argv: list[str] = []
    i, n = 0, len(text)
    first = True
    while True:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        arg: list[str] = []
        quoted = False
        while i < n and (quoted or text[i] not in " \t"):
            char = text[i]
            if first:
                if char == '"':
                    quoted = not quoted
                else:
                    arg.append(char)
                i += 1
            elif char == "\\":
                end = i
                while end < n and text[end] == "\\":
                    end += 1
                count = end - i
                if end < n and text[end] == '"':
                    arg.append("\\" * (count // 2))
                    if count % 2:
                        arg.append('"')
                        i = end + 1
                    else:
                        i = end
                else:
                    arg.append("\\" * count)
                    i = end
            elif char == '"':
                if quoted and i + 1 < n and text[i + 1] == '"':
                    arg.append('"')
                    i += 2
                else:
                    quoted = not quoted
                    i += 1
            else:
                arg.append(char)
                i += 1
        if quoted:
            raise ValueError("No closing quotation")
        argv.append("".join(arg))
        first = False
    return argv


def describe_argv(argv: Sequence[str]) -> str:
    """One numbered line per argument, so argument boundaries are unambiguous."""
    return "\n".join(f"  [{index}] {arg}" for index, arg in enumerate(argv))


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
    def key_description(self) -> str:
        """Where the key actually comes from, for the status line."""
        if self.key_source == "file":
            raw = (self._environ.get(KEY_FILE_ENV) or "").strip()
            return f"key file {self.key_file or raw or '(not chosen)'}"
        if self.key_source == "env":
            return f"environment variable {self.key_env or DEFAULT_KEY_ENV}"
        return "OS key store only"

    @property
    def unlocked(self) -> bool:
        return self._store is not None

    def _chosen_key_file(self) -> Optional[Path]:
        if self.key_source != "file":
            return None
        if self.key_file is not None:
            return self.key_file
        raw = (self._environ.get(KEY_FILE_ENV) or "").strip()
        return Path(raw) if raw else None

    def _import_plan(self, env_file, *, skip: Sequence[str], prefix: str):
        return plan_env_import(
            env_file,
            skip=skip,
            prefix=prefix,
            key_env=self.key_env,
            key_file=self._chosen_key_file(),
            environ=self._environ,
        )

    def _open(self, *, create: bool):
        key_bytes = None
        key_env = None
        if self.key_source == "file":
            path = self._chosen_key_file()
            if path is None:
                raise GuiError(f"choose a key file, or set ${KEY_FILE_ENV}")
            key_bytes = read_key_file(path)
        elif self.key_source == "env":
            key_env = self.key_env or DEFAULT_KEY_ENV
        else:
            return self._open_os_only(create=create)
        return open_store(
            self.vault_dir,
            key_env=key_env,
            key_bytes=key_bytes,
            create=create,
            environ=self._environ,
        )

    def _open_os_only(self, *, create: bool):
        """Open (or create) the store with a key from the OS key store alone.

        ``strict=True`` makes the provider refuse FLOOR_VAULT_KEY and
        VAULT_MASTER_KEY instead of adopting them, and refuse disk-file
        custody, so this source means what its label says. The CLI's
        ``open_store`` default is not strict and prefers those variables.
        """
        if not create and not self.store_exists():
            raise GuiError(f"no vault at {self.vault_dir}")
        provider = AdaptiveKeyProvider(
            service_name=SERVICE_NAME, fallback_dir=self.vault_dir, strict=True
        )
        try:
            key = provider.resolve_key(allow_create=create)
        except KeyProviderError as exc:
            # Provider messages name variables and paths, never key material.
            raise GuiError(f"OS key store: {exc}") from None
        return VaultStore(self.vault_dir, crypto=FloorVault(key, app_instance_id=APP_CONTEXT))

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
            argv = split_command_line(text, windows=os.name == "nt")
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
            # One transaction: the item exists bound as chosen, or not at all.
            meta = store.add_item(
                kind="generic",
                label=label,
                secret=dict(fields),
                item_id=item_id,
                allowed_commands=[list(bind_to)] if bind_to else None,
            )
        except Exception as exc:  # noqa: BLE001
            raise _failed("adding the item", exc) from None
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
            store.update_allowed_commands(item_id, lambda current: [*(current or []), list(argv)])
        except Exception as exc:  # noqa: BLE001
            raise _failed(f"binding {item_id}", exc) from None

    def unbind_line(self, item_id: str, argv: Sequence[str]) -> None:
        """Remove one command line. Refuses the last one: see ``clear_binding``.

        The read and the write are one transaction, so a concurrent change
        cannot bring back a line removed here (audit SEC-2).
        """
        store = self._require()

        def change(current):
            current = current or []
            remaining = [entry for entry in current if not command_allowed(list(argv), [entry])]
            if len(remaining) == len(current):
                raise GuiError(f"item {item_id} is not bound to {_format_command(argv)}")
            if not remaining:
                raise GuiError(
                    f"that is the last command line {item_id} is bound to; removing it would "
                    "let any command resolve the item. Use “Allow any command” for that."
                )
            return remaining

        try:
            store.update_allowed_commands(item_id, change)
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
        to_store, left, problems = self._import_plan(env_file, skip=skip, prefix=prefix)
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
            prefix=prefix,
            skip=tuple(sorted(set(skip))),
            rows=tuple(rows),
            problems=tuple([*problems, *conflicts.values()]),
            vault_exists=vault_exists,
        )

    def run_import(self, preview: ImportPreview) -> ImportResult:
        """Execute ``preview``: store its values and rewrite its file to references.

        Uses only the preview's own path, prefix and selection. Refuses when the
        file changed, or the plan no longer comes out the same. No backup is made.
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
        to_store, _left, problems = self._import_plan(
            env_file, skip=preview.skip, prefix=preview.prefix
        )
        if problems:
            raise GuiError("; ".join(problems))
        if not to_store:
            raise GuiError("nothing to import")
        planned = tuple((line.name, item_id) for line, item_id in to_store)
        if planned != preview.references:
            raise GuiError("the import no longer matches its preview; preview it again")
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

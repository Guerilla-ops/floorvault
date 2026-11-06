"""``hermes hvault`` operator CLI: manage items in the agent-secret vault.

``bind ENV_NAME`` is the one-step path: it creates the store on first use,
prompts for the value, stores it and writes the ``secrets.hermesvault.env``
mapping into config.yaml. With no command the CLI prints status and the next
step. The remaining commands add, list, show and remove ``generic`` items in the store backing
``secrets.hermesvault.env`` refs. Values are never logged; ``put`` reads the
value via getpass so it never appears on argv and updates its encrypted payload
in a single SQLite transaction. ``add`` accepts
``field=value`` pairs on argv (visible to ``ps`` while the command runs —
prefer ``put`` for single values) or ``--stdin`` reading ``field=value``
lines.
"""

from __future__ import annotations

import getpass
import json
import os
import shlex
import shutil
import sys
import warnings
from pathlib import Path

from agent.secret_sources.base import get_source_environment, is_valid_env_name
from hermes_constants import get_hermes_home

from .binding_guard import hermes_command_lines
from .source import HermesVaultSource, parse_ref, resolve_base_dir, validate_config


class CLIInputError(ValueError):
    """An operator-facing validation message containing no input values."""


def _item_id(value):
    item, field = parse_ref(f"hv:{value}")
    if item is None or field is not None or item != value:
        raise CLIInputError("item ID must use 1-128 letters, numbers, dots, underscores or hyphens")
    return item


def _field(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CLIInputError("field must be non-empty and contain no control characters")
    return value


def _secrets_cfg() -> dict:
    """The ``secrets.hermesvault`` section exactly as the user wrote it.

    Read through ``read_user_config_raw`` — Hermes' own raw reader, the same
    parse the secret-source loader applies at startup: it raises on a
    malformed file. ``load_config()`` merges defaults and swallows a parse
    failure into them, and defaults must never silently select a store or
    custody."""
    try:
        from hermes_cli.config import read_user_config_raw
    except ImportError:
        raise CLIInputError(
            "cannot read Hermes configuration: this hermesvault needs a Hermes "
            "release with hermes_cli.config.read_user_config_raw"
        ) from None
    try:
        config = read_user_config_raw()
    except Exception:
        raise CLIInputError(
            "cannot load Hermes configuration; correct config.yaml before retrying"
        ) from None
    if not isinstance(config, dict):
        raise CLIInputError("Hermes configuration must be a mapping")
    secrets = config.get("secrets", {})
    if not isinstance(secrets, dict):
        raise CLIInputError("secrets configuration must be a mapping")
    section = secrets.get("hermesvault", {})
    try:
        validate_config(section)
    except ValueError as error:
        raise CLIInputError(str(error)) from None
    return section


def _store(*, setup: bool = False):
    cfg = _secrets_cfg()
    from .source import _open_store

    return _open_store(cfg, Path(get_hermes_home()), setup=setup)


def _field_values(pairs, *, where: str = "argument", start: int = 1) -> dict:
    """Parse ``field=value`` items. Errors name the position, never the text:
    a mistyped line may be the secret itself."""
    out = {}
    for number, pair in enumerate(pairs or [], start=start):
        field, sep, value = str(pair).partition("=")
        field = field.strip()
        if not sep or not field:
            raise CLIInputError(f"{where} {number} is not in field=value form")
        out[_field(field)] = value
    return out


def register_cli(subparser) -> None:
    sub = subparser.add_subparsers(dest="hvault_command", metavar="<command>")

    bind = sub.add_parser(
        "bind",
        help=(
            "Store a secret and map it to an environment variable in one step "
            "(creates the store on first use; the value is prompted, never argv)"
        ),
    )
    bind.add_argument("env_name", help="Environment variable the agent reads, e.g. OPENAI_API_KEY")
    bind.add_argument(
        "--id",
        dest="item_id",
        default=None,
        help="Item id (default: the variable name, lowercased)",
    )
    bind.add_argument("--field", default="value", help="Field to set on the item (default: value)")
    bind.add_argument("--label", default=None, help="Human label (default: the variable name)")
    bind.add_argument(
        "--print-only",
        action="store_true",
        help="Do not edit config.yaml; print the mapping to paste instead",
    )
    bind.add_argument(
        "--stdin",
        action="store_true",
        help="Read the secret value from stdin (for scripts); no prompt",
    )

    allow = sub.add_parser(
        "allow",
        help=(
            "Bind an item to command lines, so Hermes resolves it only when "
            "started as one of them (default: this Hermes' own command line)"
        ),
        usage=(
            "hermes hvault allow ITEM_ID [--clear | --accept | [--remove] [-- PROGRAM [ARGS...]]]"
        ),
        description=(
            "Command bindings live in the vault; a bound item is resolved only "
            "when the process was started as one of the bound command lines "
            "(secrets.hermesvault.require_binding also refuses items with none). "
            "With no command, the lines this Hermes was started with are bound — "
            "run it from the same command Hermes runs as. Give an explicit line "
            "after -- the way `floorvault secrets allow` takes it."
        ),
    )
    allow.add_argument("item_id")
    allow.add_argument(
        "--clear",
        action="store_true",
        help="Remove every binding (the item resolves for any command)",
    )
    allow.add_argument("--remove", action="store_true", help="Remove one command line")
    allow.add_argument(
        "--accept",
        action="store_true",
        help="Trust the item's binding as stored, when it was changed outside this command",
    )
    # Named command_line rather than command: plugin args share the namespace
    # hermes_cli.main dispatches on, and its `command` attribute is a string.
    allow.add_argument("command_line", nargs="*", metavar="PROGRAM [ARGS...]")

    sub.add_parser(
        "setup",
        help=(
            "Create the store and its key (OS key store, which may prompt; or a "
            "systemd-creds credential), as secrets.hermesvault.custody says"
        ),
    )

    add = sub.add_parser("add", help="Create a generic secret item")
    add.add_argument("label", help="Human label for the item")
    add.add_argument(
        "fields",
        nargs="*",
        metavar="field=value",
        help="Secret fields (argv-visible; prefer --stdin or `put`)",
    )
    add.add_argument(
        "--stdin", action="store_true", help="Read field=value lines from stdin instead of argv"
    )
    add.add_argument(
        "--id", dest="item_id", default=None, help="Explicit item id (default: vault_<random>)"
    )

    put = sub.add_parser("put", help="Set one field on an item (prompted, never argv)")
    put.add_argument("item_id")
    put.add_argument("field")

    show = sub.add_parser("show", help="Show one item's fields")
    show.add_argument("ref", help="hv:<item_id>[:field] or a bare item id")
    show.add_argument(
        "--reveal",
        action="store_true",
        help="Display masked value status; plaintext is not printed",
    )

    rm = sub.add_parser("rm", help="Delete an item")
    rm.add_argument("item_id")

    sub.add_parser("list", help="List items (metadata only)")
    sub.add_parser(
        "doctor",
        help="Check configured mappings and environment precedence without printing values",
    )

    env = sub.add_parser(
        "env", help="Print the secrets.hermesvault.env mapping to paste into config.yaml"
    )
    env.add_argument("item_id")
    env.add_argument("env_name", help="Env var name to bind")
    env.add_argument("--field", default=None)


def _custody_line(cfg: dict) -> str:
    """Which key route opens the store. Prints fixed text only, never a configured value."""
    from .source import CUSTODIES, DEFAULT_CUSTODY, DEFAULT_TOKEN_ENV

    token_env = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV)
    if token_env in get_source_environment():
        return "key: the token_env variable (set in this environment; custody is not used)"
    configured = cfg.get("custody", DEFAULT_CUSTODY)
    label = next((name for name in CUSTODIES if name == configured), "unknown")
    return f"key: custody {label}"


def _cmd_setup(_args) -> int:
    from .source import resolve_base_dir

    cfg = _secrets_cfg()
    store = _store(setup=True)
    del store
    print(f"store ready at {resolve_base_dir(cfg, Path(get_hermes_home()))}")
    print(_custody_line(cfg))
    print("the secret source now opens it at startup without prompting")
    if cfg.get("custody") == "systemd-creds":
        print(
            "checked: the credential unseals from this shell. Not checked: unsealing from "
            "the service or session Hermes runs in; restart Hermes and run "
            "`hermes hvault doctor` there before relying on it",
            file=sys.stderr,
        )
    return 0


def _cmd_add(args) -> int:
    if args.item_id is not None:
        _item_id(args.item_id)
    fields = _field_values(args.fields)
    if args.stdin:
        for number, line in enumerate(sys.stdin, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields.update(_field_values([line], where="stdin line", start=number))
    if not fields:
        print("hvault add: give at least one field=value (argv, or --stdin)", file=sys.stderr)
        return 2
    meta = _store().add_item(kind="generic", label=args.label, secret=fields, item_id=args.item_id)
    print(f"created {meta.id}")
    return 0


def _read_secret(prompt: str, command: str) -> "str | None":
    """Prompt without echo. ``getpass`` falls back to echoing stdin, with only a
    warning, when it cannot control the terminal; that is refused here, so a
    value is never read where it would be shown. Returns None after reporting."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning:
        print(
            f"hvault {command}: cannot hide the input here (no secure terminal); "
            "nothing read or stored",
            file=sys.stderr,
        )
        return None


def _cmd_put(args) -> int:
    _item_id(args.item_id)
    _field(args.field)
    store = _store()
    try:
        meta = store.get_meta(args.item_id)
    except Exception:
        print(f"hvault put: item {args.item_id} not found", file=sys.stderr)
        return 1
    if meta is None:
        print(f"hvault put: item {args.item_id} not found", file=sys.stderr)
        return 1
    value = _read_secret(f"{args.item_id}.{args.field}: ", "put")
    if value is None:
        return 2
    if not value:
        print("hvault put: empty value", file=sys.stderr)
        return 2
    try:
        if not store.update_generic_field(args.item_id, args.field, value):
            print(f"hvault put: item {args.item_id} not found", file=sys.stderr)
            return 1
    except Exception as exc:
        print(
            f"hvault put: update failed ({type(exc).__name__}); check item and key custody",
            file=sys.stderr,
        )
        return 1
    print(f"updated {args.item_id}.{args.field}")
    return 0


def _cmd_show(args) -> int:
    item_id, field = parse_ref(args.ref) if str(args.ref).startswith("hv:") else (args.ref, None)
    if item_id is None:
        raise CLIInputError("invalid hv: reference")
    _item_id(item_id)
    if field is not None:
        _field(field)
    try:
        store = _store()
        secret = store.resolve_secret(item_id)
    except Exception:
        print(f"hvault show: item {item_id} not found", file=sys.stderr)
        return 1
    if args.reveal:
        items = {field: secret.get(field)} if field else secret
        for _name, value in items.items():
            masked = "****" if value else "(empty)"
            print(masked)
    else:
        if field:
            print("(set)" if secret.get(field) else "(empty)")
        else:
            total = len(secret)
            set_count = sum(1 for v in secret.values() if v)
            empty_count = total - set_count
            print(f"{total} field(s): {set_count} set, {empty_count} empty")
        print("use --reveal to show masked value status", file=sys.stderr)
    _print_binding(store, item_id)
    return 0


def _print_binding(store, item_id: str) -> None:
    """Show the command lines the plugin will resolve ``item_id`` for.

    Command lines are not secret. A binding that cannot be read is said so: the
    plugin skips such an item, so the operator should see why.
    """
    getter = getattr(store, "get_allowed_commands", None)
    if getter is None:
        print("bindings: not supported by this floorvault (older than 0.3.0)")
        return
    try:
        allowed = getter(item_id)
    except Exception:
        print("bindings: cannot be read; the plugin will not resolve this item")
        return
    if not allowed:
        print("bindings: none; resolved for any command (see secrets.hermesvault.require_binding)")
        return
    print(f"bindings: {len(allowed)} command line(s); resolved only when Hermes was started as:")
    for line in allowed:
        print(f"  {shlex.join(line)}")


def _cmd_rm(args) -> int:
    _item_id(args.item_id)
    if _store().remove_item(args.item_id):
        print(f"removed {args.item_id}")
        return 0
    print(f"hvault rm: item {args.item_id} not found", file=sys.stderr)
    return 1


def _cmd_list(_args) -> int:
    items = _store().list_items()
    if not items:
        print("(empty vault)")
        return 0
    for meta in items:
        parts = [meta.id, meta.kind, meta.label]
        if meta.origin:
            parts.append(meta.origin)
        print("\t".join(str(p) for p in parts))
    return 0


def _print_mapping(env_name: str, ref: str) -> None:
    print("secrets:")
    print("  hermesvault:")
    print("    enabled: true")
    print("    env:")
    print(f"      {json.dumps(env_name)}: {json.dumps(ref)}")


def _cmd_env(args) -> int:
    _item_id(args.item_id)
    if not is_valid_env_name(args.env_name):
        raise CLIInputError("invalid environment variable name")
    if args.field is not None:
        _field(args.field)
    field = f":{args.field}" if args.field else ""
    _print_mapping(args.env_name, f"hv:{args.item_id}{field}")
    return 0


def _write_mapping(env_name: str, ref: str) -> bool:
    """Merge one ``secrets.hermesvault.env`` entry (and ``enabled: true``) into the
    profile's config.yaml through Hermes' own writer, the way Hermes' plugin
    settings are saved: a partial document, deep-merged over the file on disk,
    so no other section is rewritten. Returns False, writing nothing, when the
    host offers no merging writer (older releases, managed installs); the caller
    then prints the mapping for the operator to paste."""
    try:
        import inspect

        from hermes_cli import config as config_mod

        params = inspect.signature(config_mod.save_config).parameters
        if "merge_existing" not in params or "preserve_keys" not in params:
            return False
        is_managed = getattr(config_mod, "is_managed", None)
        if is_managed is not None and is_managed():
            return False
        # Fail closed on malformed YAML before a read-modify-write (as Hermes does).
        raw_read = getattr(config_mod, "read_user_config_raw", None)
        if raw_read is not None:
            raw_read()
        partial = {"secrets": {"hermesvault": {"enabled": True, "env": {env_name: ref}}}}
        config_mod.save_config(
            partial,
            preserve_keys={
                ("secrets", "hermesvault", "enabled"),
                ("secrets", "hermesvault", "env", env_name),
            },
            merge_existing=True,
        )
    except Exception as exc:  # noqa: BLE001 — any failure falls back to the paste path
        # Not a refusal (no merging writer, managed install: those returned
        # above, silently): a read or write that failed. Say so, by type only.
        print(
            f"hvault: config.yaml was not updated ({type(exc).__name__}); add the mapping by hand",
            file=sys.stderr,
        )
        return False
    return True


def _cmd_bind(args) -> int:
    if not is_valid_env_name(args.env_name):
        raise CLIInputError("invalid environment variable name")
    item_id = _item_id(args.item_id if args.item_id is not None else args.env_name.lower())
    field = _field(args.field)
    label = args.label if args.label is not None else args.env_name
    ref = f"hv:{item_id}" if field == "value" else f"hv:{item_id}:{field}"

    if args.stdin and sys.stdin.isatty():
        print("hvault bind: --stdin reads the value from a pipe or file", file=sys.stderr)
        return 2

    cfg = _secrets_cfg()
    if args.env_name in HermesVaultSource().protected_env_vars(cfg):
        # Hermes never applies a mapping onto the bootstrap or key variables, so
        # binding one would store a value that nothing can use.
        print(
            f"hvault bind: {args.env_name} is a protected key variable; "
            "Hermes will not apply a mapping onto it",
            file=sys.stderr,
        )
        return 2
    env_map = cfg.get("env")
    for other, other_ref in env_map.items() if isinstance(env_map, dict) else ():
        other_item, other_field = parse_ref(other_ref)
        if other != args.env_name and other_item == item_id and (other_field or "value") == field:
            # The default item id is the lower-cased name, so API_KEY and api_key
            # would share one item and the second bind would overwrite the first.
            # No name from the configuration is echoed (CodeQL treats the
            # secrets section as sensitive); the operator can run `hvault show`.
            print(
                "hvault bind: another configured variable already maps to the same "
                f"item, so binding {args.env_name} there would overwrite its value. "
                "Pass --id to use a different item",
                file=sys.stderr,
            )
            return 2
    home = Path(get_hermes_home())
    created = not (resolve_base_dir(cfg, home) / "vault.db").is_file()
    store = _store(setup=created)
    if created:
        print(f"store created at {resolve_base_dir(cfg, home)}")
        print(_custody_line(cfg))

    if args.stdin:
        value = sys.stdin.read().rstrip("\n")
    else:
        value = _read_secret(f"{args.env_name}: ", "bind")
    if value is None:
        return 2
    if not value.strip():
        # add_item() drops whitespace-only fields, which would leave an empty
        # record and a mapping to a field that does not exist. The value itself
        # is stored as typed, not stripped.
        print("hvault bind: empty value; nothing stored", file=sys.stderr)
        return 2
    existing = store.get_meta(item_id)
    if existing is None:
        store.add_item(kind="generic", label=label, secret={field: value}, item_id=item_id)
        print(f"stored {item_id}.{field}")
    else:
        if not store.update_generic_field(item_id, field, value):
            print(f"hvault bind: item {item_id} vanished during update", file=sys.stderr)
            return 1
        print(f"updated {item_id}.{field}")
    del value

    if args.print_only or not _write_mapping(args.env_name, ref):
        print("add this to config.yaml, then run `hermes hvault doctor`:")
        _print_mapping(args.env_name, ref)
        return 0
    print(f"mapped {args.env_name} -> {ref} in config.yaml")
    code = _cmd_doctor(args)
    print("restart Hermes to apply")
    return code


class _AllowRefused(Exception):
    """A binding change refused inside the store's write transaction; nothing was written."""


def _binding_record(base: Path):
    """This store's sealed-binding record — the same file `floorvault secrets allow` keeps."""
    try:
        from floorvault.binding_record import (
            BindingRecord,
            BindingRecordError,
            default_state_dir,
        )
    except ImportError:
        raise CLIInputError("command bindings need floorvault 0.3.0 or newer") from None
    try:
        return BindingRecord(base, default_state_dir(os.environ)), BindingRecordError
    except BindingRecordError as exc:
        raise CLIInputError(str(exc)) from None


def _resolve_program(prog: str) -> str:
    """The absolute program path a binding records, resolved the way `secrets allow` does."""
    seps = {os.sep, os.altsep} - {None}
    if any(sep in prog for sep in seps) or os.path.splitdrive(prog)[0]:
        candidate = Path(prog)
        if not candidate.exists() or candidate.is_dir() or not os.access(candidate, os.X_OK):
            raise CLIInputError(f"{prog} is not an executable file")
        return str(candidate)
    found = shutil.which(prog)
    if found is None:
        raise CLIInputError(f"{prog}: command not found on PATH")
    return os.path.abspath(found)


def _cmd_allow(args) -> int:
    item_id = _item_id(args.item_id)
    command = list(args.command_line or [])
    if args.clear and (command or args.remove):
        raise CLIInputError("--clear takes no command and cannot be combined with --remove")
    if args.accept and (command or args.remove or args.clear):
        raise CLIInputError(
            "--accept takes no command and cannot be combined with --clear or --remove"
        )
    store = _store()
    if any(
        getattr(store, name, None) is None
        for name in ("update_allowed_commands", "set_allowed_commands", "binding_fingerprint")
    ):
        print("hvault allow: command bindings need floorvault 0.3.0 or newer", file=sys.stderr)
        return 1
    try:
        meta = store.get_meta(item_id)
    except Exception:
        meta = None
    if meta is None:
        print(f"hvault allow: item {item_id} not found", file=sys.stderr)
        return 1
    cfg = _secrets_cfg()
    base = resolve_base_dir(cfg, Path(get_hermes_home()))
    record, record_error = _binding_record(base)
    try:
        if args.accept:
            fingerprint = store.binding_fingerprint(item_id)
            record.record(item_id, fingerprint)
            _print_binding(store, item_id)
            print(f"{item_id}: this binding is trusted from now on")
            return 0
        if args.clear:
            store.set_allowed_commands(item_id, None)
            record.record(item_id, store.binding_fingerprint(item_id))
            print(f"{item_id}: not bound; the plugin resolves it for any command")
            return 0
        # Adding to or removing from a binding that was changed behind our back
        # would make the changed one look trusted.
        if record.check({item_id: store.binding_fingerprint(item_id)}):
            print(
                f"hvault allow: the binding for {item_id} was changed outside this "
                "command; inspect it with `hermes hvault show` and confirm it with "
                f"`hermes hvault allow {item_id} --accept`",
                file=sys.stderr,
            )
            return 1
    except record_error as exc:
        print(f"hvault allow: {exc}", file=sys.stderr)
        return 1
    if command:
        if len(command) == 1 and command[0].lstrip().startswith("["):
            # `hermes --print-runtime-command <argv>` prints the exact command
            # line a launcher starts Hermes with, as a JSON list — pasting it
            # after -- is the way to bind that start line.
            try:
                parsed = json.loads(command[0])
            except ValueError:
                parsed = None
            if not (
                isinstance(parsed, list) and parsed and all(isinstance(a, str) for a in parsed)
            ):
                raise CLIInputError(
                    "after -- a JSON command line must be a non-empty list of strings, "
                    "as `hermes --print-runtime-command` prints it"
                )
            command = parsed
        line = [_resolve_program(command[0]), *command[1:]]
        for arg in command[1:]:
            if not arg.startswith("-") and not os.path.isabs(arg) and os.path.exists(arg):
                print(
                    f"hvault allow: warning: {arg} is a relative path; it is resolved "
                    "against the directory the command starts in. Prefer an absolute path.",
                    file=sys.stderr,
                )
        lines = [line]
    else:
        # A bound item resolves only for the commands it is bound to, and this
        # `hvault` invocation is never the one a user means — the agent's start
        # command is. Drop self-references from the captured lines; if the
        # `allow` invocation is all there is, the operator must spell the line
        # out (the skip warning prints what the source was started with).
        captured = [line for line in hermes_command_lines() if "hvault" not in line]
        if not captured:
            raise CLIInputError(
                "the only command line this process was started with is this "
                "`hvault` invocation; bound to it the item would resolve for "
                "hvault commands but not the agent. Give the start command after "
                "-- instead: the skip warning prints it, and `hermes "
                "--print-runtime-command gateway run` prints the launcher's line "
                "as JSON (paste it quoted)"
            )
        lines = captured

    def change(current):
        # Runs under the store's write lock, so a concurrent change is not lost.
        current = current or []
        if not args.remove:
            return [*current, *lines]
        from floorvault.agentenv import command_allowed

        remaining = list(current)
        for line in lines:
            remaining = [e for e in remaining if not command_allowed(line, [e])]
        if len(remaining) == len(current):
            raise _AllowRefused(
                f"item {item_id} is not bound to {shlex.join(lines[0])}"
                if len(lines) == 1
                else f"item {item_id} is bound to none of this process's command lines"
            )
        if not remaining:
            # Unbinding widens access to every command; make that explicit.
            raise _AllowRefused(
                f"that is the last command line {item_id} is bound to; removing it "
                "would let the plugin resolve the item for any command. Use --clear for that."
            )
        return remaining

    try:
        store.update_allowed_commands(item_id, change)
    except _AllowRefused as exc:
        print(f"hvault allow: {exc}", file=sys.stderr)
        return 1
    try:
        record.record(item_id, store.binding_fingerprint(item_id))
    except record_error as exc:
        print(f"hvault allow: the binding was written, but {exc}", file=sys.stderr)
        return 1
    _print_binding(store, item_id)
    return 0


def _cmd_status(_args) -> int:
    """``hermes hvault`` with no command: where things stand and the next step.
    Opens the store exactly as the secret source does — no prompt, nothing created."""
    cfg = _secrets_cfg()
    home = Path(get_hermes_home())
    base = resolve_base_dir(cfg, home)
    exists = (base / "vault.db").is_file()
    env_map = cfg.get("env", {})
    mappings = len(env_map) if isinstance(env_map, dict) else 0
    enabled = cfg.get("enabled") is True

    print(f"profile: {home}")
    print(f"store: {base} ({'present' if exists else 'missing'})")
    print(_custody_line(cfg))
    print(f"source: {'enabled' if enabled else 'disabled'}, {mappings} mapping(s)")
    if exists and enabled and mappings:
        result = HermesVaultSource().fetch(cfg, home)
        if result.ok:
            print(f"resolved {len(result.secrets)}/{mappings} mapping(s); values are not displayed")
        else:
            print(f"resolve failed: {result.error}", file=sys.stderr)
    if not mappings:
        print("next: hermes hvault bind <ENV_NAME>   # stores a secret and maps it")
    elif not enabled:
        print("next: set secrets.hermesvault.enabled: true, or run `hermes hvault bind`")
    else:
        print("next: hermes hvault doctor   # full check; `bind` adds more")
    print("commands: bind, allow, list, doctor, show, rm; advanced: setup, add, put, env")
    return 0


def _cmd_doctor(_args) -> int:
    cfg = _secrets_cfg()
    home = Path(get_hermes_home())
    base = resolve_base_dir(cfg, home)
    print(f"profile: {home}")
    print(f"store: {base}")
    print(_custody_line(cfg))
    if cfg.get("enabled") is not True:
        print(
            "hvault doctor: source is disabled; set secrets.hermesvault.enabled: true "
            "(or run `hermes hvault bind` once — it enables it)",
            file=sys.stderr,
        )
        return 1
    env_map = cfg.get("env", {})
    if not isinstance(env_map, dict):
        raise CLIInputError("secrets.hermesvault.env must be a mapping")
    if not env_map:
        print("hvault doctor: no mappings configured", file=sys.stderr)
        return 1
    if not (base / "vault.db").is_file():
        print(
            "hvault doctor: store does not exist; check the profile and dir setting",
            file=sys.stderr,
        )
        return 1
    source = HermesVaultSource()
    result = source.fetch(cfg, home)
    if not result.ok:
        print(f"hvault doctor: {result.error}", file=sys.stderr)
        return 1
    # The same lines Hermes prints at startup: they name configured variables,
    # items and bound command lines, never values. Naming them is the point of
    # a doctor — "1 warning" alone cannot be acted on.
    for warning in result.warnings:
        print(f"hvault doctor: {warning}", file=sys.stderr)
    problems = bool(result.warnings)
    environ = get_source_environment()
    protected = source.protected_env_vars(cfg)
    for idx, name in enumerate(env_map, start=1):
        if not is_valid_env_name(name):
            continue
        if name in protected:
            print(
                f"mapping #{idx}: bootstrap variable is protected; Hermes will not apply this mapping",
                file=sys.stderr,
            )
            problems = True
        elif name in environ:
            if cfg.get("override_existing", False):
                print(
                    f"mapping #{idx}: existing environment value will be overridden; plaintext copies are not removed"
                )
            else:
                print(
                    f"mapping #{idx}: existing environment value takes precedence over the vault",
                    file=sys.stderr,
                )
                problems = True
    print(f"resolved {len(result.secrets)}/{len(env_map)} mapping(s); values are not displayed")
    print(
        "Restart Hermes after changes and verify the consuming service; this checks the current process environment."
    )
    return 1 if problems else 0


def hvault_command(args) -> int:
    """``hermes hvault ...`` dispatch. Returns the process exit code."""
    from .source import CustodyUnavailable, StoreNotSetUp

    cmd = getattr(args, "hvault_command", None)
    try:
        if cmd is None:
            return _cmd_status(args)
        if cmd == "bind":
            return _cmd_bind(args)
        if cmd == "allow":
            return _cmd_allow(args)
        if cmd == "setup":
            return _cmd_setup(args)
        if cmd == "add":
            return _cmd_add(args)
        if cmd == "put":
            return _cmd_put(args)
        if cmd == "show":
            return _cmd_show(args)
        if cmd == "rm":
            return _cmd_rm(args)
        if cmd == "list":
            return _cmd_list(args)
        if cmd == "env":
            return _cmd_env(args)
        if cmd == "doctor":
            return _cmd_doctor(args)
    except (StoreNotSetUp, CustodyUnavailable) as error:
        # Messages written by this plugin or floorvault; they name no key material.
        print(f"hvault {cmd}: {error}", file=sys.stderr)
        return 1
    except CLIInputError as error:
        print(f"hvault {cmd}: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 — operator CLI surfaces the reason, never a traceback value
        print(
            f"hvault {cmd}: operation failed ({type(error).__name__}); check configuration, item and key custody",
            file=sys.stderr,
        )
        return 2 if isinstance(error, ValueError) else 1
    print(
        "usage: hermes hvault {bind|allow|list|doctor|show|rm|setup|add|put|env}", file=sys.stderr
    )
    return 2

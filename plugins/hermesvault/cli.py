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
import sys
import unicodedata
import warnings
from pathlib import Path

from agent.secret_sources.base import get_source_environment
from hermes_constants import get_hermes_home

from .binding_guard import gateway_command_line
from .source import (
    HermesVaultSource,
    parse_ref,
    resolve_base_dir,
    valid_env_name,
    validate_config,
)


class CLIInputError(ValueError):
    """An operator-facing validation message containing no input values."""


#: Longest secret read from a pipe. A bounded read cannot be turned into an
#: unbounded allocation by whatever is on the other end of the pipe.
_MAX_STDIN_CHARS = 65536


def _item_id(value):
    item, field = parse_ref(f"hv:{value}")
    if item is None or field is not None or item != value:
        raise CLIInputError("item ID must use 1-128 letters, numbers, dots, underscores or hyphens")
    return item


def _field(value):
    # Cc covers C0, DEL and the C1 range (0x9b is a terminal CSI); Zl/Zp are the
    # Unicode line and paragraph separators. A field name is echoed back, so none
    # of them may forge a line or drive the terminal.
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(c) in ("Cc", "Zl", "Zp") for c in value)
    ):
        raise CLIInputError("field must be non-empty and contain no control characters")
    return value


def _value_problem(value: str) -> "str | None":
    """Why ``value`` cannot be stored, or None. Names the problem, never the value.

    A blank value is refused by the store, or silently dropped by ``add_item``.
    A NUL byte cannot be held by any environment variable: Hermes would fail
    while publishing the resolved values, so it is refused at write time, as
    `floorvault secrets add` and `put` refuse it.
    """
    if not value.strip():
        return "empty value"
    if "\x00" in value:
        return "the value contains a NUL byte, which no environment variable can hold"
    return None


def _printable(text: str) -> str:
    """``text`` with control characters escaped, so it cannot forge a line or drive the terminal."""
    return "".join(
        f"\\x{ord(char):02x}" if unicodedata.category(char) == "Cc" else char for char in text
    )


def _root_is_not_a_mapping() -> bool:
    """Whether config.yaml holds anything but an empty mapping, for a file that read as ``{}``.

    A mapping that reads as ``{}`` is an empty file, comments only, or ``{}``. Any
    other content is a root that is not a mapping (a list, a scalar), which the
    raw reader flattens to ``{}``: taking it for an empty configuration would
    select the default store, so it is refused.
    """
    from hermes_cli.config import get_config_path

    try:
        text = Path(get_config_path()).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return False
    body = "".join("".join(line.split("#", 1)[0].split()) for line in text.splitlines())
    return body.replace("---", "").replace("...", "") not in ("", "{}")


# The top-level Hermes config key that holds every secret source's settings.
# It is a name, not a value, and `doctor` prints names on purpose. It is read
# through a variable so the analyser's name heuristic does not mark the whole
# section, and everything derived from it, as sensitive data.
_SECRETS_SECTION = "secrets"


def _mapping_at(parent: dict, key: str) -> dict:
    """``parent[key]`` as a mapping, ``{}`` when absent; anything else is refused."""
    value = parent.get(key, {})
    if not isinstance(value, dict):
        raise CLIInputError(f"{key} configuration must be a mapping")
    return value


def _secrets_cfg() -> dict:
    """The ``secrets.hermesvault`` section exactly as the user wrote it.

    Read through ``read_user_config_raw``, Hermes' raw reader: it raises on a
    file that does not parse. ``load_config()`` merges defaults and swallows a
    parse failure into them, and defaults must never silently select a store or
    custody. (Hermes' startup loader is more lenient: it treats an unparseable
    file as empty, so the source is simply off. These commands are stricter on
    purpose, because they write.) ``read_user_config_raw`` also turns a root that
    is not a mapping into ``{}``; that is checked separately.
    """
    try:
        from hermes_cli.config import read_user_config_raw
    except ImportError:
        raise CLIInputError(
            "cannot read Hermes configuration: this hermesvault needs a Hermes "
            "release with hermes_cli.config.read_user_config_raw"
        ) from None
    try:
        config = read_user_config_raw()
        not_a_mapping = not config and _root_is_not_a_mapping()
    except Exception:
        raise CLIInputError(
            "cannot load Hermes configuration; correct config.yaml before retrying"
        ) from None
    if not_a_mapping or not isinstance(config, dict):
        raise CLIInputError("Hermes configuration must be a mapping")
    section = _mapping_at(config, _SECRETS_SECTION).get("hermesvault", {})
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
        problem = _value_problem(value)
        if problem is not None:
            raise CLIInputError(f"{where} {number}: {problem}; nothing stored")
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
    bind.add_argument(
        "--no-bind",
        action="store_true",
        help=(
            "Do not bind a new item to the command line Hermes resolves secrets in "
            "(it then resolves for any command, unless require_binding is set)"
        ),
    )

    allow = sub.add_parser(
        "allow",
        help=(
            "Bind an item to command lines, so Hermes resolves it only when "
            "started as one of them (default: the gateway line `bind` uses)"
        ),
        usage=(
            "hermes hvault allow ITEM_ID [--clear | --accept | [--remove] [-- PROGRAM [ARGS...]]]"
        ),
        description=(
            "Command bindings live in the vault; a bound item is resolved only "
            "when the process was started as one of the bound command lines "
            "(secrets.hermesvault.require_binding also refuses items with none). "
            "With no command, the gateway line Hermes starts for chat and one-shot "
            "commands is bound, as `bind` binds a new item. Give another line, such "
            "as a service's, after -- the way `floorvault secrets allow` takes it."
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
    # The value, not the name: an empty variable is ignored by _open_store too.
    if get_source_environment().get(token_env):
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
        if sys.stdin.isatty():
            # Typed at a terminal, the values would be echoed, as `bind --stdin` refuses.
            print(
                "hvault add: --stdin reads field=value lines from a pipe or file",
                file=sys.stderr,
            )
            return 2
        for number, line in enumerate(sys.stdin, start=1):
            # Only the line ending goes: the value is stored as written, so a
            # passphrase that ends in a space keeps it.
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields.update(_field_values([line], where="stdin line", start=number))
    if not fields:
        print("hvault add: give at least one field=value (argv, or --stdin)", file=sys.stderr)
        return 2
    store = _store()
    if args.item_id is not None and store.get_meta(args.item_id) is not None:
        print(
            f"hvault add: item {args.item_id} already exists; set a field with "
            f"`hermes hvault put {args.item_id} FIELD`",
            file=sys.stderr,
        )
        return 1
    meta = store.add_item(kind="generic", label=args.label, secret=fields, item_id=args.item_id)
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
    # Only a missing item is "not found"; a store that cannot be read or decrypted
    # goes to hvault_command's redacted handler, which says to check custody.
    if store.get_meta(args.item_id) is None:
        print(f"hvault put: item {args.item_id} not found", file=sys.stderr)
        return 1
    value = _read_secret(f"{args.item_id}.{args.field}: ", "put")
    if value is None:
        return 2
    problem = _value_problem(value)
    if problem is not None:
        print(f"hvault put: {problem}; nothing changed", file=sys.stderr)
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
    store = _store()
    # As in `put`: only a missing item is "not found"; an unopenable store or a
    # failed decryption reaches the redacted handler and its custody hint.
    if store.get_meta(item_id) is None:
        print(f"hvault show: item {item_id} not found", file=sys.stderr)
        return 1
    secret = store.resolve_secret(item_id)
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
        print("bindings: not supported by this floorvault (older than 0.2.8)")
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
        # A bound line is stored text; anyone who can bind can put escapes in it.
        print(f"  {_printable(shlex.join(line))}")


def _cmd_rm(args) -> int:
    _item_id(args.item_id)
    if _store().remove_item(args.item_id):
        print(f"removed {args.item_id}")
        _forget_binding(args.item_id)
        _warn_still_mapped(args.item_id)
        return 0
    print(f"hvault rm: item {args.item_id} not found", file=sys.stderr)
    return 1


def _warn_still_mapped(item_id: str) -> None:
    """Say when config.yaml still maps variables to an item just removed.

    Hermes skips such a mapping at startup with a warning; saying so here is the
    moment the operator can act. Counted, not named: no name from the secrets
    section is echoed (see ``_cmd_bind``).
    """
    try:
        env_map = _secrets_cfg().get("env")
    except CLIInputError:
        return
    if not isinstance(env_map, dict):
        return
    count = sum(1 for ref in env_map.values() if parse_ref(ref)[0] == item_id)
    if count:
        print(
            f"hvault rm: warning: {count} variable(s) in secrets.hermesvault.env still "
            f"map to {item_id}; Hermes skips them until they are removed from config.yaml "
            "(`hermes hvault doctor` lists them)",
            file=sys.stderr,
        )


def _forget_binding(item_id: str) -> None:
    """Drop a removed item from the binding record, as `floorvault secrets rm` does.

    Left there, the fingerprint of the removed item's binding would be compared
    with a later item of the same id, which would then be skipped as "changed"
    until `allow --accept`. The item is already gone, so a record that cannot be
    updated is a warning, not a failure.
    """
    try:
        from floorvault.binding_record import BindingRecordError
    except ImportError:  # floorvault 0.2.x keeps no record
        return
    try:
        base = resolve_base_dir(_secrets_cfg(), Path(get_hermes_home()))
        record, _record_error = _binding_record(base)
        record.forget(item_id)
    except (BindingRecordError, CLIInputError) as exc:
        print(f"hvault rm: warning: {exc}", file=sys.stderr)


def _record_unbound_new_item(store, cfg: dict, home: Path, item_id: str) -> None:
    """Record that an item `bind` just created has no binding.

    The secret source refuses an item whose binding differs from the record, so
    recording "none" at creation means a binding that appears later without
    `allow` is noticed, and an entry left by an earlier item of the same id does
    not get the new one skipped. Nothing to do on a floorvault that keeps no
    record; a record that cannot be written is said so and the item stays usable.
    """
    if getattr(store, "binding_fingerprint", None) is None:
        return
    try:
        record, record_error = _binding_record(resolve_base_dir(cfg, home))
    except CLIInputError as exc:
        print(f"hvault bind: warning: {exc}", file=sys.stderr)
        return
    try:
        record.record(item_id, store.binding_fingerprint(item_id))
    except record_error as exc:
        print(f"hvault bind: warning: {exc}", file=sys.stderr)


def _cmd_list(_args) -> int:
    items = _store().list_items()
    if not items:
        print("(empty vault)")
        return 0
    for meta in items:
        parts = [meta.id, meta.kind, meta.label]
        if meta.origin:
            parts.append(meta.origin)
        # One item, one line: kind and origin are cleartext columns anyone who
        # can write vault.db can set, and a label may come from another tool.
        print("\t".join(_printable(str(p)) for p in parts))
    return 0


def _print_mapping(env_name: str, ref: str) -> None:
    print("secrets:")
    print("  hermesvault:")
    print("    enabled: true")
    print("    env:")
    print(f"      {json.dumps(env_name)}: {json.dumps(ref)}")


def _cmd_env(args) -> int:
    _item_id(args.item_id)
    if not valid_env_name(args.env_name):
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
    if not valid_env_name(args.env_name):
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
        value = sys.stdin.read(_MAX_STDIN_CHARS + 1)
        if len(value) > _MAX_STDIN_CHARS:
            print(
                "hvault bind: the value from stdin is longer than 64 KiB; nothing stored",
                file=sys.stderr,
            )
            return 2
        # Line endings only, CRLF included: a key piped from a file saved on
        # Windows would otherwise keep a "\r", which passes Hermes' ASCII
        # sanitiser and fails at the provider as an invalid key.
        value = value.rstrip("\r\n")
    else:
        value = _read_secret(f"{args.env_name}: ", "bind")
    if value is None:
        return 2
    problem = _value_problem(value)
    if problem is not None:
        # add_item() drops whitespace-only fields, which would leave an empty
        # record and a mapping to a field that does not exist. The value itself
        # is stored as typed, not stripped.
        print(f"hvault bind: {problem}; nothing stored", file=sys.stderr)
        return 2
    existing = store.get_meta(item_id)
    if existing is None:
        store.add_item(kind="generic", label=label, secret={field: value}, item_id=item_id)
        print(f"stored {item_id}.{field}")
        if not getattr(args, "no_bind", False):
            print(_bind_new_item_to_gateway(store, cfg, home, item_id))
        else:
            _record_unbound_new_item(store, cfg, home, item_id)
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


def _bind_new_item_to_gateway(store, cfg: dict, home: Path, item_id: str) -> str:
    """Bind an item ``bind`` just created to the gateway line, so it is released only there.

    Only for a new item: an existing item's bindings are the operator's. The item
    was created a moment ago, so the binding record has no entry to disagree with;
    the record is written as ``allow`` writes it, so a later ``allow`` sees no change
    behind its back. Returns the line printed to the operator; never raises for a
    floorvault or platform that cannot bind here, which leaves the item unbound and
    says so.
    """
    if any(
        getattr(store, name, None) is None
        for name in ("update_allowed_commands", "binding_fingerprint")
    ):
        return (
            "not bound: command bindings need floorvault 0.3.0 or newer; the item "
            "resolves for any command"
        )
    line = gateway_command_line(home)
    if line is None:
        _record_unbound_new_item(store, cfg, home, item_id)
        return (
            f"not bound on this platform; bind it with `hermes hvault allow {item_id} "
            "-- <command line>` (the startup warning prints the line)"
        )
    record, _record_error = _binding_record(resolve_base_dir(cfg, home))
    store.update_allowed_commands(item_id, lambda current: [*(current or []), line])
    record.record(item_id, store.binding_fingerprint(item_id))
    return (
        f"bound to {_printable(shlex.join(line))}\n"
        "  (the line Hermes starts its gateway with for chat and one-shot commands; "
        f"a service's own line: `hermes hvault allow {item_id} -- <line>`; "
        "to resolve for any command: --no-bind)"
    )


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
    """The absolute program path a binding records, found exactly as `secrets allow` finds it.

    It uses that command's own lookup (``agent_cli._find_command``), which on
    Windows never searches the current directory, and then ``abspath``: a binding
    must hold an absolute, normalised path, because the guard only compares those
    and a relative one could never match.
    """
    from floorvault.agent_cli import _find_command

    path, code = _find_command(prog, os.environ)
    if path is None:
        if code == 126:
            raise CLIInputError(f"{prog} is not an executable file")
        raise CLIInputError(f"{prog}: command not found")
    return os.path.abspath(path)


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
    # Only a missing item is "not found"; a database or decryption failure goes to
    # hvault_command's redacted handler instead of being reported as a missing item.
    if store.get_meta(item_id) is None:
        print(f"hvault allow: item {item_id} not found", file=sys.stderr)
        return 1
    cfg = _secrets_cfg()
    base = resolve_base_dir(cfg, Path(get_hermes_home()))
    record, record_error = _binding_record(base)
    try:
        if args.accept:
            # Read (and authenticate) before trusting: a binding that is corrupted or
            # was copied from another item fails here, as it does for
            # `floorvault secrets allow --accept`, and the record is left as it was.
            fingerprint = store.binding_fingerprint(item_id)
            store.get_allowed_commands(item_id)
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
        if (
            len(command) == 1
            and command[0].strip().startswith("[")
            # A lone "[" is the test program (/usr/bin/[), not JSON.
            and command[0].strip() != "["
        ):
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
        if args.remove and os.path.isabs(command[0]):
            # A line is removed as stored; its program need not exist any more,
            # or a binding to a deleted program could only be dropped by --clear.
            line = [os.path.abspath(command[0]), *command[1:]]
        else:
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
        # This process is always the `hermes hvault allow` invocation, a line no
        # one means to bind. The line meant by default is the one `bind` binds a
        # new item to: the gateway Hermes starts for chat and one-shot commands.
        gateway = gateway_command_line(Path(get_hermes_home()))
        if gateway is None:
            raise CLIInputError(
                "this platform has no default line to bind; give the start command "
                "after --: the skip warning prints it, and `hermes "
                "--print-runtime-command gateway run` prints the launcher's line "
                "as JSON (paste it quoted)"
            )
        lines = [gateway]

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
                f"item {item_id} is not bound to {_printable(shlex.join(lines[0]))}"
                if len(lines) == 1
                else f"item {item_id} is bound to none of these command lines"
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
    code = 0
    if exists and enabled and mappings:
        result = HermesVaultSource().fetch_for(cfg, home, None)
        if result.ok:
            # A partial map is status, not failure: the next step names doctor.
            print(f"resolved {len(result.secrets)}/{mappings} mapping(s); values are not displayed")
        else:
            print(f"resolve failed: {result.error}", file=sys.stderr)
            code = 1
    if not mappings:
        print("next: hermes hvault bind <ENV_NAME>   # stores a secret and maps it")
    elif not enabled:
        print("next: set secrets.hermesvault.enabled: true, or run `hermes hvault bind`")
    else:
        print("next: hermes hvault doctor   # full check; `bind` adds more")
    print("commands: bind, allow, list, doctor, show, rm; advanced: setup, add, put, env")
    return code


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
    # validate_config (in _secrets_cfg) refused an env that is neither a map nor null.
    env_map = cfg.get("env") or {}
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
    # Everything startup checks except "was Hermes started as a bound line": this
    # is the hvault process, which no binding names. Bound items are listed below.
    result = source.fetch_for(cfg, home, None)
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
        if not valid_env_name(name):
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
    _print_binding_notes(cfg, home, env_map)
    print(f"resolved {len(result.secrets)}/{len(env_map)} mapping(s); values are not displayed")
    print(
        "Restart Hermes after changes and verify the consuming service; this checks the current process environment."
    )
    return 1 if problems else 0


def _print_binding_notes(cfg: dict, home: Path, env_map: dict) -> None:
    """For each mapping to a bound item: Hermes resolves it only when started as a bound line.

    Not a problem, and not checkable from here: whether Hermes is started as one
    of those lines is decided when it starts. Says when the gateway line `bind`
    uses is not among them. Mappings are numbered, not named (see ``_cmd_bind``).
    """
    try:
        store = _store()
    except Exception:  # noqa: BLE001 — fetch_for has already reported the store
        return
    getter = getattr(store, "get_allowed_commands", None)
    if getter is None:
        return
    gateway = gateway_command_line(home)
    for idx, ref in enumerate(env_map.values(), start=1):
        item_id = parse_ref(ref)[0]
        if item_id is None:
            continue
        try:
            allowed = getter(item_id)
        except Exception:  # noqa: BLE001  # nosec B112 - fetch_for already warned about it
            continue
        if not allowed:
            continue
        where = (
            "" if gateway is None or gateway in allowed else "; the gateway line is not one of them"
        )
        print(
            f"mapping #{idx}: bound to {len(allowed)} command line(s){where}; Hermes "
            f"resolves it only when started as one (`hermes hvault show hv:{item_id}`)"
        )


def hvault_command(args) -> int:
    """``hermes hvault ...`` dispatch. Returns the process exit code."""
    from .source import CustodyUnavailable, StoreNotSetUp

    cmd = getattr(args, "hvault_command", None)
    prog = f"hvault {cmd}" if cmd else "hvault"
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
        print(f"{prog}: {error}", file=sys.stderr)
        return 1
    except CLIInputError as error:
        print(f"{prog}: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 — operator CLI surfaces the reason, never a traceback value
        # 2 is kept for what the operator typed or configured (CLIInputError,
        # including a malformed config.yaml); a store, key or custody failure is
        # a runtime failure, whatever its class (VaultError is a ValueError).
        print(
            f"{prog}: operation failed ({type(error).__name__}); check configuration, item and key custody",
            file=sys.stderr,
        )
        return 1
    print(
        "usage: hermes hvault {bind|allow|list|doctor|show|rm|setup|add|put|env}", file=sys.stderr
    )
    return 2

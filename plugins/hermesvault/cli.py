"""``hermes hvault`` operator CLI: manage items in the agent-secret vault.

Adds, lists, shows and removes ``generic`` items in the store backing
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
import sys
from pathlib import Path

from agent.secret_sources.base import get_source_environment, is_valid_env_name
from hermes_constants import get_hermes_home

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
    try:
        import yaml
        from hermes_cli.config import get_config_path, load_config

        # Hermes may return defaults or a last-known-good config after a parse
        # failure. Vault commands must not silently select a different store.
        path = Path(get_config_path())
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            raw = "{}"
        parsed = yaml.safe_load(raw)
        if parsed is not None and not isinstance(parsed, dict):
            raise ValueError("configuration must be a mapping")
        config = load_config()
        if getattr(config, "read_error", None) is not None:
            raise ValueError("Hermes returned a configuration fallback")
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


def _store():
    cfg = _secrets_cfg()
    from .source import _open_store

    return _open_store(cfg, Path(get_hermes_home()))


def _field_values(pairs) -> dict:
    out = {}
    for pair in pairs or []:
        field, sep, value = str(pair).partition("=")
        field = field.strip()
        if not sep or not field:
            raise CLIInputError("field must be given as field=value")
        out[_field(field)] = value
    return out


def register_cli(subparser) -> None:
    sub = subparser.add_subparsers(dest="hvault_command", metavar="<command>")

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


def _cmd_add(args) -> int:
    if args.item_id is not None:
        _item_id(args.item_id)
    fields = _field_values(args.fields)
    if args.stdin:
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields.update(_field_values([line]))
    if not fields:
        print("hvault add: give at least one field=value (argv, or --stdin)", file=sys.stderr)
        return 2
    meta = _store().add_item(kind="generic", label=args.label, secret=fields, item_id=args.item_id)
    print(f"created {meta.id}")
    return 0


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
    value = getpass.getpass(f"{args.item_id}.{args.field}: ")
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
        secret = _store().resolve_secret(item_id)
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
    return 0


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


def _cmd_env(args) -> int:
    _item_id(args.item_id)
    if not is_valid_env_name(args.env_name):
        raise CLIInputError("invalid environment variable name")
    if args.field is not None:
        _field(args.field)
    field = f":{args.field}" if args.field else ""
    print("secrets:")
    print("  hermesvault:")
    print("    enabled: true")
    print("    env:")
    print(f"      {json.dumps(args.env_name)}: {json.dumps(f'hv:{args.item_id}{field}')}")
    return 0


def _cmd_doctor(_args) -> int:
    cfg = _secrets_cfg()
    home = Path(get_hermes_home())
    base = resolve_base_dir(cfg, home)
    print(f"profile: {home}")
    print(f"store: {base}")
    if cfg.get("enabled") is not True:
        print(
            "hvault doctor: source is disabled; set secrets.hermesvault.enabled: true",
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
    cmd = getattr(args, "hvault_command", None)
    try:
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
    except CLIInputError as error:
        print(f"hvault {cmd}: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 — operator CLI surfaces the reason, never a traceback value
        print(
            f"hvault {cmd}: operation failed ({type(error).__name__}); check configuration, item and key custody",
            file=sys.stderr,
        )
        return 2 if isinstance(error, ValueError) else 1
    print("usage: hermes hvault {add|put|show|rm|list|env|doctor}", file=sys.stderr)
    return 2

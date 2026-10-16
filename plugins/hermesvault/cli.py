"""``hermes hvault`` operator CLI: manage items in the agent-secret vault.

Adds, lists, shows and removes ``generic`` items in the store backing
``secrets.hermesvault.env`` refs. Values are never logged; ``put`` reads the
value via getpass so it never appears on argv. ``add`` accepts
``field=value`` pairs on argv (visible to ``ps`` while the command runs —
prefer ``put`` for single values) or ``--stdin`` reading ``field=value``
lines.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Optional

from hermes_constants import get_hermes_home

from .source import DEFAULT_TOKEN_ENV, parse_ref, resolve_base_dir


def _secrets_cfg() -> dict:
    try:
        from hermes_cli.config import load_config

        cfg = (load_config() or {}).get("secrets") or {}
        section = cfg.get("hermesvault")
        return section if isinstance(section, dict) else {}
    except Exception:
        return {}


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
            raise ValueError(f"field must be given as field=value: {pair!r}")
        out[field] = value
    return out


def register_cli(subparser) -> None:
    sub = subparser.add_subparsers(dest="hvault_command", metavar="<command>")

    add = sub.add_parser("add", help="Create a generic secret item")
    add.add_argument("label", help="Human label for the item")
    add.add_argument("fields", nargs="*", metavar="field=value",
                     help="Secret fields (argv-visible; prefer --stdin or `put`)")
    add.add_argument("--stdin", action="store_true",
                     help="Read field=value lines from stdin instead of argv")
    add.add_argument("--id", dest="item_id", default=None,
                     help="Explicit item id (default: vault_<random>)")

    put = sub.add_parser("put", help="Set one field on an item (prompted, never argv)")
    put.add_argument("item_id")
    put.add_argument("field")

    show = sub.add_parser("show", help="Show one item's fields")
    show.add_argument("ref", help="hv:<item_id>[:field] or a bare item id")
    show.add_argument("--reveal", action="store_true",
                     help="Print values; default lists field names only")

    rm = sub.add_parser("rm", help="Delete an item")
    rm.add_argument("item_id")

    sub.add_parser("list", help="List items (metadata only)")

    env = sub.add_parser("env", help="Print the secrets.hermesvault.env mapping to paste into config.yaml")
    env.add_argument("item_id")
    env.add_argument("env_name", help="Env var name to bind")
    env.add_argument("--field", default=None)


def _cmd_add(args) -> int:
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
    meta = _store().add_item(kind="generic", label=args.label, secret=fields,
                             item_id=args.item_id)
    print(f"created {meta.id}")
    return 0


def _cmd_put(args) -> int:
    store = _store()
    try:
        secret = store.resolve_secret(args.item_id)
    except Exception:
        print(f"hvault put: item {args.item_id} not found", file=sys.stderr)
        return 1
    value = getpass.getpass(f"{args.item_id}.{args.field}: ")
    if not value:
        print("hvault put: empty value", file=sys.stderr)
        return 2
    secret[args.field] = value
    meta = store.get_meta(args.item_id)
    store.remove_item(args.item_id)
    store.add_item(kind="generic", label=meta.label if meta else args.item_id,
                   secret=secret, item_id=args.item_id)
    print(f"updated {args.item_id}.{args.field}")
    return 0


def _cmd_show(args) -> int:
    item_id, field = parse_ref(args.ref) if str(args.ref).startswith("hv:") else (args.ref, None)
    if item_id is None:
        item_id, field = args.ref, None
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
        print("use --reveal to print values", file=sys.stderr)
    return 0


def _cmd_rm(args) -> int:
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
    field = f":{args.field}" if args.field else ""
    print("secrets:")
    print("  hermesvault:")
    print("    enabled: true")
    print("    env:")
    print(f'      {args.env_name}: "hv:{args.item_id}{field}"')
    return 0


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
    except ValueError as error:
        print(f"hvault {cmd}: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 — operator CLI surfaces the reason, never a traceback value
        print(f"hvault {cmd}: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print("usage: hermes hvault {add|put|show|rm|list|env}", file=sys.stderr)
    return 2

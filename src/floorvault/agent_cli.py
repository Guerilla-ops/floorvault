"""``floorvault run`` and ``floorvault secrets``: vault secrets for any process.

``run`` fills ``fv:`` references into environment variables and starts a
command with them. ``secrets`` manages the items those references name.

Rules this module keeps:

* ``run`` writes nothing to stdout. MCP stdio servers speak JSON-RPC there,
  so every diagnostic goes to stderr.
* ``run`` fails closed: every reference resolves or the command never starts.
* Only ``secrets add`` may create a store or a master key. Every other command
  opens an existing store and resolves the key with ``allow_create=False``.
* The child never inherits a vault key variable.
* No command prints a secret value. Plaintext leaves the vault only into the
  environment of the process ``run`` starts.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import shutil
import sqlite3
import stat
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .agentenv import (
    AgentEnvError,
    collect,
    default_vault_dir,
    is_valid_env_name,
    parse_env_file,
    parse_ref,
    resolve,
)

# The custody identity VaultStore and the hermesvault plugin use, so one store
# opens the same way from Hermes and from these commands.
SERVICE_NAME = "floor-vault"
APP_CONTEXT = "floor-agent"

_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HEX_KEY = re.compile(r"[0-9A-Fa-f]{64}")


class StoreUnavailable(Exception):
    """The store or its key could not be opened. The message is safe to print."""


def _err(prog: str, message: str) -> None:
    print(f"{prog}: {message}", file=sys.stderr)


def _vault_dir(arg: Optional[Path], environ: Mapping[str, str]) -> Path:
    return arg.expanduser() if arg is not None else default_vault_dir(environ)


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def open_store(
    vault_dir: Path,
    *,
    key_env: Optional[str] = None,
    create: bool = False,
    environ: Optional[Mapping[str, str]] = None,
):
    """Open the agent-secret store at ``vault_dir``.

    With ``create=False`` (every command but ``secrets add``) the store must
    already exist and the master key is only read, never created.
    """
    from .core import FloorVault
    from .memory import HardenedMemoryKey
    from .providers.adaptive import AdaptiveKeyProvider
    from .providers.base import KeyProviderError
    from .vaultkit.vault import VaultError, VaultStore

    environ = os.environ if environ is None else environ
    if not create and not _is_regular_file(vault_dir / "vault.db"):
        raise StoreUnavailable(f"no vault at {vault_dir}; create one with `floorvault secrets add`")
    try:
        if key_env:
            raw = (environ.get(key_env) or "").strip()
            if not raw:
                raise StoreUnavailable(f"--key-env {key_env} is not set")
            if not _HEX_KEY.fullmatch(raw):
                raise StoreUnavailable(f"{key_env} must hold 64 hexadecimal characters")
            crypto = FloorVault(HardenedMemoryKey(bytes.fromhex(raw)), app_instance_id=APP_CONTEXT)
            return VaultStore(vault_dir, crypto=crypto)
        if create:
            return VaultStore(vault_dir)
        provider = AdaptiveKeyProvider(service_name=SERVICE_NAME, fallback_dir=vault_dir)
        key = provider.resolve_key(allow_create=False)
        return VaultStore(vault_dir, crypto=FloorVault(key, app_instance_id=APP_CONTEXT))
    except StoreUnavailable:
        raise
    except (KeyProviderError, VaultError, ValueError, OSError, sqlite3.Error) as exc:
        raise StoreUnavailable(f"cannot open vault at {vault_dir}: {exc}") from None


# --------------------------------------------------------------------------- run


def _run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="floorvault run",
        usage="floorvault run [options] -- <command> [args...]",
        description=(
            "Fill fv: references into environment variables, then start <command>. "
            "References come from the inherited environment, --env-file and -e. "
            "If any reference cannot be resolved the command is not started."
        ),
    )
    _add_store_options(parser)
    parser.add_argument(
        "--env-file",
        action="append",
        type=Path,
        default=[],
        metavar="PATH",
        help="dotenv-style file of NAME=value lines; fv: values are resolved (repeatable)",
    )
    parser.add_argument(
        "-e",
        dest="explicit",
        action="append",
        default=[],
        metavar="NAME=fv:REF",
        help="bind one variable to a reference (repeatable; highest precedence)",
    )
    parser.add_argument(
        "--no-inherit-refs",
        action="store_true",
        help="do not resolve fv: values already in the inherited environment",
    )
    return parser


def _find_command(command: str, env: Mapping[str, str]) -> tuple[Optional[str], int]:
    """Locate ``command`` on the child's PATH: (path, 0) or (None, 126/127)."""
    seps = {os.sep, os.altsep} - {None}
    if any(sep in command for sep in seps):
        path = Path(command)
        if not path.exists():
            return None, 127
        if path.is_dir() or not os.access(path, os.X_OK):
            return None, 126
        return str(path), 0
    found = shutil.which(command, path=env.get("PATH", os.defpath))
    return (found, 0) if found else (None, 127)


def _prepare_environment(args: argparse.Namespace, prog: str) -> tuple[Optional[dict], int]:
    """Build the child environment. Store and key do not outlive this call."""
    try:
        files = [parse_env_file(path) for path in args.env_file]
        env, refs = collect(
            dict(os.environ),
            files,
            args.explicit,
            inherit_refs=not args.no_inherit_refs,
            key_env=args.key_env,
        )
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return None, 2
    if not refs:
        return env, 0
    try:
        store = open_store(_vault_dir(args.vault, os.environ), key_env=args.key_env)
    except StoreUnavailable as exc:
        _err(prog, str(exc))
        return None, 1
    except Exception as exc:  # noqa: BLE001 - the type is safe; a message may not be
        _err(prog, f"cannot open vault ({type(exc).__name__})")
        return None, 1
    try:
        values = resolve(store, refs)
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return None, 2
    finally:
        del store
    env.update(values)
    return env, 0


def _spawn_and_wait(path: str, argv: Sequence[str], env: Mapping[str, str]) -> int:
    """Start the child and wait for it, returning its exit code.

    Used on Windows, where ``os.exec*`` starts a new process and exits the
    caller at once, which an MCP client reads as the server exiting. The child
    shares this console, so Ctrl+C and Ctrl+Break reach it directly; this
    process keeps waiting for it to finish.
    """
    # Starting the operator's own command is this function's purpose; the
    # argv is passed as a list, never through a shell.
    import subprocess  # nosec B404

    try:
        proc = subprocess.Popen([path, *argv[1:]], env=dict(env))  # nosec B603
    except OSError as exc:
        _err("floorvault run", f"cannot start {argv[0]}: {type(exc).__name__}")
        return 126
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue


def _launch(path: str, argv: Sequence[str], env: dict) -> int:
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        return _spawn_and_wait(path, argv, env)
    try:
        os.execve(path, list(argv), env)  # nosec B606 - the operator's command, no shell
    except OSError as exc:
        _err("floorvault run", f"cannot start {argv[0]}: {type(exc).__name__}")
        return 126
    raise AssertionError("unreachable")  # pragma: no cover


def run_main(argv: Sequence[str]) -> int:
    """``floorvault run [options] -- <command> [args...]``."""
    prog = "floorvault run"
    argv = list(argv)
    if "--" in argv:
        split = argv.index("--")
        options, command = argv[:split], argv[split + 1 :]
    else:
        options, command = argv, []
    args = _run_parser().parse_args(options)
    if not command:
        _err(prog, "give the command after --, for example: floorvault run -- python app.py")
        return 2
    env, code = _prepare_environment(args, prog)
    if env is None:
        return code
    path, code = _find_command(command[0], env)
    if path is None:
        reason = "not found" if code == 127 else "not executable"
        _err(prog, f"{command[0]}: command {reason}")
        return code
    return _launch(path, command, env)


# ----------------------------------------------------------------------- secrets


def _add_store_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        metavar="DIR",
        help="store directory (default: $FLOORVAULT_DIR or ~/.floorvault/agent-vault)",
    )
    parser.add_argument(
        "--key-env",
        default=None,
        metavar="NAME",
        help="read the master key (64 hex) from this variable instead of OS custody",
    )


def add_secrets_parser(subparsers) -> None:
    secrets = subparsers.add_parser(
        "secrets",
        help="Manage items in the agent-secret store used by `floorvault run`",
        description="Manage generic items in the agent-secret store. No command prints a value.",
    )
    common = argparse.ArgumentParser(add_help=False)
    _add_store_options(common)
    sub = secrets.add_subparsers(dest="secrets_command", metavar="<command>", required=True)

    add = sub.add_parser("add", parents=[common], help="Create an item and print its id")
    add.add_argument("label", help="human label for the item")
    add.add_argument(
        "fields",
        nargs="*",
        metavar="field=value",
        help="secret fields (visible to `ps` while running; prefer --stdin or `put`)",
    )
    add.add_argument("--stdin", action="store_true", help="read field=value lines from stdin")
    add.add_argument("--id", dest="item_id", default=None, help="item id (default: random)")

    put = sub.add_parser("put", parents=[common], help="Set one field (prompted, never argv)")
    put.add_argument("item_id")
    put.add_argument("field")

    sub.add_parser("list", parents=[common], help="List items: id, kind and label")

    show = sub.add_parser("show", parents=[common], help="Show whether an item's fields are set")
    show.add_argument("ref", help="item id, item_id:field, or an fv: reference")

    rm = sub.add_parser("rm", parents=[common], help="Delete an item")
    rm.add_argument("item_id")

    ref = sub.add_parser("ref", parents=[common], help="Print the fv: reference for an item")
    ref.add_argument("item_id")
    ref.add_argument("--field", default=None)
    ref.add_argument("--env", dest="env_name", default=None, help="print NAME=fv:... instead")


def _field_values(pairs: Sequence[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for pair in pairs:
        field, sep, value = str(pair).partition("=")
        field = field.strip()
        if not sep or not field:
            raise ValueError("fields must be given as field=value")
        fields[field] = value
    return fields


def _split_target(text: str) -> tuple[Optional[str], Optional[str]]:
    if text.startswith(("fv:", "hv:")):
        try:
            ref = parse_ref(text)
        except AgentEnvError:
            return None, None
        return (ref.item_id, ref.field) if ref else (None, None)
    item_id, _, field = text.partition(":")
    if not _ITEM_ID.fullmatch(item_id):
        return None, None
    return item_id, (field or None)


def _store_for(args, *, create: bool = False):
    return open_store(_vault_dir(args.vault, os.environ), key_env=args.key_env, create=create)


def _cmd_add(args, prog: str) -> int:
    if args.item_id is not None and not _ITEM_ID.fullmatch(args.item_id):
        _err(prog, "--id must match [A-Za-z0-9._-]{1,128}")
        return 2
    fields = _field_values(args.fields)
    if args.stdin:
        for line in sys.stdin:
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields.update(_field_values([line]))
    if not fields:
        _err(prog, "give at least one field=value (argv, or --stdin)")
        return 2
    store = _store_for(args, create=True)
    meta = store.add_item(kind="generic", label=args.label, secret=fields, item_id=args.item_id)
    print(meta.id)
    return 0


def _cmd_put(args, prog: str) -> int:
    store = _store_for(args)
    if store.get_meta(args.item_id) is None:
        _err(prog, f"item {args.item_id} not found")
        return 1
    value = getpass.getpass(f"{args.item_id}.{args.field}: ")
    if not value:
        _err(prog, "empty value; nothing changed")
        return 2
    if not store.update_generic_field(args.item_id, args.field, value):
        _err(prog, f"item {args.item_id} not found")
        return 1
    print(f"updated {args.item_id}.{args.field}")
    return 0


def _cmd_list(args, prog: str) -> int:
    for meta in sorted(_store_for(args).list_items(), key=lambda m: m.id):
        print("\t".join((meta.id, meta.kind, meta.label)))
    return 0


def _cmd_show(args, prog: str) -> int:
    item_id, field = _split_target(args.ref)
    if item_id is None:
        _err(prog, "expected an item id, item_id:field, or fv:<item_id>[:<field>]")
        return 2
    store = _store_for(args)
    try:
        secret = store.resolve_secret(item_id)
    except Exception as exc:  # noqa: BLE001 - report the type, never a message
        _err(prog, f"item {item_id} is unavailable ({type(exc).__name__})")
        return 1
    if field is not None:
        if field not in secret:
            _err(prog, f"item {item_id} has no field {field!r}")
            return 1
        print("(set)" if secret[field] else "(empty)")
        return 0
    filled = sum(1 for value in secret.values() if value)
    print(f"{len(secret)} field(s): {filled} set, {len(secret) - filled} empty")
    return 0


def _cmd_rm(args, prog: str) -> int:
    if _store_for(args).remove_item(args.item_id):
        print(f"removed {args.item_id}")
        return 0
    _err(prog, f"item {args.item_id} not found")
    return 1


def _cmd_ref(args, prog: str) -> int:
    if not _ITEM_ID.fullmatch(args.item_id):
        _err(prog, "item id must match [A-Za-z0-9._-]{1,128}")
        return 2
    if args.env_name is not None and not is_valid_env_name(args.env_name):
        _err(prog, "--env must be a variable name such as OPENAI_API_KEY")
        return 2
    reference = f"fv:{args.item_id}" + (f":{args.field}" if args.field else "")
    try:
        parse_ref(reference)
    except AgentEnvError:
        _err(prog, "--field must be non-empty and contain no NUL or newline")
        return 2
    if _store_for(args).get_meta(args.item_id) is None:
        _err(prog, f"item {args.item_id} not found")
        return 1
    print(f"{args.env_name}={reference}" if args.env_name else reference)
    return 0


_SECRETS_COMMANDS = {
    "add": _cmd_add,
    "put": _cmd_put,
    "list": _cmd_list,
    "show": _cmd_show,
    "rm": _cmd_rm,
    "ref": _cmd_ref,
}


def secrets_main(args: argparse.Namespace) -> int:
    from .vaultkit.vault import VaultError

    prog = f"floorvault secrets {args.secrets_command}"
    try:
        return _SECRETS_COMMANDS[args.secrets_command](args, prog)
    except StoreUnavailable as exc:
        _err(prog, str(exc))
        return 1
    except VaultError as exc:
        _err(prog, str(exc))
        return 1
    except ValueError as exc:
        _err(prog, str(exc))
        return 2
    except Exception as exc:  # noqa: BLE001 - the type is safe; values never are
        _err(prog, f"failed ({type(exc).__name__})")
        return 1

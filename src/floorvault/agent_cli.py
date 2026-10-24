"""``floorvault run`` and ``floorvault secrets``: vault secrets for any process.

``run`` fills ``fv:`` references into environment variables and starts a
command with them. ``secrets`` manages the items those references name.

Rules this module keeps:

* ``run`` writes nothing to stdout. MCP stdio servers speak JSON-RPC there,
  so every diagnostic goes to stderr.
* ``run`` fails closed: every reference resolves or the command never starts.
* Only ``secrets add`` and ``secrets import --write`` may create a store or a
  master key. Every other command opens an existing store and resolves the key
  with ``allow_create=False``.
* The child never inherits a vault key variable, nor another variable holding
  a copy of one's value.
* ``run`` exits 125 when it fails itself, so its failures never look like the
  command's own exit status.
* No ``secrets`` command prints a secret value. That is a convenience rule, not
  a control: ``run`` is the one path out of the vault, and whatever it starts
  can print what it receives (``floorvault run -e X=fv:id -- printenv X``).
* The command is looked up on ``run``'s own PATH, never on a PATH set by an
  env file or ``-e``, so configuration cannot choose which binary runs.
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
import tempfile
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .agentenv import (
    CUSTODY_ENV_NAMES,
    AgentEnvError,
    EnvFile,
    collect,
    default_vault_dir,
    is_ref_like,
    is_valid_env_name,
    parse_env_file,
    parse_ref,
    read_env_file,
    render_env_file,
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


KEY_FILE_ENV = "FLOOR_VAULT_KEY_FILE"
_MAX_KEY_FILE_BYTES = 4096


def read_key_file(path: Path) -> bytes:
    """Read a 64-hex master key from ``path``, such as an orchestrator secret mount.

    Symlinks are followed (Kubernetes mounts secrets through ``..data`` links),
    but the target must be a regular file owned by this user or root and not
    writable by group or others: a replaceable key file would let someone else
    choose the key new items are sealed under. A file readable by others is
    used with a warning. Errors name the path, never the content.
    """
    path = Path(path).expanduser()
    try:
        resolved = path.resolve(strict=True)
        st = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise StoreUnavailable(f"key file {path}: cannot read ({type(exc).__name__})") from None
    if not stat.S_ISREG(st.st_mode):
        raise StoreUnavailable(f"key file {path} is not a regular file")
    if os.name != "nt":
        if st.st_uid not in (os.geteuid(), 0):
            raise StoreUnavailable(f"key file {path} is owned by another user")
        if st.st_mode & 0o022:
            raise StoreUnavailable(
                f"key file {path} is writable by group or others; run chmod go-w on it"
            )
        if st.st_mode & 0o004:
            _err("floorvault", f"warning: key file {path} is readable by other users")
    if st.st_size > _MAX_KEY_FILE_BYTES:
        raise StoreUnavailable(f"key file {path} is too large to hold a key")
    try:
        with resolved.open("rb") as handle:
            raw = handle.read(_MAX_KEY_FILE_BYTES + 1).decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise StoreUnavailable(f"key file {path}: cannot read ({type(exc).__name__})") from None
    if not _HEX_KEY.fullmatch(raw):
        raise StoreUnavailable(f"key file {path} must hold 64 hexadecimal characters")
    return bytes.fromhex(raw)


def _key_file_from(args, environ: Mapping[str, str]) -> Optional[Path]:
    """--key-file, else $FLOOR_VAULT_KEY_FILE unless --key-env was given."""
    if getattr(args, "key_file", None) is not None:
        return args.key_file
    if getattr(args, "key_env", None):
        return None
    raw = (environ.get(KEY_FILE_ENV) or "").strip()
    return Path(raw) if raw else None


def open_store(
    vault_dir: Path,
    *,
    key_env: Optional[str] = None,
    key_bytes: Optional[bytes] = None,
    create: bool = False,
    environ: Optional[Mapping[str, str]] = None,
):
    """Open the agent-secret store at ``vault_dir``.

    With ``create=False`` (every command but ``secrets add`` and
    ``secrets import --write``) the store must already exist and the master
    key is only read, never created. ``key_bytes`` (from ``--key-file``) and
    ``key_env`` use the given key directly, never ``AdaptiveKeyProvider``.
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
        if key_bytes is not None:
            crypto = FloorVault(HardenedMemoryKey(key_bytes), app_instance_id=APP_CONTEXT)
            return VaultStore(vault_dir, crypto=crypto)
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


# Exit status for run's own failures (usage, configuration, references, vault),
# kept apart from the 1 and 2 that commands use themselves, as GNU env does.
# 126 and 127 keep their shell meanings; anything else is the command's own.
RUN_FAILED = 125


class _RunArgumentParser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse would exit 2, a status commands use
        self.print_usage(sys.stderr)
        self.exit(RUN_FAILED, f"{self.prog}: error: {message}\n")


def _run_parser() -> argparse.ArgumentParser:
    parser = _RunArgumentParser(
        prog="floorvault run",
        usage="floorvault run [options] -- <command> [args...]",
        description=(
            "Fill fv: references into environment variables, then start <command>. "
            "References come from the inherited environment, --env-file and -e. "
            "If any reference cannot be resolved the command is not started. "
            "Exit status: 125 when run itself fails, 126 or 127 when the command "
            "cannot be started, otherwise the command's own status."
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
    """Locate ``command`` on ``env``'s PATH: (path, 0) or (None, 126/127)."""
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
        return None, RUN_FAILED
    if not refs:
        return env, 0
    key_hex = None
    try:
        _check_key_options(args)
        key_file = _key_file_from(args, os.environ)
        key_bytes = read_key_file(key_file) if key_file is not None else None
        if key_bytes is not None:
            key_hex = key_bytes.hex()
        store = open_store(
            _vault_dir(args.vault, os.environ), key_env=args.key_env, key_bytes=key_bytes
        )
    except StoreUnavailable as exc:
        _err(prog, str(exc))
        return None, RUN_FAILED
    except Exception as exc:  # noqa: BLE001 - the type is safe; a message may not be
        _err(prog, f"cannot open vault ({type(exc).__name__})")
        return None, RUN_FAILED
    try:
        values = resolve(store, refs)
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return None, RUN_FAILED
    finally:
        del store
    if key_hex is not None:
        # A copy of the key file's content under any other name stays behind.
        env = {name: value for name, value in env.items() if value.strip().lower() != key_hex}
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
        return RUN_FAILED
    env, code = _prepare_environment(args, prog)
    if env is None:
        return code
    # Look the command up on run's own PATH: a PATH in an env file reaches the
    # child, but must not pick which binary receives the secrets.
    path, code = _find_command(command[0], os.environ)
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
        help="store directory (default: $FLOOR_VAULT_DIR or ~/.floorvault/agent-vault)",
    )
    parser.add_argument(
        "--key-env",
        default=None,
        metavar="NAME",
        help="read the master key (64 hex) from this variable instead of OS custody",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "read the master key (64 hex) from this file, such as a Docker or Kubernetes "
            "secret mount, instead of OS custody (default: $FLOOR_VAULT_KEY_FILE)"
        ),
    )


def add_secrets_parser(subparsers) -> None:
    secrets = subparsers.add_parser(
        "secrets",
        help="Manage items in the agent-secret store used by `floorvault run`",
        description=(
            "Manage generic items in the agent-secret store. These commands never print a "
            "value; `floorvault run` is the only way a value leaves the vault."
        ),
    )
    common = argparse.ArgumentParser(add_help=False)
    _add_store_options(common)
    sub = secrets.add_subparsers(dest="subcommand", metavar="<command>", required=True)

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

    imp = sub.add_parser(
        "import",
        parents=[common],
        help="Move a .env file's values into the vault (a dry run unless --write)",
        description=(
            "Store each plaintext value of a dotenv-style file as a vault item and "
            "rewrite the file to fv: references. Without --write this only prints "
            "the plan; when the vault exists, the dry run unlocks it to compare values. "
            "Item ids are the lowercased variable names, after --prefix."
        ),
    )
    imp.add_argument("file", type=Path, help="the .env file")
    imp.add_argument(
        "--write",
        action="store_true",
        help="store the items, then rewrite the file in place (no backup is made)",
    )
    imp.add_argument(
        "--only", action="append", default=[], metavar="NAME", help="import only NAME (repeatable)"
    )
    imp.add_argument(
        "--skip", action="append", default=[], metavar="NAME", help="leave NAME as is (repeatable)"
    )
    imp.add_argument(
        "--prefix", default="", help="item id prefix, for example myapp. (default: none)"
    )


def _field_values(pairs: Sequence[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for pair in pairs:
        field, sep, value = str(pair).partition("=")
        field = field.strip()
        if not sep or not field:
            raise ValueError("fields must be given as field=value")
        if "\x00" in field or "\x00" in value:
            raise ValueError("fields and values may not contain a NUL byte")
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
    _check_key_options(args)
    key_file = _key_file_from(args, os.environ)
    key_bytes = read_key_file(key_file) if key_file is not None else None
    return open_store(
        _vault_dir(args.vault, os.environ),
        key_env=args.key_env,
        key_bytes=key_bytes,
        create=create,
    )


def _check_key_options(args) -> None:
    if getattr(args, "key_env", None) and getattr(args, "key_file", None) is not None:
        raise StoreUnavailable("give --key-env or --key-file, not both")


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
    if "\x00" in value:
        _err(prog, "the value may not contain a NUL byte; nothing changed")
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


class ImportFileChanged(Exception):
    """The file changed between planning and rewriting; it was left untouched."""


def _replace_file(path: Path, expected: bytes, data: bytes) -> None:
    """Atomically replace regular file ``path`` with ``data``, keeping its mode.

    Refuses when the file no longer holds ``expected``. No backup is made: a
    backup would be a second plaintext copy.
    """
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise ImportFileChanged(f"{path} is no longer a regular file")
    with path.open("rb") as handle:
        if handle.read() != expected:
            raise ImportFileChanged(f"{path} changed while importing")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _import_plan(args, env_file: EnvFile, prog: str):
    """Split a file's assignments into (to_store, left_as_is), or None on error."""
    assignments = env_file.assignments()
    names = {line.name for line in assignments}
    unknown = sorted((set(args.only) | set(args.skip)) - names)
    if unknown:
        _err(prog, f"not set in {env_file.path}: {', '.join(unknown)}")
        return None
    refused = {name.upper() for name in (*CUSTODY_ENV_NAMES, "APPSTATE_KEY")}
    if args.key_env:
        refused.add(args.key_env.upper())

    to_store: list = []
    left: list[tuple[str, str]] = []
    claimed: dict[str, str] = {}
    problems: list[str] = []
    for line in assignments:
        name = line.name
        if args.only and name not in args.only:
            left.append((name, "not selected by --only"))
        elif name in args.skip:
            left.append((name, "--skip"))
        elif name.upper() in refused:
            left.append((name, "a vault key variable cannot be stored in the vault it unlocks"))
        elif is_ref_like(line.value):
            try:
                parse_ref(line.value)
            except AgentEnvError:
                problems.append(f"{env_file.path}:{line.number}: {name}: malformed reference")
                continue
            left.append((name, "already a reference"))
        elif not line.value:
            left.append((name, "empty"))
        else:
            item_id = f"{args.prefix}{name.lower()}"
            if not _ITEM_ID.fullmatch(item_id):
                problems.append(f"{name}: item id {item_id!r} is invalid; shorten --prefix")
            elif item_id in claimed:
                problems.append(f"{claimed[item_id]} and {name} would both be stored as {item_id}")
            else:
                claimed[item_id] = name
                to_store.append((line, item_id))
    for problem in problems:
        _err(prog, problem)
    return None if problems else (to_store, left)


def _hermes_homes(environ: Mapping[str, str]) -> list[Path]:
    """Directories Hermes Agent treats as its home: $HERMES_HOME and the default."""
    homes = []
    raw = (environ.get("HERMES_HOME") or "").strip()
    if raw:
        homes.append(Path(os.path.expandvars(raw)).expanduser())
    suffix = environ.get("HERMES_DATA_DIR_SUFFIX", "")
    if os.name == "nt":
        base = (environ.get("LOCALAPPDATA") or "").strip()
        homes.append(
            (Path(base) if base else Path.home() / "AppData" / "Local") / f"hermes{suffix}"
        )
    else:
        homes.append(Path.home() / f".hermes{suffix}")
    return homes


def _is_hermes_env_file(path: Path, environ: Mapping[str, str]) -> bool:
    """Whether ``path`` is the ``.env`` of a Hermes home or profile.

    Hermes reads that file itself and lets it override the environment, so
    rewriting it to ``fv:`` references would break Hermes.
    """
    if path.name != ".env":
        return False
    try:
        directory = path.resolve().parent
    except (OSError, RuntimeError):
        return False
    candidates = {directory}
    if directory.parent.name == "profiles":
        candidates.add(directory.parent.parent)
    for home in _hermes_homes(environ):
        try:
            if home.resolve() in candidates:
                return True
        except (OSError, RuntimeError):
            continue
    return (directory / "state.db").is_file() and (directory / "config.yaml").is_file()


_RUN_ONLY_NOTE = (
    "the rewritten file works only for programs started with "
    "`floorvault run --env-file {path} -- <command>`. A program that reads the file "
    "itself (a dotenv loader set to override, Docker Compose env_file, Hermes) gets the "
    "fv: text instead of the value."
)

_HERMES_ENV_ADVICE = (
    "{path} is a Hermes Agent .env. Hermes reads it itself and lets it override the "
    "environment, so fv: references there would break Hermes. Move these keys with the "
    "hermesvault plugin instead: store each one with `hermes hvault add`, delete its line "
    "from .env, and map it under secrets.hermesvault.env (`hermes hvault env` prints the "
    "mapping). See plugins/hermesvault/README.md."
)


def _cmd_import(args, prog: str) -> int:
    if not re.fullmatch(r"[A-Za-z0-9._-]*", args.prefix):
        _err(prog, "--prefix may contain only A-Z a-z 0-9 . _ -")
        return 2
    path = args.file.expanduser()
    if args.write:
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                _err(prog, f"{path} is not a regular file; --write refuses symlinks")
                return 2
        except OSError as exc:
            _err(prog, f"{path}: cannot read env file ({type(exc).__name__})")
            return 2
    if _is_hermes_env_file(path, os.environ):
        _err(prog, _HERMES_ENV_ADVICE.format(path=path))
        if args.write:
            _err(prog, "refusing to rewrite it; nothing changed")
            return 2
    try:
        env_file = read_env_file(path)
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return 2
    plan = _import_plan(args, env_file, prog)
    if plan is None:
        return 2
    to_store, left = plan
    if not to_store:
        for name, reason in left:
            print(f"{name}: left as is ({reason})")
        print(f"nothing to import from {path}")
        return 0

    vault_dir = _vault_dir(args.vault, os.environ)
    vault_exists = _is_regular_file(vault_dir / "vault.db")
    store = _store_for(args, create=args.write) if (args.write or vault_exists) else None
    already: set[str] = set()
    problems: list[str] = []
    for line, item_id in to_store:
        if store is None or store.get_meta(item_id) is None:
            continue
        try:
            same = store.resolve_secret(item_id) == {"value": line.value}
        except Exception:  # noqa: BLE001 - an unreadable item is a conflict
            same = False
        if same:
            already.add(item_id)
        else:
            problems.append(
                f"{line.name}: vault item {item_id} already exists with different "
                "contents; choose another --prefix"
            )
    for problem in problems:
        _err(prog, problem)
    if problems:
        return 2

    for line, item_id in to_store:
        state = "already in the vault" if item_id in already else "new item"
        print(f"{line.name} -> fv:{item_id} ({state})")
    for name, reason in left:
        print(f"{name}: left as is ({reason})")
    if not args.write:
        if not vault_exists:
            print(f"the vault at {vault_dir} does not exist yet; --write creates it")
        print(f"dry run: nothing changed. Re-run with --write to store and rewrite {path}.")
        _err(prog, _RUN_ONLY_NOTE.format(path=path))
        return 0

    stored = 0
    for line, item_id in to_store:
        if item_id in already:
            continue
        try:
            store.add_item(
                kind="generic",
                label=f"{line.name} (imported from {path.name})",
                secret={"value": line.value},
                item_id=item_id,
            )
        except Exception as exc:  # noqa: BLE001 - the type is safe; a message may not be
            _err(prog, f"storing {line.name} failed ({type(exc).__name__}); {path} is unchanged")
            _err(prog, "items stored so far are kept; re-running the import reuses them")
            return 1
        stored += 1
    data = render_env_file(env_file, {line.number: f"fv:{item_id}" for line, item_id in to_store})
    try:
        _replace_file(path, env_file.raw, data)
    except (ImportFileChanged, OSError) as exc:
        _err(prog, f"{path} was not rewritten: {exc}")
        _err(prog, "the items are stored; re-running the import reuses them")
        return 1
    print(f"stored {stored} new item(s); rewrote {path} with {len(to_store)} reference(s)")
    _err(
        prog,
        "no backup was made. Earlier copies of the plaintext may remain in backups, "
        "editor swap files or git history; rotate any key that was ever committed or shared.",
    )
    _err(prog, _RUN_ONLY_NOTE.format(path=path))
    return 0


_SECRETS_COMMANDS = {
    "add": _cmd_add,
    "put": _cmd_put,
    "list": _cmd_list,
    "show": _cmd_show,
    "rm": _cmd_rm,
    "ref": _cmd_ref,
    "import": _cmd_import,
}


def secrets_main(args: argparse.Namespace) -> int:
    from .vaultkit.vault import VaultError

    prog = f"floorvault secrets {args.subcommand}"
    try:
        return _SECRETS_COMMANDS[args.subcommand](args, prog)
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

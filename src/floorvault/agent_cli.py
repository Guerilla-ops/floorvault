"""``floorvault run`` and ``floorvault secrets``: vault secrets for any process.

``run`` fills ``fv:`` references into environment variables and starts a
command with them. ``secrets`` manages the items those references name.

Rules this module keeps:

* ``run`` writes nothing to stdout. MCP stdio servers speak JSON-RPC there,
  so every diagnostic goes to stderr.
* ``run`` fails closed: every reference resolves or the command never starts.
* Only ``secrets add``, ``secrets import --write`` and ``secrets init`` may
  create a store or a master key. Every other command opens an existing store
  and resolves the key with ``allow_create=False``.
* The child never inherits a vault key variable, nor another variable holding
  a copy of one's value.
* ``run`` exits 125 when it fails itself, so its failures never look like the
  command's own exit status.
* An item bound with ``secrets allow`` resolves only for one of its exact
  command lines, and not while a code-loading variable such as
  ``LD_PRELOAD`` is set. A guardrail, not a boundary against the same user.
* No ``secrets`` command prints a secret value. That is a convenience rule, not
  a control: ``run`` is the one path out of the vault, and whatever it starts
  can print what it receives (``floorvault run -e X=fv:id -- printenv X``).
* The command is looked up on ``run``'s own PATH, never on a PATH set by an
  env file or ``-e``, so configuration cannot choose which binary runs.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import re
import shlex
import shutil
import sqlite3
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Mapping, Optional, Sequence

from . import systemd_creds
from .agentenv import (
    CUSTODY_ENV_NAMES,
    KEY_POINTER_ENV_NAMES,
    AgentEnvError,
    EnvFile,
    code_injection_variables,
    collect,
    command_allowed,
    default_vault_dir,
    is_ref_like,
    is_valid_env_name,
    parse_env_file,
    parse_ref,
    read_env_file,
    render_env_file,
    render_env_file_without,
    resolve,
)
from .key_file import KeyFileError
from .key_file import read_key_file as _read_key_file

# The custody identity VaultStore and the hermesvault plugin use, so one store
# opens the same way from Hermes and from these commands.
SERVICE_NAME = "floor-vault"
APP_CONTEXT = "floor-agent"

_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HEX_KEY = re.compile(r"[0-9A-Fa-f]{64}")


class StoreUnavailable(Exception):
    """The store or its key could not be opened. The message is safe to print."""


class KeyOptionsConflict(StoreUnavailable):
    """--key-env and --key-file were both given: a usage error (exit 2 in `secrets`)."""


# A field name a reference can name: fv:<item_id>:<field> (see agentenv._REF).
_FIELD = re.compile(r"[^\x00\r\n:][^\x00\r\n]*")


def _printable(text: str) -> str:
    """``text`` with control characters escaped, so one record stays one line."""
    return "".join(
        f"\\x{ord(char):02x}" if unicodedata.category(char) == "Cc" else char for char in text
    )


def _bad_label(label: str) -> Optional[str]:
    """Why ``label`` cannot be used, or None."""
    if not label.strip():
        return "the label is empty"
    if any(unicodedata.category(char) == "Cc" for char in label):
        return "the label contains a control character such as a tab or newline"
    return None


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


def read_key_file(path: Path) -> bytes:
    """Read a 64-hex master key from ``path``, such as an orchestrator secret mount.

    The checks live in :mod:`floorvault.key_file`, shared with the Hermes
    plugin's ``custody: key_file``. A file readable by others is used with a
    warning on stderr. Errors name the path, never the content.
    """
    try:
        return _read_key_file(path, warn=lambda message: _err("floorvault", f"warning: {message}"))
    except KeyFileError as exc:
        raise StoreUnavailable(str(exc)) from None


def _key_file_from(args, environ: Mapping[str, str]) -> Optional[Path]:
    """--key-file, else $FLOOR_VAULT_KEY_FILE unless --key-env was given."""
    if getattr(args, "key_file", None) is not None:
        return args.key_file
    if getattr(args, "key_env", None):
        return None
    raw = (environ.get(KEY_FILE_ENV) or "").strip()
    return Path(raw) if raw else None


def _custody_key(args, environ: Mapping[str, str], vault_dir: Optional[Path]) -> Optional[bytes]:
    """The master key from a file or a sealed credential, or None for ``--key-env`` / default custody.

    Order: ``--key-env`` (None here, ``open_store`` reads it), ``--key-file``,
    the systemd-creds credential beside the vault, ``$FLOOR_VAULT_KEY_FILE``.
    A vault that has a credential gets its key from it and from nowhere else
    unless a key option names another; ``$FLOOR_VAULT_KEY`` is not consulted.
    """
    if getattr(args, "key_env", None):
        return None
    if getattr(args, "key_file", None) is not None:
        return read_key_file(args.key_file)
    if vault_dir is not None:
        try:
            sealed = systemd_creds.read_key(vault_dir)
        except systemd_creds.SystemdCredsError as exc:
            raise StoreUnavailable(str(exc)) from None
        if sealed is not None:
            return sealed
    key_file = _key_file_from(args, environ)
    return read_key_file(key_file) if key_file is not None else None


def _env_key(key_env: str, environ: Mapping[str, str]) -> bytes:
    """The 64-hex master key held in the variable ``key_env``, as ``open_store`` reads it."""
    raw = (environ.get(key_env) or "").strip()
    if not raw:
        raise StoreUnavailable(f"--key-env {key_env} is not set")
    if not _HEX_KEY.fullmatch(raw):
        raise StoreUnavailable(f"{key_env} must hold 64 hexadecimal characters")
    return bytes.fromhex(raw)


def explicit_key(args, environ: Mapping[str, str], key_dir: Optional[Path]) -> Optional[bytes]:
    """The master key the CLI's key options name, or None for default custody.

    The same options and order as ``run`` and ``secrets``: ``--key-env``,
    ``--key-file``, the systemd-creds credential in ``key_dir`` (when given),
    then ``$FLOOR_VAULT_KEY_FILE``. Used by ``inspect`` (#100). Raises
    ``KeyOptionsConflict`` for both key options, ``StoreUnavailable`` for a
    key that cannot be read.
    """
    _check_key_options(args)
    if getattr(args, "key_env", None):
        return _env_key(args.key_env, environ)
    return _custody_key(args, environ, key_dir)


def open_store(
    vault_dir: Path,
    *,
    key_env: Optional[str] = None,
    key_bytes: Optional[bytes] = None,
    create: bool = False,
    environ: Optional[Mapping[str, str]] = None,
    provider_environ: Optional[Mapping[str, str]] = None,
    sealed_listing: bool = False,
    migrate_listing: bool = False,
):
    """Open the agent-secret store at ``vault_dir``.

    With ``create=False`` (every command but ``secrets add`` and
    ``secrets import --write``) the store must already exist and the master
    key is only read, never created. ``key_bytes`` (from ``--key-file``) and
    ``key_env`` use the given key directly, never ``AdaptiveKeyProvider``.
    ``provider_environ`` is where the default provider reads key variables
    (``{}``: none, as the Hermes plugin does); ``None`` is the process
    environment.

    Listing metadata (#98): a store whose ``kind``/``has_otp`` are sealed is
    opened in sealed mode. ``sealed_listing=True`` asserts that mode, so a
    store holding cleartext rows (never converted, or turned back by someone
    who can write ``vault.db``) is refused. ``migrate_listing`` converts the
    store (``secrets seal-listing``).
    """
    from .core import FloorVault
    from .memory import HardenedMemoryKey
    from .providers.adaptive import AdaptiveKeyProvider
    from .providers.base import KeyProviderError, NoCustodyError
    from .vaultkit.vault import VaultError, VaultStore

    environ = os.environ if environ is None else environ
    if not create and not _is_regular_file(vault_dir / "vault.db"):
        raise StoreUnavailable(f"no vault at {vault_dir}; create one with `floorvault secrets add`")
    sealed_rows, cleartext_rows = _listing_rows(vault_dir)
    if sealed_listing and cleartext_rows and not migrate_listing:
        raise StoreUnavailable(
            f"the vault at {vault_dir} has cleartext listing metadata, but sealed listing "
            f"metadata was asserted ({SEALED_LISTING_HINT}); nothing was changed. Convert "
            "it with `floorvault secrets seal-listing`; if it was converted before, "
            "someone who can write vault.db has turned it back"
        )
    listing = {
        "seal_listing_metadata": bool(sealed_listing or sealed_rows or migrate_listing),
        "migrate_listing_metadata": migrate_listing,
    }
    provider = None
    try:
        if key_bytes is not None:
            crypto = FloorVault(HardenedMemoryKey(key_bytes), app_instance_id=APP_CONTEXT)
            store = VaultStore(vault_dir, crypto=crypto, **listing)
        elif key_env:
            raw = (environ.get(key_env) or "").strip()
            if not raw:
                raise StoreUnavailable(f"--key-env {key_env} is not set")
            if not _HEX_KEY.fullmatch(raw):
                raise StoreUnavailable(f"{key_env} must hold 64 hexadecimal characters")
            crypto = FloorVault(HardenedMemoryKey(bytes.fromhex(raw)), app_instance_id=APP_CONTEXT)
            store = VaultStore(vault_dir, crypto=crypto, **listing)
        else:
            # VaultStore's own default custody, resolved here before VaultStore
            # creates the store directory, so a refusal leaves nothing behind and
            # can be explained in terms of this CLI's options.
            provider = AdaptiveKeyProvider(
                service_name=SERVICE_NAME, fallback_dir=vault_dir, environ=provider_environ
            )
            key = provider.resolve_key(allow_create=create)
            store = VaultStore(
                vault_dir, crypto=FloorVault(key, app_instance_id=APP_CONTEXT), **listing
            )
        target = store.rotation_in_progress()
    except StoreUnavailable:
        raise
    except NoCustodyError:
        reason = getattr(provider, "keychain_unavailable_reason", None)
        raise StoreUnavailable(
            f"cannot open vault at {vault_dir}: no key is available here"
            + (f" (OS key store: {reason})" if reason else "")
            + ". Give one with --key-file PATH or $FLOOR_VAULT_KEY_FILE, or --key-env NAME; "
            "seal a new one with `floorvault secrets init --custody systemd-creds` "
            "(Linux, systemd 256 or newer); or install floorvault[linux] or "
            "floorvault[macos] to use the OS key store"
        ) from None
    except (KeyProviderError, VaultError, ValueError, OSError, sqlite3.Error) as exc:
        raise StoreUnavailable(f"cannot open vault at {vault_dir}: {exc}") from None
    if target is not None:
        # Part of the store is under the old key generation and part under the
        # new one; this CLI holds a single key, so it would open some items and
        # report the rest as sealed under "another key" (audit SEC-16, #99).
        raise StoreUnavailable(
            f"the vault at {vault_dir} is part-way through a key rotation (to key "
            f"generation {target}), so no single key opens all of it; nothing was "
            "changed. Finish the rotation with floorvault.rotate_vault_store and a "
            "KeyRing holding both keys, then use the new key"
        )
    return store


SEALED_LISTING_ENV = "FLOOR_VAULT_SEALED_LISTING"
SEALED_LISTING_HINT = f"--sealed-listing or ${SEALED_LISTING_ENV}=1"


def _sealed_listing_asserted(args, environ: Mapping[str, str]) -> bool:
    """--sealed-listing, or $FLOOR_VAULT_SEALED_LISTING set to 1/true/yes."""
    if getattr(args, "sealed_listing", False):
        return True
    return (environ.get(SEALED_LISTING_ENV) or "").strip().lower() in ("1", "true", "yes")


def _listing_rows(vault_dir: Path) -> tuple[int, int]:
    """How many items have sealed and how many cleartext listing metadata.

    Read-only and before any key is used, so the mode can be chosen; the
    library then refuses a store mixing both (#98).
    """
    import urllib.parse

    db = vault_dir / "vault.db"
    if not _is_regular_file(db):
        return 0, 0  # a store being created
    uri = f"file:{urllib.parse.quote(db.as_posix(), safe='/')}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vault_items'"
            ).fetchone():
                return 0, 0  # created, but no items table yet
            row = conn.execute(
                "SELECT "
                "COALESCE(SUM(typeof(kind) = 'blob' OR typeof(has_otp) = 'blob'), 0), "
                "COALESCE(SUM(typeof(kind) != 'blob' AND typeof(has_otp) != 'blob'), 0) "
                "FROM vault_items"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # The mode is unknown, so nothing may be assumed about it.
        raise StoreUnavailable(
            f"cannot read the listing metadata of {db}: {type(exc).__name__}: {exc}"
        ) from None
    return int(row[0]), int(row[1])


# --------------------------------------------------------------------------- run


# Exit status for run's own failures (usage, configuration, references, vault),
# kept apart from the 1 and 2 that commands use themselves, as GNU env does.
# 126 and 127 keep their shell meanings; anything else is the command's own.
RUN_FAILED = 125


class _RunArgumentParser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse would exit 2, a status commands use
        self.print_usage(sys.stderr)
        self.exit(RUN_FAILED, f"{self.prog}: error: {message}\n")

    def print_help(self, file=None):  # run writes nothing to stdout, help included
        super().print_help(sys.stderr)


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


#: What Windows uses when PATHEXT is unset (as in ``shutil``).
_WINDOWS_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC"


def _windows_which(command: str, search_path: str, pathext: Optional[str]) -> Optional[str]:
    """Find ``command`` on a Windows ``PATH``, searching only the entries it lists.

    ``shutil.which`` on Windows also searches the current directory first (always
    before Python 3.12, and on 3.12+ unless NoDefaultCurrentDirectoryInExePath is
    set), so a ``node.exe`` in the working directory would receive the secrets
    (audit RUN-10). Empty entries, such as a trailing ``;``, are skipped for the
    same reason; an explicit ``.`` entry is the operator's choice and is kept.
    """
    extensions = [ext for ext in (pathext or _WINDOWS_DEFAULT_PATHEXT).split(";") if ext]
    lowered = command.lower()
    names = [command] if any(lowered.endswith(ext.lower()) for ext in extensions) else []
    names += [command + ext for ext in extensions]
    for directory in search_path.split(";"):
        if not directory:
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _find_command(command: str, env: Mapping[str, str]) -> tuple[Optional[str], int]:
    """Locate ``command`` on ``env``'s PATH: (path, 0) or (None, 126/127)."""
    seps = {os.sep, os.altsep} - {None}
    try:
        # A drive-qualified name ("C:node.exe") is a path relative to that
        # drive's working directory, never a name to join onto PATH entries.
        if any(sep in command for sep in seps) or os.path.splitdrive(command)[0]:
            path = Path(command)
            if not path.exists():
                return None, 127
            if path.is_dir() or not os.access(path, os.X_OK):
                return None, 126
            return str(path), 0
        if os.name == "nt":
            # Not os.defpath: on Windows it starts with the current directory.
            found = _windows_which(command, env.get("PATH", ""), env.get("PATHEXT"))
        else:
            found = shutil.which(command, path=env.get("PATH", os.defpath))
    except PermissionError:
        return None, 126
    except (OSError, ValueError):  # e.g. a name too long for the filesystem
        return None, 127
    return (found, 0) if found else (None, 127)


def _format_command(argv: Sequence[str]) -> str:
    return shlex.join(argv)


def _check_bindings(store, refs, env, command_line, prog: str) -> bool:
    """Enforce per-item command allowlists. Returns False after reporting."""
    by_item: dict[str, list[str]] = {}
    for name, ref in refs.items():
        by_item.setdefault(ref.item_id, []).append(name)
    bound: list[str] = []
    problems: list[str] = []
    for item_id in sorted(by_item):
        try:
            if store.get_meta(item_id) is None:
                continue  # resolve() reports the missing item
            allowed = store.get_allowed_commands(item_id)
        except Exception as exc:  # noqa: BLE001 - fail closed; report the type only
            problems.append(
                f"vault item {item_id}: its command binding cannot be read "
                f"({type(exc).__name__}), so it is not resolved"
            )
            continue
        if allowed is None:
            continue
        bound.append(item_id)
        if command_line is not None and not command_allowed(command_line, allowed):
            for name in sorted(by_item[item_id]):
                problems.append(
                    f"{name}: vault item {item_id} is not allowed for "
                    f"{_format_command(command_line)}"
                )
    if bound and command_line is not None and not problems:
        # Reference targets are not in env yet: they are filled in after this
        # check, and LD_PRELOAD=fv:x is as much a code-loading variable.
        for name in code_injection_variables({**env, **{name: "" for name in refs}}):
            problems.append(
                f"{name} is set; it can change what the command loads, so items bound "
                f"to commands ({', '.join(bound)}) are not resolved. Unset it, or clear "
                "the binding with `floorvault secrets allow <id> --clear`"
            )
    for problem in problems:
        _err(prog, problem)
    return not problems


def _prepare_environment(
    args: argparse.Namespace, prog: str, command_line: Optional[Sequence[str]] = None
) -> tuple[Optional[dict], int]:
    """Build the child environment. Store and key do not outlive this call.

    ``command_line`` is the command run will start (absolute program path,
    then arguments), or None when it was not found; items bound to commands
    are checked against it.
    """
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
        # No vault is opened, but a copy of a key file's key under another
        # name must not reach the child either. Reading the file opens nothing.
        key_file = _key_file_from(args, os.environ)
        if key_file is not None:
            try:
                copy = read_key_file(key_file).hex()
            except StoreUnavailable as exc:
                _err(prog, str(exc))
                return None, RUN_FAILED
            env = {name: value for name, value in env.items() if value.strip().lower() != copy}
        return env, 0
    key_hex = None
    try:
        _check_key_options(args)
        vault_dir = _vault_dir(args.vault, os.environ)
        key_bytes = _custody_key(args, os.environ, vault_dir)
        if key_bytes is not None:
            key_hex = key_bytes.hex()
        store = open_store(
            vault_dir,
            key_env=args.key_env,
            key_bytes=key_bytes,
            sealed_listing=_sealed_listing_asserted(args, os.environ),
        )
    except StoreUnavailable as exc:
        _err(prog, str(exc))
        return None, RUN_FAILED
    except Exception as exc:  # noqa: BLE001 - the type is safe; a message may not be
        _err(prog, f"cannot open vault ({type(exc).__name__})")
        return None, RUN_FAILED
    try:
        if not _check_bindings(store, refs, env, command_line, prog):
            return None, RUN_FAILED
        values = resolve(store, refs)
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return None, RUN_FAILED
    finally:
        del store
    if key_hex is not None:
        # A copy of the key under any other name (from a key file or a sealed credential).
        env = {name: value for name, value in env.items() if value.strip().lower() != key_hex}
    env.update(values)
    return env, 0


def _spawn_and_wait(path: str, argv: Sequence[str], env: Mapping[str, str]) -> int:
    """Start the child and wait for it, returning its exit code.

    Used on Windows, where ``os.exec*`` starts a new process and exits the
    caller at once, which an MCP client reads as the server exiting. The child
    shares this console, so Ctrl+C and Ctrl+Break reach it directly; this
    process keeps waiting for it to finish: Ctrl+C raises KeyboardInterrupt,
    which is caught, and SIGBREAK is ignored until the child exits (audit
    RUN-11), since by default Ctrl+Break would end this process and leave the
    child running without it.
    """
    # Starting the operator's own command is this function's purpose; the
    # argv is passed as a list, never through a shell.
    import signal
    import subprocess  # nosec B404

    sigbreak = getattr(signal, "SIGBREAK", None)
    previous = None
    if sigbreak is not None:
        try:
            previous = signal.signal(sigbreak, signal.SIG_IGN)
        except ValueError:  # not the main thread: keep the default
            sigbreak = None
    try:
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
    finally:
        if sigbreak is not None:
            signal.signal(sigbreak, signal.SIG_DFL if previous is None else previous)


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
    # Look the command up on run's own PATH: a PATH in an env file reaches the
    # child, but must not pick which binary receives the secrets. It is looked
    # up first so items bound to commands can be checked against it; run's own
    # failures (125) still take precedence over a missing command (127).
    path, code = _find_command(command[0], os.environ)
    command_line = [os.path.abspath(path), *command[1:]] if path is not None else None
    env, env_code = _prepare_environment(args, prog, command_line)
    if env is None:
        return env_code
    if path is None:
        reason = "not found" if code == 127 else "not executable"
        _err(prog, f"{command[0]}: command {reason}")
        return code
    # Start exactly the path the bindings were checked against. The lookup's
    # own path may hold '..' after a symlink, which the kernel resolves to a
    # different binary than abspath's textual normalisation.
    return _launch(command_line[0], command, env)


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
    parser.add_argument(
        "--sealed-listing",
        action="store_true",
        help=(
            "refuse a store whose item kinds are not sealed, and seal them in a new "
            "store (default: $FLOOR_VAULT_SEALED_LISTING)"
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

    # init creates the key, so it takes only --vault. The key options are still
    # parsed, hidden, so giving one gets init's own explanation, not argparse's.
    init_options = argparse.ArgumentParser(add_help=False)
    init_options.add_argument(
        "--vault",
        type=Path,
        default=None,
        metavar="DIR",
        help="store directory (default: $FLOOR_VAULT_DIR or ~/.floorvault/agent-vault)",
    )
    init_options.add_argument("--key-env", default=None, help=argparse.SUPPRESS)
    init_options.add_argument("--key-file", type=Path, default=None, help=argparse.SUPPRESS)
    init = sub.add_parser(
        "init",
        parents=[init_options],
        help="Create the master key for a new store, sealed by systemd-creds",
        description=(
            "Create a random master key and seal it with `systemd-creds encrypt --user` "
            "beside the store (master.key.sdcred). `run` and `secrets` then unseal it without "
            "a prompt. Needs Linux with systemd 256 or newer, and fails rather than fall back "
            "to a weaker custody. Only for a store that does not exist yet."
        ),
    )
    init.add_argument(
        "--custody", required=True, choices=["systemd-creds"], help="where the key is kept"
    )

    allow = sub.add_parser(
        "allow",
        parents=[common],
        help="Bind an item to the exact command lines `run` may start with it",
        usage="floorvault secrets allow [options] ITEM_ID [--clear | [--remove] -- PROGRAM [ARGS...]]",
        description=(
            "Bind an item to command lines. Once bound, `floorvault run` resolves the "
            "item only when the command it starts is one of them: the program's absolute "
            "path as found on PATH, plus exactly the same arguments. A guardrail against "
            "mistakes and against a .env or MCP entry naming the item for another command; "
            "not a defence against code already running as you."
        ),
    )
    allow.add_argument("item_id")
    allow.add_argument(
        "--clear",
        action="store_true",
        help="remove every binding (the item resolves for any command)",
    )
    allow.add_argument("--remove", action="store_true", help="remove this one command line")
    # The command after `--` is split off before parsing (split_allow_argv):
    # argparse handles `--` after an option differently across Python versions.
    allow.set_defaults(allowed_argv=[])

    rm = sub.add_parser("rm", parents=[common], help="Delete an item")
    rm.add_argument("item_id")

    sub.add_parser(
        "seal-listing",
        parents=[common],
        help="Seal each item's kind and OTP flag, so vault.db reveals only ids",
    )

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
            "Item ids are the lowercased variable names, after --prefix. "
            "For a Hermes Agent .env use --hermes instead: Hermes reads that file "
            "itself, so it is never rewritten to references."
        ),
    )
    imp.add_argument(
        "file",
        type=Path,
        nargs="?",
        default=None,
        help="the .env file (with --hermes: default $HERMES_HOME/.env)",
    )
    imp.add_argument(
        "--hermes",
        action="store_true",
        help=(
            "move a Hermes Agent .env into the hermesvault plugin's store "
            "($HERMES_HOME/agent-vault) and print the secrets.hermesvault.env mapping; "
            "the .env is not rewritten to references"
        ),
    )
    imp.add_argument(
        "--remove-from-env",
        action="store_true",
        help=(
            "with --hermes --write: delete the imported lines from the .env, once "
            "config.yaml maps each of them (run it after adding the mapping)"
        ),
    )
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
        if "\x00" in value:
            raise ValueError("fields and values may not contain a NUL byte")
        _check_field_name(field)
        if not value.strip():
            # The store keeps no empty generic field; say so rather than drop it.
            raise ValueError(f"field {_printable(field)!r} has no value")
        fields[field] = value
    return fields


def _check_field_name(field: str) -> None:
    if not field.strip() or not _FIELD.fullmatch(field):
        raise ValueError(
            f"field name {_printable(field)!r} cannot be named by a reference: it may not be "
            "blank, start with ':' or contain a NUL or newline"
        )


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


def _store_for(
    args, *, create: bool = False, provider_environ=None, environ=None, assert_listing=True
):
    """Open the store; with ``create``, create it (and a key) only if there is none.

    An existing store is never opened in create mode, so a missing key is an
    error rather than a new key, and the key is checked against the items
    already there before any command writes: a store sealed under two keys
    can no longer be listed. ``environ`` is where ``--key-env`` is read (default:
    the process environment).
    """
    _check_key_options(args)
    vault_dir = _vault_dir(args.vault, os.environ)
    existed = _is_regular_file(vault_dir / "vault.db")
    store = open_store(
        vault_dir,
        key_env=args.key_env,
        key_bytes=_custody_key(args, os.environ, vault_dir),
        create=create and not existed,
        environ=environ,
        provider_environ=provider_environ,
        sealed_listing=assert_listing and _sealed_listing_asserted(args, os.environ),
    )
    if existed:
        _check_store_key(store, vault_dir)
    return store


def _check_store_key(store, vault_dir: Path) -> None:
    from .core import DecryptionVerificationError
    from .vaultkit.vault import VaultError

    try:
        store.list_items()  # authenticates every item's sealed metadata
    except DecryptionVerificationError:
        raise StoreUnavailable(
            f"this key does not open the vault at {vault_dir}; nothing was changed. "
            "Use the key the store was created with"
        ) from None
    except VaultError:
        pass  # e.g. sealed listing metadata: nothing this check can read


def _check_key_options(args) -> None:
    if getattr(args, "key_env", None) and getattr(args, "key_file", None) is not None:
        raise KeyOptionsConflict("give --key-env or --key-file, not both")


def _cmd_add(args, prog: str) -> int:
    if args.item_id is not None and not _ITEM_ID.fullmatch(args.item_id):
        _err(prog, "--id must match [A-Za-z0-9._-]{1,128}")
        return 2
    problem = _bad_label(args.label)
    if problem:
        _err(prog, f"{problem}; give a one-line label")
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
    if args.item_id is not None and store.get_meta(args.item_id) is not None:
        _err(prog, f"item {args.item_id} already exists; use `put` to change a field")
        return 1
    meta = store.add_item(kind="generic", label=args.label, secret=fields, item_id=args.item_id)
    print(meta.id)
    return 0


def _cmd_put(args, prog: str) -> int:
    if not _ITEM_ID.fullmatch(args.item_id):
        _err(prog, "item id must match [A-Za-z0-9._-]{1,128}")
        return 2
    try:
        _check_field_name(args.field)
    except ValueError as exc:
        _err(prog, str(exc))
        return 2
    store = _store_for(args)
    if store.get_meta(args.item_id) is None:
        _err(prog, f"item {args.item_id} not found")
        return 1
    value = getpass.getpass(f"{args.item_id}.{args.field}: ")
    if not value.strip():
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
        print("\t".join((meta.id, meta.kind, _printable(meta.label))))
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
    allowed = store.get_allowed_commands(item_id)
    if allowed:
        _print_bindings(item_id, allowed)
    return 0


def split_allow_argv(argv: Sequence[str]) -> tuple[list[str], Optional[list[str]]]:
    """Split ``secrets allow ... -- PROGRAM [ARGS...]`` at the first ``--``.

    Returns ``(argv without the command, the command)``; the command is None
    for any other invocation, or when there is no ``--``.
    """
    argv = list(argv)
    if argv[:2] != ["secrets", "allow"] or "--" not in argv:
        return argv, None
    split = argv.index("--")
    return argv[:split], argv[split + 1 :]


def _cmd_init(args, prog: str) -> int:
    if args.key_env or args.key_file is not None:
        _err(prog, "init creates the key; it takes no --key-env or --key-file")
        return 2
    vault_dir = _vault_dir(args.vault, os.environ)
    if _is_regular_file(vault_dir / "vault.db"):
        _err(
            prog,
            f"a vault already exists at {vault_dir}; init creates the key for a new store "
            "only. Moving an existing store's key here is not supported",
        )
        return 2
    try:
        path = systemd_creds.create_credential(vault_dir)
    except systemd_creds.SystemdCredsError as exc:
        raise StoreUnavailable(str(exc)) from None
    print(f"created {path}")
    print(
        f"the master key is sealed by systemd-creds (--user); "
        f"`run` and `secrets` use it for the vault at {vault_dir}"
    )
    _err(
        prog,
        "systemd chooses what else the key is bound to (its automatic selection: the TPM2 "
        "chip, the host key, or both; per its documentation it fails when neither is "
        "available). floorvault cannot choose or check which, so do not assume hardware "
        "binding. The host key is a root-only file on this machine's disk: it keeps other "
        "users and a copied credential out, not root or a full disk image.",
    )
    _err(
        prog,
        "checked: the credential unseals from this shell. Not checked: unsealing from a "
        "service, a cron job or an SSH session without a login. Losing the credential or "
        "this machine's keys loses the data: keep your own backup of the secrets.",
    )
    return 0


def _cmd_allow(args, prog: str) -> int:
    command = list(args.allowed_argv)
    if not _ITEM_ID.fullmatch(args.item_id):
        _err(prog, "item id must match [A-Za-z0-9._-]{1,128}")
        return 2
    if args.clear and (command or args.remove):
        _err(prog, "--clear takes no command and cannot be combined with --remove")
        return 2
    if not args.clear and not command:
        _err(prog, "give the command after --, for example: -- npx -y @scope/server")
        return 2
    store = _store_for(args)
    if store.get_meta(args.item_id) is None:
        _err(prog, f"item {args.item_id} not found")
        return 1
    if args.clear:
        store.set_allowed_commands(args.item_id, None)
        print(f"{args.item_id}: not bound; `run` resolves it for any command")
        return 0
    path, code = _find_command(command[0], os.environ)
    if path is None:
        reason = "not found" if code == 127 else "not executable"
        _err(prog, f"{command[0]}: command {reason} on PATH")
        return 1
    line = [os.path.abspath(path), *command[1:]]
    if not args.remove:
        for arg in command[1:]:
            if not arg.startswith("-") and not os.path.isabs(arg) and os.path.exists(arg):
                _err(
                    prog,
                    f"warning: {arg} is a relative path; it is resolved against the "
                    "directory the command starts in, which its configuration chooses. "
                    "Prefer an absolute path.",
                )

    def change(current):
        # Runs under the store's write lock, so a concurrent change is not lost.
        current = current or []
        if not args.remove:
            return [*current, line]
        remaining = [entry for entry in current if not command_allowed(line, [entry])]
        if len(remaining) == len(current):
            raise _AllowRefused(f"item {args.item_id} is not bound to {_format_command(line)}")
        if not remaining:
            # Unbinding widens access to every command; make that explicit.
            raise _AllowRefused(
                f"that is the last command line {args.item_id} is bound to; removing it "
                "would let `run` resolve the item for any command. Use --clear for that."
            )
        return remaining

    try:
        stored = store.update_allowed_commands(args.item_id, change)
    except _AllowRefused as exc:
        _err(prog, str(exc))
        return 1
    _print_bindings(args.item_id, stored)
    return 0


class _AllowRefused(Exception):
    """A `secrets allow` change refused inside its transaction; nothing was written."""


def _print_bindings(item_id: str, allowed: Optional[list]) -> None:
    if not allowed:
        print(f"{item_id}: not bound; `run` resolves it for any command")
        return
    print(f"{item_id}: bound to {len(allowed)} command line(s):")
    for entry in allowed:
        print(f"  {_format_command(entry)}")


def _cmd_seal_listing(args, prog: str) -> int:
    """Convert the store to sealed listing metadata (#98), after checking the key."""
    vault_dir = _vault_dir(args.vault, os.environ)
    # The key must open every item before anything changes. The assertion is
    # not applied here: converting is how a store comes to satisfy it.
    store = _store_for(args, assert_listing=False)
    sealed_rows, cleartext_rows = _listing_rows(vault_dir)
    if not cleartext_rows:
        if sealed_rows:
            print(f"listing metadata in {vault_dir} is already sealed; nothing was changed")
        else:
            print(
                f"{vault_dir} holds no items; nothing was changed. New items are sealed "
                f"when sealed listing is asserted ({SEALED_LISTING_HINT})"
            )
        return 0
    with contextlib.closing(sqlite3.connect(vault_dir / "vault.db")) as conn:
        active = conn.execute(
            "SELECT active FROM vault_rotation_state WHERE singleton = 1"
        ).fetchone()
    if active is not None and bool(active[0]):
        _err(prog, "a key rotation of this store is in progress; finish it first")
        return 1
    del store
    sealed = open_store(
        vault_dir,
        key_env=args.key_env,
        key_bytes=_custody_key(args, os.environ, vault_dir),
        migrate_listing=True,
    )
    count = len(sealed.list_items())  # authenticates every sealed row
    print(f"sealed the listing metadata of {count} item(s) in {vault_dir}")
    _err(
        prog,
        f"note: set ${SEALED_LISTING_ENV}=1 where floorvault runs (or pass --sealed-listing) "
        "so a store turned back to cleartext is refused. floorvault 0.2.8 and earlier, and "
        "the hermesvault plugin, cannot open a sealed store",
    )
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
    if args.field is not None and not args.field:
        _err(prog, "--field must be non-empty and contain no NUL or newline")
        return 2
    reference = f"fv:{args.item_id}" + (f":{args.field}" if args.field is not None else "")
    try:
        parse_ref(reference)
    except AgentEnvError:
        _err(prog, "--field must be non-empty and contain no NUL or newline")
        return 2
    store = _store_for(args)
    if store.get_meta(args.item_id) is None:
        _err(prog, f"item {args.item_id} not found")
        return 1
    # Only print a reference `run` can resolve. The payload is read for its
    # field names; no value is printed.
    try:
        fields = list(store.resolve_secret(args.item_id))
    except Exception as exc:  # noqa: BLE001 - report the type, never a message
        _err(prog, f"item {args.item_id} is unavailable ({type(exc).__name__})")
        return 1
    if args.field is None and len(fields) > 1:
        names = ", ".join(_printable(name) for name in fields)
        _err(prog, f"item {args.item_id} holds several fields ({names}); name one with --field")
        return 1
    if args.field is not None and args.field not in fields:
        _err(prog, f"item {args.item_id} has no field {_printable(args.field)!r}")
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


def _known_key_values(
    env_file: EnvFile,
    *,
    key_env: Optional[str],
    key_file: Optional[Path],
    environ: Mapping[str, str],
) -> set[str]:
    """Lower-cased master-key values in sight: the key variables in ``environ``
    and in the file, ``key_env``, and ``key_file``. A copy of one under another
    name must not be stored, or `run` would hand the key to the child."""
    names = {name.upper() for name in CUSTODY_ENV_NAMES}
    if key_env:
        names.add(key_env.upper())
    values = {value.strip().lower() for name, value in environ.items() if name.upper() in names}
    values |= {
        line.value.strip().lower() for line in env_file.assignments() if line.name.upper() in names
    }
    if key_file is not None:
        try:
            values.add(read_key_file(key_file).hex())
        except StoreUnavailable:
            pass  # opening the store reports it
    return {value for value in values if len(value) >= 32}


def plan_env_import(
    env_file: EnvFile,
    *,
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    prefix: str = "",
    key_env: Optional[str] = None,
    key_file: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> tuple[list, list[tuple[str, str]], list[str]]:
    """Split a file's assignments into ``(to_store, left_as_is, problems)``.

    ``to_store`` holds ``(line, item_id)`` pairs and ``left_as_is`` holds
    ``(name, reason)`` pairs. A non-empty ``problems`` means nothing may be
    imported. Messages name variables and ids, never values. Vault key
    variables, key-file pointers and copies of a key in sight (see
    ``_known_key_values``; ``environ`` defaults to ``os.environ``) are left
    as is.
    """
    assignments = env_file.assignments()
    names = {line.name for line in assignments}
    unknown = sorted((set(only) | set(skip)) - names)
    if unknown:
        return [], [], [f"not set in {env_file.path}: {', '.join(unknown)}"]
    refused = {
        name.upper() for name in (*CUSTODY_ENV_NAMES, *KEY_POINTER_ENV_NAMES, "APPSTATE_KEY")
    }
    if key_env:
        refused.add(key_env.upper())
    key_copies = _known_key_values(
        env_file,
        key_env=key_env,
        key_file=key_file,
        environ=os.environ if environ is None else environ,
    )

    to_store: list = []
    left: list[tuple[str, str]] = []
    claimed: dict[str, str] = {}
    problems: list[str] = []
    for line in assignments:
        name = line.name
        if only and name not in only:
            left.append((name, "not selected by --only"))
        elif name in skip:
            left.append((name, "--skip"))
        elif name.upper() in refused:
            left.append((name, "a vault key variable cannot be stored in the vault it unlocks"))
        elif line.value.strip().lower() in key_copies:
            left.append((name, "a copy of a vault key cannot be stored in the vault it unlocks"))
        elif is_ref_like(line.value):
            try:
                parse_ref(line.value)
            except AgentEnvError:
                problems.append(f"{env_file.path}:{line.number}: {name}: malformed reference")
                continue
            left.append((name, "already a reference"))
        elif not line.value.strip():
            left.append((name, "empty"))
        else:
            item_id = f"{prefix}{name.lower()}"
            if not _ITEM_ID.fullmatch(item_id):
                problems.append(f"{name}: item id {item_id!r} is invalid; shorten --prefix")
            elif item_id in claimed:
                problems.append(f"{claimed[item_id]} and {name} would both be stored as {item_id}")
            else:
                claimed[item_id] = name
                to_store.append((line, item_id))
    return to_store, left, problems


def _import_plan(args, env_file: EnvFile, prog: str, *, environ=None):
    """Split a file's assignments into (to_store, left_as_is), or None on error.

    ``environ`` is where key values are looked up to leave copies of them in the
    file (default: the process environment).
    """
    to_store, left, problems = plan_env_import(
        env_file,
        only=args.only,
        skip=args.skip,
        prefix=args.prefix,
        key_env=args.key_env,
        key_file=_key_file_from(args, os.environ),
        environ=environ,
    )
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
    try:
        directory = path.resolve().parent
    except (OSError, RuntimeError):
        return False
    if path.name != ".env":
        # On a case-insensitive filesystem (macOS, Windows) `.ENV` is Hermes' `.env`.
        try:
            if not os.path.samefile(path, directory / ".env"):
                return False
        except OSError:
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
    "hermesvault plugin instead: `floorvault secrets import --hermes {path}` stores them "
    "in the plugin's store and prints the secrets.hermesvault.env mapping to add to "
    "config.yaml; then `--hermes --write --remove-from-env` deletes the imported lines. "
    "See plugins/hermesvault/README.md."
)


def find_import_conflicts(store, to_store) -> tuple[set[str], dict[str, str]]:
    """``(ids already holding the same value, {conflicting id: message})``.

    An existing item with different contents, or one that cannot be read, is a
    conflict: the import must not overwrite it.
    """
    already: set[str] = set()
    conflicts: dict[str, str] = {}
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
            conflicts[item_id] = (
                f"{line.name}: vault item {item_id} already exists with different "
                "contents; choose another --prefix"
            )
    return already, conflicts


def _find_conflicts(store, to_store, prog: str) -> Optional[set[str]]:
    """Item ids already holding the same value, or None after reporting conflicts."""
    already, conflicts = find_import_conflicts(store, to_store)
    for problem in conflicts.values():
        _err(prog, problem)
    return None if conflicts else already


def store_imported_items(
    store, to_store, already: set[str], path: Path
) -> tuple[int, Optional[str]]:
    """Store the items not already present: ``(count stored, failure message or None)``.

    Stops at the first failure; items stored before it are kept. The message
    names the variable and the error type, never a value.
    """
    stored = 0
    for line, item_id in to_store:
        if item_id in already:
            continue
        try:
            store.add_item(
                kind="generic",
                label=f"{line.name} (imported from {_printable(path.name)})",
                secret={"value": line.value},
                item_id=item_id,
            )
        except Exception as exc:  # noqa: BLE001 - the type is safe; a message may not be
            return stored, f"storing {line.name} failed ({type(exc).__name__})"
        stored += 1
    return stored, None


def _store_new_items(store, to_store, already: set[str], path: Path, prog: str) -> Optional[int]:
    """Store the items not already present; the count, or None after reporting a failure."""
    stored, failure = store_imported_items(store, to_store, already, path)
    if failure is not None:
        _err(prog, f"{failure}; {path} is unchanged")
        _err(prog, "items stored so far are kept; re-running the import reuses them")
        return None
    return stored


def _default_hermes_env_file(environ: Mapping[str, str]) -> Optional[Path]:
    for home in _hermes_homes(environ):
        candidate = home / ".env"
        if candidate.is_file():
            return candidate
    return None


def _maps_item(env_map: Mapping, name: str, item_id: str) -> bool:
    """Whether ``secrets.hermesvault.env`` maps ``name`` to the item's ``value``."""
    return env_map.get(name) in (f"hv:{item_id}", f"hv:{item_id}:value")


def _config_maps(config_text: str, name: str, item_id: str) -> bool:
    """Whether the enabled YAML source maps this variable to the imported field."""
    from .hermes_config import load_hermes_config

    try:
        cfg = load_hermes_config(config_text)
    except ValueError:
        return False
    return _maps_item(cfg["env"], name, item_id)


def _verify_hermes_removal(config_text, home, vault_dir, env_file, to_store):
    """Check the plugin's store and prospective key route before removing plaintext."""
    from .hermes_config import load_hermes_config

    cfg = load_hermes_config(config_text)
    missing = [
        line.name for line, item_id in to_store if not _maps_item(cfg["env"], line.name, item_id)
    ]
    if missing:
        raise ValueError(f"config.yaml does not map {', '.join(missing)} to the stored hv: items")
    raw_dir = cfg.get("dir", "")
    if not isinstance(raw_dir, str):
        raise ValueError("secrets.hermesvault.dir must be a string")
    directory = Path(raw_dir.strip()).expanduser() if raw_dir.strip() else Path("agent-vault")
    if not directory.is_absolute():
        directory = home / directory
    if directory.resolve() != vault_dir.resolve():
        raise ValueError(
            "secrets.hermesvault.dir does not match the import store; use matching --vault"
        )
    if "override_existing" in cfg and not isinstance(cfg["override_existing"], bool):
        raise ValueError("secrets.hermesvault.override_existing must be a boolean")
    token_env = cfg.get("token_env", _HERMES_KEY_VAR)
    if not isinstance(token_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env):
        raise ValueError("secrets.hermesvault.token_env must be an environment variable name")
    custody = _hermes_custody(cfg)
    removed = {line.name for line, _ in to_store}
    if token_env in removed:
        raise ValueError("cannot remove the plugin bootstrap key from .env")
    # Hermes loads the profile .env with override semantics before fetching.
    environ = dict(os.environ)
    environ.update(
        {line.name: line.value for line in env_file.assignments() if line.name not in removed}
    )
    # The plugin's key route: token_env from the profile's environment, else the
    # configured custody (OS key store with no environment tier and no prompt, the
    # key_file, or the systemd-creds credential beside the store). FLOOR_VAULT_KEY,
    # VAULT_MASTER_KEY and FLOOR_VAULT_KEY_FILE are not read, so they cannot certify
    # a removal either.
    key_hex = environ.get(token_env)
    if not key_hex and custody != "os":
        _require_plugin_custody(home, custody)
    try:
        from . import FloorVault
        from .vaultkit import VaultStore

        if key_hex:
            key = bytes.fromhex(key_hex.strip())
        elif custody == "key_file":
            key = read_key_file(_hermes_key_file(cfg, home))
        elif custody == "systemd-creds":
            key = systemd_creds.read_key(directory)
            if key is None:
                raise ValueError("no credential")
        else:
            from .providers.adaptive import AdaptiveKeyProvider

            provider = AdaptiveKeyProvider(
                service_name=SERVICE_NAME, fallback_dir=directory, environ={}, interactive=False
            )
            key = provider.resolve_key(allow_create=False)
        plugin_store = VaultStore(directory, crypto=FloorVault(key, app_instance_id=APP_CONTEXT))
        for line, item_id in to_store:
            if plugin_store.resolve_secret(item_id).get("value") != line.value:
                raise ValueError("value mismatch")
    except Exception:
        raise ValueError(
            "plugin key cannot decrypt the imported values; align token_env and import custody"
        ) from None


_HERMES_KEY_VAR = "HERMES_VAULT_KEY"  # the plugin's default token_env


def _hermes_environ(env_file: EnvFile, environ: Mapping[str, str]) -> dict[str, str]:
    """The environment the plugin sees: ``environ`` with the profile ``.env`` loaded over it.

    Hermes loads ``<home>/.env`` with override before secret sources run, and a
    later line wins over an earlier one, as in python-dotenv.
    """
    view = dict(environ)
    for line in env_file.assignments():
        view[line.name] = line.value
    return view


_HERMES_CUSTODIES = ("os", "key_file", "systemd-creds")
#: The first hermesvault plugin release that reads ``custody`` other than os.
_PLUGIN_CUSTODY_SINCE = (0, 2, 8)


def _hermes_custody(cfg: dict) -> str:
    """``secrets.hermesvault.custody``, checked as the plugin checks it."""
    custody = cfg.get("custody", "os")
    if custody not in _HERMES_CUSTODIES:
        raise ValueError(
            "secrets.hermesvault.custody must be one of: " + ", ".join(_HERMES_CUSTODIES)
        )
    key_file = cfg.get("key_file")
    if custody == "key_file":
        if not isinstance(key_file, str) or not key_file.strip():
            raise ValueError("secrets.hermesvault.custody: key_file needs a key_file path")
    elif key_file is not None:
        raise ValueError("secrets.hermesvault.key_file is used only with custody: key_file")
    return custody


def _hermes_key_file(cfg: dict, home: Path) -> Path:
    """The plugin's ``key_file``; a relative path is taken from the profile home."""
    path = Path(cfg["key_file"].strip()).expanduser()
    return path if path.is_absolute() else home / path


def _require_plugin_custody(home: Path, custody: str) -> None:
    """Refuse unless the plugin installed in this profile reads ``custody``.

    An older plugin ignores the setting and opens the OS key store, so it could
    not read what the removal check just decrypted another way.
    """
    manifest = home / "plugins" / "hermesvault" / "plugin.yaml"
    try:
        import yaml

        data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        parts = str(data["version"]).split(".")
        version = tuple(int(part) for part in parts[:3])
    except Exception:
        raise ValueError(
            f"custody: {custody} needs the hermesvault plugin "
            f"{'.'.join(map(str, _PLUGIN_CUSTODY_SINCE))} or newer, and its version could "
            f"not be read from {manifest}"
        ) from None
    if version < _PLUGIN_CUSTODY_SINCE:
        raise ValueError(
            f"custody: {custody} needs the hermesvault plugin "
            f"{'.'.join(map(str, _PLUGIN_CUSTODY_SINCE))} or newer; {manifest} is "
            f"{'.'.join(map(str, version))}. Update the plugin first"
        )


def _cmd_import_hermes(args, prog: str) -> int:
    """Move a Hermes ``.env`` into the plugin's store; never rewrite it to references.

    Hermes reads its ``.env`` itself and lets it win over the environment, so the
    values go into ``<home>/agent-vault`` and the user maps them under
    ``secrets.hermesvault.env``. The imported lines are deleted from ``.env`` only
    with ``--remove-from-env``, after config.yaml maps each of them.
    """
    if args.file is None:
        path = _default_hermes_env_file(os.environ)
        if path is None:
            _err(prog, "no Hermes .env found under $HERMES_HOME or ~/.hermes; give the file")
            return 2
    else:
        path = args.file.expanduser()
    if args.remove_from_env and not args.write:
        _err(prog, "--remove-from-env needs --write")
        return 2
    if args.remove_from_env:
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                _err(prog, f"{path} is not a regular file; --remove-from-env refuses symlinks")
                return 2
        except OSError as exc:
            _err(prog, f"{path}: cannot read env file ({type(exc).__name__})")
            return 2
    try:
        home = path.resolve().parent
    except (OSError, RuntimeError):
        _err(prog, f"{path}: cannot resolve the file's directory")
        return 2
    if args.vault is None:
        if not _is_hermes_env_file(path, os.environ):
            _err(
                prog,
                f"{path} does not look like a Hermes .env (no state.db and config.yaml "
                "beside it); give --vault DIR to choose the store",
            )
            return 2
        args.vault = home / "agent-vault"
    try:
        env_file = read_env_file(path)
    except AgentEnvError as exc:
        for problem in exc.problems:
            _err(prog, problem)
        return 2
    # Hermes loads this .env with override before the plugin fetches, so a
    # HERMES_VAULT_KEY line here, even an empty one, decides the key the plugin
    # sees, not the importing shell's environment.
    hermes_environ_view = _hermes_environ(env_file, os.environ)
    if args.key_env is None and args.key_file is None:
        in_file = any(line.name == _HERMES_KEY_VAR for line in env_file.assignments())
        if hermes_environ_view.get(_HERMES_KEY_VAR):
            # The plugin uses this variable's key directly when it is set.
            args.key_env = _HERMES_KEY_VAR
            where = path.name if in_file else "the environment"
            _err(
                prog,
                f"using the key in ${_HERMES_KEY_VAR} from {where}, as the hermesvault plugin does",
            )
        elif in_file and os.environ.get(_HERMES_KEY_VAR):
            _err(
                prog,
                f"${_HERMES_KEY_VAR} is empty in {path.name}, which Hermes loads over the "
                "environment, so the plugin does not use it; the store is opened with the "
                "plugin's custody instead",
            )
    if (
        args.key_env is None
        and args.key_file is None
        and (os.environ.get(KEY_FILE_ENV) or "").strip()
    ):
        _err(
            prog,
            f"the hermesvault plugin does not read ${KEY_FILE_ENV}, so Hermes could not open "
            "a store keyed by it. Nothing was stored and .env is unchanged. Name the file "
            "with --key-file (and set custody: key_file and key_file for the plugin), or "
            f"unset ${KEY_FILE_ENV} for this command",
        )
        return 2
    plan = _import_plan(args, env_file, prog, environ=hermes_environ_view)
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
    sealed = args.key_env is None and systemd_creds.credential_present(vault_dir)
    if sealed and args.key_file is not None:
        # The credential holds this store's key; storing under the key file's would fork it.
        _err(
            prog,
            f"{vault_dir} holds a systemd-creds credential, which is this store's key; "
            "--key-file names another. Nothing was stored and .env is unchanged. Drop "
            "--key-file to use the credential (custody: systemd-creds)",
        )
        return 2
    if args.key_env is None and args.key_file is None:
        ignored = [name for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY") if os.environ.get(name)]
        if ignored:
            _err(
                prog,
                f"${ignored[0]} is ignored here: the hermesvault plugin does not read it. "
                f"Use ${_HERMES_KEY_VAR} (the plugin's token_env) or --key-file to name a key",
            )
    # Open the store as the plugin will: its own key variable, a key file named on the
    # command line (the plugin's custody: key_file), the sealed credential beside the
    # store (custody: systemd-creds), or the OS key store with no environment tier.
    # $FLOOR_VAULT_KEY and $VAULT_MASTER_KEY are not read and $FLOOR_VAULT_KEY_FILE is
    # refused above, so nothing is stored under a key the plugin never uses.
    hermes_environ = None if args.key_env else {}
    key_environ = hermes_environ_view if args.key_env == _HERMES_KEY_VAR else None
    store = (
        _store_for(args, create=args.write, provider_environ=hermes_environ, environ=key_environ)
        if (args.write or vault_exists)
        else None
    )
    already = _find_conflicts(store, to_store, prog)
    if already is None:
        return 2

    config = home / "config.yaml"
    for line, item_id in to_store:
        state = "already in the vault" if item_id in already else "new item"
        print(f"{line.name} -> hv:{item_id} ({state})")
    for name, reason in left:
        print(f"{name}: left as is ({reason})")
    print(f"store: {vault_dir} (pass --vault if secrets.hermesvault.dir names another)")
    print(f"# Add this to {config}, merged with any existing secrets.hermesvault block:")
    print("secrets:")
    print("  hermesvault:")
    print("    enabled: true")
    if args.key_file is not None:
        print("    custody: key_file")
        print(f"    key_file: {json.dumps(str(args.key_file.expanduser()))}")
    elif sealed:
        print("    custody: systemd-creds")
    print("    env:")
    for line, item_id in to_store:
        print(f'      {line.name}: "hv:{item_id}"')
    if not args.write:
        if not vault_exists:
            print(f"the vault at {vault_dir} does not exist yet; --write creates it")
        print(
            f"dry run: nothing changed. Re-run with --write to store the items; {path} is not edited."
        )
        _err(
            prog,
            "only secrets belong in the vault: use --only NAME or --skip NAME to leave "
            "plain settings (a DEBUG flag, a model name) in .env",
        )
        return 0

    stored = _store_new_items(store, to_store, already, path, prog)
    if stored is None:
        return 1
    if not args.remove_from_env:
        print(f"stored {stored} new item(s) in {vault_dir}; {path} is unchanged")
        print(
            "next: add the mapping above to config.yaml, then re-run with --write "
            "--remove-from-env (and the same --only/--skip/--prefix) to delete the "
            "imported lines from .env"
        )
        return 0

    for line, item_id in to_store:
        try:
            ok = store.resolve_secret(item_id) == {"value": line.value}
        except Exception:  # noqa: BLE001 - treat an unreadable item as a mismatch
            ok = False
        if not ok:
            _err(prog, f"{line.name}: vault item {item_id} does not return the .env value")
            _err(prog, "nothing was removed from .env")
            return 1
    try:
        config_text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _err(prog, f"cannot read {config} ({type(exc).__name__}); add the mapping, then re-run")
        _err(prog, "nothing was removed from .env")
        return 2
    try:
        _verify_hermes_removal(config_text, home, vault_dir, env_file, to_store)
        if config.read_text(encoding="utf-8") != config_text:
            raise ValueError("config.yaml changed during validation; retry")
    except (ValueError, OSError) as exc:
        _err(prog, str(exc) if isinstance(exc, ValueError) else "cannot re-read config.yaml")
        _err(prog, "nothing was removed from .env")
        return 2
    data = render_env_file_without(env_file, [line.number for line, _ in to_store])
    try:
        _replace_file(path, env_file.raw, data)
    except (ImportFileChanged, OSError) as exc:
        _err(prog, f"{path} was not rewritten: {exc}")
        _err(prog, "the items are stored; re-running reuses them")
        return 1
    print(f"stored {stored} new item(s); removed {len(to_store)} line(s) from {path}")
    _err(
        prog,
        "no backup was made. Earlier copies of the plaintext may remain in backups, "
        "editor swap files or git history; rotate any key that was ever committed or shared.",
    )
    _err(
        prog,
        f"checked enabled YAML mappings in {config}, the store directory and plugin key decryption. "
        "The running Hermes process may have a different environment or OS key-store session. "
        "Restart Hermes and confirm before relying on it.",
    )
    _err(
        prog,
        "expect two wrong readings from Hermes: `hermes doctor` warns that no API key is "
        "in .env, and `hermes status` may name another provider, because both read the .env "
        "text. Chat uses the vault key. If Hermes cannot open the vault it starts without "
        "these keys and fails at its first API call, not at startup.",
    )
    if any(line.name.upper() == _HERMES_KEY_VAR for line in env_file.assignments()):
        _err(
            prog,
            f"{_HERMES_KEY_VAR} is still in {path.name}: anyone who can read that file and "
            "the vault can open it, so the move adds little protection for these keys until "
            "the key is held by the OS key store instead.",
        )
    return 0


def _cmd_import(args, prog: str) -> int:
    if args.hermes:
        if not re.fullmatch(r"[A-Za-z0-9._-]*", args.prefix):
            _err(prog, "--prefix may contain only A-Z a-z 0-9 . _ -")
            return 2
        return _cmd_import_hermes(args, prog)
    if args.remove_from_env:
        _err(prog, "--remove-from-env is for --hermes")
        return 2
    if args.file is None:
        _err(prog, "give the .env file to import (or --hermes for a Hermes .env)")
        return 2
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
    already = _find_conflicts(store, to_store, prog)
    if already is None:
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

    stored = _store_new_items(store, to_store, already, path, prog)
    if stored is None:
        return 1
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
    "init": _cmd_init,
    "allow": _cmd_allow,
    "rm": _cmd_rm,
    "seal-listing": _cmd_seal_listing,
    "ref": _cmd_ref,
    "import": _cmd_import,
}


def secrets_main(args: argparse.Namespace) -> int:
    from .vaultkit.vault import VaultError

    prog = f"floorvault secrets {args.subcommand}"
    try:
        return _SECRETS_COMMANDS[args.subcommand](args, prog)
    except KeyOptionsConflict as exc:
        _err(prog, str(exc))
        return 2
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

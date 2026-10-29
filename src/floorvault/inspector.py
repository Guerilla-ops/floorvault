"""Command-line inspection and query debugging tool for floorvault."""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import urllib.parse
from pathlib import Path

from .core import DecryptionVerificationError, FloorVault
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProviderError
from .sqlite_adapter import _fold_sqlite, _quoted_identifier, _safe_column, _safe_identifier


def safe_identifier(name: str) -> str:
    """Return ``name`` iff it is a safe SQL identifier, else ValueError.

    Delegates to the adapters' validator so the CLI and the library can never
    drift into accepting different identifier sets.
    """
    return _safe_identifier(name)


def main(argv: list[str] | None = None) -> int:
    """Entry point for floorvault CLI."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["run"]:
        # `run` splits its own argv at `--`, so the child's arguments never
        # reach argparse (whose REMAINDER handling of `--` varies by version).
        from .agent_cli import run_main

        return run_main(argv[1:])

    parser = argparse.ArgumentParser(
        prog="floorvault",
        description=(
            "Inspect encrypted SQLite databases, and run commands with secrets "
            "from a local FloorVault store."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "run",
        add_help=False,
        help="Run a command with fv: references filled in (floorvault run -h)",
    )
    from .agent_cli import add_secrets_parser

    add_secrets_parser(subparsers)

    # Subcommand: inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a specific encrypted record")
    inspect_parser.add_argument("db_path", type=Path, help="Path to SQLite database")
    inspect_parser.add_argument("table", type=str, help="Table name")
    inspect_parser.add_argument("record_id", type=str, help="Record primary key ID")
    inspect_parser.add_argument("column", type=str, help="Encrypted column name")
    inspect_parser.add_argument(
        "--service-name",
        help="Key custody service name the record was written under (default: floorvault)",
    )
    inspect_parser.add_argument(
        "--app-instance",
        help="App instance the record's context was bound to (default: default)",
    )
    inspect_parser.add_argument(
        "--reveal",
        action="store_true",
        help="print the decrypted plaintext (default: redacted)",
    )
    inspect_parser.add_argument(
        "--id-column",
        default="id",
        help="column holding the record id (default: id), as an adapter's id_column",
    )
    inspect_parser.add_argument(
        "--revision",
        type=int,
        default=None,
        help="revision the record was written at, when it was written with one",
    )
    inspect_parser.add_argument(
        "--schema-id",
        default="floor.vault.v1",
        help="schema id the record was written under (default: floor.vault.v1)",
    )
    inspect_parser.add_argument(
        "--schema-version",
        type=int,
        default=1,
        help="schema version the record was written under (default: 1)",
    )
    # Key options, as for `run` and `secrets` (#100). Without one, the key
    # comes from default custody for --service-name, read-only.
    inspect_parser.add_argument(
        "--key-env",
        default=None,
        metavar="NAME",
        help="read the master key (64 hex) from this variable instead of OS custody",
    )
    inspect_parser.add_argument(
        "--key-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="read the master key (64 hex) from this file instead of OS custody "
        "(default: $FLOOR_VAULT_KEY_FILE)",
    )
    inspect_parser.add_argument(
        "--key-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="directory holding the key: a systemd-creds credential sealed by "
        "`secrets init --custody systemd-creds`, or default custody's key files",
    )

    from .agent_cli import split_allow_argv

    argv, allowed_argv = split_allow_argv(argv)
    args = parser.parse_args(argv)
    if allowed_argv is not None:
        args.allowed_argv = allowed_argv

    if args.command == "secrets":
        from .agent_cli import secrets_main

        return secrets_main(args)

    if args.command == "inspect":
        # Containment: the target must resolve to a regular file that is
        # actually a SQLite database before it is opened. A FIFO, device or
        # non-database file never reaches sqlite3.connect, and the read-only
        # URI keeps the tool from writing to (or journaling beside) the file.
        try:
            db_path = args.db_path.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            # A cyclic symlink raises here, before any controlled check can
            # run - report it like every other unusable path.
            print(f"Error: cannot resolve database path: {exc}", file=sys.stderr)
            return 1
        if not db_path.is_file():
            print(f"Error: Database file not found: {args.db_path}", file=sys.stderr)
            return 1
        try:
            with open(db_path, "rb") as handle:
                magic = handle.read(16)
        except OSError as exc:
            print(f"Error: cannot read database file: {exc}", file=sys.stderr)
            return 1
        if magic != b"SQLite format 3\x00":
            print(f"Error: {args.db_path} is not a SQLite database", file=sys.stderr)
            return 1

        return _inspect_record(args, db_path)

    return 0


def _inspect_record(args, db_path: Path) -> int:
    """Read one encrypted field read-only and report whether it authenticates."""
    for label, value in (
        ("table", args.table),
        ("column", args.column),
        ("record id", args.record_id),
        ("id column", args.id_column),
        ("schema id", args.schema_id),
    ):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            print(f"Error: the {label} is not valid UTF-8", file=sys.stderr)
            return 1
    try:
        table = safe_identifier(args.table)
        # Bare names only, as the adapters require: a qualified spelling would
        # name the same column under a different authenticated identity.
        column = _safe_column(args.column)
        id_column = _safe_column(args.id_column)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    if args.app_instance is not None and not args.app_instance.strip():
        print("Error: --app-instance must not be empty", file=sys.stderr)
        return 1
    if not args.schema_id.strip():
        print("Error: --schema-id must not be empty", file=sys.stderr)
        return 1

    db_uri = f"file:{urllib.parse.quote(db_path.as_posix(), safe='/')}?mode=ro"
    query = (
        f"SELECT {_quoted_identifier(column)} FROM {_quoted_identifier(table)} "  # nosec B608
        f"WHERE {_quoted_identifier(id_column)} = ?"  # identifiers allow-listed + quoted
    )
    try:
        conn = sqlite3.connect(db_uri, uri=True)
        try:
            rows = conn.execute(query, (args.record_id,)).fetchmany(2)
        finally:
            conn.close()
    except sqlite3.DatabaseError as error:  # also a corrupt or truncated file
        print(f"Error: {error}", file=sys.stderr)
        return 1
    if not rows:
        print(f"Error: Record {args.record_id!r} not found in {args.table}", file=sys.stderr)
        return 1
    if len(rows) > 1:
        print(
            f"Error: more than one row in {args.table} has {args.id_column} = "
            f"{args.record_id!r}; refusing to pick one",
            file=sys.stderr,
        )
        return 1
    ciphertext = rows[0][0]
    if not isinstance(ciphertext, (bytes, bytearray)):
        # Decline to echo the value: a diagnostic that prints stored
        # plaintext to the terminal defeats the encryption it exists
        # to verify.
        print(
            f"Value in {args.column} is not binary ciphertext "
            f"(type: {type(ciphertext).__name__}); contents not displayed"
        )
        return 0
    # Custody is touched last, and read-only: a read path that resolved
    # keys with the default allow_create=True would mint a fresh
    # Keychain/Secret-Service/file entry for any typo'd --service-name
    # before decryption ever ran. allow_create=False turns an absent
    # key into a plain error instead.
    from .agent_cli import KeyOptionsConflict, StoreUnavailable, explicit_key

    key_dir = args.key_dir.expanduser() if args.key_dir is not None else None
    try:
        master_key = explicit_key(args, os.environ, key_dir)
    except KeyOptionsConflict as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except StoreUnavailable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if master_key is None:
        provider_kwargs: dict = {}
        if args.service_name is not None:
            provider_kwargs["service_name"] = args.service_name
        if key_dir is not None:
            provider_kwargs["fallback_dir"] = key_dir
        try:
            master_key = AdaptiveKeyProvider(**provider_kwargs).resolve_key(allow_create=False)
        except KeyProviderError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
    vault_kwargs = {"app_instance_id": args.app_instance} if args.app_instance is not None else {}
    try:
        crypto = FloorVault(master_key, **vault_kwargs)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # The names as given first; then ASCII-folded, as the SQLite adapter binds
    # them (SQLite treats Users and users as one table).
    spellings = [(args.table, args.column)]
    folded = (_fold_sqlite(args.table), _fold_sqlite(args.column))
    if folded != spellings[0]:
        spellings.append(folded)
    failure: Exception | None = None
    for bound_table, bound_column in spellings:
        try:
            plaintext = crypto.decrypt_bytes(
                bytes(ciphertext),
                table=bound_table,
                record_id=args.record_id,
                column=bound_column,
                schema_id=args.schema_id,
                schema_version=args.schema_version,
                revision=args.revision,
            )
        except DecryptionVerificationError as exc:
            failure = exc
            continue
        except Exception as exc:  # noqa: BLE001 - malformed envelope, wiped key, ...
            print(f"Decryption failed: {exc}", file=sys.stderr)
            return 1
        if (bound_table, bound_column) != spellings[0]:
            print(f"Authenticated as {bound_table}.{bound_column} (SQLite folds name case)")
        _print_plaintext(plaintext, reveal=args.reveal)
        return 0
    print(f"Decryption failed: {failure}", file=sys.stderr)
    return 1


def _print_plaintext(plaintext: bytes, *, reveal: bool) -> None:
    try:
        text: str | None = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if not reveal:
        # No length, hash or prefix: even the exact plaintext length is a
        # leak once this output lands in logs.
        kind = "binary value" if text is None else "value"
        print(f"Decrypted {kind}: <redacted> (pass --reveal to print it)")
    elif text is None:
        print(f"Decrypted binary value (hex): {plaintext.hex()}")
    else:
        print(f"Decrypted value: {text}")


if __name__ == "__main__":
    sys.exit(main())

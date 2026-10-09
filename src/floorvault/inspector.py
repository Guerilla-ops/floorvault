"""Command-line inspection and query debugging tool for floorvault."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import urllib.parse
from pathlib import Path

from .core import FloorVault
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProviderError
from .sqlite_adapter import _quoted_identifier, _safe_identifier


def safe_identifier(name: str) -> str:
    """Return ``name`` iff it is a safe SQL identifier, else ValueError.

    Delegates to the adapters' validator so the CLI and the library can never
    drift into accepting different identifier sets.
    """
    return _safe_identifier(name)


def main(argv: list[str] | None = None) -> int:
    """Entry point for floorvault CLI."""
    parser = argparse.ArgumentParser(
        prog="floorvault",
        description="Inspect and debug encrypted SQLite databases.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    args = parser.parse_args(argv)

    if args.command == "inspect":
        # Containment: the target must resolve to a regular file that is
        # actually a SQLite database before it is opened. A FIFO, device or
        # non-database file never reaches sqlite3.connect, and the read-only
        # URI keeps the tool from writing to (or journaling beside) the file.
        db_path = args.db_path.expanduser().resolve()
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

        db_uri = f"file:{urllib.parse.quote(db_path.as_posix(), safe='/')}?mode=ro"
        with sqlite3.connect(db_uri, uri=True) as conn:
            try:
                table = safe_identifier(args.table)
                column = safe_identifier(args.column)
            except ValueError as error:
                print(f"Error: {error}", file=sys.stderr)
                return 1
            query = f"SELECT {_quoted_identifier(column)} FROM {_quoted_identifier(table)} WHERE id = ?"  # identifiers allow-listed + quoted  # nosec B608
            try:
                row = conn.execute(query, (args.record_id,)).fetchone()
            except sqlite3.OperationalError as error:
                print(f"Error: {error}", file=sys.stderr)
                return 1
            if not row:
                print(
                    f"Error: Record {args.record_id!r} not found in {args.table}", file=sys.stderr
                )
                return 1
            ciphertext = row[0]
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
            provider_kwargs = (
                {"service_name": args.service_name} if args.service_name is not None else {}
            )
            vault_kwargs = (
                {"app_instance_id": args.app_instance} if args.app_instance is not None else {}
            )
            try:
                master_key = AdaptiveKeyProvider(**provider_kwargs).resolve_key(allow_create=False)
            except KeyProviderError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
            crypto = FloorVault(master_key, **vault_kwargs)
            try:
                decrypted = crypto.decrypt(
                    bytes(ciphertext),
                    table=args.table,
                    record_id=args.record_id,
                    column=args.column,
                )
                if args.reveal:
                    print(f"Decrypted value: {decrypted}")
                else:
                    print(
                        "Decrypted value: <redacted> "
                        f"({len(decrypted)} characters; pass --reveal to print plaintext)"
                    )
                return 0
            except Exception as exc:
                print(f"Decryption failed: {exc}", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

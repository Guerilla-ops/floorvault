"""Command-line inspection and query debugging tool for floorvault."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from .core import FloorVault
from .providers.adaptive import AdaptiveKeyProvider
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

    args = parser.parse_args(argv)

    provider = AdaptiveKeyProvider()
    master_key = provider.resolve_key()
    crypto = FloorVault(master_key)

    if args.command == "inspect":
        if not args.db_path.exists():
            print(f"Error: Database file not found: {args.db_path}", file=sys.stderr)
            return 1

        with sqlite3.connect(args.db_path) as conn:
            try:
                table = safe_identifier(args.table)
                column = safe_identifier(args.column)
            except ValueError as error:
                print(f"Error: {error}", file=sys.stderr)
                return 1
            query = f"SELECT {_quoted_identifier(column)} FROM {_quoted_identifier(table)} WHERE id = ?"  # identifiers allow-listed + quoted  # nosec B608  # nosemgrep: floorvault-sql-interpolation
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
            try:
                decrypted = crypto.decrypt(
                    bytes(ciphertext),
                    table=args.table,
                    record_id=args.record_id,
                    column=args.column,
                )
                print(f"Decrypted value: {decrypted}")
                return 0
            except Exception as exc:
                print(f"Decryption failed: {exc}", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Command-line inspection and query debugging tool for floorvault."""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

from .core import FloorVault
from .providers.adaptive import AdaptiveKeyProvider

# Strict SQL identifier allowlist (deny-first). Identifiers may only contain
# alphanumerics, underscore, and dots (for schema-qualified names), be
# 1..128 chars, and must be valid unquoted SQL identifiers. Anything else is
# refused BEFORE reaching SQL text, closing the H1 raw-interpolation sink.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?$")


def safe_identifier(name: str) -> str:
    """Return ``name`` iff it is a safe unquoted SQL identifier, else ValueError."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Identifier must be a non-empty string")
    if len(name) > 128:
        raise ValueError("Identifier is too long")
    if _IDENTIFIER_RE.fullmatch(name) is None:
        raise ValueError(f"{name!r} is not a valid SQL identifier")
    return name


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
            query = f"SELECT {column} FROM {table} WHERE id = ?"  # identifiers allow-listed  # nosec B608
            row = conn.execute(query, (args.record_id,)).fetchone()
            if not row:
                print(
                    f"Error: Record {args.record_id!r} not found in {args.table}", file=sys.stderr
                )
                return 1
            ciphertext = row[0]
            if not isinstance(ciphertext, (bytes, bytearray)):
                print(
                    f"Value in {args.column} is not binary ciphertext (type: {type(ciphertext).__name__})"
                )
                print(f"Plaintext: {ciphertext}")
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

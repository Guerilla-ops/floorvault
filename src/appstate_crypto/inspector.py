"""Command-line inspection and query debugging tool for appstate-crypto."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from .core import AppStateCrypto
from .providers.adaptive import AdaptiveKeyProvider


def main(argv: list[str] | None = None) -> int:
    """Entry point for appstate-crypto CLI."""
    parser = argparse.ArgumentParser(
        prog="appstate-crypto",
        description="Inspect and debug encrypted SQLite databases.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a specific encrypted record")
    inspect_parser.add_argument("db_path", type=Path, help="Path to SQLite database")
    inspect_parser.add_argument("table", type=str, help="Table name")
    inspect_parser.add_argument("record_id", type=str, help="Record primary key ID")
    inspect_parser.add_argument("column", type=str, help="Encrypted column name")

    # Subcommand: index
    index_parser = subparsers.add_parser("index", help="Compute blind index for a search term")
    index_parser.add_argument("value", type=str, help="Plaintext search value")
    index_parser.add_argument(
        "--scope", type=str, required=True, help="Scope string (e.g. users.email)"
    )

    args = parser.parse_args(argv)

    provider = AdaptiveKeyProvider()
    master_key = provider.resolve_key()
    crypto = AppStateCrypto(master_key)

    if args.command == "index":
        digest = crypto.blind_index(args.value, scope=args.scope)
        print(f"Blind Index (hex): {digest.hex()}")
        return 0

    if args.command == "inspect":
        if not args.db_path.exists():
            print(f"Error: Database file not found: {args.db_path}", file=sys.stderr)
            return 1

        with sqlite3.connect(args.db_path) as conn:
            query = f"SELECT {args.column} FROM {args.table} WHERE id = ?"
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

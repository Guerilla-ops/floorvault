"""Entry point for ``floorvault-gui``. Imports Qt only after parsing arguments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

INSTALL_HINT = 'floorvault-gui needs PySide6: python -m pip install "floorvault[gui]"'


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="floorvault-gui",
        description=(
            "A desktop window over the `floorvault secrets` store. Stored values are "
            "never shown; programs receive them through `floorvault run`."
        ),
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        metavar="DIR",
        help="store directory (default: $FLOOR_VAULT_DIR or ~/.floorvault/agent-vault)",
    )
    key = parser.add_mutually_exclusive_group()
    key.add_argument(
        "--key-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="start with the master key read from this file (64 hex)",
    )
    key.add_argument(
        "--key-env",
        default=None,
        metavar="NAME",
        help="start with the master key read from this variable (64 hex)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        from PySide6 import QtWidgets  # noqa: F401
    except ImportError as exc:
        print(f"{INSTALL_HINT} ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 1

    from .backend import GuiError, VaultSession
    from .window import run

    source = "file" if args.key_file else "env" if args.key_env else "os"
    try:
        session = VaultSession(
            args.vault, key_source=source, key_file=args.key_file, key_env=args.key_env
        )
    except GuiError as exc:
        print(f"floorvault-gui: {exc}", file=sys.stderr)
        return 2
    return run(session)


if __name__ == "__main__":
    raise SystemExit(main())

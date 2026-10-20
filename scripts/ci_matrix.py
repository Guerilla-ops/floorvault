"""Emit the ordinary or expanded GitHub Actions test matrix as JSON."""

from __future__ import annotations

import argparse
import json

PR_CELLS = (
    ("ubuntu-latest", "3.10"),
    ("ubuntu-latest", "3.14"),
    ("macos-latest", "3.13"),
    ("windows-latest", "3.13"),
)
EXPANDED_CELLS = (
    *(("ubuntu-latest", version) for version in ("3.10", "3.11", "3.12", "3.13", "3.14")),
    ("macos-latest", "3.10"),
    ("macos-latest", "3.13"),
    ("windows-latest", "3.10"),
    ("windows-latest", "3.13"),
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expanded", action="store_true")
    args = parser.parse_args()
    cells = EXPANDED_CELLS if args.expanded else PR_CELLS
    print(json.dumps({"include": [{"os": system, "python": version} for system, version in cells]}))


if __name__ == "__main__":
    main()

"""Assert the built distribution is a universal, pure-Python wheel.

FloorVault's positioning is "zero C compilation": it must ship a single
``py3-none-any`` wheel and never a platform/ABI-specific one. This module turns
that claim into a check the security gate enforces, so a regression to a
compiled or platform wheel fails the build instead of passing silently.

Usage:
    python scripts/verify_wheel.py [dist_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

# Tags that mean "pure Python, works anywhere".
UNIVERSAL_TAGS = ("py3-none-any", "py2.py3-none-any")


def is_universal(filename: str) -> bool:
    """True if the wheel filename carries a universal (pure-Python) tag.

    Wheel filenames are ``<dist>-<version>-<python tag>-<abi tag>-<platform tag>.whl``.
    """
    name = Path(filename).name
    if not name.endswith(".whl"):
        return False
    parts = name[: -len(".whl")].split("-")
    if len(parts) < 5:
        return False
    return f"{parts[-3]}-{parts[-2]}-{parts[-1]}" in UNIVERSAL_TAGS


def wheel_names(dist_dir: Path) -> list[str]:
    """All wheel filenames in ``dist_dir``, sorted."""
    return sorted(p.name for p in Path(dist_dir).glob("*.whl"))


def assert_universal(*filenames: str) -> None:
    """Exit non-zero unless every given wheel is universal."""
    bad = [f for f in filenames if not is_universal(f)]
    if bad:
        print(f"[FAIL] Non-universal wheel(s) built: {', '.join(bad)}", file=sys.stderr)
        print(
            "[FAIL] FloorVault must ship py3-none-any (zero C compilation).",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"[PASS] Universal wheel verified: {', '.join(filenames)}")


def main(dist_dir: str = "dist") -> None:
    names = wheel_names(Path(dist_dir))
    if not names:
        print(f"[FAIL] No wheel found in {dist_dir}/", file=sys.stderr)
        raise SystemExit(1)
    assert_universal(*names)


if __name__ == "__main__":
    main(*sys.argv[1:])

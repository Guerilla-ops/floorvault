#!/usr/bin/env python3
"""Report the memory-hardening controls available on the current host."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

# Ensure src/ is in sys.path when executed directly from the repo root
_SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_PATH) not in sys.path:
    sys.path.insert(0, str(_SRC_PATH))

from floorvault.memory import HardenedMemoryKey  # noqa: E402


def main() -> int:
    key = HardenedMemoryKey(b"\x29" * 32, mode="opportunistic")
    try:
        result = {
            "os": platform.system(),
            "platform": sys.platform,
            "memory_locked": key.is_locked,
            "core_dump_limit_applied": sys.platform in ("darwin", "linux"),
            "crash_dump_exclusion": sys.platform in ("darwin", "linux") and key.is_locked,
            "fork_exclusion": sys.platform in ("darwin", "linux") and key.is_locked,
            "windows_virtual_lock": sys.platform == "win32" and key.is_locked,
            "note": "This probe reports requested API outcomes; it cannot prove absence of backend key copies.",
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if key.is_locked else 2
    finally:
        key.wipe()


if __name__ == "__main__":
    raise SystemExit(main())

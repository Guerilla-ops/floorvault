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

from floorvault.memory import MADV_DONTDUMP, MADV_DONTFORK, HardenedMemoryKey  # noqa: E402


def main() -> int:
    key = HardenedMemoryKey(b"\x29" * 32, mode="opportunistic")
    try:
        dump_supported = MADV_DONTDUMP is not None
        fork_supported = MADV_DONTFORK is not None
        result = {
            "os": platform.system(),
            "platform": sys.platform,
            "memory_locked": key.is_locked,
            "core_dump_limit_applied": sys.platform in ("darwin", "linux"),
            "crash_dump_exclusion": key._dump_excluded,
            "crash_dump_exclusion_supported": dump_supported,
            "fork_exclusion": key._fork_excluded,
            "fork_exclusion_supported": fork_supported,
            "windows_virtual_lock": sys.platform == "win32" and key.is_locked,
            "note": "Reports only observed protections. Dump/fork exclusion via madvise is "
            "Linux-only; on Darwin only RLIMIT_CORE=0 and mlock are in effect. This probe "
            "cannot prove absence of backend key copies.",
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if key.is_locked else 2
    finally:
        key.wipe()


if __name__ == "__main__":
    raise SystemExit(main())

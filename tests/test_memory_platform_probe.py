"""Portable checks for the platform-specific memory-hardening probe."""

import json
import subprocess
import sys
from pathlib import Path

from floorvault.memory import HardenedMemoryKey, disable_core_dumps


def test_memory_probe_reports_platform_status():
    key = HardenedMemoryKey(b"\x28" * 32, mode="opportunistic")
    try:
        assert isinstance(key.is_locked, bool)
        if sys.platform in ("darwin", "linux"):
            assert key.is_locked is True
    finally:
        key.wipe()


def test_disable_core_dumps_safe_without_resource(monkeypatch):
    import floorvault.memory as mem

    monkeypatch.setattr(mem, "resource", None)
    # Should safely no-op without raising AttributeError
    disable_core_dumps()


def test_memory_probe_script_execution():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "memory_probe.py"
    proc = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 2)
    output = json.loads(proc.stdout)
    assert "memory_locked" in output
    assert "platform" in output


def test_memory_probe_reports_observed_dump_fork_state():
    """The probe must report observed madvise outcomes, not mlock success.

    Regression: dump/fork exclusion was derived from is_locked, so Darwin
    (which has no MADV_DONTDUMP/MADV_DONTFORK) reported true for both.
    """
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "memory_probe.py"
    proc = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = json.loads(proc.stdout)
    assert "crash_dump_exclusion_supported" in output
    assert "fork_exclusion_supported" in output
    if sys.platform == "darwin":
        assert output["crash_dump_exclusion_supported"] is False
        assert output["fork_exclusion_supported"] is False
        assert output["crash_dump_exclusion"] is False
        assert output["fork_exclusion"] is False

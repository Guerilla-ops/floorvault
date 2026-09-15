"""Property tests for the local security gate script.

CI runs ``scripts/security-check.sh`` unchanged, so the properties CI depends on
are pinned here. The script itself is not executed (it shells out to gitleaks,
uv and friends); we assert its shape so a refactor cannot silently break CI.
"""

from __future__ import annotations

from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "security-check.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")


def test_script_is_fail_fast():
    """A gate must stop at the first failure, not report success after one."""
    assert "set -euo pipefail" in TEXT


def test_path_setup_handles_the_windows_venv_layout():
    """The venv bin dir is .venv/bin on POSIX and .venv/Scripts on Windows."""
    assert ".venv/bin" in TEXT
    assert ".venv/Scripts" in TEXT, "gate script cannot find the venv on Windows"


def test_strict_mode_fails_when_a_gate_tool_is_missing():
    """In CI a missing tool must be fatal; locally it may only warn."""
    assert "FLOORVAULT_STRICT" in TEXT
    assert "require_tool" in TEXT


def test_secret_scan_can_be_skipped_for_non_linux_runners():
    """History is identical on every runner, so the scan runs once, on Linux."""
    assert "FLOORVAULT_SKIP_SECRET_SCAN" in TEXT


def test_gate_runs_the_entire_test_suite():
    """The gate must not run a hand-listed subset of test files.

    It previously invoked pytest on 8 of 18 files, so test_platform_providers.py
    (which would have exercised the DPAPI and keyring paths on Windows) and the
    protected-store safety tests never ran in CI. A regression could pass the
    gate while the suite failed locally.
    """
    assert "pytest -q tests/" in TEXT, "gate does not run the whole tests/ directory"

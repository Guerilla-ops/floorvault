"""scripts/check_systemd_creds_host.sh: the parts that run without a real systemd 256+.

The checks themselves need a real host (see docs/USAGE.md); this guards the
option handling, so a typo cannot turn the script into one that does nothing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_systemd_creds_host.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="bash script"
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=60, check=False
    )


def test_help_lists_every_context():
    result = _run("--help")
    assert result.returncode == 0
    for context in ("shell", "bare", "user", "system", "cron", "ssh"):
        assert f"\n  {context} " in result.stdout


def test_unknown_option_is_refused_before_anything_runs():
    result = _run("--with-sudoo")
    assert result.returncode == 2
    assert "unknown option: --with-sudoo" in result.stderr


@pytest.mark.skipif(sys.platform == "linux", reason="checks the non-Linux refusal")
def test_refuses_off_linux():
    result = _run()
    assert result.returncode == 2
    assert "Linux only" in result.stderr

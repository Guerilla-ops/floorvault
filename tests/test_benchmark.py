"""Guards the comparative benchmark harness (Slice 5).

Ensures scripts/benchmark_compare.py runs end-to-end and produces sane,
self-consistent numbers: all operations measured, positive, and the surfaced
floorvault-vs-Fernet ratios within an expected band. This is a harness smoke
test, not a latency claim — it protects compatibility, not absolute timings.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH = REPO_ROOT / "scripts" / "benchmark_compare.py"


def _run(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BENCH), *extra],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_benchmark_harness_runs_smoke(tmp_path):
    out = _run("--iterations", "300", "--json", str(tmp_path / "b.json"))
    assert out.returncode == 0, out.stderr
    payload = tmp_path / "b.json"
    assert payload.exists()
    import json

    data = json.loads(payload.read_text())
    assert data["iterations"] == 300
    # Every operation present and a sane positive median.
    for key in (
        "sqlite_write",
        "sqlite_read",
        "fernet_encrypt",
        "fernet_decrypt",
        "floorvault_encrypt",
        "floorvault_decrypt",
        "floorvault_beacon16",
        "floorvault_beacon_matches",
    ):
        assert key in data and data[key] > 0, key
    # Sane ratios: floorvault should be in the same order as Fernet (not 100x).
    assert 0.0 < data["floorvault_vs_fernet_encrypt"] < 10.0
    assert 0.0 < data["floorvault_vs_fernet_decrypt"] < 10.0


def test_benchmark_script_is_importable_executable():
    # The module's main() path is the CLI; ensure it parses arguments without
    # crashing (help path).
    r = _run("--help")
    assert r.returncode == 0
    assert "comparative micro-benchmark" in r.stdout or "usage" in r.stdout.lower()

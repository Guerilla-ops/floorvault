"""The CI workflow's shape: required check names survive, shards cannot drop mutants.

Branch protection names checks, and the mutation controls are split across
parallel jobs behind aggregator jobs that keep the old names. These tests pin the
parts of that arrangement that fail silently: a renamed required check never
reports, and a shard count that disagrees with the shard list skips mutants.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
CFLITE = yaml.safe_load((ROOT / ".github" / "workflows" / "cflite.yml").read_text(encoding="utf-8"))
CELLS = (
    ("ubuntu-latest", "3.10"),
    ("ubuntu-latest", "3.14"),
    ("macos-latest", "3.13"),
    ("windows-latest", "3.13"),
)


def _required_contexts() -> list[str]:
    text = (ROOT / "docs" / "CI.md").read_text(encoding="utf-8")
    block = text.split("```text", 1)[1].split("```", 1)[0]
    return [line.strip() for line in block.strip().splitlines()]


def _static_names() -> set[str]:
    names = set()
    for job in CI["jobs"].values():
        name = job.get("name", "")
        if name == "${{ matrix.os }} / py${{ matrix.python }}":
            names |= {f"{os_} / py{py}" for os_, py in CELLS}
        elif "${{" not in name:
            names.add(name)
    for os_ in ("ubuntu-latest", "macos-latest", "windows-latest"):
        names.add(f"Dependency CVE audit (all extras) ({os_})")
    return names


def test_every_required_context_is_still_produced():
    produced = _static_names() | {"fuzz (code-change)"}
    missing = [name for name in _required_contexts() if name not in produced]
    assert not missing, f"no job reports these required checks any more: {missing}"


def test_the_fuzz_check_runs_in_a_merge_queue_under_the_same_name():
    assert "merge_group" in CI[True] and "merge_group" in CFLITE[True]
    name = CFLITE["jobs"]["fuzz"]["name"]
    assert '"merge_group"' in name and "'code-change'" in name


def test_shard_jobs_read_their_count_from_one_place():
    jobs = CI["jobs"]
    for job_id, count in (
        ("mutation-shards", "linux_count"),
        ("platform-mutations", "platform_count"),
    ):
        job = jobs[job_id]
        shards = job["strategy"]["matrix"]["shard"]
        assert shards == "${{ fromJSON(needs.changes.outputs.%s) }}" % (
            count.replace("count", "shards")
        )
        run = " ".join(step.get("run", "") for step in job["steps"])
        assert re.search(
            r"--shard \$\{\{ matrix\.shard \}\}/\$\{\{ needs\.changes\.outputs\.%s \}\}" % count,
            run,
        ), (job_id, run)
        # No hard-coded denominator anywhere in the job.
        assert not re.search(r"--shard \S*/\d", run), job_id
    shard_step = next(s for s in jobs["changes"]["steps"] if s.get("id") == "shards")["run"]
    for name in ("linux", "platform"):
        assert f"{name}_count=$" in shard_step and f"{name}_shards=$(list" in shard_step


def test_aggregators_keep_the_required_names_and_always_run():
    jobs = CI["jobs"]
    assert jobs["mutations"]["name"] == "Full mutation controls (Linux)"
    assert jobs["gates"]["name"] == "${{ matrix.os }} / py${{ matrix.python }}"
    for job_id, needed in (("mutations", "mutation-shards"), ("gates", "platform-mutations")):
        assert jobs[job_id]["if"] == "always()", job_id
        assert needed in jobs[job_id]["needs"], job_id
    assert "tests" in jobs["gates"]["needs"]
    # The shard jobs themselves are not required checks and must not reuse a required name.
    for job_id in ("mutation-shards", "platform-mutations", "tests"):
        assert jobs[job_id]["name"] not in _required_contexts()
        assert not jobs[job_id]["name"].startswith(
            ("ubuntu-latest /", "macos-latest /", "windows-latest /")
        )

"""Invariants for the CI matrix.

The matrix is the only place platform-specific behaviour gets exercised, and
every defect it has found so far was invisible on macOS and Linux alike (see
``docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md``). These assertions pin the
properties that must not silently regress.

The workflow is parsed with a regex rather than a YAML library: PyYAML is neither
a runtime nor a dev dependency, and the matrix entries have one fixed shape.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT = ROOT / "pyproject.toml"

TEXT = WORKFLOW.read_text(encoding="utf-8")
CELL = re.compile(r'\{\s*os:\s*([\w.-]+),\s*python:\s*"([\d.]+)"\s*\}')
CLASSIFIER = re.compile(r"Programming Language :: Python :: (\d+\.\d+)")


def _cells() -> list[tuple[str, str]]:
    return CELL.findall(TEXT)


def _declared_versions() -> set[str]:
    """Versions the package claims to support, from its own classifiers."""
    return set(CLASSIFIER.findall(PYPROJECT.read_text(encoding="utf-8")))


def _floor() -> str:
    match = re.search(
        r'requires-python\s*=\s*">=\s*([\d.]+)"', PYPROJECT.read_text(encoding="utf-8")
    )
    assert match, "could not read requires-python from pyproject.toml"
    return match.group(1)


def test_the_matrix_parses_and_is_not_empty():
    assert _cells(), "no matrix cells found in ci.yml - has the matrix been restructured?"


def test_all_supported_operating_systems_are_covered():
    systems = {os_name for os_name, _ in _cells()}
    for required in ("ubuntu-latest", "macos-latest", "windows-latest"):
        assert required in systems, f"{required} is missing from the CI matrix"


def test_every_supported_python_version_is_tested_somewhere():
    tested = {version for _, version in _cells()}
    declared = _declared_versions()
    assert declared, "no Python version classifiers found in pyproject.toml"
    missing = declared - tested
    assert not missing, f"declared as supported but never tested: {sorted(missing)}"


def test_every_operating_system_tests_the_declared_python_floor():
    """macOS and Windows initially ran only the newest interpreter.

    A platform-specific code path can pass on 3.13 and fail on the 3.10 floor
    that pyproject.toml declares, which is precisely the class of defect this
    matrix exists to find. Asking for both ends of the range on every OS is
    deliberate.
    """
    floor = _floor()
    cells = _cells()
    for os_name in sorted({os_name for os_name, _ in cells}):
        versions = {version for cell_os, version in cells if cell_os == os_name}
        assert floor in versions, (
            f"{os_name} does not test the declared floor {floor}: it tests {sorted(versions)}"
        )


# ---------------------------------------------------------------------------
# Release artifacts
#
# The gate builds a wheel and sdist and verifies their shape, then discards
# them. Nothing recorded which artifact a given run produced, so a build from
# source could not be compared against another runner's or against a published
# download - reproducibility was unprovable rather than merely unproven.
# ---------------------------------------------------------------------------


def _upload_step() -> str:
    """The whole upload-artifact step, including its condition and inputs.

    Walks out to the YAML list-item boundaries rather than slicing from the
    ``uses:`` line, so the step's ``if:`` and ``with:`` are included regardless
    of the order the keys are written in.
    """
    lines = TEXT.splitlines()
    marker = next((i for i, text in enumerate(lines) if "actions/upload-artifact@" in text), None)
    assert marker is not None, "the workflow does not upload the built artifacts"
    start = marker
    while start > 0 and not re.match(r"\s*- ", lines[start]):
        start -= 1
    end = marker + 1
    while end < len(lines) and not re.match(r"\s*- ", lines[end]):
        end += 1
    return "\n".join(lines[start:end])


def test_the_built_artifacts_are_published_by_ci():
    step = _upload_step()
    assert ".whl" in step, "the wheel is not among the published artifacts"
    assert ".tar.gz" in step, "the sdist is not among the published artifacts"


def test_publishing_is_fail_closed_when_no_artifact_was_built():
    """An upload step that silently publishes nothing is worse than none."""
    assert "if-no-files-found" in _upload_step(), (
        "upload-artifact defaults to warning when its path matches nothing"
    )
    assert re.search(r"if-no-files-found:\s*error", _upload_step()), (
        "a missing artifact must fail the job, not warn"
    )


def test_only_one_matrix_leg_publishes_the_artifacts():
    """Ten legs publishing the same name would collide or overwrite silently.

    One leg is the release identity; the digests printed by the gate on every
    leg (see test_gate_script.py) are what make the other platforms comparable.
    """
    step = _upload_step()
    assert re.search(r"if:\s*\S", step), (
        "the upload step has no condition, so every matrix leg would publish"
    )
    assert "matrix." in step, "the upload condition does not reference the matrix"


# ---------------------------------------------------------------------------
# The secret scan
#
# The gitleaks ACTION requires a licence for organization-owned repositories. The
# repository moved into the `vaultfloor` organization, so the Action began failing
# with "License key is required", and because the workflow cancels in-progress
# runs, that single failure cancelled five other legs. The comment above the job
# had asserted the licence was unnecessary - true when written, false after the
# move, and the kind of stale claim that turns into a red build.
#
# The OSS CLI has no such gate and runs exactly the command the local gate runs,
# so CI and the local run now agree on what the scan is.
# ---------------------------------------------------------------------------


def test_the_secret_scan_does_not_use_the_license_gated_action():
    assert "gitleaks/gitleaks-action@" not in TEXT, (
        "the gitleaks Action needs a licence for organization-owned repos; use the CLI"
    )
    assert "gitleaks git" in TEXT, "CI does not run the same scan command as the local gate"


def test_the_secret_scanner_is_pinned_and_its_checksum_verified():
    """The scanner is part of the gate, so its provenance is part of the gate."""
    assert re.search(r"VERSION=\d+\.\d+\.\d+", TEXT), "the scanner version is not pinned"
    assert re.search(r"SHA256=[0-9a-f]{64}", TEXT), "no pinned checksum for the download"
    assert "sha256sum -c -" in TEXT, "the downloaded scanner is not verified before use"


def test_the_secret_scan_still_runs_over_full_history():
    """A shallow checkout would make a history scan meaningless."""
    assert "fetch-depth: 0" in TEXT


# ---------------------------------------------------------------------------
# Third-party assurance tooling
#
# Bandit, Semgrep CE, OpenSSF Scorecard and ClusterFuzzLite are external checks
# on the repository. Each is only worth its green tick if it runs the command the
# local gate runs, against pinned inputs, with no more token scope than it needs.
# ---------------------------------------------------------------------------

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
GATE = (ROOT / "scripts" / "security-check.sh").read_text(encoding="utf-8")
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_every_action_in_every_workflow_is_pinned_to_a_commit():
    """A tag can be moved; a 40-hex commit cannot. Covers every workflow file."""
    unpinned = [
        f"{path.name}: {ref}"
        for path in WORKFLOWS
        for ref in USES.findall(path.read_text(encoding="utf-8"))
        if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref)
    ]
    assert not unpinned, f"actions not pinned to a full commit SHA: {unpinned}"


def test_sast_job_runs_the_gates_own_commands():
    for command in (
        "bandit -q -r src/ scripts/ fuzz/",
        "semgrep scan --config p/python --metrics=off --error src/ scripts/ fuzz/",
    ):
        assert command in GATE, f"the gate no longer runs: {command}"
        assert command in TEXT, f"the sast job does not run the gate's command: {command}"


def test_semgrep_is_version_pinned_and_skipped_on_the_matrix_legs():
    assert re.search(r"SEMGREP_VERSION=\d+\.\d+\.\d+", TEXT), "Semgrep version is not pinned"
    assert "semgrep==${SEMGREP_VERSION}" in TEXT
    assert 'FLOORVAULT_SKIP_SEMGREP: "1"' in TEXT, "every matrix leg would rerun Semgrep"


def test_scorecard_runs_read_only_and_publishes_the_public_repo():
    """The repo is public: results go to the public Scorecard API and SARIF.

    ``publish_results: false`` was the private-repo setting; on a public repo
    it would hide the scorecard from securityscorecards.dev for no benefit.
    Top-level permissions stay read-only regardless.
    """
    scorecard = _workflow("scorecard.yml")
    assert re.search(r"^permissions:\s*read-all\s*$", scorecard, re.MULTILINE)
    assert "publish_results: true" in scorecard
    assert "persist-credentials: false" in scorecard
    assert "upload-sarif" in scorecard, "Scorecard findings never reach code scanning"


def test_clusterfuzzlite_builds_and_runs_with_the_token_a_private_repo_needs():
    cflite = _workflow("cflite.yml")
    assert "clusterfuzzlite/actions/build_fuzzers@" in cflite
    assert "clusterfuzzlite/actions/run_fuzzers@" in cflite
    prune = _workflow("cflite-prune.yml")
    assert (cflite + prune).count("github-token: ${{ secrets.GITHUB_TOKEN }}") == 4, (
        "every cflite step (fuzz build/run + weekly prune build/run) needs the token"
    )
    assert "language: python" in cflite
    assert "pull_request" in cflite, "a crash introduced by a PR would not fail the PR"


def test_clusterfuzzlite_batch_mode_keeps_and_bounds_the_corpus():
    """Without a storage repo, corpora persist as per-run artifacts; the weekly
    schedule must also prune or the persisted corpus grows unboundedly."""
    cflite = _workflow("cflite.yml")
    assert "actions: read" in cflite, "corpus artifacts from previous runs are unreadable"
    prune = _workflow("cflite-prune.yml")
    assert "mode: prune" in prune, "batch fuzzing without pruning grows the corpus forever"
    assert "github.event.workflow_run.event == 'schedule'" in prune


def test_clusterfuzzlite_does_not_discard_a_crash_it_cannot_reproduce():
    """The first run found a real crash, timed out reproducing it, and went green."""
    assert "report-unreproducible-crashes: true" in _workflow("cflite.yml")


def test_corpus_pruning_follows_the_completed_trusted_weekly_batch():
    path = ROOT / ".github" / "workflows" / "cflite-prune.yml"
    assert path.is_file(), "pruning needs a separate post-batch workflow and artifact namespace"
    prune = path.read_text(encoding="utf-8")
    assert "workflow_run:" in prune
    assert "workflows: [ClusterFuzzLite]" in prune
    assert "types: [completed]" in prune
    assert "workflow_dispatch:" in prune
    condition = (
        "      github.event_name == 'workflow_dispatch' ||\n"
        "      (github.event.workflow_run.event == 'schedule' &&\n"
        "       github.event.workflow_run.conclusion == 'success' &&\n"
        "       github.event.workflow_run.head_branch == 'main' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository)"
    )
    assert condition in prune, "automatic pruning must follow a successful trusted main batch"
    assert "\n  prune:" not in _workflow("cflite.yml"), "same-run corpus uploads would collide"
    assert "mode: prune" in prune
    assert "contents: read" in prune and "actions: read" in prune
    assert "write" not in prune

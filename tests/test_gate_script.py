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


def test_strict_mode_is_the_default_and_requires_an_explicit_opt_out():
    """A missing gate tool must be fatal unless someone opts out deliberately.

    The previous default warned and continued, so a missing pip-audit removed the
    dependency CVE audit from the gate while it still reported every gate as
    passing. Failing closed has to be the default; weakening the gate must be an
    explicit act, not the path of least resistance.
    """
    assert 'STRICT="${FLOORVAULT_STRICT:-1}"' in TEXT, "strict mode is not the default"
    assert "FLOORVAULT_STRICT=0" in TEXT, "no documented opt-out from strict mode"
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


def test_gate_runs_curated_mutation_checks():
    """The security gate must detect regressions that ordinary tests miss."""
    assert "scripts/mutation_check.py --mode curated" in TEXT


def test_lint_covers_the_whole_shipped_tree():
    """Linting must cover scripts/, not only src/ and tests/.

    Step 3 ran ``ruff check src/ tests/``. ``scripts/`` holds the gate helper,
    the mutation harness whose verdict *is* step 11, the wheel verifier whose
    verdict is step 10, and the benchmark harness the README quotes - none of
    which CI linted, even though the README tells developers to run
    ``ruff check .``. A harness that decides a gate step can therefore regress
    unlinted.
    """
    assert "ruff check src/ tests/ scripts/" in TEXT, "gate lints only part of the tree"
    assert "ruff format --check src/ tests/ scripts/" in TEXT, "gate formats only part of the tree"


def test_gate_prints_the_artifact_digests():
    """The built wheel and sdist must be reported by digest.

    The gate builds the artifacts and verifies their *shape*, then discards them.
    Without a digest in the output there is no record of the artifact any given
    run produced - so a build from source cannot be compared against another
    runner's, nor against a published download. The digests are printed on every
    leg (including the three operating systems), which is what makes
    cross-platform reproducibility checkable from the logs.
    """
    assert "sha256" in TEXT.lower(), "gate does not report SHA-256 digests"
    assert "dist/*.whl" in TEXT or "dist/floorvault" in TEXT or "DIGEST" in TEXT, (
        "gate reports no digest for the built artifacts"
    )
    assert "digest" in TEXT.lower(), "digest output is not labelled"


def test_gate_reports_the_archive_metadata_that_varies_by_platform():
    """Digests alone cannot explain a digest that differs between runners.

    Two attributions of the platform delta have already been falsified by a CI
    run, so the gate prints the fields that could actually cause one: the zip
    creating-system byte, the gzip OS byte and the tar member modes. Without this
    the next investigation starts by guessing again.
    """
    assert "[ARTIFACT]" in TEXT, "gate prints no archive metadata"
    for field in ("create_system", "tar_modes", "gzip_os_byte"):
        assert field in TEXT, f"gate does not report {field}"

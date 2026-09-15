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

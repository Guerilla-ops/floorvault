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

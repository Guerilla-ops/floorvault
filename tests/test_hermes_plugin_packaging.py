"""Packaging contract for plugins/hermesvault as an installable Hermes plugin.

`hermes plugins install owner/repo/plugins/hermesvault` copies only that
directory, Hermes' security scan rejects symlinks that leave it, and Hermes'
package manager installs PyPI requirements only (no direct URLs). These checks
need no Hermes checkout, so they run on every CI leg.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "hermesvault"


def _manifest() -> dict:
    return yaml.safe_load((PLUGIN / "plugin.yaml").read_text(encoding="utf-8"))


def _requirements() -> list[Requirement]:
    return [Requirement(entry) for entry in _manifest().get("python_dependencies") or []]


def test_plugin_directory_is_self_contained():
    links = [p.relative_to(PLUGIN) for p in PLUGIN.rglob("*") if p.is_symlink()]
    assert links == [], f"symlinks fail Hermes' install security scan: {links}"


def test_floorvault_is_declared_from_pypi_within_this_release_line():
    # tomllib is 3.11+; the project supports 3.10.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    checkout = Version(re.search(r'^version = "([^"]+)"$', pyproject, re.M).group(1))
    floorvault = [r for r in _requirements() if r.name == "floorvault"]
    assert len(floorvault) == 1, "plugin.yaml must declare floorvault"
    (req,) = floorvault
    assert req.url is None, "Hermes does not install direct-URL requirements"
    assert req.marker is None, "floorvault is needed on every platform"
    floors = [Version(s.version) for s in req.specifier if s.operator == ">="]
    assert floors, "floorvault needs a version floor"
    # The floor names a release the plugin's API calls exist in; it can never be
    # newer than the code this checkout ships.
    assert max(floors) <= checkout
    assert req.specifier.contains(str(checkout)), (
        f"{req} must admit this checkout's version {checkout}"
    )


def test_every_dependency_has_an_upper_bound():
    # Hermes' dependency policy: plugins pin upper bounds; reviewers flag bare floors.
    for req in _requirements():
        assert any(s.operator in {"<", "<=", "=="} for s in req.specifier), (
            f"{req} has no upper bound"
        )


def test_manifest_declares_a_semver_hermes_floor():
    # Catalog rule 14: requires_hermes is a SemVer floor (never a CalVer date),
    # declared in plugin.yaml as well as the catalog entry, because older Hermes
    # versions enforce only the manifest copy.
    spec = _manifest().get("requires_hermes")
    assert isinstance(spec, str), "plugin.yaml must declare requires_hermes"
    match = re.fullmatch(r">=\s*(\d+)\.(\d+)\.(\d+)", spec.strip())
    assert match, f"requires_hermes must be a '>=X.Y.Z' SemVer floor, got {spec!r}"
    assert int(match.group(1)) < 2000, "requires_hermes is SemVer, not a CalVer date"


def test_manifest_metadata():
    manifest = _manifest()
    assert manifest["name"] == "hermesvault" == PLUGIN.name
    assert manifest["license"] == "MIT"
    assert (PLUGIN / "__init__.py").is_file()
    assert (PLUGIN / "README.md").is_file()

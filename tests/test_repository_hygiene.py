"""Repository-wide hygiene properties, pinned so a fix cannot quietly regress.

The first property here came from a CodeQL alert (``py/insecure-temporary-file``)
on ``scripts/benchmark_compare.py``: ``tempfile.mktemp()`` returns a *name* rather
than creating the file, so the window before the caller opens it can be won by
another process - which is why it is deprecated, and why the query flags it in
every language. The repo's own guard list had no equivalent check, so nothing
would have caught a reintroduction.

The second property pins the fix rather than the ban: the script must obtain its
temporary location in a way that also cleans up, since the old form left a stray
database behind on every run.

Detection is by AST, not by text. A text matcher for ``mktemp(`` matched this
file's own prose - a scanner that reports the comments describing a defect is
neither evidence of the defect nor of its absence - so the matcher walks call
nodes instead, and a third test proves the matcher can still see the pattern it
exists to ban.
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import floorvault
from floorvault.core import FloorVault
from floorvault.vaultkit.vault import VaultStore

ROOT = Path(__file__).resolve().parent.parent
SHIPPED_ROOTS = ("src", "tests", "scripts")


def _mktemp_call_lines(source: str) -> list[int]:
    """Line numbers of real calls to ``mktemp`` (never its mentions in prose)."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "mktemp":
            lines.append(node.lineno)
        elif isinstance(func, ast.Name) and func.id == "mktemp":
            lines.append(node.lineno)
    return lines


def _shipped_python_files() -> list[Path]:
    files: list[Path] = []
    for root in SHIPPED_ROOTS:
        files.extend(sorted((ROOT / root).rglob("*.py")))
    return files


def test_the_matcher_can_see_the_pattern_it_bans():
    """A guard that cannot detect its own target reports a green it did not earn."""
    sample = 'import tempfile\n\ndb = tempfile.mktemp(".bench.db")\n'
    assert _mktemp_call_lines(sample) == [3]
    # ...and it must not fire on prose that merely names the API.
    prose = '"""Never use tempfile.mktemp() here."""\n# mktemp( is banned\n'
    assert _mktemp_call_lines(prose) == []


def test_no_shipped_code_calls_the_racy_tempfile_mktemp():
    offenders = [
        f"{path.relative_to(ROOT)}:{lineno}"
        for path in _shipped_python_files()
        for lineno in _mktemp_call_lines(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "tempfile.mktemp() returns a name, not a file: the gap before the caller "
        f"creates it is a race. Use TemporaryDirectory/NamedTemporaryFile instead. Found: {offenders}"
    )


def test_the_benchmark_uses_a_temp_directory_that_cleans_up():
    """The fix must obtain a location and remove it, not merely avoid the banned call."""
    text = (ROOT / "scripts" / "benchmark_compare.py").read_text(encoding="utf-8")
    assert "TemporaryDirectory(" in text, (
        "the benchmark must use a self-cleaning temporary directory; the previous "
        "mktemp form also leaked a .bench.db on every run"
    )


def test_search_surface_is_removed_from_public_and_vault_store_apis(tmp_path):
    assert not hasattr(floorvault, "compute_blind_index")
    assert not hasattr(floorvault, "BlindIndexer")
    assert not hasattr(FloorVault, "blind_index")
    assert not hasattr(FloorVault, "beacon")
    assert not hasattr(VaultStore, "find_by_origin")

    VaultStore(tmp_path / "vault", crypto=FloorVault(b"x" * 32, memory_mode="disabled"))
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_items)")}
    assert "origin_idx" not in columns


# --------------------------------------------------------------------------
# Public API surface
#
# SECURITY.md names the error types a caller is expected to handle. One of them
# - LegacyRetiredError, the read failure when a migrated legacy id's modern
# record has gone - was documented but not exported, so a caller following the
# docs could not catch it without reaching into a private module path.
# --------------------------------------------------------------------------


def test_every_exported_name_is_actually_importable():
    missing = [name for name in floorvault.__all__ if not hasattr(floorvault, name)]
    assert not missing, f"__all__ lists names that are not exported: {missing}"


def test_documented_read_failure_types_are_exported():
    """The errors SECURITY.md tells callers to handle must be importable."""
    for name in ("LegacyVaultError", "LegacyRetiredError"):
        assert name in floorvault.__all__, f"{name} is missing from __all__"

    from floorvault import LegacyRetiredError
    from floorvault.migration import LegacyRetiredError as private_path

    assert LegacyRetiredError is private_path

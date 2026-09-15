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
from pathlib import Path

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

#!/usr/bin/env python3
"""Mutation testing for FloorVault: curated safety mutants plus a full AST sweep.

Two modes:

  --mode curated   A small hand-picked set targeting the permission/custody
                   contract (fast; suitable for a pre-push gate).
  --mode auto      Systematically generates mutants across the whole package by
                   walking the AST with standard mutation operators, then runs
                   the test suite once per mutant. This is a real mutation
                   score rather than a spot check.

Design choices:
  * Deterministic and dependency-free - no mutation framework, so it runs in CI
    and in a project that advertises zero toolchain requirements.
  * Every mutant is applied to a throwaway copy of the repository, never the
    working tree, so an interrupted run cannot leave mutated source behind.
  * Mutants that do not compile are reported as INVALID and excluded from the
    score rather than counted as "killed".
  * Curated mode includes a deliberately equivalent docstring mutant that must
    SURVIVE; if everything were reported killed the harness would be measuring
    nothing.

Usage:
    python scripts/mutation_check.py                       # curated
    python scripts/mutation_check.py --mode auto --list     # count mutants
    python scripts/mutation_check.py --mode auto --jobs 8
    python scripts/mutation_check.py --mode auto --limit 200
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATHS = ("src/floorvault",)

CURATED_TESTS = [
    "tests/test_protected_store_safety.py",
    "tests/test_platform_providers.py",
    "tests/test_adaptive_provider.py",
    "tests/test_platform_support.py",
    "tests/test_crypto_core.py",
]

# --------------------------------------------------------------------------
# Curated mutants (fast, contract-focused)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    find: str
    replace: str
    why: str
    expect: str = "killed"


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "PC-1",
        "src/floorvault/platform_support.py",
        "    if is_windows():\n        return False",
        "    if False:  # MUTANT\n        return False",
        "Windows exemption disabled: a synthesised 0o666 treated as insecure",
    ),
    Mutation(
        "PC-2",
        "src/floorvault/platform_support.py",
        "    return bool(mode & 0o077)",
        "    return False  # MUTANT",
        "POSIX group/other gate disabled entirely",
    ),
    Mutation(
        "PC-3",
        "src/floorvault/platform_support.py",
        "    return bool(mode & 0o077)",
        "    return mode != 0o600  # MUTANT",
        "Exact-equality bug: any non-0600 owner-only mode refused",
    ),
    Mutation(
        "PC-4",
        "src/floorvault/providers/platform_custody.py",
        'raise ProtectedStoreMissing("protected store not present") from exc',
        'raise ProtectedStoreError("protected store not present") from exc',
        "Loses the absent/unreadable distinction",
    ),
    Mutation(
        "PC-5",
        "src/floorvault/providers/windows_dpapi.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Reintroduces the data-loss bug: corrupt store treated as absent",
    ),
    Mutation(
        "PC-6",
        "src/floorvault/providers/linux_keyring.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Same regression on the Linux provider",
    ),
    Mutation(
        "PC-7",
        "src/floorvault/providers/platform_custody.py",
        "        os.link(temporary, path)",
        "        os.replace(temporary, path)  # MUTANT",
        "Atomic no-clobber replaced by os.replace, which always clobbers",
    ),
    Mutation(
        "PC-8",
        "src/floorvault/providers/adaptive.py",
        "                # custody. This clause is why they are no longer dead code.\n                raise",
        "                # custody. This clause is why they are no longer dead code.\n                return None  # MUTANT",
        "Reinstates swallowing a deliberate provider error (silent custody downgrade)",
    ),
    Mutation(
        "AD-1",
        "src/floorvault/providers/adaptive.py",
        "        if has_posix_group_or_other_access(file_stat.st_mode):",
        "        if False:  # MUTANT",
        "Adaptive provider stops refusing group/other-accessible files",
    ),
    Mutation(
        "CANARY",
        "src/floorvault/platform_support.py",
        '"""Whether POSIX permission bits grant group or other access.',
        '"""Whether POSIX permission bits grant group or other access. (mutated)',
        "Equivalent docstring mutant: must survive (harness validity check)",
        expect="survived",
    ),
    Mutation(
        "PC-9",
        "src/floorvault/providers/platform_custody.py",
        "        item.mkdir(mode=0o700, exist_ok=True)",
        "        item.mkdir(mode=0o777, exist_ok=True)",
        "Ancestor custody directory created world-searchable (0o777)",
    ),
    Mutation(
        "PC-10",
        "src/floorvault/providers/platform_custody.py",
        "    _mkdir_owner_only(path.parent)",
        "    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)",
        "Ancestors revert to Path.mkdir(parents=True) default of 0o777",
    ),
    Mutation(
        "PC-11",
        "src/floorvault/providers/platform_custody.py",
        '    temporary = path.parent / f".{path.name}.{os.urandom(6).hex()}.tmp"',
        '    temporary = Path(os.environ.get("TMPDIR", "/tmp")) / f".{path.name}.{os.urandom(6).hex()}.tmp"',
        "Temp file moved to TMPDIR: cross-device publish (EXDEV) breaks atomicity",
    ),
    Mutation(
        "PC-12",
        "src/floorvault/providers/platform_custody.py",
        '        raise ProtectedStoreInvalidLength("protected store key has an unexpected length")',
        '        raise ProtectedStoreError("protected store key has an unexpected length")',
        "Length failure loses its distinct type and can be masked by another check",
    ),
    Mutation(
        "WD-1",
        "src/floorvault/providers/windows_dpapi.py",
        "        self._assert_store_location_is_private()",
        "        pass  # MUTANT",
        "Windows store-location policy silently disabled (no ACL verification)",
    ),
    Mutation(
        "CR-1",
        "src/floorvault/core.py",
        "encrypt(data_bytes, [aad, nonce])",
        "encrypt(data_bytes, [aad])  # MUTANT",
        "Static AD vector: SIV becomes deterministic and leaks plaintext equality",
    ),
)

# --------------------------------------------------------------------------
# Automatic AST mutation
# --------------------------------------------------------------------------

COMPARE_SWAPS = {
    "==": "!=",
    "!=": "==",
    "<": "<=",
    "<=": "<",
    ">": ">=",
    ">=": ">",
    "is": "is not",
    "is not": "is",
    "in": "not in",
    "not in": "in",
}


@dataclass(frozen=True)
class AutoMutant:
    id: str
    relpath: str
    start: int
    end: int
    replacement: str
    operator: str
    line: int


def _line_offsets(src: str) -> list[int]:
    offsets = [0]
    for line in src.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _node_start(offsets: list[int], node: ast.AST) -> int:
    return offsets[getattr(node, "lineno", 1) - 1] + getattr(node, "col_offset", 0)


def _node_end(offsets: list[int], node: ast.AST) -> int:
    end_lineno = getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)
    end_col = getattr(node, "end_col_offset", None) or 0
    return offsets[end_lineno - 1] + end_col


def _span(offsets: list[int], node: ast.AST) -> tuple[int, int]:
    return _node_start(offsets, node), _node_end(offsets, node)


def generate_mutants(src: str, relpath: str) -> list[AutoMutant]:
    """Yield mutants for one module using standard mutation operators."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    offsets = _line_offsets(src)
    out: list[AutoMutant] = []
    counter = 0

    def add(start: int, end: int, replacement: str, operator: str, line: int) -> None:
        nonlocal counter
        counter += 1
        out.append(
            AutoMutant(
                id=f"{relpath.split('/')[-1]}:{line}:{counter}",
                relpath=relpath,
                start=start,
                end=end,
                replacement=replacement,
                operator=operator,
                line=line,
            )
        )

    for node in ast.walk(tree):
        # `if <cond>:` -> `if not (<cond>):`
        if isinstance(node, ast.If):
            s, e = _span(offsets, node.test)
            add(s, e, f"not ({src[s:e]})", "negate-condition", node.lineno)

        # comparison operator swaps
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left_end = _node_end(offsets, node.left)
            right = node.comparators[0]
            right_start = _node_start(offsets, right)
            between = src[left_end:right_start]
            stripped = between.strip()
            if stripped in COMPARE_SWAPS:
                lead = between[: len(between) - len(between.lstrip())]
                trail = between[len(between.rstrip()) :]
                add(
                    left_end,
                    right_start,
                    lead + COMPARE_SWAPS[stripped] + trail,
                    "compare-swap",
                    node.lineno,
                )

        # and <-> or
        if isinstance(node, ast.BoolOp):
            for a, b in zip(node.values, node.values[1:]):
                a_end = _node_end(offsets, a)
                b_start = _node_start(offsets, b)
                between = src[a_end:b_start]
                stripped = between.strip()
                if stripped in ("and", "or"):
                    new = "or" if stripped == "and" else "and"
                    lead = between[: len(between) - len(between.lstrip())]
                    trail = between[len(between.rstrip()) :]
                    add(a_end, b_start, lead + new + trail, "boolop-swap", node.lineno)

        # True <-> False, and integer off-by-one
        if isinstance(node, ast.Constant):
            s, e = _span(offsets, node)
            if node.value is True:
                add(s, e, "False", "bool-literal-swap", node.lineno)
            elif node.value is False:
                add(s, e, "True", "bool-literal-swap", node.lineno)
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                if node.value % 2 == 0:  # touches sizes/limits/counts
                    add(s, e, str(node.value + 1), "int-offbyone", node.lineno)

        # drop a raise
        if isinstance(node, ast.Raise):
            s, e = _span(offsets, node)
            add(s, e, "pass", "raise-to-pass", node.lineno)

    # de-duplicate identical edits
    seen: set[tuple[int, int, str]] = set()
    unique: list[AutoMutant] = []
    for m in out:
        key = (m.start, m.end, m.replacement)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique


def _source_files(paths: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        target = REPO / raw
        if target.is_file():
            files.append(target)
        else:
            files.extend(sorted(p for p in target.rglob("*.py") if "__pycache__" not in p.parts))
    return files


def _collect_auto_mutants(paths: tuple[str, ...]) -> list[AutoMutant]:
    mutants: list[AutoMutant] = []
    for path in _source_files(paths):
        rel = str(path.relative_to(REPO))
        mutants.extend(generate_mutants(path.read_text(encoding="utf-8"), rel))
    return mutants


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _copy_repo(destination: Path) -> None:
    shutil.copytree(
        REPO,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "dist",
            "build",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            "*.egg-info",
        ),
    )


def _run_tests(workdir: Path, tests: list[str], first_failure_only: bool) -> int:
    argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    if first_failure_only:
        argv.append("-x")
    argv.extend(tests)
    # PYTHONDONTWRITEBYTECODE is load-bearing for correctness, not speed: a .pyc
    # records only the source mtime (whole seconds) and size, so consecutive
    # same-length mutants written within one second can be served from stale
    # bytecode - the mutant then appears to survive because the original code
    # ran. Two full sweeps disagreed by 28 mutants until this was pinned down.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(argv, cwd=workdir, capture_output=True, text=True, env=env).returncode


def _classify(code: int) -> str:
    if code == 0:
        return "survived"
    if code == 1:
        return "killed"
    if code == 5:
        return "no-tests"
    return "error"


def _auto_worker(payload: tuple[list[AutoMutant], list[str]]) -> list[tuple[AutoMutant, str]]:
    mutants, _ = payload
    results: list[tuple[AutoMutant, str]] = []
    with tempfile.TemporaryDirectory(prefix="fv-mut-auto-") as tmp:
        workdir = Path(tmp) / "repo"
        _copy_repo(workdir)
        # Belt and braces alongside PYTHONDONTWRITEBYTECODE: a copy can arrive
        # with __pycache__ from the source tree, and stale bytecode silently
        # makes mutants look survived.
        for cached in workdir.rglob("__pycache__"):
            shutil.rmtree(cached, ignore_errors=True)
        baseline = _run_tests(workdir, ["tests/"], False)
        if baseline != 0:
            return [(m, "baseline-broken") for m in mutants]
        for mutant in mutants:
            target = workdir / mutant.relpath
            original = target.read_text(encoding="utf-8")
            mutated = original[: mutant.start] + mutant.replacement + original[mutant.end :]
            try:
                compile(mutated, mutant.relpath, "exec")
            except SyntaxError:
                results.append((mutant, "invalid"))
                continue
            target.write_text(mutated, encoding="utf-8")
            try:
                code = _run_tests(workdir, ["tests/"], True)
            finally:
                target.write_text(original, encoding="utf-8")
            results.append((mutant, _classify(code)))
    return results


def _run_auto(mutants: list[AutoMutant], jobs: int, report_path: Path | None = None) -> int:
    if not mutants:
        print("no mutants generated")
        return 0
    jobs = max(1, min(jobs, len(mutants)))
    chunks: list[list[AutoMutant]] = [mutants[i::jobs] for i in range(jobs)]
    print(f"running {len(mutants)} mutants across {jobs} worker(s)...\n")
    collected: list[tuple[AutoMutant, str]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
        for result in pool.map(_auto_worker, [(c, []) for c in chunks]):
            collected.extend(result)

    tally: dict[str, int] = {}
    survivors: list[AutoMutant] = []
    for mutant, outcome in collected:
        tally[outcome] = tally.get(outcome, 0) + 1
        if outcome == "survived":
            survivors.append(mutant)

    print(f"{'operator':20} {'count':>6}")
    print("-" * 40)
    by_op: dict[str, int] = {}
    for mutant, _ in collected:
        by_op[mutant.operator] = by_op.get(mutant.operator, 0) + 1
    for op, count in sorted(by_op.items(), key=lambda kv: -kv[1]):
        print(f"{op:20} {count:>6}")

    print("-" * 40)
    for key in ("killed", "survived", "invalid", "no-tests", "error", "baseline-broken"):
        if tally.get(key):
            print(f"{key:20} {tally[key]:>6}")

    scored = tally.get("killed", 0) + tally.get("survived", 0)
    if scored:
        score = 100.0 * tally.get("killed", 0) / scored
        print(f"\nmutation score: {score:.1f}%  ({tally.get('killed', 0)}/{scored})")

    if survivors:
        print(f"\nsurviving mutants (untested or equivalent behaviour): {len(survivors)}")
        for mutant in survivors[:40]:
            print(f"  {mutant.relpath}:{mutant.line}  {mutant.operator}")
        if len(survivors) > 40:
            print(f"  ... and {len(survivors) - 40} more")
    if report_path:
        import json

        report_path.write_text(
            json.dumps(
                {
                    "total": len(mutants),
                    "tally": tally,
                    "score": (100.0 * tally.get("killed", 0) / scored if scored else None),
                    "survivors": [
                        {
                            "id": m.id,
                            "file": m.relpath,
                            "line": m.line,
                            "operator": m.operator,
                            "replacement": m.replacement[:120],
                        }
                        for m in survivors
                    ],
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        print(f"\nreport written to {report_path}")
    return 0


def _run_curated(verbose: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="fv-mut-curated-") as tmp:
        workdir = Path(tmp) / "repo"
        _copy_repo(workdir)
        if _run_tests(workdir, CURATED_TESTS, False) != 0:
            print("[FAIL] the unmutated copy is not green; aborting", file=sys.stderr)
            return 2
        print("[BASELINE] unmutated copy: tests pass\n")
        failures = 0
        print(f"{'id':8} {'result':9} {'expected':9} mutation")
        print("-" * 92)
        for mutation in MUTATIONS:
            target = workdir / mutation.path
            original = target.read_text(encoding="utf-8")
            if mutation.find not in original:
                print(f"{mutation.id:8} {'PATTERN?':9} {'-':9} not found in {mutation.path}")
                failures += 1
                continue
            target.write_text(
                original.replace(mutation.find, mutation.replace, 1), encoding="utf-8"
            )
            try:
                result = _classify(_run_tests(workdir, CURATED_TESTS, False))
            finally:
                target.write_text(original, encoding="utf-8")
            ok = result == mutation.expect
            failures += 0 if ok else 1
            print(
                f"{mutation.id:8} {result:9} {mutation.expect:9} [{'OK ' if ok else 'BAD'}] {mutation.why}"
            )
        print("-" * 92)
        if failures:
            print(f"[FAIL] {failures} mutation(s) did not behave as expected")
            return 1
        killed = sum(1 for m in MUTATIONS if m.expect == "killed")
        print(f"[PASS] {killed} behavioural mutants killed; canary survived")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("curated", "auto"), default="curated")
    parser.add_argument("--paths", nargs="*", default=list(DEFAULT_PATHS))
    parser.add_argument("--list", action="store_true", help="count mutants and exit")
    parser.add_argument("--limit", type=int, default=0, help="cap the number of mutants")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--report", type=Path, default=None, help="write a JSON report")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.mode == "curated":
        return _run_curated(args.verbose)

    mutants = _collect_auto_mutants(tuple(args.paths))
    if args.list:
        per_file: dict[str, int] = {}
        per_op: dict[str, int] = {}
        for mutant in mutants:
            per_file[mutant.relpath] = per_file.get(mutant.relpath, 0) + 1
            per_op[mutant.operator] = per_op.get(mutant.operator, 0) + 1
        for path, count in sorted(per_file.items(), key=lambda kv: -kv[1]):
            print(f"{count:>5}  {path}")
        print()
        for op, count in sorted(per_op.items(), key=lambda kv: -kv[1]):
            print(f"{count:>5}  {op}")
        print(f"\nTOTAL {len(mutants)} mutants")
        return 0

    if args.limit:
        mutants = mutants[: args.limit]
    return _run_auto(mutants, args.jobs, args.report)


if __name__ == "__main__":
    sys.exit(main())

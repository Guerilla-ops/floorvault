#!/usr/bin/env python3
"""Targeted mutation testing for FloorVault's security-critical logic.

Why this exists
---------------
The other checks answer "is the code wrong?". This one answers "would our tests
notice if the code were wrong?". It mutates a security predicate, runs the
focused tests, and requires them to FAIL (the mutant is "killed"). A surviving
mutant means the tests pass for reasons unrelated to the behaviour they claim
to pin - which is exactly how the unreadable-vs-absent key store bug survived a
green suite.

Design choices:
  * Deterministic and dependency-free - no mutation framework, so it runs in CI
    and in a "zero C compilation" project without adding a toolchain.
  * Runs against a throwaway copy of the repository, never the working tree, so
    an interrupted run cannot leave mutated source behind.
  * Includes one deliberately *equivalent* mutant (a docstring-only change) and
    requires it to SURVIVE. If every mutant were reported killed the harness
    would be measuring nothing, so the canary proves it can tell the difference.

Usage:
    python scripts/mutation_check.py [-v]

Exit code 0 iff every behavioural mutant is killed and the canary survives.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Focused tests that pin the permission/custody contract. Kept small so the
# harness stays fast enough to run on every push.
FOCUSED = [
    "tests/test_protected_store_safety.py",
    "tests/test_platform_providers.py",
    "tests/test_adaptive_provider.py",
]


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    find: str
    replace: str
    why: str
    expect: str = "killed"  # or "survived" (canary)


MUTATIONS: tuple[Mutation, ...] = (
    # --- the permission predicate -------------------------------------------
    Mutation(
        "PC-1",
        "src/floorvault/providers/platform_custody.py",
        "    if IS_WINDOWS:\n        return False",
        "    if False:  # MUTANT\n        return False",
        "Windows exemption disabled: a synthesised 0o666 would be treated as insecure",
    ),
    Mutation(
        "PC-2",
        "src/floorvault/providers/platform_custody.py",
        "    return bool(mode & 0o077)",
        "    return False  # MUTANT",
        "POSIX group/other gate disabled entirely",
    ),
    Mutation(
        "PC-3",
        "src/floorvault/providers/platform_custody.py",
        "    return bool(mode & 0o077)",
        "    return mode != 0o600  # MUTANT",
        "Reintroduces the exact-equality bug: any non-0600 owner-only mode is refused",
    ),
    # --- absent vs unreadable ----------------------------------------------
    Mutation(
        "PC-4",
        "src/floorvault/providers/platform_custody.py",
        'raise ProtectedStoreMissing("protected store not present") from exc',
        'raise ProtectedStoreError("protected store not present") from exc',
        "Loses the absent/unreadable distinction",
    ),
    # --- data-loss path: the two providers ----------------------------------
    Mutation(
        "PC-5",
        "src/floorvault/providers/windows_dpapi.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Reintroduces the original bug: a corrupt store is treated as absent, so the key is rotated",
    ),
    Mutation(
        "PC-6",
        "src/floorvault/providers/linux_keyring.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Same regression on the Linux provider",
    ),
    # --- no-clobber guard ---------------------------------------------------
    Mutation(
        "PC-7",
        "src/floorvault/providers/platform_custody.py",
        "    if path.exists():",
        "    if False:  # MUTANT",
        "No-clobber guard removed, so a store can be silently overwritten",
    ),
    # --- adaptive provider --------------------------------------------------
    Mutation(
        "AD-1",
        "src/floorvault/providers/adaptive.py",
        "        if has_posix_group_or_other_access(file_stat.st_mode):",
        "        if False:  # MUTANT",
        "Adaptive provider stops refusing group/other-accessible key files",
    ),
    # --- canary (equivalent mutant; MUST survive) ---------------------------
    Mutation(
        "CANARY",
        "src/floorvault/providers/platform_custody.py",
        '"""Whether POSIX permission bits grant group or other access.',
        '"""Whether POSIX permission bits grant group or other access. (mutated)',
        "Docstring-only change: behaviourally equivalent, so no test can detect it",
        expect="survived",
    ),
)


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


def _run_tests(workdir: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *FOCUSED, "-p", "no:cacheprovider"],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    return proc.returncode, (proc.stdout + proc.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="fv-mutation-") as tmp:
        workdir = Path(tmp) / "repo"
        _copy_repo(workdir)

        # Sanity: the unmutated copy must be green, or every result is meaningless.
        code, output = _run_tests(workdir)
        if code != 0:
            print("[FAIL] the unmutated copy is not green; aborting", file=sys.stderr)
            print(output[-2000:], file=sys.stderr)
            return 2
        print("[BASELINE] unmutated copy: tests pass\n")

        failures = 0
        print(f"{'id':8} {'result':9} {'expected':9} mutation")
        print("-" * 92)
        for mutation in MUTATIONS:
            target = workdir / mutation.path
            original = target.read_text(encoding="utf-8")
            if mutation.find not in original:
                print(
                    f"{mutation.id:8} {'PATTERN?':9} {'-':9} pattern not found in {mutation.path}"
                )
                failures += 1
                continue
            target.write_text(
                original.replace(mutation.find, mutation.replace, 1), encoding="utf-8"
            )
            try:
                code, output = _run_tests(workdir)
            finally:
                target.write_text(original, encoding="utf-8")

            # pytest exit codes: 0 = passed, 1 = failures, 5 = no tests collected.
            if code == 5:
                result = "NO-TESTS"
            elif code == 0:
                result = "survived"
            else:
                result = "killed"

            ok = result == mutation.expect
            failures += 0 if ok else 1
            mark = "OK " if ok else "BAD"
            print(f"{mutation.id:8} {result:9} {mutation.expect:9} [{mark}] {mutation.why}")
            if args.verbose and not ok:
                print(output[-1500:])

        print("-" * 92)
        if failures:
            print(f"[FAIL] {failures} mutation(s) did not behave as expected")
            return 1
        killed = sum(1 for m in MUTATIONS if m.expect == "killed")
        print(
            f"[PASS] {killed} behavioural mutants killed; canary survived (harness discriminates)"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())

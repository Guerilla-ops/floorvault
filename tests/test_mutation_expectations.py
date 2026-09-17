"""The curated mutation gate must be platform-aware, not platform-blind.

CI runs ``scripts/mutation_check.py --mode curated`` on six POSIX legs and two
Windows legs. Two of the curated mutants target checks that are *POSIX-only*: on
Windows the guard being removed is already dead, so no test can kill the mutant
there. Declaring them "killed" unconditionally turned the Windows legs red for
five consecutive pushes while every POSIX leg stayed green - the gate failed for
a reason that had nothing to do with the code under test.

The fix must be a declared, explicit expectation, not a deleted mutant: the
POSIX kill is real and is the whole point of the mutant.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "mutation_check.py"


def _load():
    """Load the gate script as a module without executing its CLI.

    The module must be registered in ``sys.modules`` before execution: its
    dataclasses resolve their own module namespace during class creation, and
    ``dataclasses`` looks it up via ``sys.modules[cls.__module__]``.
    """
    spec = importlib.util.spec_from_file_location("mutation_check", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_posix_only_mutants_keep_their_posix_kill_and_declare_windows():
    """PC-17/PC-18 must still be required to die on POSIX, and to survive on Windows."""
    module = _load()
    by_id = {mutant.id: mutant for mutant in module.MUTATIONS}

    for mutant_id in ("PC-17", "PC-18"):
        mutant = by_id[mutant_id]
        assert mutant.expect == "killed", (
            f"{mutant_id} must still require a kill on POSIX; weakening it to "
            f"'survived' would delete the POSIX regression it was written for"
        )
        assert module.expected_result(mutant, on_windows=True) == "survived", (
            f"{mutant_id} removes a POSIX-only guard, so on Windows it is an "
            f"equivalent mutant and cannot be killed"
        )
        assert module.expected_result(mutant, on_windows=False) == "killed"


def test_platform_overrides_are_declared_explicitly():
    """A platform override is an assertion about the mutant, so it must be stated.

    Every mutant that relaxes its expectation on Windows has to say so in the
    declaration; a silent default would hide an unkillable mutant rather than
    documenting it.
    """
    module = _load()
    relaxed = [mutant.id for mutant in module.MUTATIONS if mutant.expect_on_windows is not None]
    assert relaxed == ["PC-17", "PC-18"], f"unexpected set of platform-relaxed mutants: {relaxed}"
    for mutant in module.MUTATIONS:
        assert mutant.expect_on_windows in (None, "survived"), (
            f"{mutant.id} declares a Windows expectation other than 'survived'"
        )


def test_posix_default_is_unchanged_for_every_other_mutant():
    """On POSIX, every mutant must still resolve to exactly its declared expectation."""
    module = _load()
    for mutant in module.MUTATIONS:
        assert module.expected_result(mutant, on_windows=False) == mutant.expect

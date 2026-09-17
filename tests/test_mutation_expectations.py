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
import subprocess
import sys
from pathlib import Path

import pytest

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
    """PC-18 must still be required to die on POSIX, and to survive on Windows.

    PC-17 used to be in this list. It is not any more: the check it removes is now
    observable on every platform (see the non-regular-type test in
    ``test_protected_store_safety.py``), so the platform relaxation was deleted
    rather than kept. PC-18's ``os.getuid`` guard genuinely does not exist on
    Windows, so it keeps its declared equivalent-mutant expectation.
    """
    module = _load()
    by_id = {mutant.id: mutant for mutant in module.MUTATIONS}

    mutant = by_id["PC-18"]
    assert mutant.expect == "killed", (
        "PC-18 must still require a kill on POSIX; weakening it to 'survived' "
        "would delete the POSIX regression it was written for"
    )
    assert module.expected_result(mutant, on_windows=True) == "survived", (
        "PC-18 removes a POSIX-only guard, so on Windows it is an equivalent "
        "mutant and cannot be killed"
    )
    assert module.expected_result(mutant, on_windows=False) == "killed"

    killer = by_id["PC-17"]
    assert module.expected_result(killer, on_windows=True) == "killed", (
        "PC-17 must be killed on every platform now that its check has a "
        "platform-independent test; a relaxation here would be stale"
    )


def test_ambiguous_anchors_are_detected_as_a_gate_failure(tmp_path):
    """An ambiguous anchor is a gate failure, not a silent mis-mutation.

    PC-17's anchor matched the same two lines twice (once at the store reader's
    main path, once inside its ``except OSError`` branch), so ``replace(..., 1)``
    always mutated the first one. Every test still passed, the POSIX kill count was
    unchanged, and only a Windows CI leg noticed - because the mutated check was not
    the one the mutant described.

    The check lives in the harness (``anchor_status``) rather than in a test that
    reads the files, because during a mutant run those files *are* mutated: a
    test-side version of this guard fails inside every other mutant's run and
    corrupts the kill classification.
    """
    module = _load()

    assert module.anchor_status(1) is None, "a unique anchor is not a failure"
    assert module.anchor_status(0) == "PATTERN?", "a moved anchor must report PATTERN?"
    assert module.anchor_status(2) == "AMBIGUOUS", (
        "an anchor matching more than once must fail the gate explicitly; silently "
        "mutating the first match is how PC-17 mutated a line it did not describe"
    )
    assert module.anchor_status(3) == "AMBIGUOUS"


def test_curated_anchors_are_unique_in_the_pristine_sources():
    """Every curated anchor must match its target exactly once at HEAD.

    The harness checks this at run time (``anchor_status``); this pins the checked-in
    list so an ambiguous anchor is caught in a normal test run, on the **committed**
    revision, instead of on a CI leg hours later. The committed revision matters: the
    harness excludes ``.git`` from its mutant copy and mutates the working tree, so
    reading the working tree here would make this test fail inside other mutants'
    runs (CR-5's mutation deletes CR-5's own anchor) and corrupt the kill counts.
    Where no pristine revision can be read, this check is skipped - never downgraded
    to reading the possibly-mutated file.
    """
    module = _load()
    repo = Path(__file__).resolve().parent.parent
    ambiguous = []
    skipped = []
    for mutant in module.MUTATIONS:
        try:
            text = subprocess.run(
                ["git", "show", f"HEAD:{mutant.path}"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            skipped.append(mutant.id)
            continue
        matches = text.count(mutant.find)
        if matches != 1:
            ambiguous.append(f"{mutant.id}: {matches} match(es) in {mutant.path}")
    if skipped and not ambiguous:
        pytest.skip(f"no committed revision available for: {', '.join(sorted(set(skipped)))}")
    assert not ambiguous, (
        "curated anchors must match their target exactly once, otherwise the harness "
        f"mutates a line it does not describe: {ambiguous}"
    )


def test_platform_overrides_are_declared_explicitly():
    """A platform override is an assertion about the mutant, so it must be stated.

    Every mutant that relaxes its expectation on Windows has to say so in the
    declaration; a silent default would hide an unkillable mutant rather than
    documenting it.
    """
    module = _load()
    relaxed = [mutant.id for mutant in module.MUTATIONS if mutant.expect_on_windows is not None]
    assert relaxed == ["PC-18"], f"unexpected set of platform-relaxed mutants: {relaxed}"
    for mutant in module.MUTATIONS:
        assert mutant.expect_on_windows in (None, "survived"), (
            f"{mutant.id} declares a Windows expectation other than 'survived'"
        )


def test_posix_default_is_unchanged_for_every_other_mutant():
    """On POSIX, every mutant must still resolve to exactly its declared expectation."""
    module = _load()
    for mutant in module.MUTATIONS:
        assert module.expected_result(mutant, on_windows=False) == mutant.expect

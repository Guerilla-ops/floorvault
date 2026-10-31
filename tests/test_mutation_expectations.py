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
    Without Git metadata this check is skipped, never downgraded to reading a
    possibly-mutated file. With a committed revision, a missing target is a failure:
    skipping it would hide stale paths until the mutation harness reaches them.
    """
    module = _load()
    repo = Path(__file__).resolve().parent.parent
    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("no committed revision available")
    ambiguous = []
    for mutant in module.MUTATIONS:
        try:
            text = subprocess.run(
                ["git", "show", f"HEAD:{mutant.path}"],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        except subprocess.CalledProcessError:
            ambiguous.append(f"{mutant.id}: missing committed target {mutant.path}")
            continue
        matches = text.count(mutant.find)
        if matches != 1:
            ambiguous.append(f"{mutant.id}: {matches} match(es) in {mutant.path}")
    assert not ambiguous, (
        "curated anchors must match their target exactly once, otherwise the harness "
        f"mutates a line it does not describe: {ambiguous}"
    )


def test_platform_overrides_are_declared_explicitly():
    """A platform override is an assertion about the mutant, so it must be stated.

    Every mutant that relaxes its expectation on Windows has to say so in the
    declaration; a silent default would hide an unkillable mutant rather than
    documenting it. Mutants of Windows-only guards are listed the same way.
    """
    module = _load()
    relaxed = [mutant.id for mutant in module.MUTATIONS if mutant.expect_on_windows == "survived"]
    # AUD-2 (CLI audit): like BIND-7, only a symlink test can kill it.
    assert relaxed == [
        "DS-5",
        "PC-18",
        "DUR-1",
        "DUR-2",
        "DUR-3",
        "DUR-4",
        "BIND-7",
        "HIM-4",
        "AUD-2",
    ], f"unexpected set of platform-relaxed mutants: {relaxed}"
    # The reverse: a guard that exists only on Windows is dead code elsewhere,
    # so its mutant is equivalent off Windows and must be killed on Windows.
    # AUD-12 / AUD-13 (CLI audit RUN-10 / RUN-11).
    windows_only = [m.id for m in module.MUTATIONS if m.expect_on_windows == "killed"]
    assert windows_only == ["AUD-12", "AUD-13"], (
        f"unexpected set of Windows-only mutants: {windows_only}"
    )
    for mutant in module.MUTATIONS:
        assert mutant.expect_on_windows in (None, "survived", "killed"), (
            f"{mutant.id} declares an unknown Windows expectation"
        )
        if mutant.expect_on_windows == "killed":
            assert mutant.expect == "survived", (
                f"{mutant.id}: a Windows-only kill is declared on a mutant POSIX kills anyway"
            )


def test_posix_default_is_unchanged_for_every_other_mutant():
    """On POSIX, every mutant must still resolve to exactly its declared expectation."""
    module = _load()
    for mutant in module.MUTATIONS:
        assert module.expected_result(mutant, on_windows=False) == mutant.expect


def test_platform_scope_keeps_custody_memory_and_harness_controls():
    module = _load()
    selected = module.curated_mutations("platform")
    ids = {mutation.id for mutation in selected}
    assert {"PC-1", "PC-16", "WD-1", "WD-2", "WACL-1", "AD-2", "AD-6", "DS-4", "CANARY"} <= ids
    assert "CR-1" not in ids
    assert "FA-1" not in ids
    assert 0 < len(selected) < len(module.MUTATIONS)
    assert all(m in selected for m in module.MUTATIONS if m.expect_on_windows is not None)
    assert module.curated_mutations("all") == module.MUTATIONS
    for mutation in selected:
        assert module.expected_result(mutation, on_windows=True) == module.expected_result(
            next(m for m in module.MUTATIONS if m.id == mutation.id), on_windows=True
        )


def test_curated_scope_can_be_listed_without_running_mutations():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--mode", "curated", "--scope", "platform", "--list"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "CANARY" in result.stdout
    assert "WD-1" in result.stdout
    assert "CR-1 " not in result.stdout
    assert "BASELINE" not in result.stdout


def test_shards_partition_the_roster_and_each_carries_the_canary():
    module = _load()
    for scope in ("all", "platform"):
        roster = module.curated_mutations(scope)
        everything = {m.id for m in roster if m.id != "CANARY"}
        for count in (1, 2, 7, 10, 12):
            shards = [module.curated_mutations(scope, (i, count)) for i in range(1, count + 1)]
            seen: list[str] = []
            for shard in shards:
                ids = [m.id for m in shard]
                assert ids.count("CANARY") == 1, (scope, count)
                seen.extend(i for i in ids if i != "CANARY")
                # Roster order is kept inside a shard.
                assert ids == [m.id for m in roster if m.id in set(ids)]
            assert sorted(seen) == sorted(everything), (scope, count)  # every mutant, once
            sizes = [len(s) for s in shards]
            assert max(sizes) - min(sizes) <= 1, (scope, count, sizes)


def test_shard_specs_are_validated():
    module = _load()
    assert module.parse_shard("3/10") == (3, 10)
    for bad in ("", "3", "0/5", "6/5", "a/b", "1/0", "-1/3", "1/2/3"):
        with pytest.raises(ValueError):
            module.parse_shard(bad)
    with pytest.raises(ValueError, match="empty"):
        module.curated_mutations("all", (1, len(module.MUTATIONS) + 5))


def test_a_shard_can_be_listed_without_running_mutations():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--mode", "curated", "--shard", "2/10", "--list"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "CANARY" in result.stdout
    assert "shard 2/10" in result.stdout.splitlines()[-1]
    bad = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--mode", "auto", "--shard", "1/2", "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 2

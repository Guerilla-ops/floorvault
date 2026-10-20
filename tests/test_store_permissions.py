"""Key-store permission verification on every platform.

On POSIX the check is the file mode. On Windows there are no POSIX permission
bits - ``os.stat().st_mode`` is synthesised (``0o666`` for any writable file)
whatever the ACL - so the mode check is deliberately a no-op and, until now,
nothing else looked at the store's protection either. A key store placed in a
mis-ACLed directory was therefore accepted silently, under a "hardened key
handling" claim that could not see the ACL it was relying on.

The policy is separated from the query so the decision is testable everywhere:
``acl_sids_granting_others_access`` is pure, and ``windows_dacl_sids`` is the
Windows-only ctypes glue. Anything the query cannot determine is reported as a
problem, so the store fails closed rather than being trusted by default.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from floorvault import platform_support
from floorvault.platform_support import (
    acl_sids_granting_others_access,
    store_permission_problem,
)

SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"


# ---------------------------------------------------------------------------
# The pure policy
# ---------------------------------------------------------------------------


def test_owner_and_trusted_sids_are_not_offenders():
    assert (
        acl_sids_granting_others_access(
            {"S-1-5-21-1-2-3-1001", SYSTEM, ADMINISTRATORS},
            owner_sid="S-1-5-21-1-2-3-1001",
        )
        == frozenset()
    )


def test_an_unexpected_sid_is_an_offender():
    offenders = acl_sids_granting_others_access(
        {"S-1-5-21-1-2-3-1001", SYSTEM, "S-1-1-0"},  # Everyone
        owner_sid="S-1-5-21-1-2-3-1001",
    )
    assert offenders == frozenset({"S-1-1-0"})


def test_an_unexpected_sid_is_an_offender_when_the_owner_is_unknown():
    assert acl_sids_granting_others_access({"S-1-1-0"}, owner_sid=None) == frozenset({"S-1-1-0"})


def test_no_sids_at_all_is_not_a_problem():
    assert acl_sids_granting_others_access(set(), owner_sid=None) == frozenset()


# ---------------------------------------------------------------------------
# The POSIX branch
#
# These tests assert POSIX file-mode semantics. On Windows the mode is
# synthesised and the gate consults the DACL instead, so the branch under test is
# selected explicitly rather than inherited from the runner: a `skipif` would
# leave the POSIX path uncovered on the Windows legs, and inheriting the runner's
# platform makes the assertion mean something different there (which is exactly
# how two of these tests failed on windows-latest).
# ---------------------------------------------------------------------------


def _posix_branch(monkeypatch):
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    # Fail loudly if the patch ever stops taking effect.
    assert platform_support.has_posix_group_or_other_access(0o644) is True


def test_posix_owner_only_modes_are_accepted(tmp_path, monkeypatch):
    """Owner-only modes are accepted by the POSIX branch.

    The mode is supplied explicitly, never read from a real file. On Windows
    ``os.stat()`` reports a synthesised ``0o666`` whatever the ACL, so a real
    file's mode is not a POSIX mode at all - reading it made an earlier version of
    this test fail on `windows-latest` even with the branch selected correctly.
    """
    _posix_branch(monkeypatch)
    store = tmp_path / "master.key"
    for mode in (0o600, 0o400, 0o700):
        assert store_permission_problem(store, mode) is None, oct(mode)


def test_posix_group_or_other_access_is_reported(tmp_path, monkeypatch):
    _posix_branch(monkeypatch)
    store = tmp_path / "master.key"
    problem = store_permission_problem(store, 0o644)
    assert problem is not None
    assert "group" in problem or "other" in problem


def test_posix_missing_mode_is_reported(monkeypatch):
    _posix_branch(monkeypatch)
    # No mode to inspect is not "fine": the gate must fail closed.
    problem = store_permission_problem(Path("/nonexistent"), None)
    assert problem is not None


# ---------------------------------------------------------------------------
# The Windows branch, driven by a patched query
# ---------------------------------------------------------------------------


def _patch_windows(monkeypatch, sids=None, owner=SYSTEM, error=None):
    """Pretend to be Windows with a synthetic DACL/owner (or a failing query)."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)

    def fake_dacl_sids(path):
        if error is not None:
            raise error
        return (frozenset(sids or ()), owner)

    monkeypatch.setattr(platform_support, "windows_dacl_sids", fake_dacl_sids)


def test_windows_owner_only_acl_is_accepted(monkeypatch):
    _patch_windows(
        monkeypatch, sids={SYSTEM, ADMINISTRATORS, "S-1-5-21-9-9-1001"}, owner="S-1-5-21-9-9-1001"
    )
    assert store_permission_problem(Path("C:/store/master.key"), 0o666) is None


def test_windows_world_readable_acl_is_reported(monkeypatch):
    _patch_windows(monkeypatch, sids={SYSTEM, "S-1-1-0"}, owner=SYSTEM)
    problem = store_permission_problem(Path("C:/store/master.key"), 0o666)
    assert problem is not None
    assert "S-1-1-0" in problem


def test_windows_query_failure_fails_closed(monkeypatch):
    _patch_windows(monkeypatch, error=OSError(5, "access denied"))
    problem = store_permission_problem(Path("C:/store/master.key"), 0o666)
    assert problem is not None
    assert "determin" in problem  # "could not be determined"


def test_windows_path_is_passed_to_the_query(monkeypatch):
    seen: list[Path] = []

    def fake_dacl_sids(path):
        seen.append(Path(path))
        return frozenset({SYSTEM}), SYSTEM

    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(platform_support, "windows_dacl_sids", fake_dacl_sids)
    store_permission_problem(Path("C:/store/master.key"), 0o666)
    assert seen == [Path("C:/store/master.key")]


# ---------------------------------------------------------------------------
# The real Windows query: exercised only on Windows (CI windows-latest legs)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows ACL")
def test_windows_dacl_sids_reads_a_real_file(tmp_path):
    """A file we created inherits a DACL naming at least its owner."""
    store = tmp_path / "master.key"
    store.write_bytes(b"k" * 32)
    sids, owner = platform_support.windows_dacl_sids(store)
    assert owner
    assert sids, "a file always has at least one allowing ACE"


@pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows ACL")
def test_windows_world_accessible_file_is_refused(tmp_path):
    """Granting Everyone access must be detected and refused (needs icacls)."""
    import subprocess

    store = tmp_path / "master.key"
    store.write_bytes(b"k" * 32)
    # The mode is irrelevant on the Windows branch (it is synthesised there); it is
    # passed explicitly so this test depends on nothing but the ACL.
    assert store_permission_problem(store, 0o100666) is None

    subprocess.run(
        ["icacls", str(store), "/grant", "*S-1-1-0:(R)"],
        check=True,
        capture_output=True,
    )
    problem = store_permission_problem(store, 0o100666)
    assert problem is not None
    assert "S-1-1-0" in problem


# ---------------------------------------------------------------------------
# The gate must not regress the POSIX behaviour it replaces
# ---------------------------------------------------------------------------


def test_posix_gate_is_unchanged_for_a_real_store(tmp_path, monkeypatch):
    """The predicate still refuses group/other bits (explicit modes, no real file).

    Real-file chmod integration is covered on POSIX runners by
    `test_owner_only_modes_are_accepted_on_posix` in test_protected_store_safety.py;
    here the mode is stated so the assertion means the same thing on every runner.
    """
    _posix_branch(monkeypatch)
    store = tmp_path / "master.key"
    assert platform_support.has_posix_group_or_other_access(0o600) is False
    assert platform_support.has_posix_group_or_other_access(0o640) is True
    assert store_permission_problem(store, 0o640) is not None


def test_platform_predicates_read_the_flag_at_call_time(monkeypatch):
    """The predicates consult the module flag per call.

    This is what makes the branch selection in these tests meaningful: it is how
    a test drives the other platform's branch on any runner, and it is the
    property the Windows legs of the matrix rely on.
    """
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    assert platform_support.has_posix_group_or_other_access(0o644) is False
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    assert platform_support.has_posix_group_or_other_access(0o644) is True


def test_synthesised_windows_mode_is_not_a_posix_mode(tmp_path, monkeypatch):
    """Pin the exact input that failed the windows-latest legs.

    On Windows ``os.stat()`` reports ``0o100666`` (33206) for any writable file,
    so a reader that treats that value as a POSIX mode sees group/other access on
    every file. The platform dispatch is what prevents that; this test records the
    consequence, and is why the tests above state modes explicitly rather than
    reading them - an earlier version of this file read ``stat().st_mode`` and
    failed on Windows with these two assertions while the library was correct.
    """
    _posix_branch(monkeypatch)
    problem = store_permission_problem(tmp_path / "master.key", 0o100666)
    assert problem is not None
    assert "group" in problem or "other" in problem

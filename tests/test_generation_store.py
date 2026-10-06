"""Generation-store contract tests (roadmap R1).

The store exists because ``write_protected``'s create-never-replace rule is
right for a master key and wrong for a *wrapped* master key, which must be
rewritten when the KEK rotates. These tests pin the replacement protocol:
immutable generations, an authoritative pointer, a single-writer lock, and
expected-generation CAS.
"""

from __future__ import annotations

import os

import pytest

from floorvault.providers.generation_store import (
    GENERATION_HEADER,
    MAX_PAYLOAD_BYTES,
    GenerationMismatchError,
    GenerationStore,
    StoreLockError,
)
from floorvault.providers.platform_custody import (
    ProtectedStoreError,
    ProtectedStoreInvalidLength,
    ProtectedStoreMissing,
    ProtectedStoreRaceError,
    write_protected,
)

PAYLOAD_A = b"vault:v1:wrapped-blob-A"
PAYLOAD_B = b"vault:v1:wrapped-blob-B"
PAYLOAD_C = b"vault:v1:wrapped-blob-C"


def test_uninitialized_store_reports_missing(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    with pytest.raises(ProtectedStoreMissing):
        store.read_active()
    assert store.active_generation() is None


def test_provision_publishes_generation_one(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    assert store.provision(PAYLOAD_A) == 1
    assert store.read_active() == (1, PAYLOAD_A)
    assert store.active_generation() == 1


def test_provision_refuses_a_second_provision(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    with pytest.raises(ProtectedStoreError):
        store.provision(PAYLOAD_B)
    assert store.read_active() == (1, PAYLOAD_A)


def test_update_advances_with_expected_generation(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    assert store.update(PAYLOAD_B, expected_generation=1) == 2
    assert store.update(PAYLOAD_C, expected_generation=2) == 3
    assert store.read_active() == (3, PAYLOAD_C)
    # Earlier generations stay immutable and still readable on disk.
    assert (tmp_path / "gens" / "g-00000001.gen").exists()
    assert (tmp_path / "gens" / "g-00000002.gen").exists()


def test_update_rejects_a_stale_expectation(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    with pytest.raises(GenerationMismatchError):
        store.update(PAYLOAD_B, expected_generation=7)
    # The pointer must not move on a refused CAS.
    assert store.read_active() == (1, PAYLOAD_A)


def test_update_fails_closed_when_uninitialized(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    with pytest.raises(ProtectedStoreMissing):
        store.update(PAYLOAD_A, expected_generation=1)


def test_update_rejects_nonpositive_expected_generation(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    with pytest.raises(ValueError):
        store.update(PAYLOAD_B, expected_generation=0)


def test_update_rejects_empty_payload(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    with pytest.raises(ProtectedStoreInvalidLength):
        store.update(b"", expected_generation=1)


def test_held_lock_excludes_a_second_writer(tmp_path):
    first = GenerationStore(tmp_path / "gens")
    second = GenerationStore(tmp_path / "gens")
    with first.writer_lock():
        with pytest.raises(StoreLockError):
            second.provision(PAYLOAD_A)
        # Readers never take the lock; a held lock must not stall reads of a
        # provisioned store either.
    first.provision(PAYLOAD_A)
    with first.writer_lock():
        assert second.read_active() == (1, PAYLOAD_A)


def test_lock_releases_after_exception(tmp_path):
    store = GenerationStore(tmp_path / "gens")
    with pytest.raises(RuntimeError), store.writer_lock():
        raise RuntimeError("writer died")
    with store.writer_lock():  # a released lock is acquirable again
        pass


def test_crashed_provision_with_same_payload_is_adopted(tmp_path):
    """Gen file written but pointer never published: same-content retry heals."""
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    write_protected(
        PAYLOAD_A,
        directory / "g-00000001.gen",
        header=GENERATION_HEADER,
        expected_length=None,
    )
    assert store.provision(PAYLOAD_A) == 1
    assert store.read_active() == (1, PAYLOAD_A)


def test_crashed_provision_with_different_payload_fails_closed(tmp_path):
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    write_protected(
        PAYLOAD_B,
        directory / "g-00000001.gen",
        header=GENERATION_HEADER,
        expected_length=None,
    )
    with pytest.raises(ProtectedStoreError):
        store.provision(PAYLOAD_A)


def test_crashed_update_with_same_payload_is_adopted(tmp_path):
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    write_protected(
        PAYLOAD_B,
        directory / "g-00000002.gen",
        header=GENERATION_HEADER,
        expected_length=None,
    )
    assert store.update(PAYLOAD_B, expected_generation=1) == 2
    assert store.read_active() == (2, PAYLOAD_B)


def test_crashed_update_with_different_payload_fails_closed(tmp_path):
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    write_protected(
        PAYLOAD_C,
        directory / "g-00000002.gen",
        header=GENERATION_HEADER,
        expected_length=None,
    )
    with pytest.raises(ProtectedStoreError):
        store.update(PAYLOAD_B, expected_generation=1)
    assert store.read_active() == (1, PAYLOAD_A)


def test_pointer_and_payload_hash_are_bound(tmp_path):
    """A swapped generation file fails the pointer's content hash."""
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    store.update(PAYLOAD_B, expected_generation=1)

    gen2 = directory / "g-00000002.gen"
    gen2.write_bytes(GENERATION_HEADER + PAYLOAD_C)
    with pytest.raises(ProtectedStoreError):
        store.read_active()


def test_pointer_to_missing_generation_is_corruption_not_absence(tmp_path):
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    (directory / "g-00000001.gen").unlink()
    with pytest.raises(ProtectedStoreError) as excinfo:
        store.read_active()
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_corrupt_pointer_is_not_mistaken_for_absent(tmp_path):
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    pointer = directory / "active"
    pointer.write_bytes(b"garbage")
    with pytest.raises(ProtectedStoreError) as excinfo:
        store.read_active()
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_stale_lock_file_fails_closed(tmp_path):
    """A lockfile left by a dead writer denies new writers, never steals."""
    directory = tmp_path / "gens"
    store = GenerationStore(directory)
    store.provision(PAYLOAD_A)
    lock = directory / ".active.lock"
    lock.touch()
    with pytest.raises(StoreLockError):
        store.update(PAYLOAD_B, expected_generation=1)


def test_payload_at_the_reader_boundary_round_trips(tmp_path):
    """MAX_PAYLOAD_BYTES is derived from read_protected's cap - the exact
    ceiling must publish and read back."""
    store = GenerationStore(tmp_path / "gens")
    payload = b"x" * MAX_PAYLOAD_BYTES
    assert store.provision(payload) == 1
    assert store.read_active() == (1, payload)
    assert store.update(b"y" * MAX_PAYLOAD_BYTES, expected_generation=1) == 2
    assert store.read_active()[0] == 2


def test_payload_one_byte_over_the_reader_boundary_is_rejected(tmp_path):
    """One byte over publishes state read_protected can never return."""
    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    oversized = b"x" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(ProtectedStoreInvalidLength):
        store.update(oversized, expected_generation=1)
    fresh = GenerationStore(tmp_path / "gens2")
    with pytest.raises(ProtectedStoreInvalidLength):
        fresh.provision(oversized)
    # Nothing was published: the store is still at generation 1.
    assert store.read_active() == (1, PAYLOAD_A)
    assert fresh.active_generation() is None


def test_pointer_identity_race_is_retried(tmp_path, monkeypatch):
    """An atomic pointer replace straddling the read is a race, not corruption."""
    import floorvault.providers.generation_store as gs_mod

    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    real_read = gs_mod.read_protected
    calls = 0

    def flaky(path, **kwargs):
        nonlocal calls
        if os.path.basename(str(path)) == "active":
            calls += 1
            if calls <= 2:
                raise ProtectedStoreRaceError("simulated atomic pointer swap")
        return real_read(path, **kwargs)

    monkeypatch.setattr(gs_mod, "read_protected", flaky)
    assert store.read_active() == (1, PAYLOAD_A)
    assert calls == 3


def test_a_pointer_that_never_settles_still_fails_closed(tmp_path, monkeypatch):
    """Unbounded churn must not mean unbounded retries."""
    import floorvault.providers.generation_store as gs_mod

    store = GenerationStore(tmp_path / "gens")
    store.provision(PAYLOAD_A)
    real_read = gs_mod.read_protected
    calls = 0

    def always_racing(path, **kwargs):
        nonlocal calls
        if os.path.basename(str(path)) == "active":
            calls += 1
            raise ProtectedStoreRaceError("churning pointer")
        return real_read(path, **kwargs)

    monkeypatch.setattr(gs_mod, "read_protected", always_racing)
    with pytest.raises(ProtectedStoreRaceError):
        store.read_active()
    assert calls == gs_mod._POINTER_READ_RETRIES + 1


def test_lock_metadata_write_failure_leaves_no_stranded_lock(tmp_path, monkeypatch):
    """A failed lockfile write must close the fd and unlink the lockfile -
    a stranded lock blocks every writer until an operator intervenes."""
    import floorvault.providers.generation_store as gs_mod

    store = GenerationStore(tmp_path / "gens")

    def out_of_space(descriptor, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(gs_mod, "_write_all", out_of_space)
    with pytest.raises(OSError):
        with store.writer_lock():
            pass
    assert not store._lock_path.exists()
    monkeypatch.undo()
    # A healthy writer takes the lock immediately - nothing stranded.
    with store.writer_lock():
        pass

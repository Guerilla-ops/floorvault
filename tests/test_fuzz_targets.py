"""Replay the coverage-guided fuzz targets in the ordinary suite.

ClusterFuzzLite runs ``fuzz/fuzz_*.py`` under Atheris on Linux only. Their
properties are just as meaningful on macOS and Windows - the protected-store
reader in particular has platform-specific branches - so each target's entry
point is replayed here over its seeds plus deterministic mutations of them, on
every leg of the CI matrix, without needing Atheris.

The structural tests keep the ClusterFuzzLite integration honest: a target that
``build.sh`` does not compile, or that ships without seeds, is never fuzzed.
"""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
FUZZ_DIR = ROOT / "fuzz"
TARGETS = sorted(FUZZ_DIR.glob("fuzz_*.py"))
MUTATIONS_PER_SEED = 300
RANDOM_INPUTS = 500


def _load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"floorvault_fuzz_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    data = bytearray(seed)
    for _ in range(rng.randint(1, 4)):
        choice = rng.randrange(4)
        if choice == 0 and data:
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif choice == 1 and data:
            del data[rng.randrange(len(data)) :]
        elif choice == 2:
            data[rng.randrange(len(data) + 1) : 0] = rng.randbytes(rng.randint(1, 8))
        elif data:
            data[rng.randrange(len(data))] = rng.choice((0x00, 0x01, 0x10, 0x7F, 0x80, 0xFF))
    return bytes(data)


def test_the_fuzz_targets_exist():
    names = {path.stem for path in TARGETS}
    assert {
        "fuzz_envelope",
        "fuzz_associated_data",
        "fuzz_protected_store",
        "fuzz_identifiers",
        "fuzz_beacons",
    } <= names


@pytest.mark.parametrize("path", TARGETS, ids=lambda path: path.stem)
def test_target_exposes_the_atheris_contract(path: Path):
    module = _load(path)
    assert callable(module.TestOneInput)
    assert callable(module.main), "the target cannot be run under Atheris"
    assert module.seed_inputs(), "a target without seeds starts every fuzz run cold"
    source = path.read_text(encoding="utf-8")
    assert "\n    assert " not in source, "fuzz properties must not use assert (stripped by -O)"


@pytest.mark.parametrize("path", TARGETS, ids=lambda path: path.stem)
def test_target_properties_hold_over_seeds_and_mutations(path: Path):
    module = _load(path)
    rng = random.Random(f"floorvault-fuzz-replay:{path.stem}")
    inputs = list(module.seed_inputs())
    inputs += [
        _mutate(rng, seed) for seed in module.seed_inputs() for _ in range(MUTATIONS_PER_SEED)
    ]
    inputs += [rng.randbytes(rng.randint(0, 96)) for _ in range(RANDOM_INPUTS)]
    for data in inputs:
        try:
            module.TestOneInput(data)
        except Exception as exc:
            raise AssertionError(f"{path.stem} failed on input {data!r}: {exc!r}") from exc


def test_the_envelope_target_detects_a_forgery(monkeypatch):
    """The forgery check must be able to fire, or it is decoration."""
    module = _load(FUZZ_DIR / "fuzz_envelope.py")
    genuine = next(iter(module._GENUINE))
    monkeypatch.setattr(module, "_GENUINE", {})
    with pytest.raises(AssertionError, match="forged envelope"):
        module.TestOneInput(genuine)


def test_clusterfuzzlite_compiles_every_target_and_ships_its_seeds():
    build = (ROOT / ".clusterfuzzlite" / "build.sh").read_text(encoding="utf-8")
    assert "fuzz/fuzz_*.py" in build, "build.sh does not compile every fuzz target"
    assert "compile_python_fuzzer" in build
    assert "write_seed_corpus.py" in build and "_seed_corpus.zip" in build
    assert "set -eu" in build or "-eu" in build.splitlines()[0], "build.sh is not fail-fast"
    project = (ROOT / ".clusterfuzzlite" / "project.yaml").read_text(encoding="utf-8")
    assert "language: python" in project


def test_the_fuzzing_base_image_is_pinned_by_digest():
    dockerfile = (ROOT / ".clusterfuzzlite" / "Dockerfile").read_text(encoding="utf-8")
    base = next(line for line in dockerfile.splitlines() if line.startswith("FROM "))
    assert "gcr.io/oss-fuzz-base/base-builder-python@sha256:" in base, (
        "the fuzzing toolchain image must be pinned by digest, not by a moving tag"
    )

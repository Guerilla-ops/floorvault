#!/bin/bash -eu
# Build every Atheris fuzz target in fuzz/ for ClusterFuzzLite.
#
# Installs FloorVault from this checkout (not from PyPI), so the fuzzers exercise
# the code under review, then packages each target with the seed corpus it
# declares in seed_inputs(). A target added to fuzz/ is picked up automatically;
# tests/test_fuzz_targets.py pins that this glob covers them all.

pip3 install --no-cache-dir "$SRC/floorvault"

for fuzzer in "$SRC"/floorvault/fuzz/fuzz_*.py; do
  name="$(basename -s .py "$fuzzer")"
  compile_python_fuzzer "$fuzzer"
  python3 "$SRC/floorvault/fuzz/write_seed_corpus.py" "$fuzzer" "$OUT/${name}_seed_corpus.zip"
done

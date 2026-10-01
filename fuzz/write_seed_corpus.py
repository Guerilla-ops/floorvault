"""Write a fuzz target's ``seed_inputs()`` to a libFuzzer seed-corpus zip.

Used by ``.clusterfuzzlite/build.sh``: ClusterFuzzLite picks up
``$OUT/<target>_seed_corpus.zip`` automatically.

    python fuzz/write_seed_corpus.py fuzz/fuzz_envelope.py $OUT/fuzz_envelope_seed_corpus.zip
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import zipfile
from pathlib import Path


def main(target: str, destination: str) -> int:
    spec = importlib.util.spec_from_file_location(Path(target).stem, target)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import fuzz target {target}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    seeds = module.seed_inputs()
    if not seeds:
        raise SystemExit(f"{target} declares no seed inputs")
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for seed in seeds:
            archive.writestr(hashlib.sha256(seed).hexdigest(), seed)
    print(f"wrote {len(seeds)} seeds to {destination}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))

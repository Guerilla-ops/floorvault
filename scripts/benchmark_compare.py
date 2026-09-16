#!/usr/bin/env python3
"""Comparative micro-benchmark: floorvault vs. Fernet vs. plain SQLite.

Backs the latency claims in the docs with measured numbers on the CURRENT host.
Measures median per-op latency (not marketing estimates):

  * plain SQLite     — baseline (no encryption)
  * Fernet           — the typical ad-hoc whole-field approach
  * floorvault       — AES-256-SIV contextual AEAD

Run:  uv run python scripts/benchmark_compare.py  [--iterations N] [--json out.json]

The script uses only what is installed; SQLCipher (custom C build) is not
required to run — we benchmark the layers that floorvault actually replaces
(Fernet + naive field encryption) plus plain SQLite as the ceiling.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.fernet import Fernet

from floorvault import FloorVault, HardenedMemoryKey

PAYLOAD = "model tool result: " + "x" * 1000  # ~1 KB message, realistic agent workload


def _median_ms(fn, iterations: int) -> float:
    fn()  # warm
    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return statistics.median(samples)


def run(iterations: int = 2000) -> dict[str, float]:
    results: dict[str, float] = {}

    # --- plain SQLite write/read (no crypto) -------------------------------
    import sqlite3
    import tempfile

    # A TemporaryDirectory, never tempfile.mktemp(): mktemp hands back a *name*,
    # and the gap before the caller creates the file is a race another process
    # can win - which is why it is deprecated (CodeQL py/insecure-temporary-file
    # flagged this line). This form also cleans up after itself; the old one left
    # a stray .bench.db in the temp directory on every run.
    with tempfile.TemporaryDirectory(prefix="fv-bench-") as tmpdir:
        conn = sqlite3.connect(Path(tmpdir) / "bench.db")
        conn.execute("CREATE TABLE t (id TEXT PRIMARY KEY, blob BLOB)")
        conn.commit()

        def sqlite_write():
            conn.execute("INSERT OR REPLACE INTO t VALUES (?, ?)", ("r", PAYLOAD.encode()))

        def sqlite_read():
            conn.execute("SELECT blob FROM t WHERE id=?", ("r",)).fetchone()

        results["sqlite_write"] = _median_ms(sqlite_write, iterations)
        results["sqlite_read"] = _median_ms(sqlite_read, iterations)
        conn.close()

    # --- Fernet (whole-field, no AAD binding) ------------------------------
    fernet_key = Fernet.generate_key()
    f = Fernet(fernet_key)
    f_ct = f.encrypt(PAYLOAD.encode())
    results["fernet_encrypt"] = _median_ms(lambda: f.encrypt(PAYLOAD.encode()), iterations)
    results["fernet_decrypt"] = _median_ms(lambda: f.decrypt(f_ct), iterations)

    # --- floorvault AES-256-SIV contextual AEAD ----------------------------
    fv = FloorVault(HardenedMemoryKey(bytes.fromhex("ab" * 32)))
    fv_ct = fv.encrypt(PAYLOAD, table="messages", record_id="run-1", column="content")
    results["floorvault_encrypt"] = _median_ms(
        lambda: fv.encrypt(PAYLOAD, table="messages", record_id="run-1", column="content"),
        iterations,
    )
    results["floorvault_decrypt"] = _median_ms(
        lambda: fv.decrypt(fv_ct, table="messages", record_id="run-1", column="content"),
        iterations,
    )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="floorvault comparative micro-benchmark")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    results = run(iterations=args.iterations)
    header = f"median per op (ms), {args.iterations} iterations, payload ~{len(PAYLOAD)} bytes"
    print(header)
    print("-" * len(header))
    for name, ms in results.items():
        print(f"{name:24} {ms:8.5f}")

    rel = {
        "floorvault_encrypt_over_sqlite_write": results["floorvault_encrypt"]
        / results["sqlite_write"],
        "floorvault_vs_fernet_encrypt": results["floorvault_encrypt"] / results["fernet_encrypt"],
        "floorvault_vs_fernet_decrypt": results["floorvault_decrypt"] / results["fernet_decrypt"],
    }
    print("\nratios (lower is better where compared):")
    for k, v in rel.items():
        print(f"{k:38} {v:8.2f}x")

    if args.json:
        payload = {"iterations": args.iterations, "bytes": len(PAYLOAD), **results, **rel}
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

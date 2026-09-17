# Comparative Micro-Benchmark: FloorVault vs. Fernet vs. plain SQLite

**Date:** 2026-09-17
**Commit:** `aa1b2d80b40055a27caa961f2af6f9fabb2d3229`
**Harness:** `scripts/benchmark_compare.py`
**Runs:** 5 independent runs, 10,000 iterations per operation
**Payload:** 1,019-byte UTF-8 message (`model tool result: ` plus 1,000 `x` characters)
**Host:** macOS 27.0 arm64, Python 3.13.15, PyCA/OpenSSL, cryptography 50.0.1

These are measured numbers, not universal performance claims.

## Method

The harness measures median per-operation latency with `time.perf_counter_ns()` for:

- plain SQLite write/read without encryption;
- Fernet whole-field encryption/decryption;
- FloorVault contextual AES-256-SIV encryption/decryption.

The FloorVault timing includes contextual AAD construction and envelope handling. The Fernet
timing includes token encoding/decoding. The cryptographic comparison does not include database
I/O. A fresh key and engine are created for each benchmark process.

## Median per-operation latency

Values are milliseconds. The aggregate is the median of the five per-run medians; min/max show
the observed spread across runs.

| Operation | Median | Min | Max |
|---|---:|---:|---:|
| Plain SQLite write | 0.00067 | 0.00067 | 0.00067 |
| Plain SQLite read | 0.00067 | 0.00063 | 0.00067 |
| Fernet encrypt | 0.00700 | 0.00692 | 0.00704 |
| Fernet decrypt | 0.00629 | 0.00617 | 0.00637 |
| **FloorVault encrypt** | **0.00583** | **0.00579** | **0.00588** |
| **FloorVault decrypt** | **0.00517** | **0.00513** | **0.00521** |

## Ratios

| Comparison | Median ratio |
|---|---:|
| FloorVault encrypt ÷ plain SQLite write | 8.70x |
| FloorVault encrypt ÷ Fernet encrypt | **0.83329x** |
| FloorVault decrypt ÷ Fernet decrypt | **0.82117x** |

For this host, payload and backend, FloorVault's median encryption latency was approximately
16.7% lower than Fernet's, and median decryption latency was approximately 17.9% lower.
The observed between-run ratios were `0.82832x–0.84328x` for encryption and
`0.81035x–0.83117x` for decryption.

## Ciphertext size

A separate direct measurement with the same payload produced:

| Format | Size |
|---|---:|
| Fernet token | 1,444 bytes |
| FloorVault v2 envelope | 1,058 bytes |

FloorVault was 386 bytes smaller in this measurement. This is not a pure cryptographic-overhead
comparison because Fernet emits URL-safe base64 and FloorVault emits a binary envelope.

## Interpretation and limits

The plain SQLite figures are only a no-encryption baseline; they provide neither confidentiality
nor integrity. This benchmark is not an apples-to-apples security comparison:

- Fernet provides authenticated encryption for a token but does not bind it to database table,
  record, column, schema or application-instance coordinates in this benchmark.
- FloorVault binds those coordinates as associated authenticated data and rejects ciphertext
  relocation to another context.
- FloorVault's nonce tracking is a bounded process-lifetime deduplication window. It is not a
  cross-restart freshness mechanism; trusted caller-supplied revisions are required for that
  documented use case.
- Neither result establishes concurrent throughput, storage-sync cost, cross-platform behavior,
  or universal performance superiority.
- SQLCipher is not benchmarked because it requires a separate native build and is outside this
  harness's measured comparison.

## Reproduction

```bash
uv run python scripts/benchmark_compare.py --iterations 10000 --json /tmp/floorvault-fernet.json
```

Raw five-run JSON and text outputs are retained in the audit evidence directory for this run.

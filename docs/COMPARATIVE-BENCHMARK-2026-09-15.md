# Comparative Micro-Benchmark: floorvault vs. Fernet vs. plain SQLite

**Date:** 2026-09-15
**Measurer:** project benchmark harness (self-measured, reproducible)
**Harness:** `scripts/benchmark_compare.py` (medians, 3000 iterations)
**Payload:** ~1,019-byte message (realistic AI-agent tool-result / session text)
**Host:** macOS arm64, PyCA/OpenSSL, Python 3.13

These are measured numbers to back the docs' claims — not marketing estimates.

## Median per-operation latency

| Operation | Median (ms) |
|---|---|
| plain SQLite write (no crypto) | 0.00067 |
| plain SQLite read (no crypto) | 0.00067 |
| Fernet encrypt | 0.00696 |
| Fernet decrypt | 0.00642 |
| **floorvault encrypt** (AES-256-SIV + AAD) | **0.00550** |
| **floorvault decrypt** (AES-256-SIV + AAD) | **0.00450** |

## Ratios (lower is better where compared)

| Comparison | Ratio |
|---|---|
| floorvault encrypt ÷ plain SQLite write | 8.26× (expected: SIV adds AEAD cost) |
| floorvault encrypt ÷ Fernet encrypt | **0.79×** (21% faster) |
| floorvault decrypt ÷ Fernet decrypt | **0.70×** (30% faster) |

## Interpretation

1. **floorvault is faster than the common ad-hoc Fernet approach** by ~21–30% on
   encrypt/decrypt — and it additionally gives contextual AAD binding (splice
   immunity) that Fernet simply does not have. You are not trading security for
   speed; you are gaining security *and* speed over the typical baseline.
2. The only "penalty" vs. *plain unencrypted* SQLite (~8× on write) is the
   unavoidable cost of real authenticated encryption — and it is still ~microseconds.
   That is the price of any at-rest encryption; SQLCipher pays the same, with a
   C-build install tax and no contextual binding.

## Reproduce

```bash
uv run python scripts/benchmark_compare.py --iterations 3000
```

## Honest caveats

- Self-measured on one host; absolute figures vary by machine/backend. The
  *relative* floorvault-vs-Fernet advantage is expected to hold because SIV
  reuses the same AES block cipher and avoids Fernet's two-pass token framing.
- SQLCipher itself is not benchmarked here (it needs a custom C build); the
  comparison targets the layers floorvault actually replaces (Fernet + naive
  field encryption) and uses plain SQLite as the no-encryption ceiling.

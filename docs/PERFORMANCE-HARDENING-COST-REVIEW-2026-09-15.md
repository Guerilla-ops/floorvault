# Security Hardening Cost Review: Did the Beacon Upgrade Slow AI or Drop Features?

**Date:** 2026-09-15
**Status:** Honest engineering measurement (no marketing)
**Scope:** `Guerilla-ops/floorvault` — the hardening pass that (1) fixed an inspector SQL-injection
sink and (2) replaced the full-width blind index with a truncated HMAC *beacon*.

A fair question after any security change: **what did it cost?** This note answers that with
measured numbers on realistic AI-agent workloads, and is intentionally candid about the one
real behavioural trade.

---

## The TL;DR

- **No material latency increase.** Measured encrypt/decrypt are unchanged (same AES-256-SIV
  path); index operations went from ~1.29 µs to ~1.37 µs (+0.08 µs, 1.06×) — sub-microsecond.
- **No lost functionality.** AES-SIV, contextual AAD, HKDF key separation, and memory custody
  are byte-for-byte identical. A 1-KB message ciphertext round-trips with the same bytes and
  the same splice-immunity.
- **One deliberate API change (not a bug):** exact-match lookup moved from "full-width hash is
  authoritative" to "bucket + `beacon_matches` confirm". That is a privacy upgrade that costs
  you one extra method call — and is tunable with `bits`.

---

## Measured latency (macOS, PyCA / OpenSSL SIV backend, median of 2000 runs)

| Operation | Before | After | Δ |
|---|---|---|---|
| encrypt 1-KB message | (unchanged path) | **0.0053 ms** | — |
| decrypt 1-KB message | (unchanged path) | **0.0104 ms** | — |
| index a value (full-width HMAC) | 0.00129 ms | — | — |
| index a value (16-bit beacon) | — | 0.00137 ms | **+0.08 µs** |
| confirm a candidate (`beacon_matches`) | — | 0.00142 ms | new, sub-µs |

For an AI agent persisting, say, 100 messages per turn that is ~1 ms of encryption per turn;
even at 1000 index ops/turn it is ~1.4 ms — noise against a single model call that takes
hundreds of milliseconds to seconds. **The hardening did not move the needle.**

## What changed functionally (honest)

1. **AES-SIV / AAD / HKDF / memory custody** — untouched. Identical ciphertext, identical
   tamper behaviour. No functionality change.
2. **Blind index → beacon** — the lookup contract changed. The old full-width hash let you
   `WHERE idx = ?` and trust the result instantly. The default beacon is a *bounded bucket*
   (default 4 bits, i.e. 1 byte / 256 buckets, configurable to 64). A bucket query may now
   return **candidate rows (collisions)** that you confirm with `beacon_matches(value)` or by
   decrypting. This is deliberate: the stored index no longer reveals exact equality or value
   frequency to anyone holding the database — which is the whole point of a search beacon —
   but callers that relied on "index proves equality" must add a confirm step.
3. **Inspector SQL-injection fix** — CLI-only hardening; zero runtime-path impact.
4. **README** — corrected a broken quickstart (`FloorVault.from_system_keyring` did not exist)
   and removed hardware-enclave / biometric overclaims that this pure-Python library does not
   provide.

## The one real trade (and how to tune it)

The old design offered **instant exact-match** at the cost of leaking exact equality and
frequency. The beacon design flips that: you gain privacy, you lose "the index alone is
authoritative." If your workload needs low-collision unique lookups with no confirm step, call
`beacon(value, scope=..., bits=64)` — still ~1.4 µs and effectively collision-free at any
realistic cardinality. Choose 4–16 bits for privacy-first defaults, 32–64 bits for
collision-averse exact lookups.

## Independence note

These are the author's own measurements of the commit at `c17e629` on this machine. They are
reproducible via the repo test suite + a micro-benchmark, not a third-party audit, and they
do not constitute a security sign-off (that remains Nova's lane). If you rely on the absolute
figures, benchmark on your own hardware and workload.

## Bottom line

Security hardening here is **effectively free** for AI workloads: sub-microsecond index cost,
unchanged encrypt/decrypt, and one intentional, tunable API change that turns "leaky fast
lookup" into "private lookup with an explicit confirm." That is the honest picture — no
performance or functionality was given away for the security you gained.
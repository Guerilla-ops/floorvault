# FloorVault Architecture Review

**Date:** 2026-10-02
**Reviewer:** Independent (external review, full source read)
**Revision reviewed:** `fd7441e` (`origin/main`) plus the then-pending heads of
`fix/protected-store-dir-fsync` (custody fsync fixes) and `ci/tooling-hardening`
(vendored Semgrep ruleset). Suite at review time: 427 passed, 4 skipped on
macOS; `ruff check` clean.
**Relation to prior work:** builds on `docs/DEEP-DIVE-REVIEW-2026-10-01.md`
(independent review) and `docs/FLOORVAULT-ARCHITECTURE-CRYPTO-REPORT-2026-09-16.md` (now
superseded). This review covers architecture and peer comparison, not a new
bug hunt.

---

## 1. What this is

`floorvault` 0.1.0 is a pure-Python field-level encryption layer for SQLite:
AES-256-SIV records cryptographically bound to their
`(table, record_id, column, schema, app instance)` coordinates, a three-tier
platform key-custody system, resumable key rotation, authenticated key
recovery, legacy-Fernet migration, and opt-in truncated-HMAC search beacons.
Single runtime dependency (`cryptography` >= 50). Universal wheel, no native
builds. ~4,900 lines of source across 20 modules.

## 2. Architecture by layer

**Crypto core (`core.py`).** `HKDF-SHA256(master_key, info="floorvault-v1-aes-siv")`
expands a 32-byte master key into the 64-byte AES-256-SIV key. Encryption passes
`[canonical-JSON AAD, v2 header, nonce]` as *separate* associated-data elements —
the element boundaries are load-bearing, so a rewritten `crypto_version` or
`key_id` fails authentication instead of being ignored. Envelope:
`FLV2 | ver(1) | key_id(1) | nonce_len(1) | nonce(16) | ct` — 39 bytes of fixed
overhead including the 16-byte SIV tag. v1 `FLRV` records remain readable via
the original two-element AD vector. Nonces are random 128-bit values deduplicated
in a bounded in-process window (documented as process-lifetime only).

**Memory custody (`memory.py`).** `HardenedMemoryKey` — page-aligned `mmap`
buffer, `mlock`/`VirtualLock`, Linux `MADV_DONTDUMP`/`MADV_DONTFORK`,
deterministic `memset` wipe, and process-wide `RLIMIT_CORE=0` (a documented,
deliberate side effect). Honesty modes `disabled/opportunistic/required` report
rather than promise.

**Key custody (`providers/`).** Tier chain: env vars → OS-native (macOS Keychain
via pyobjc, Windows DPAPI via ctypes, Linux Secret Service via `secretstorage`)
→ opt-in 0600 file. Fail-closed throughout: a present-but-unusable native tier
raises `CustodyDowngradeError` rather than silently degrading. The shared
`platform_custody.py` is the best-engineered module: `O_EXCL|O_NOFOLLOW` temp
file → `os.link` no-clobber publish → directory `fsync`; descriptor-bound
validation (`fstat` + `st_dev`/`st_ino` identity re-check); POSIX 0600 *and*
real Windows DACL inspection via `GetNamedSecurityInfoW`; a store whose
protection cannot be established is refused. Per-scheme store names
(`master.key`, `.dpapi`, `.ss`) prevent cross-format lockout.

**Record/store layer (`sqlite_adapter.py`, `vaultkit/`).** SQL identifiers are
validated then bracket-quoted; values are bound parameters; store/load enforce
exactly-one-row semantics. `VaultStore` seals the payload *and* every metadata
column under `meta:<column>` AAD; `SessionCrypto` adds a best-effort FTS scrub
that is off by default and honestly scoped.

**Lifecycle (`keyring.py`, `vault_rotation.py`, `migration.py`,
`key_recovery.py`, `sqlite_migration.py`).** `KeyRing` selects the key a record's
authenticated header names — it never tries all keys, and an unknown `key_id`
raises a distinct operational error, not a tamper error. Rotation is
transaction-journaled, resumable, write-barriered, and post-verified including
tombstone reseal. Migration tombstones make a retired legacy id unreadable even
if its modern row is later deleted — closing silent resurrection of rotated
credentials. Recovery bundles are ordinary FloorVault envelopes under a
separately-protected recovery key.

**Search beacons (`beacons.py`).** Opt-in truncated `HMAC-SHA256` over a
length-prefixed `(scope, value)` pair, under a HKDF subkey with a distinct
`info` label (`floorvault-v1-beacon-index`). Widths are byte-aligned and
non-aligned requests are refused; `suggest_beacon_bits()` sizes width to the
real row count; the leakage model (coarse equality, bucket frequency, access
patterns) is stated in the module and in `SECURITY.md` §5.

## 3. Cryptographic assessment

- **Primitive choice is right.** Randomized AES-256-SIV provides AEAD with
  nonce-misuse resistance: a repeated random nonce degrades the ciphertext to
  deterministic rather than catastrophic — the correct default where nonce
  discipline cannot be guaranteed.
- **AAD construction is strong.** Canonical JSON is injective over the
  coordinate tuple; separate AD elements prevent boundary blurring; the v1 and
  v2 AD vectors are deliberately non-interchangeable.
- **Parse-before-verify hygiene.** Magic, version, nonce length and header are
  validated before decryption; the header is re-verified *inside* the AEAD, so
  header parsing exposes no oracle.
- **Honest residual limits.** HKDF `salt=None` is acceptable for a uniform
  master key; same-coordinate replay requires the caller-supplied `revision`
  (stated plainly); zeroization cannot reach immutable `bytes` or OpenSSL
  internals (stated plainly).

## 4. Assurance posture

Unusually strong for a 0.1.0: RFC 5297 vectors plus an independent from-spec
AES-SIV implementation; 1,342 vendored Wycheproof AES-SIV-CMAC vectors pinned
by SHA-256; ClusterFuzzLite corpus fuzzing; mutation testing of the security
gate itself (with a canary mutant that must survive); vendored Semgrep ruleset;
gitleaks; pip-audit; OpenSSF Scorecard; SHA-pinned actions; checksum-pinned
tool binaries; pinned hatchling build backend.

Admitted gaps: no third-party audit; the macOS Keychain and Linux Secret
Service tiers are unit-tested but never live-verified in CI (only DPAPI runs
unmocked).

## 5. Architectural weaknesses (ranked)

1. **No DEK/envelope layer.** One master key derives one SIV key that seals
   every record; `key_id` supports generation rotation but there is no
   per-record or per-tenant wrapped data key — no crypto-shredding, no
   blast-radius narrowing, and master compromise is total. A future envelope
   version could carry a wrapped DEK.
2. **No external KMS/HSM provider interface.** `KeyProvider` is abstract, but
   the only tiers are OS-native. A Vault-transit / cloud-KMS backend would let
   keys live outside the process — the largest available custody upgrade.
3. **Nonce tracking is symbolic.** The bounded in-memory window cannot catch
   cross-session reuse; harmless under SIV and honestly documented, but it
   should not be cited as a stronger guarantee than it is.
4. **SQLite-only, sync-only.** `sqlite3` adapter and `VaultStore`; no async
   API, no SQLAlchemy/Postgres. The record format itself is DB-agnostic.
5. **`decrypt()` returns `str`.** Python-interned plaintext has no wipe path;
   `decrypt_bytes()` exists, but the default API returns the least-hygienic
   type.
6. **Branch sprawl** — addressed 2026-10-02: merged-content branches deleted,
   open fix PRs queued (see commit history); three feature branches were left
   for their owners (active worktrees).

## 6. Comparison against five peers

| | **FloorVault** | **CipherSweet** v4.10 | **AWS DB Encryption SDK** v4.1 | **Google Tink** | **SQLCipher** 4.19 | **Vault Transit** |
|---|---|---|---|---|---|---|
| Category | Field-level enc lib (SQLite) | Field-level enc lib (RDBMS) | Field-level enc SDK (DynamoDB) | General crypto toolkit | Whole-DB encryption | Crypto-as-a-service |
| Cipher | AES-256-SIV | XChaCha20-Poly1305 / AES-CTR+HMAC | AES-GCM, per-item DEK | AES-SIV + others | AES-256-CBC + page HMAC | AES-256-GCM server-side |
| Context binding | Canonical-JSON AAD, always on | Enhanced AAD auto-binds PK/table/field | Sign-only attrs + encryption context | Single AD element | None (page MAC) | Derivation/convergent context |
| Search | Truncated-HMAC equality beacons | Blind indexes + Bloom filters, transforms | Standard/compound/signed beacons | — | Full SQL (transparent) | Convergent lookup only |
| Key layer | HKDF subkey, OS custody, key_id rotation | Per-index subkeys, key providers | KMS hierarchical keyring, wrapped DEKs | Keysets, KMS envelopes | PBKDF2 passphrase | Versioned named keys, BYOK, rewrap |
| Trust model | In-process library | In-process library | In-process library | In-process library | In-engine | Keys never leave the server |
| Lang / maturity | Python, 0.1.0 beta, no external audit | PHP+JS, mature | Java/.NET/Rust, formally-specified core | Multi-language, Google-scale | C, commercially backed | Go, enterprise-grade |

**CipherSweet** — the closest analog and the honest comparison. It beats
FloorVault on search richness (per-index subkeys, Bloom-filter indexes,
plaintext transforms enabling substring-class queries, multi-tenant providers)
and on maturity. FloorVault answers with deeper key custody (DPAPI / Keychain /
mlock plumbing CipherSweet does not attempt), a stricter authenticated-envelope
discipline, and a Python-native install. CipherSweet's Enhanced AAD
auto-binding to row coordinates is essentially the same idea as FloorVault's
coordinate binding — convergent design, which is validating for both.

**AWS Database Encryption SDK** — the same beacon concept (truncated keyed
HMAC) but a deeper key architecture: per-item DEKs wrapped by a KMS
hierarchical keyring, a crypto-materials cache, and a formally-specified core.
It is the clearest template for FloorVault gap #1: a wrapped-DEK layer is what
separates a keying *system* from a single-key scheme.

**Google Tink** — a toolkit, not a storage system. Its `DeterministicAead` is
AES-SIV but deterministic with a single AD element; FloorVault needs
randomized SIV with a multi-element AD vector, which Tink's public API does not
expose. PyCA `AESSIV` was the correct substrate. Not a competitor — a reminder
that FloorVault's value is the storage/custody layer, not the primitive.

**SQLCipher** — the layer FloorVault exists to replace the need for. SQLCipher
encrypts pages transparently so all SQL keeps working (joins, ranges, LIKE),
but offers no per-record context binding: a ciphertext spliced inside a page is
only page-MAC'd, and a stolen file plus key is total loss either way.
FloorVault's field binding is strictly finer-grained; the price is
query-ability except through beacons.

**Vault Transit** — the orthogonal trust model: encryption is server-side,
keys never leave Vault, rotation/rewrap are native, convergent encryption gives
equality lookup, and access is centrally audited. FloorVault is
offline-capable, zero-latency, zero-infra; Transit centralizes custody and
policy at the cost of a network call per operation and plaintext egress to the
server. An integration target, not a replacement.

## 7. Verdict

A well-above-average beta crypto library: sound primitives, consistent
fail-closed discipline, an unusually honest threat model (including the
authorised-agent / prompt-injection scope statement), and assurance tooling
stronger than many mature projects. The real gaps against the peers are not
cryptographic: they are **keying depth** (no DEK layer, no external KMS) and
**platform breadth** (Python/SQLite only, no live-verified macOS/Linux custody
tier).

Recommended order: (1) wrapped-DEK envelope option in a v3 record format;
(2) external `KeyProvider` backend (Vault transit / cloud KMS); (3) keep the
unmerged-fix-branch hygiene from 2026-10-02; (4) third-party audit before 1.0;
(5) live CI legs for Keychain and Secret Service.

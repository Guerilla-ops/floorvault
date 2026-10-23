# FloorVault audit packet — external review orientation

Prepared for an independent security review of FloorVault `v0.2.0` ("Groundwork").
This packet indexes the normative spec, threat model, prior internal reviews and their
dispositions, the verification surface, and the known limitations an auditor should be
aware of before starting. It is an orientation document — every claim here is backed by
a file in this repository; when in doubt, the code and the mutation suite win.
FloorVault is beta: no completed independent code audit, formal verification or
certification is claimed (`SECURITY.md`).

## 1. Scope of the review

**In scope**

- `src/floorvault/` — all modules: envelope construction, contextual AAD, key custody
  providers (adaptive OS/file tiers, passphrase-wrapped Tier-3, generation store,
  Vault Transit), adapters (SQLite / SQLAlchemy / libSQL / PostgreSQL and MySQL via
  DB-API), opt-in libSQL file-layer encryption, freshness anchors, rotation,
  migration, recovery bundles, the `vaultkit` credential store (including sealed
  listing metadata) and session framing, search beacons, `inspector` CLI.
- `src/floorvault/testing/siv_reference.py` — independent RFC 5297 implementation used
  for cross-validation (test-support, not production crypto), exercised by
  `tests/test_rfc5297_independent.py` and `tests/test_wycheproof_vectors.py`.
- `plugins/hermesvault/` — optional Hermes Agent integration. Supplied separately from
  the library wheel; it resolves item references into plaintext for host-managed
  environment injection (`SECURITY.md`, "System and scope").
- `scripts/` — `gen_vectors.py`, `mutation_check.py`, `realworld_exercise.py`,
  `verify_wheel.py`, `security-check.sh`, `benchmark_compare.py`, `ci_matrix.py`,
  `memory_probe.py`.
- `fuzz/` — ClusterFuzzLite harnesses.
- Build/release supply chain: `.github/workflows/release.yml`, `.github/workflows/ci.yml`,
  `pyproject.toml`, `uv.lock`, CycloneDX SBOM generation, PEP 740 attestation path.

**Out of scope**

- Third-party dependencies (`cryptography`, `keyring`, `hvac`, `sqlalchemy`, `libsql`,
  `psycopg`, `mysql-connector-python`) — review their upgrades through `pyproject.toml`
  ranges and `uv.lock` diffs (`SECURITY.md`, "Assurance and supply chain").
- libSQL's native page-cipher format and KDF — FloorVault only derives and supplies the
  key (SPEC §14.2, §15).
- The Hermes Agent host itself — its APIs, profile scoping and environment injection are
  integration boundaries the plugin relies on, not code in this repository.
- Deployment environment, host OS hardening, physical access.
- The separate `Floor` application (private estate) that embeds FloorVault — not part
  of this repository or package.

## 2. Cryptographic inventory

| Primitive | Purpose | Construction | Source |
| --- | --- | --- | --- |
| AES-256-SIV | Field encryption | RFC 5297 (S2V + CTR), 128-bit tag doubles as nonce — misuse-resistant | `cryptography` `AESSIV` in production; independent from-spec reference in `src/floorvault/testing/siv_reference.py` (single-block ECB primitive for CMAC/S2V/CTR) |
| HKDF-SHA256 | Master key → purpose subkeys | RFC 5869, context-separated labels `floorvault-v1-aes-siv`, `-beacon-index`, `-libsql-file`, `-freshness` (SPEC §3) | `src/floorvault/core.py` |
| Envelope | `FLV2` record format (`FLRV` v1 read-only) | Header `crypto_version`+`key_id`+`nonce_len` is *cleartext but authenticated* via AAD; full layout in `docs/SPEC.md` §4 and `docs/RECORD-FORMAT-2026-09-15.md` | `src/floorvault/records.py` |
| Contextual AAD | Anti-splice binding | `table`, `record_id`, `column`, `schema_id`/`schema_version`, `app_instance_id`, optional `revision` — exact byte serialization frozen in SPEC §5–§6 (NFC/NFD as-written, `ensure_ascii=False`, unbounded ints) | `src/floorvault/records.py` |
| Adaptive custody | OS tier → file tier resolution | OS-tier marker plus locked re-checks so a backend appearing, disappearing or being skipped never mints a second master key (SPEC §10.5) | `src/floorvault/providers/adaptive.py` (mutants `AD-4`–`AD-17`) |
| Passphrase-wrapped Tier-3 | File custody that a copy alone does not unlock | `FVPW1`: scrypt (`log2_n=17`, `r=8`, `p=1`; readers refuse `log2_n` outside `[15, 20]` or other `(r, p)` before deriving) → AES-SIV wrap of the master key (SPEC §10.8) | `src/floorvault/providers/passphrase_store.py` (mutants `PW-*`) |
| Generation custody | Master-key versioning | Immutable generation files + single-writer CAS pointer + directory fsync barriers | `src/floorvault/providers/generation_store.py` |
| Vault Transit | Remote key custody | `transit/datakey` + `transit/decrypt`/`rewrap`, versioned context binding, TTL cache, redirect vetting, fail-closed | `src/floorvault/providers/vault_transit.py`, `docs/VAULT-TRANSIT.md` |
| Recovery bundle | Offline recovery | `FVRB1`: wrapped master key under an independent recovery key; self-wrap refused (SPEC §11) | `src/floorvault/key_recovery.py` (mutant `REC-1`) |
| Rotation | Re-key stores | Resumable journal, authenticated target commitment, both-generations resume ring | `src/floorvault/vault_rotation.py` (mutant `ROT-5`) |
| Freshness anchor | Opt-in rollback detection | `FVFA1`: HMAC-SHA256 digest of anchored tables' rows and governing schema (every trigger included), held outside the database in an `AnchorStore` with two-phase `committed`/`pending` compare-and-swap (SPEC §14.3) | `src/floorvault/freshness.py` (mutants `FA-*`) |
| Sealed listing metadata | Hide credential `kind`/`has_otp` | Opt-in `seal_listing_metadata=True`: sealed under `meta:kind`/`meta:has_otp` coordinates, `kind` space-padded to a fixed 7 characters (SPEC §12.2–§12.3) | `src/floorvault/vaultkit/vault.py` (mutants `VM-*`) |
| libSQL file key | Opt-in page-layer encryption beneath the envelopes | `connect_encrypted` hands the §3 libSQL subkey to libSQL's native cipher; local files only (SPEC §14.2) | `src/floorvault/libsql_adapter.py` |
| Search beacons | Opt-in truncated equality index | HMAC-derived, fixed-width, scope-separated; strictly opt-in | `src/floorvault/beacons.py` |
| Memory custody | In-process key protection | `HardenedMemoryKey`: mlock where available, zeroization on wipe, core-dump suppression | `src/floorvault/memory.py` |

## 3. Prior reviews and dispositions

All reviews below are internal. Historical review documents apply to the revisions they
state (`SECURITY.md`).

| Report | Coverage | Findings | Disposition |
| --- | --- | --- | --- |
| `docs/PENTEST-2026-10-04.md` | Adversarial pentest of custody, rotation, release surface | F1 self-wrap accepted; F2 rotation bound to `key_id` only; F3 internal names in shipped surfaces; F4 PyPI doc gap; F5 CI pin drift | All five fixed and regression-tested; F1→`REC-1`, F2→`ROT-5` mutants; merged |
| Red-team remediation (PRs #49, #50) | Beacons, canaries, rotation journal, nonce docs, dependency audit | Red-team P1 #10/#11 and P2 findings: beacon subkey and width; canary store-binding; journal key-id; nonce documentation; dependency-audit CI | Fixed and merged between `v0.1.0` and `v0.2.0` |
| `docs/DEEP-DIVE-REVIEW-2026-10-01.md` | Full-codebase deep dive | Findings tracked in-repo | See report + `test_security_scan.py` regression coverage |
| `docs/REMEDIATION-REPORT-2026-09-16.md` | Remediation after first review cycle | — | Landed |
| `docs/FLOORVAULT-ARCHITECTURE-CRYPTO-REPORT-2026-09-16.md` | Crypto architecture report | — | Design record |
| `docs/ARCHITECTURE-REVIEW-2026-10-02.md` | Architecture review | — | Design record |
| `docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md` | Windows/POSIX custody differences | Per-platform findings | `PC-*`/`WACL-*` mutants, per-tier docs |
| `docs/HARDWARE-CUSTODY.md` | PKCS#11/Swissbit design (issue #35) | — | Design only; not implemented, not claimed |

**Security fixes landed between `v0.1.0` and `v0.2.0`** (each with regression tests and
named mutants):

- **Master-key fork on custody changes** (PRs #62, #64; issue #63) — an OS key store
  appearing after Tier-3 file custody, or a headless resolver without the OS tier,
  could mint a second master key. Fixed with the OS-tier marker and locked re-checks;
  `tests/test_tier3_no_key_fork.py`, `tests/test_os_tier_marker.py`, `AD-4`–`AD-17`.
- **Freshness transaction semantics** (PR #61) — commit/rollback now use explicit SQL
  under every `sqlite3` autocommit mode, the order column must be unique, and anchor
  names are restricted; `tests/test_freshness_anchor.py`, `FA-15`–`FA-19`.

## 4. Verification surface — how to reproduce our claims

- **Full local gate:** `scripts/security-check.sh` — gitleaks → pip-audit → ruff →
  Bandit → Semgrep → RFC 5297/5869 + Wycheproof AES-SIV vectors → mlock tests →
  splice-immunity → adapter tests → deterministic fuzz harness, ClusterFuzzLite
  properties and deep-dive security scan → full pytest suite → real-world exercise (no
  mocks, public surfaces) → universal-wheel verification → curated mutation suite.
- **Mutation suite:** `scripts/mutation_check.py` — a curated named-mutant roster (`PC`, `AD`,
  `WACL`, `MIG`, `KR`, `ROT`, `DS`, `CR`, `SS`, `KP`, `IQ`, `REC`, `DUR`, `BC`,
  `VS`, `GS`, `VT`, `SA`, `LQ`, `VM`, `PW`, `FA`, `WD`, `PKG` families) each anchored
  to a specific security invariant; every mutant must be killed by a test or
  documented as an equivalent.
- **Wire vectors:** `tests/vectors/floorvault_wire_vectors.json` +
  `tests/vectors/independent_wire.py` — a serializer that does **not** import
  `floorvault`; a second implementation can prove byte-compatibility without reading
  our code.
- **Compatibility fixtures:** `tests/vectors/main_f3760fe_compat.json` +
  `tests/test_floorvault_compatibility.py` — artifacts written by the earlier `main`
  revision (including an on-disk sealed store and recovery bundle) must still open;
  new round trips alone are not compatibility evidence.
- **Fuzz:** `fuzz/*.py` — ClusterFuzzLite entrypoints (envelope, associated data,
  identifiers, beacons, protected store).
- **CI matrix:** PRs use Ubuntu Python 3.10/3.14 and macOS/Windows Python 3.13.
  Weekly, version-tag and expanded manual runs cover all declared Python versions
  on Ubuntu plus Python 3.10/3.13 on macOS/Windows. Full mutations run once on
  Linux; platform subsets run on macOS/Windows. Native Windows DPAPI stays in the
  ordinary suite. Live Vault transit, ClusterFuzzLite and Scorecard remain separate.
  Required checks and the Windows test-temp ACL setup are in `docs/CI.md`.
- **Skips to check:** Hermes plugin tests need a compatible host checkout and may skip
  entirely; the plugin is outside the standalone gate's lint/static-analysis paths.
  Inspect actual CI results rather than the configured matrix.

## 5. Known limitations — stated, not claimed away

`SECURITY.md`, "Design limits and known limitations", is the authoritative list; the
points below are the ones most relevant to scoping.

- **In-process key disclosure:** once resolved, the 32-byte master exists as plaintext
  in `HardenedMemoryKey`. mlock/coredump suppression raise the bar; they are not a
  hardware boundary, and wiping does not reach every Python, provider or AEAD-engine
  copy. On macOS/Linux, construction permanently sets the process-wide `RLIMIT_CORE`
  limits to zero (`docs/USAGE.md`).
- **Freshness is opt-in:** ordinary decryption accepts same-context replay, and
  revision binding is optimistic concurrency only. `FreshnessAnchor` detects
  whole-database rollback, row replay/deletion/insertion and planted schema for the
  SQLite/libSQL tables it is configured with — only if the anchor store cannot be
  rolled back together with the database. Interrupted commits require a deliberate
  `discard_interrupted_commit`. Credential stores and the plugin do not enable
  anchoring automatically.
- **Generation replay:** generation files are content-bound to their pointer, but an
  older *valid* generation can be replayed if the pointer is rolled back — freshness
  needs a trusted monotonic anchor (corrected wording in `docs/HARDWARE-CUSTODY.md`).
  The freshness anchor covers database tables, not the generation pointer.
- **Tier-3 file custody:** an unwrapped `master.key` *is* the key. Passphrase wrapping
  adds scrypt + AES-SIV, not hardware custody; weak or stolen passphrases defeat it,
  and wrapping a previously exposed key does not revoke earlier copies (raw-file
  residue may remain after `protect_key_file()`).
- **OS custody is account-based:** Keychain, DPAPI and Secret Service do not protect
  against the account or an administrator; default DPAPI entropy is public.
- **Vault Transit availability:** custody is online-dependent by design — Vault down
  means no unlock, never a fallback to weaker custody (`docs/VAULT-TRANSIT.md`,
  "Failure semantics").
- **Transit context is separation, not authorization:** Vault policies authorize;
  the context (with `derived=true`) provides cryptographic domain separation
  (`docs/VAULT-TRANSIT.md`).
- **Metadata remains visible:** field encryption does not hide unencrypted columns,
  counts, IDs, lengths or access patterns. Credential `kind`/`has_otp` are cleartext
  unless sealed listing is enabled; sealed mode still leaves item count and ids visible
  and does not erase historical plaintext residue.
- **Migration can write during listing:** the migration-aware `list_items()` path can
  write modern records and retirement tombstones; it is not a read-only operation.
- **libSQL remote-residue:** `PRAGMA secure_delete`/checkpoint semantics cannot be
  verified through a remote libSQL connection; residue guarantees apply to local
  files only (stated in `libsql_adapter.py` docs).
- **libSQL file-layer encryption is libSQL's cipher, not ours:** `connect_encrypted`
  only derives and supplies the key (SPEC §3, §14.2). The native `aes256cbc` page cipher
  is unauthenticated, and its format and KDF are outside this audit surface.
- **Search beacons leak equality** within a scope — opt-in and truncated; the default
  API exposes no search index. ORE/OPE remain a research item (roadmap WS6), not
  implemented.
- **Hermes plugin returns plaintext:** credentials handed to the host are plaintext and
  there is no separate authorization broker; a prompt-injected agent the host allows
  can request authentic secrets. At `v0.2.0` the plugin's `put` removes and recreates
  an item in separate transactions (non-atomic); on `main` after PR #68 it uses
  `VaultStore.update_generic_field` in one immediate SQLite transaction.
- **Live-verified custody tiers:** Windows DPAPI custody is CI-verified on real
  Windows; macOS Keychain and Linux Secret Service are unit-tested but not
  live-verified (stated in `SECURITY.md`).

## 6. Suggested audit attention

- Envelope/AAD canonicalization (`SPEC.md` §4–§6): divergence between producer and
  verifier semantics is the classic context-binding failure class — we froze the
  semantics as implemented rather than tighten them (SPEC §1, "Freeze semantics").
- `adaptive` custody resolution: OS-tier marker, symlink/unsearchable-directory
  handling and the re-checks under the lock are what prevent master-key forks;
  `AD-4`–`AD-17`, `PW-3`–`PW-7`.
- `passphrase_store` cost-parameter bounds and empty-passphrase refusal: `PW-1`, `PW-2`.
- `freshness` digest coverage (every trigger, unique ordering), the two-phase
  `committed`/`pending` record and the `transaction()` path under each `sqlite3`
  autocommit mode: `FA-*`.
- Sealed-listing mode transitions and migration (re-deriving `has_otp` from the
  authenticated payload): `VM-*`.
- `generation_store` CAS + fsync sequencing: the durability contract is subtle;
  `GS-*`/`DUR-*` mutants document intended invariants.
- `vault_transit` redirect vetting + token sanitization paths: `VT-*` mutants.
- `sqlalchemy_adapter` SQL-boundary coverage: ORM hooks alone are not an encryption
  boundary; `SA-*` mutants enumerate the bypass surfaces we guard.
- `dbapi_adapter` identifier quoting per dialect (MySQL `"name"` degrades to a string
  literal outside ANSI mode) — covered by `tests/test_dbapi_adapter.py`; there is no
  dedicated mutant family.
- `key_recovery` self-wrap refusal and `vault_rotation` resume authentication:
  `REC-1`, `ROT-5`, `ROT-6`.
- Hermes plugin boundaries: agent-secret vs. browser-vault directory separation,
  disabled legacy migration on the read path, bootstrap key handling via `token_env`.
- The independent SIV reference must not share code with `core.py`; the value of
  the module is independence, not reuse.

## 7. Logistics

- Repository: `https://github.com/Guerilla-ops/floorvault` (public; canonical).
- Point-in-time audit target: tag `v0.2.0` (commit `920591e`,
  `920591ec14cc072b649161ca073a2159f0f16bf2`), or a later rc tag by arrangement.
  `main` has moved past the tag (PR #67 docs; PR #68 plugin hardening and
  `VaultStore.update_generic_field`). The previous target, `v0.1.0` (commit
  `44c5ec1`), is unsupported.
- Release artifacts: PyPI `floorvault`, SHA-256 digests in the `v0.2.0` release notes,
  Sigstore + PEP 740 attestations (`gh attestation verify`, `/integrity` endpoints);
  verification steps in `docs/RELEASING.md`.
- Reporting: see `SECURITY.md`, "Reporting a vulnerability" — private vulnerability
  reporting, not public issues.

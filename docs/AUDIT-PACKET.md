# FloorVault audit packet — external review orientation

Prepared for an independent security review of FloorVault `v0.1.0`. This packet indexes
the normative spec, threat model, prior internal reviews and their dispositions, the
verification surface, and the known limitations an auditor should be aware of before
starting. It is an orientation document — every claim here is backed by a file in this
repository; when in doubt, the code and the mutation suite win.

## 1. Scope of the review

**In scope**

- `src/floorvault/` — all modules: envelope construction, contextual AAD, key custody
  providers, adapters (SQLite / SQLAlchemy / libSQL), rotation, migration, recovery
  bundles, session framing, search beacons, Vault Transit custody, `inspector` CLI.
- `tests/test_rfc5297_independent.py` — independent RFC 5297 implementation used for
  cross-validation (test-support, not production crypto). PR #31 moves it to a stable
  importable path at `src/floorvault/testing/siv_reference.py`.
- `scripts/` — `gen_vectors.py`, `mutation_check.py`, `realworld_exercise.py`,
  `verify_wheel.py`, `security-check.sh`, `benchmark_compare.py`.
- `fuzz/` — ClusterFuzzLite harnesses.
- Build/release supply chain: `.github/workflows/release.yml`, `pyproject.toml`,
  `uv.lock`, SBOM generation, PEP 740 attestation path.

**Out of scope**

- Third-party dependencies (`cryptography`, `keyring`, `hvac`, `sqlalchemy`, `libsql`)
  — trusted per `SECURITY.md` §7; audit their upgrades through `uv.lock` diffs.
- Deployment environment, host OS hardening, physical access.
- The separate `Floor` application (private estate) that embeds FloorVault — not part
  of this repository or package.

## 2. Cryptographic inventory

| Primitive | Purpose | Construction | Source |
| --- | --- | --- | --- |
| AES-256-SIV | Field encryption | RFC 5297 (S2V + CTR), 128-bit tag doubles as nonce — misuse-resistant | `cryptography` `AESSIV` in production; independent from-spec reference in `tests/test_rfc5297_independent.py` (single-block ECB primitive for CMAC/S2V/CTR; moving to `src/floorvault/testing/` in #31) |
| HKDF-SHA256 | Master key → encryption key derivation | RFC 5869, context-separated info | `src/floorvault/core.py` |
| Envelope | `FLV2` record format | Header `crypto_version`+`key_id`+`nonce_len` is *cleartext but authenticated* via AAD; full layout in `docs/SPEC.md` and `docs/RECORD-FORMAT-2026-09-15.md` | `src/floorvault/records.py` |
| Contextual AAD | Anti-splice binding | `table`, `record_id`, `column`, `schema_id`/`schema_version`, `app_instance_id`, optional `revision` — exact byte serialization frozen in SPEC §4 (NFC/NFD as-written, `ensure_ascii=False`, unbounded ints) | `src/floorvault/records.py` |
| Generation custody | Master-key versioning | Immutable generation files + single-writer CAS pointer + directory fsync barriers | `src/floorvault/providers/generation_store.py` |
| Vault Transit | Remote key custody | `transit/datakey` + `transit/decrypt`/`rewrap`, versioned context binding, TTL cache, redirect vetting, fail-closed | `src/floorvault/providers/vault_transit.py`, `docs/VAULT-TRANSIT.md` |
| Recovery bundle | Offline recovery | Wrapped master key under an independent recovery key; self-wrap refused | `src/floorvault/key_recovery.py` (mutant `REC-1`) |
| Rotation | Re-key stores | Resumable journal, authenticated target commitment, both-generations resume ring | `src/floorvault/vault_rotation.py` (mutant `ROT-5`) |
| Search beacons | Opt-in truncated equality index | HMAC-derived, fixed-width, scope-separated; strictly opt-in | `src/floorvault/beacons.py` |
| Memory custody | In-process key protection | `HardenedMemoryKey`: mlock where available, zeroization on wipe, core-dump suppression | `src/floorvault/memory.py` |

## 3. Prior reviews and dispositions

| Report | Coverage | Findings | Disposition |
| --- | --- | --- | --- |
| `docs/PENTEST-2026-10-04.md` | Adversarial pentest of custody, rotation, release surface | F1 self-wrap accepted; F2 rotation bound to `key_id` only; F3 internal names in shipped surfaces; F4 PyPI doc gap; F5 CI pin drift | All five fixed and regression-tested; F1→`REC-1`, F2→`ROT-5` mutants; merged |
| `docs/DEEP-DIVE-REVIEW-2026-10-01.md` | Full-codebase deep dive | Findings tracked in-repo | See report + `test_security_scan.py` regression coverage |
| `docs/REMEDIATION-REPORT-2026-09-16.md` | Remediation after first review cycle | — | Landed |
| `docs/FLOORVAULT-ARCHITECTURE-CRYPTO-REPORT-2026-09-16.md` | Crypto architecture report | — | Design record |
| `docs/ARCHITECTURE-REVIEW-2026-10-02.md` | Architecture review | — | Design record |
| `docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md` | Windows/POSIX custody differences | Per-platform findings | `PC-*`/`WACL-*` mutants, per-tier docs |
| `docs/HARDWARE-CUSTODY.md` | PKCS#11/Swissbit design (issue #35) | — | Design only; not implemented, not claimed |

## 4. Verification surface — how to reproduce our claims

- **Full local gate:** `scripts/security-check.sh` — gitleaks → pip-audit → ruff →
  Bandit → Semgrep → RFC 5297/5869 vectors → mlock tests → splice-immunity → adapter
  tests → deterministic fuzz harness → full pytest suite → real-world exercise (no
  mocks, public surfaces) → universal-wheel verification → curated mutation suite.
- **Mutation suite:** `scripts/mutation_check.py` — a curated named-mutant roster (`PC`, `AD`,
  `WACL`, `MIG`, `KR`, `ROT`, `DS`, `CR`, `SS`, `KP`, `IQ`, `REC`, `DUR`, `BC`,
  `VS`, `GS`, `VT`, `SA`, `LQ` families) each anchored to a specific security
  invariant; every mutant must be killed by a test or documented as an equivalent.
- **Wire vectors:** `tests/vectors/floorvault_wire_vectors.json` +
  `tests/vectors/independent_wire.py` — a serializer that does **not** import
  `floorvault`; a second implementation can prove byte-compatibility without reading
  our code.
- **Fuzz:** `fuzz/*.py` — ClusterFuzzLite entrypoints (envelope, associated data,
  identifiers, beacons, protected store).
- **CI matrix:** Ubuntu/macOS/Windows × py3.10–3.14 + Windows DPAPI live custody +
  live Vault dev-container transit + ClusterFuzzLite + Scorecard.

## 5. Known limitations — stated, not claimed away

- **In-process key disclosure:** once resolved, the 32-byte master exists as plaintext
  in `HardenedMemoryKey`. mlock/coredump suppression raise the bar; they are not a
  hardware boundary. Documented in `SECURITY.md` §5–§6.
- **Revision binding is optimistic concurrency,** not rollback protection: an attacker
  who rewrites the *database* can replay whole rows. Freshness anchors must live
  outside the attacker's rewrite domain.
- **Vault Transit availability:** custody is online-dependent by design — Vault down
  means no unlock (a deliberate availability-for-custody trade, `R4`).
- **Transit context is separation, not authorization:** Vault policies authorize;
  the context provides cryptographic domain separation (`R2`).
- **libSQL remote-residue:** `PRAGMA secure_delete`/checkpoint semantics cannot be
  verified through a remote libSQL connection; residue guarantees apply to local
  files only (stated in `libsql_adapter.py` docs).
- **Generation replay:** generation files are content-bound to their pointer, but an
  older *valid* generation can be replayed if the pointer is rolled back — freshness
  needs a trusted monotonic anchor (corrected wording in `docs/HARDWARE-CUSTODY.md`).
- **Search beacons leak equality** within a scope — opt-in and truncated; the default
  API exposes no search index. ORE/OPE remain a research item (roadmap WS6), not
  implemented.
- **Live-verified custody tiers:** Windows DPAPI custody is CI-verified on real
  Windows; macOS Keychain and Linux Secret Service are unit-tested but not
  live-verified (stated in `SECURITY.md`).

## 6. Suggested audit attention

- Envelope/AAD canonicalization (`SPEC.md` §4–5): divergence between producer and
  verifier semantics is the classic context-binding failure class — we froze the
  semantics rather than tighten them (R5).
- `generation_store` CAS + fsync sequencing: the durability contract is subtle;
  `GS-*`/`DUR-*` mutants document intended invariants.
- `vault_transit` redirect vetting + token sanitization paths: `VT-*` mutants.
- `sqlalchemy_adapter` SQL-boundary coverage: ORM hooks alone are not an encryption
  boundary; `SA-*` mutants enumerate the bypass surfaces we guard.
- `key_recovery` self-wrap refusal and `vault_rotation` resume authentication:
  `REC-1`, `ROT-5`, `ROT-6`.
- The independent SIV reference must not share code with `core.py`; the value of
  the module is independence, not reuse.

## 7. Logistics

- Repository: `https://github.com/Guerilla-ops/floorvault` (public; canonical).
- Point-in-time audit target: tag `v0.1.0` (commit `44c5ec1`), or a later rc tag by
  arrangement.
- Release artifacts: PyPI `floorvault`, SHA-256 digests in the `v0.1.0` release notes,
  Sigstore + PEP 740 attestations (`gh attestation verify`, `/integrity` endpoints).
- Reporting: see `SECURITY.md` §2 — private vulnerability reporting, not public
  issues.

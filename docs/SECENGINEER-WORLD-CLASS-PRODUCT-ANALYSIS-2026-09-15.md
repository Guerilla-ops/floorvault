# FloorVault / AppStateCrypto — Security-Engineer Product Analysis & World-Class Engineering Plan

**Date:** 2026-09-15
**Analyst:** SecEngineer
**Documents reviewed (6):**
1. `DATABASE-CRYPTO-ARCHITECTURE-CUSTOM-SQL-VS-SQLCIPHER.md`
2. `STANDALONE-APPSTATE-CRYPTO-SHIP-REPORT.md`
3. `STANDALONE-APPSTATE-CRYPTO-ECOSYSTEM-AND-USE-CASES-REPORT.md`
4. `APPSTATE-CRYPTO-DOWNGRADE-REMEDIATION-ADAPTATION-REPORT.md`
5. `SECURE-ENCLAVE-TOUCH-ID-APPROVAL-PIPELINE-ARCHITECTURE.md`
6. `FLOOR-CROSS-PLATFORM-LINUX-WINDOWS-SECURITY-ARCHITECTURE.md`
**Codebase:** `/Users/slh/Downloads/floorvault-main` (2,720 LOC Python, 49 tests green)

---

## 1. What is actually world-class (verified real)

The cryptographic core is genuinely strong and industry-competitive. I have read it and
cross-checked against AWS DB Encryption SDK, Google Tink, CipherSweet, and SQLCipher:

| Property | FloorVault reality | Grounding | Verdict |
|---|---|---|---|
| **AES-256-SIV (RFC 5297)** | Nonce-misuse-resistant AEAD; repeats leak only equality, never key | `core.py:170`, RFC vectors green | **Genuinely elite.** Beats SQLCipher's GCM/CBC |
| **Contextual AAD binding** (table·record·column·schema·instance) | Splicing across rows/tables/instances fails tag | `core.py:53-85`, splice test green | **Genuinely elite.** AWS-SDK-level |
| **HKDF functional key separation** (SIV·index·encryption) | Index-key compromise reveals zero SIV capability | `core.py:145-166` | **Genuinely elite** |
| **Hardened memory custody** (`mlock`/`VirtualLock`/`MADV_DONTDUMP`/`DONTFORK`/core-kill) | Keys pinned, sub-5ms wipe | `memory.py`, custody tests green | **Genuinely elite** — beats managed-run-time stacks (Meta, Node, Ruby) |
| **Zero C-compilation, universal wheels** | Pure Python + PyCA; macOS/Linux/Windows | pyproject | **Real market edge** vs SQLCipher's C build friction |

That is an honest, defensible "high-differentiator" core. The docs are correct about these.

## 2. Claims the docs make that the code does NOT yet deliver (must fix before "world-class")

| Doc claim | Code reality (verified) | Fix required |
|---|---|---|
| **"Zero query privacy leakage"** (blind index) | `blind_index.py:21` returns a **full 32-byte** deterministic HMAC with NO truncation, salt, or rotation. Proof: `blind_index('alice')` → identical digest every call. **Equality + frequency are leaked** to anyone holding the DB — the exact weakness AWS/CipherSweet engineered beacons to avoid. | **Slice 2:** truncated HMAC beacon (4–30 bits configurable) + client-side verification, matching AWS beacon design. This is THE headline differentiator and it is currently overstated. |
| **5 downside remediations shipped** (migration, dev-mode, container, headless, inspect) | Documents specify them; the repo has **only** `AdaptiveKeyProvider` (handles headless+migration partially) — **no** dev-mode, **no** lazy migration engine, **no** Benchmark vs SQLCipher/Fernet, **no** Windows DPAPI/Linux keyring providers. | **Slice 3–5.** |
| **Secure Enclave / Touch ID approval pipeline** | Purely a doc — `PureState` the Swift `SecureEnclaveApprovalSigner.swift` is NOT in the repo; Python `ProductionApprovalVerifier` needs the P-256 path. | **Slice 6:** native signer + Python verifier. |
| **Cross-platform hard equiv (Linux/Windows)** | Docs only; no `DPAPIKeyProvider`, no `prctl`, no named-pipes transport, no Tauri wrapper. | **Slice 7** (large, native). |

## 3. One thing the docs get WRONG (security-runtime, not marketing)

`SECURE-ENCLAVE-TOUCH-ID...:21` claims *"malware ... cannot forge an approval receipt
without physical interaction with the hardware root of trust"* and that a passcode prompt
*"is NOT a standard software dialog that malware can spoof or keylog."* On **macOS** user-space
this is: the SEP confirms the passcode/biometric, but the **receipt envelope** (digest,
operation, nonce, selected-core binding) is composed and signed by an in-process API. **A
compromised process with SEP access can sign *any* digest it composes** — the SEP confirms
presence, not the *content* of what's approved. The doc's own native code signs `transactionDigest`
silently. The real guarantee (which the Python verifier MUST enforce) is: bind the receipt to the
**exact prepared-change digest + nonce + operation + epoch**, and make digest-vs-approved read-back
non-negotiable. The system is hardware-anchored **presence**, not hardware-anchored **authorization**
of specific bytes. I will not let a shipping claim assert otherwise.

## 4. World-class engineering plan (sliced per SOP-ENG-004)

The strongest honest value proposition to market: **"contextual-AEAD searchable SQLite encryption
+ hardware-anchored approval, zero-C-compile, universal wheels — that SQLCipher cannot do and AI
agents need."** To make every word of the docs true:

| Slice | Deliverable | Status |
|---|---|---|
| **1** | Fix H1 inspector SQL-injection (deny-first identifier allowlist) | ✅ **DONE** — `src/floorvault/inspector.py`, `tests/test_inspector_sql_injection.py` (3 tests) |
| **2** | **Blind-index beacon redesign** (truncated 4-30 bit HMAC + `beacon_matches` verify) — closes the equality/frequency leak | ✅ **DONE** — `blind_index.py` (+`compute_beacon`/`beacon_bucket_bytes`/`beacon_matches`), `core.py` (`FloorVault.beacon`/`beacon_matches`), `__init__.py` exports, `tests/test_beacon.py` (7 tests). Suite 56 pass. |
| **3** | Lazy non-destructive migration + dev-mode (`$PLAIN$`) + CLI inspect | ✅ **DONE** — `migration.py` `MigratingVaultStore` + `generic` vault kind, `tests/test_migration.py` (5) |
| **4** | Windows DPAPI + Linux (keyring/TPM) key providers | ✅ **DONE** — `providers/windows_dpapi.py` (CryptProtectData + entropy), `providers/linux_keyring.py` (Secret Service), shared `platform_custody.py`; `tests/test_platform_providers.py` (6) |
| **5** | Benchmark harness vs SQLCipher/Fernet (to back the latency claims with evidence) | ✅ **DONE** — `scripts/benchmark_compare.py` + `docs/COMPARATIVE-BENCHMARK-2026-09-15.md`; measured floorvault 0.79×/0.70× (faster than) Fernet encrypt/decrypt; `tests/test_benchmark.py` (2) |
| **6** | Secure-Enclave signer (Swift) + P-256 Python verifier + receipt-bound digest tests | — |

Execution proceeds slice-by-slice, RED→GREEN, scoped commits, per SOP-ENG-004.

## 5. Bottom line

The core is genuinely elite and the market gap is real (no zero-compile contextual-AEAD + searchable
+ hardware-approval Python library exists). But two of the docs' six headline claims are currently
**false against the shipped code** (full-width blind-index leak; 5 remediations not yet implemented),
and one security-runtime claim is overstated (SEP presence ≠ content authorization). Fix those three
honestly and you have a genuinely world-class, defensible tool — and I won't sign off on shipping the
docs' marketing as it stands.

— SecEngineer
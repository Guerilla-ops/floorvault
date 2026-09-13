# FloorVault Original-to-Hardened Change Report

Date: 2026-09-14  
Repository: `floorvault`  
Scope: Changes made from the original repository implementation

## Executive summary

FloorVault was changed from a cryptographic helper with optional local key fallback and plaintext searchable projections into a fail-closed, context-bound storage-encryption library with protected metadata, keyed search projections, SQLite residue reduction, and platform memory-hardening hooks.

The Hermes adapter remains API-oriented toward direct credential-vault replacement. However, encrypted message storage is currently an integration helper; it has not yet replaced Hermes's production `SessionDB` and `state.db` writer/search path.

## Change inventory

### 1. Core encryption and key separation

File: `src/floorvault/core.py`

- Preserved AES-256-SIV authenticated encryption.
- Preserved contextual associated data (AAD) binding to table, record, column, schema, and application instance.
- Preserved random per-record nonce envelopes.
- Preserved nonce reuse detection with a bounded tracking window.
- Preserved HKDF-derived functional separation between encryption and blind-index keys.
- Added/retained explicit key destruction after subkey derivation.
- Kept a closed-engine state so operations fail after wiping.

Security effect: ciphertext cannot be moved between rows, columns, tables, schema contexts, or application instances without authentication failure.

### 2. Adaptive key provider hardened to fail closed

File: `src/floorvault/providers/adaptive.py`

Original behavior allowed a local `master.key` fallback by default. The current implementation:

- Disables disk-key fallback by default.
- Requires an explicit environment key such as `APPSTATE_KEY`, `HERMES_VAULT_KEY`, or `VAULT_MASTER_KEY`, or a supported OS keychain path.
- Makes local disk fallback an explicit opt-in.
- Rejects non-regular key files.
- Rejects key files owned by another user on POSIX systems.
- Rejects group/world-readable key files.
- Creates new local fallback keys with mode `0600`.
- Refuses fallback in strict mode.

Operational effect: an unattended Hermes/FloorVault process can now fail at startup if no approved key source is configured. This is intentional and prevents silently placing the decryption key beside the database.

### 3. Hermes vault metadata encryption

File: `src/floorvault/hermes/vault.py`

The Hermes credential adapter now:

- Encrypts labels, origins, identifier types, identifiers, and creation timestamps.
- Retains a keyed `origin_idx` for equality lookup without storing the searchable origin in plaintext.
- Provides 100% API parity with Hermes's native `agent/vault_store.py`: exposes `resolve_secret()`, `remove_item()`, `has_items()`, `get_meta()`, `totp_now()`, and `scrub_secret_from_text()`, while keeping backwards-compatible aliases `get_secret()` and `delete_item()`.
- Supports RFC 6238 TOTP non-default parameter preservation (`seed|digits|period|algo`).
- Detects legacy plaintext metadata after migration rather than silently treating it as protected.
- Applies SQLite `secure_delete=ON`.
- Uses `journal_mode=DELETE` for the credential vault database to reduce persistent WAL residue.
- Uses `synchronous=FULL` to favor durability for credential writes.
- Opens connections through a common hardened connection path.

Compatibility effect: public metadata APIs remain readable after decryption, but existing plaintext rows require the migration path on first open. Existing `vault.json.enc`/`vault.key` files are identified as legacy inputs; automatic format migration still needs to be implemented if those files are in use.

### 4. Hermes message encryption and searchable projection

File: `src/floorvault/hermes/session_crypto.py`

Added or changed:

- AES-SIV encryption of message content with AAD bound to `session_id` and `message_id`.
- HMAC-tokenized search projections by default.
- Keyed query transformation through `secure_search_query()`.
- Domain separation using `hermes.messages.fts.v1`.
- Explicit legacy compatibility mode through `allow_plaintext_fts=True`.
- Existing secret-scrubbing support remains available for that compatibility mode.

Security effect: the default search projection no longer stores ordinary message words in plaintext.

Functionality effect: keyed token search supports exact token matching, but does not automatically preserve normal phrase, prefix, fuzzy, substring, snippet, or CJK/trigram search semantics.

### 5. Memory and crash-residue hardening

File: `src/floorvault/memory.py` and `scripts/memory_probe.py`

The implementation now provides best-effort platform hooks for:

- Core-dump limits on macOS/Linux.
- `mlock()` on macOS/Linux.
- `madvise()` protections against dump and fork inheritance where available.
- `VirtualLock()` on Windows.
- Deterministic zeroization and unlock on wipe.
- A portable capability probe for the current host.
- Required mode that refuses operation when page locking fails.

Limitation: Python, ctypes, OpenSSL, and SDK calls may still create temporary immutable copies of key or plaintext material. These protections reduce exposure; they do not prove that every copy is absent.

### 6. Documentation and validation additions

Files:

- `README.md`
- `scripts/security-check.sh`
- `scripts/memory_probe.py`
- `tests/test_memory_platform_probe.py`
- Updated adaptive-provider and Hermes-adapter tests

Added documentation and checks cover:

- Explicit key-source requirements.
- Blind-index leakage and search limitations.
- Best-effort memory-hardening language.
- Key-file ownership and permission checks.
- SQLite durability/residue settings.
- Memory capability reporting.

## Validation performed

The hardened FloorVault test suite passed locally with 37 tests. The security-check script also passed:

- Secret scanning (Gitleaks).
- Dependency audit (pip-audit).
- Ruff checks and formatting.
- RFC encryption vectors.
- Memory-custody tests.
- Blind-index and SQLite tests.
- Hermes adapter (including full native `VaultStore` API parity and Unicode search tokenization) and adaptive-provider tests.
- Standalone execution of host memory capability probe script.
- Source and wheel builds.

The current macOS memory probe reported successful core-dump, crash-dump, fork-exclusion, and memory-lock capability results. Linux and Windows runtime validation has not been executed.

## Known limitations and follow-up work

1. Wire `HermesSessionCrypto` into Hermes's real `SessionDB.append_message()`, batch writers, and search implementation.
2. Design and run an offline migration for existing Hermes `state.db` plaintext message and FTS data.
3. Decide how to preserve or intentionally replace Hermes phrase, CJK trigram, snippet, and fuzzy search behavior beyond token-exact matching.
4. Implement/import migration from any legacy Hermes credential-vault format actually present on the target installation.
5. Complete Linux and Windows runtime validation.
6. Benchmark encryption, decryption, indexing, and search overhead against representative Hermes workloads.

## Overall assessment

The changes materially improve protection against database theft, row/column ciphertext splicing, plaintext metadata exposure, insecure local key files, and several crash/swap/fork residue paths. They introduce operational key configuration, migration requirements, and narrower default search semantics. The credential-vault adapter is still close to a direct replacement at the API level; full encrypted Hermes state replacement remains a separate integration project.

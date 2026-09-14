# FloorVault Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the verified FloorVault integrity and key-lifecycle defects while preserving legitimate encrypted-vault behavior.

**Architecture:** Make legacy conversion explicit and one-time, require persisted key creation to succeed, reject weak implicit key derivation, and make session binding strict for new reads. Correct memory-advice constants and fail closed when required advice cannot be verified. Keep existing ciphertext format and public APIs where possible.

**Tech Stack:** Python 3, `sqlite3`, PyCA `cryptography`, macOS Security API, POSIX/Windows memory APIs, pytest.

**Spec:** `docs/FLOORVAULT-SECURITY-REVIEW-2026-09-14.md`

## Global Constraints

- Do not modify or access production vault data or real Keychain entries.
- Preserve existing ciphertext envelopes and valid current-vault reads.
- Do not silently reinterpret weak secrets as cryptographic keys.
- Every behavior change gets a failing regression test before implementation.

### Task 1: Authenticate legacy metadata migration

**Files:** Modify `src/floorvault/vaultkit/vault.py`; test `tests/test_vaultkit_adapter.py`.

- [ ] Add a test proving a plaintext replacement in an already migrated row is rejected rather than re-encrypted.
- [ ] Run that test and confirm it fails under automatic migration.
- [ ] Add an explicit migration marker/schema transition and make normal opens reject legacy plaintext after the migration boundary.
- [ ] Preserve first-open migration for genuine legacy databases through an explicit migration path.
- [ ] Run migration and lifecycle tests.

### Task 2: Make Keychain creation durable and key input strict

**Files:** Modify `src/floorvault/providers/adaptive.py`; test `tests/test_adaptive_provider.py`.

- [ ] Add tests for rejected weak environment values and failed Keychain insertion.
- [ ] Run them red.
- [ ] Require exact 32-byte raw or 64-character hex environment keys; check `SecItemAdd` status and resolve duplicate races by re-reading the persisted item.
- [ ] Run provider tests.

### Task 3: Remove unsafe legacy session fallback

**Files:** Modify `src/floorvault/vaultkit/session_crypto.py`; test `tests/test_vaultkit_adapter.py`.

- [ ] Add a test that legacy un-namespaced ciphertext is rejected by the normal decrypt API.
- [ ] Run it red.
- [ ] Remove ambient cross-session fallback; expose any migration only as an explicit caller-controlled operation.
- [ ] Run session and adapter tests.

### Task 4: Correct memory hardening semantics and cleanup

**Files:** Modify `src/floorvault/memory.py`, `src/floorvault/core.py`, `scripts/memory_probe.py`; test `tests/test_memory_custody.py` and `tests/test_crypto_core.py`.

- [ ] Add tests for platform-specific advice constants/result handling and engine cleanup state.
- [ ] Run them red.
- [ ] Use Linux DONTFORK=10 and DONTDUMP=16, isolate platform constants, check advice return codes, clear the AES reference on wipe, and report only observed protections.
- [ ] Run focused crypto and custody tests on the current host.

### Task 5: Final verification

- [ ] Inspect the complete diff and run `git diff --check`.
- [ ] Run the focused suites, then the repository test suite if dependencies are available.
- [ ] Reconcile the report wording with the implemented guarantees.

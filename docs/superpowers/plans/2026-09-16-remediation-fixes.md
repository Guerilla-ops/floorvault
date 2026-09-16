# FloorVault Remediation Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the four repository-wide findings from the 2026-09-16 remediation report and add regression/mutation coverage for each failure class.

**Architecture:** Preserve the existing provider APIs and storage formats. Make adaptive custody dispatch explicit, make migration identity persistent through retirement records, make rotation journal writes conditional on a successful row update, and validate protected stores from the opened descriptor. Add focused tests plus curated mutation anchors so future regressions fail the security gate.

**Tech Stack:** Python 3.10+, pytest, cryptography, SQLite, Ruff, custom mutation harness.

**Spec:** `docs/REMEDIATION-REPORT-2026-09-16.md`

## Global Constraints

- Preserve environment-key precedence and existing ciphertext/store compatibility.
- Do not silently rotate existing persisted keys when adding native provider dispatch.
- Every production change gets a failing regression test first.
- Existing Linux, macOS, Windows-simulation, migration, and rotation tests must remain green.

### Task 1: Make legacy migration idempotent

**Files:**
- Modify: `src/floorvault/migration.py`
- Test: `tests/test_migration.py`

- [x] Add a test that calls `migrate_all()` twice and asserts one modern record and one retirement per legacy ID.
- [x] Run that test and confirm it fails because the current code creates a duplicate.
- [x] Use `retired_modern_id()` as the authoritative existing mapping and reject a tombstone whose modern record is missing.
- [x] Add stable modern IDs so a retry after row creation can finish without duplication.
- [x] Run migration tests and the full suite.

### Task 2: Dispatch adaptive custody to native providers

**Files:**
- Modify: `src/floorvault/providers/adaptive.py`
- Modify: `src/floorvault/providers/__init__.py` only if exports are needed
- Test: `tests/test_adaptive_provider.py`

- [x] Add platform-dispatch tests with injected native providers or platform fakes.
- [x] Run them and confirm they fail on the current non-macOS-only dispatch.
- [x] Add explicit Windows and Linux provider selection while preserving macOS behavior and file fallback opt-in.
- [x] Run provider tests and the full suite.

### Task 3: Prevent false rotation completion

**Files:**
- Modify: `src/floorvault/vaultkit/vault.py`
- Test: `tests/test_rotation.py`

- [x] Add a missing-item test asserting no journal row is written.
- [x] Run it and confirm the current implementation records `done` for zero updated rows.
- [x] Check the `UPDATE` row count and raise inside the transaction before writing journal rows.
- [x] Run rotation tests and the full suite.

### Task 4: Bind protected-store validation to the opened file

**Files:**
- Modify: `src/floorvault/providers/platform_custody.py`
- Test: `tests/test_protected_store_safety.py`

- [x] Add tests for regular-file validation and descriptor-based stat use.
- [x] Run them and confirm the current implementation lacks the invariant.
- [x] Keep the descriptor open through validation, use `fstat`, reject non-regular files, and preserve platform permission checks.
- [x] Run custody tests and the full suite.

### Task 5: Extend scans and mutation coverage

**Files:**
- Modify: `scripts/mutation_check.py`
- Modify: `scripts/security-check.sh` only if a new scan command is required
- Test: `tests/test_migration.py`, `tests/test_rotation.py`, `tests/test_adaptive_provider.py`, `tests/test_protected_store_safety.py`

- [x] Add curated mutants for the migration idempotency guard, adaptive native dispatch, rotation row-count guard, and descriptor-based validation.
- [x] Run the curated mutation gate; all 46 behavioral mutants were killed and both canaries survived.
- [x] Run lint, formatting, dependency audit, wheel validation, and the full test suite.

### Task 6: Review and handoff

- [x] Inspect the final diff and `git diff --check`.
- [x] Confirm the remediation report remains present.
- [x] Report tests, scans, changed files, and the platform-only verification not available locally.

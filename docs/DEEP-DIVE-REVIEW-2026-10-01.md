# FloorVault Independent Deep-Dive Review

**Date:** 2026-10-01
**Reviewer:** Independent (evidence-led against executable source)
**Revision reviewed:** `2aa95697783b92b493ade5bc37f6f85f7fe5d169` (branch `main`, == `origin/main`)
**Working tree at review time:** clean except two uncommitted edits made during this review's
companion simplify pass (`src/floorvault/beacons.py`, `src/floorvault/migration.py`).
**Method limits:** ran the unit suite and the local security gate on macOS only; did NOT run the
Windows/Linux CI legs, real DPAPI, or a live Secret Service session. No live-service probe was
performed. All findings are from source reading plus local execution.

---

## 1. What this is

`floorvault` 0.1.0 is a pure-Python application-layer encryption library: AES-256-SIV (RFC 5297)
field encryption for SQLite with contextual AAD binding, a platform-adaptive master-key custody
layer, a structured credential `VaultStore`, resumable key rotation, authenticated master-key
recovery, and an opt-in searchable-beacon module. ~4,800 lines of source across 21 modules;
348 test functions.

## 2. Verified good (checked against code, not docs)

- **Crypto core is sound in construction.** `AESSIV` (cryptography binding) with HKDF-SHA256
  domain separation (`floorvault-v1-aes-siv`); the 7-byte v2 header (magic, crypto_version,
  key_id, nonce_len) is authenticated as a separate AD component, so a rewritten `crypto_version`
  or `key_id` fails authentication rather than being ignored (`core.py:307`). v1 envelopes stay
  readable via the two-component AD path (`core.py:311-319`).
- **Fail-closed custody.** `KeyRing` refuses a record naming an unheld key id instead of trying
  every key (`keyring.py:101-125`). `AdaptiveKeyProvider` raises `CustodyDowngradeError` when a
  native tier is present-but-unusable rather than silently weakening (`adaptive.py:159-176`).
  Protected-store writes are create-never-replace via `os.link` no-clobber (`platform_custody.py:241-263`).
- **Descriptor-bound store validation.** `read_protected()` validates the *opened descriptor*
  (`os.fstat`), re-checks path identity (`st_dev`/`st_ino`), owner, size, header, length and
  permissions before closing (`platform_custody.py:299-347`). The F-4 pathname race from the
  remediation report is closed.
- **All four remediation-report findings (2026-09-16) are fixed in HEAD:**
  | # | Finding | Status at HEAD |
  |---|---|---|
  | F1 | Adaptive provider bypassed native Windows/Linux custody | FIXED — `adaptive.py:92-114` dispatches per platform |
  | F2 | `migrate_all()` duplicated records | FIXED — tombstone-authoritative + deterministic id (`migration.py:181-184,290-298`) |
  | F3 | Rotation journal could mark a missing item done | FIXED — `write_sealed_item` requires `rowcount == 1` (`vaultkit/vault.py:713-714`) |
  | F4 | Protected-store validation pathname-based after read | FIXED — descriptor-bound (`platform_custody.py:299-347`) |
- **Test suite green:** `356 passed, 4 skipped` (macOS). `ruff check` clean; `ruff format --check`
  clean after the companion fix. No dead modules (every module is imported by src and/or tests).
- **Honest documentation of limits** throughout (best-effort FTS scrub, immutable `get_bytes()`
  copies, process-wide/permanent `disable_core_dumps()`, revision-bound replay protection).

## 3. Live findings (reproduced on this machine)

### 3.1 Security gate is RED on `main` — dependency audit fails (blocker) — FIXED during this review
`scripts/security-check.sh` exits 1 at **stage 2 of 11** (`pip-audit`): the lock resolved
`urllib3==2.7.0`, which carries **CVE-2026-97687, CVE-2026-97688, CVE-2026-97689**; all three are
fixed in `urllib3>=2.8.0`. Stage 1 (gitleaks) passes; stages 3-11 never run because the gate is
deliberately fail-closed. The vulnerable package is in the dev/audit toolchain, not the runtime
surface, but `main` was not release-green until the lock was bumped.

**Applied fix:** `uv lock --upgrade-package urllib3` → `2.8.0`, then `uv sync --extra dev`.
`pip-audit` now reports "No known vulnerabilities found". (PR #2 does the same; this is the local
equivalent.)

### 3.2 Documentation drift — architecture report contradicts the current tree (stale baseline)
`docs/FLOORVAULT-ARCHITECTURE-CRYPTO-REPORT-2026-09-16.md:11` states the beacon/search surface was
**removed** ("beacon APIs ... are no longer part of the implementation"; §"Security impact of
removing search" lists "the standalone blind-index/beacon module and package exports" as removed).
But commit `133aa3b` (2026-09-23, a week *after* that report) **re-added** `floorvault.beacons` as
an opt-in public module, now documented in `README.md` and `SECURITY.md §5`. The report also cites
commit `123d1b97` and a baseline of `234 passed, 5 skipped`, versus HEAD `2aa9569` and `356 passed,
4 skipped` today. The report describes a state that was subsequently reversed.

Note: `tests/test_repository_hygiene.py:90` asserts `not hasattr(FloorVault, "beacon")` and still
passes — beacons live in a separate module, not as a `FloorVault` method — so the hygiene guard is
too narrow to catch the re-addition.

**Applied fix (docs only):** added a `SUPERSEDED (2026-10-01)` banner to the report and an inline
correction at the false beacon claim, pointing to the current state. The report is retained as a
dated historical snapshot rather than rewritten.

### 3.3 `core.py` wipe/encrypt race — "thread-safe" over-promises (altitude) — FIXED during this review
The thread-safety hardening scoped its `threading.Lock` to `_track_nonce` and `wipe`
(`core.py:246-253,487-492`), but `encrypt()`/`decrypt()` read `self._closed` (`core.py:279,409`)
and dereference `self._aead_siv` (`core.py:307,428`) **outside** that lock. A `wipe()` that wins
the lock between `_track_nonce` and the engine call nulls `_aead_siv` and tears an in-flight
`encrypt()` with an `AttributeError`.

**Applied fix:** `encrypt`/`decrypt`/`decrypt_bytes` now snapshot the engine reference and the
closed-state atomically under `self._lock` before use (the reviewer's non-serializing option, so the
crypto path is not globally serialized). A concurrent `wipe()` can null the slot without tearing
the call; it still refuses any subsequent operation.
**Regression tests:** `tests/test_crypto_core.py::test_wipe_after_nonce_tracking_does_not_tear_encrypt`
(deterministic — wipe fired from inside `_track_nonce`, after the snapshot point) and
`::test_concurrent_wipe_never_raises_attribute_error` (stress). The deterministic test fails on the
pre-fix code with the exact `AttributeError: 'NoneType' object has no attribute 'encrypt'`, and
passes with the fix. *Original confidence was medium — now confirmed live.*

### 3.4 `platform_custody.py` ancestor-symlink loosening (altitude) — FIXED during this review
`_mkdir_owner_only` reassigned `directory = directory.parent.resolve() / directory.name`
(`platform_custody.py:155`) before the walk-up loop. `resolve()` follows **every** ancestor, so the
loop's ancestor `S_ISLNK` checks (`:166-167`) were effectively dead for all parents: any ancestor
symlink — including an attacker-controlled one — was silently followed and accepted.

**Applied fix:** added `_is_system_symlink()` and an ancestor-symlink rejection loop that runs
*before* the `resolve()` call. Any ancestor symlink that is not a root-owned system firmlink (macOS
`/tmp`, `/var`) is refused, so a user-writable parent symlink can no longer redirect the vault; the
macOS `/tmp` case still works. The practical impact had been limited (the created leaf is still
`0700` + owner-checked), and it remains so.
**Regression test:** `tests/test_protected_store_safety.py::test_mkdir_owner_only_rejects_a_symlinked_ancestor`
— fails on the pre-fix code with "DID NOT RAISE ValueError", passes with the fix. The existing `/tmp`
firmlink test still passes (44 passed in the file).

### 3.5 `linux_keyring` default remains the less-safe posture (staged migration)
`LinuxSecretServiceKeyProvider.__init__` keeps `allow_file_fallback=True` by default
(`linux_keyring.py:115`). The disk-custody hardening is re-established only through the facade:
`AdaptiveKeyProvider` passes `allow_disk_fallback` through (`adaptive.py:108`). A direct/standalone
caller of the provider still silently reads the masked `master.key.ss` store that the new tests
declare forbidden. The diff documents this as an intentional backward-compat shim, so per
Chesterton's Fence this reads as a deliberate staged migration, not an oversight. *Confidence: low
(deliberate trade).*

### 3.6 Windows test fails on the CI matrix (test defect) — FIXED during this review
`tests/test_memory_custody.py:158` unconditionally monkeypatched `mem.resource.setrlimit`. On
Windows, `import resource` raises `ImportError` so `mem.resource is None` (`memory.py:15-18`), and
the `setattr` raised `AttributeError: 'NoneType' object has no attribute 'setrlimit'`. The test
never failed locally (macOS/Linux both have `resource`).

**Applied fix:** guarded the patch with `if mem.resource is not None:`. The test body still holds on
Windows — `resource is None` already forces `disable_core_dumps()` to return `False`, which drives
the same `SecurityHardeningError` path. Verified both paths: POSIX custody tests (10 passed) and a
simulated Windows run (`resource = None`) where `required` raises and `opportunistic` reports
`False`. Full suite remains `356 passed, 4 skipped`; ruff clean. (Origin: PR #2 discussion, comment
5931686636 — the proposal there was `pytest.skip`, which drops Windows coverage; the guard keeps it.)

## 4. Minor observations

- `memory.py:82` sets `self._core_dumps_disabled = False` eagerly, then unconditionally overwrites
  it at `:92`. Harmless; only matters for a partially-initialised instance. Low value.
- `inspector.py` prints decrypted plaintext to stdout (`:86`) — documented as secret-bearing output.
- `SessionCrypto` FTS scrub is explicitly best-effort and off by default (`session_crypto.py:26-37`).
- `pip-audit` emits repeated `Cache entry deserialization failed` warnings — cosmetic.

## 5. Prioritised recommendations

1. ~~**Unblock the gate:** merge PR #2 (or bump `urllib3` to `2.8.0` in `uv.lock`).~~ **DONE** —
   `uv.lock` bumped to urllib3 2.8.0; `pip-audit` clean.
2. ~~**Fix the Windows test guard** (`tests/test_memory_custody.py:158`) so the Windows CI leg
   passes.~~ **DONE** — guarded the `resource` patch; verified on the POSIX path and a simulated
   Windows path.
3. ~~**Refresh or supersede the architecture report**~~ **DONE** — added a `SUPERSEDED` banner and an
   inline correction to the report (retained as a historical snapshot).
4. ~~**Decide on the `core.py` wipe/encrypt race**~~ **DONE** — engine snapshot under the lock;
   regression tests added and shown to fail on the pre-fix code.
5. ~~**Review the `platform_custody` ancestor-resolve trade**~~ **DONE** — ancestor symlinks are now
   validated before resolve; user-writable parent symlinks are refused, macOS firmlinks still work.

All findings are now fixed or explicitly accepted. Remaining accepted item: 3.5 (`linux_keyring`
default) is left as a deliberate staged migration — not a defect.
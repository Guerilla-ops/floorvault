# FloorVault Repository Remediation Report

Date: 2026-09-16  
Repository: `vaultfloor/floorvault`  
Reviewed revision: `32eaaa6`

## Executive summary

The repository's current tests and security gates are green, but the review found
four correctness and security-boundary issues that are not covered by the existing
tests:

1. `AdaptiveKeyProvider` does not dispatch to the existing Windows DPAPI or Linux
   Secret Service providers.
2. `MigratingVaultStore.migrate_all()` is not idempotent and duplicates records on
   repeated runs.
3. Rotation journaling can mark a missing item as completed.
4. Protected-store permission validation is path-based after the protected file
   descriptor has already been closed, creating a pathname race.

The recommended order is to fix migration idempotency first, then adaptive provider
dispatch, then rotation row-count validation, and finally harden protected-store
validation around the opened descriptor. Each change should land with a regression
test and be verified on the existing Linux, macOS, and Windows CI matrix.

## Current verification baseline

At the reviewed revision:

- 251 tests passed and 5 were skipped.
- Ruff lint and formatting checks passed.
- `pip-audit` reported no known vulnerabilities.
- The universal wheel check passed.
- All 39 curated behavioral mutants were killed; the intentional canaries survived.

These results establish a good regression baseline, but they do not exercise the
four scenarios described below.

## Finding 1: adaptive provider bypasses native Windows and Linux custody

Severity: High  
Location: `src/floorvault/providers/adaptive.py:66-75`

### Problem

`AdaptiveKeyProvider.resolve_key()` probes environment variables, then calls
`_resolve_from_system_keyring()`. That helper only contains a macOS Keychain path;
on Windows and Linux it immediately returns `None`. The provider then falls back
to the local file path or raises because file fallback is disabled.

The repository already contains `WindowsDPAPIKeyProvider` and
`LinuxSecretServiceKeyProvider`, but the default adaptive path never selects them.
This makes the cross-platform quickstart misleading and can cause deployments to
use weaker file custody when an OS-native provider is available.

### Recommended fix

Introduce explicit platform dispatch in `AdaptiveKeyProvider`, while preserving the
existing environment-variable override and fail-closed behavior:

1. Keep the environment-key path first.
2. On macOS, use the existing Keychain implementation.
3. On Windows, construct/use `WindowsDPAPIKeyProvider` with the configured store
   location and custody parameters.
4. On Linux, use `LinuxSecretServiceKeyProvider` when a desktop Secret Service is
   available.
5. Only use the local-file tier when the caller explicitly enables it.
6. Translate provider-specific missing/unavailable errors consistently without
   swallowing a present-but-unusable native store.

Avoid silently changing existing persisted locations. Either add a documented
provider-factory method or make the adaptive provider accept injected native
providers so applications can control migration and test doubles.

### Required tests

- Simulated Windows selects DPAPI and never creates the plaintext fallback file.
- Simulated Linux with Secret Service available selects Secret Service.
- Linux desktop with unavailable Secret Service fails closed.
- Headless Linux can use the explicitly enabled protected-file fallback.
- macOS Keychain success, absence, and unusable-status behavior remain unchanged.
- Environment key precedence remains unchanged on every platform.

## Finding 2: batch migration duplicates records

Severity: High  
Location: `src/floorvault/migration.py:256-261`

### Problem

`migrate_all()` tests whether `modern.get_meta(item_id)` exists, but `item_id` is
the legacy identifier. `_upgrade_legacy_item()` creates a new random modern ID,
then records the relationship only in the retirement tombstone. Therefore a second
call cannot find the existing modern record by the legacy ID and migrates the same
legacy item again.

Observed behavior:

```text
first migrate_all(): 1 modern item, migrated=1
second migrate_all(): 2 modern items, migrated=1
```

The second run also replaces the retirement mapping with the newest duplicate,
leaving the earlier modern record orphaned.

### Recommended fix

Use the retirement tombstone as the authoritative idempotency check:

1. For each legacy ID, call `modern.retired_modern_id(item_id)` first.
2. If it returns a modern ID, verify that the modern record still exists.
3. If the modern record exists, count the item as already migrated and do not
   create another record.
4. If the tombstone exists but the modern record is missing, fail migration closed
   and report that repair/recovery is required; do not silently recreate the item.
5. If no tombstone exists, migrate once and create the modern record plus tombstone
   as one logical operation.

For stronger crash safety, add a stable legacy-ID mapping table or allow the modern
record ID to be deterministically derived from the legacy ID under a migration
namespace. The tombstone approach is the smallest compatible fix.

### Required tests

- Calling `migrate_all()` twice creates no duplicate rows.
- A fresh facade instance remains idempotent; in-memory maps must not be required.
- A tombstone pointing to a missing modern row fails closed.
- A crash/failure between modern-row creation and tombstone creation is recoverable
  without creating a duplicate.
- `verify()` reports the correct number of logical migrated items.

## Finding 3: rotation journal can acknowledge a missing item

Severity: Medium  
Location: `src/floorvault/vaultkit/vault.py:727-746`

### Problem

`write_sealed_item()` executes an `UPDATE` and then writes supplied journal rows,
but never checks `cursor.rowcount`. If `item_id` does not exist, the update changes
zero rows while the journal records the work as `done`.

This can happen because of a stale rotation queue or a concurrent deletion. A
rotation coordinator may then believe the item was moved to the new key and retire
the old key, even though no row was re-sealed.

### Recommended fix

Capture the update cursor and require exactly one affected row before writing the
journal entries:

```python
cursor = conn.execute(...)
if cursor.rowcount != 1:
    raise VaultError(f"Vault item not found during rotation: {item_id}")
self._write_journal_rows(...)
```

The exception must roll back the transaction, including any journal entries. If
duplicate IDs are impossible because of the primary key, `rowcount != 1` is the
appropriate invariant.

### Required tests

- A missing item raises and leaves the journal unchanged.
- A deleted item cannot be marked `done` after a concurrent/stale rotation.
- A successful update still records its journal row in the same transaction.
- A failure while writing journal rows rolls back the re-sealed record.

## Finding 4: protected-store validation is pathname-based after reading

Severity: Medium  
Location: `src/floorvault/providers/platform_custody.py:180-213`

### Problem

`read_protected()` opens the store with `O_NOFOLLOW`, reads from the descriptor,
closes it, and then calls `os.stat(path)` to validate permissions. The pathname is
not guaranteed to refer to the same inode after the descriptor is closed. A caller
with the ability to modify the containing directory can replace the path between
the read and the permission check.

The function's docstring also promises regular-file validation, but the current
implementation does not explicitly check `stat.S_ISREG` on the object that was
opened.

### Recommended fix

Keep the file descriptor open through validation and use descriptor-based metadata:

1. Call `os.fstat(fd)` immediately after opening.
2. Reject non-regular files.
3. Validate size, ownership, and POSIX mode from that `stat_result`.
4. On Windows, perform ACL validation against the opened handle where the platform
   API permits; otherwise document and minimize the remaining pathname race.
5. Only close the descriptor after all checks have completed.

The same descriptor-bound principle should be applied to the adaptive file provider
where practical. Keep the no-symlink and no-clobber behavior intact.

### Required tests

- Non-regular stores are rejected without blocking or being read as keys.
- Permission checks use the opened object rather than a replacement pathname.
- Symlinks remain rejected.
- Existing Windows ACL and POSIX mode tests remain green.
- Oversized, truncated, malformed-header, and invalid-length stores retain their
  distinct error types.

## Implementation sequence

### Phase 1: migration safety

Fix the retirement-based idempotency check and add the repeated-run tests. This is
the highest data-integrity risk because it can silently create duplicate credentials
without causing verification to fail.

### Phase 2: native custody dispatch

Add platform-selection tests first, then implement the adaptive provider factory.
Run the provider tests on all CI platforms and confirm that no native provider
silently downgrades to a local file.

### Phase 3: rotation accounting

Add the row-count invariant and rollback tests. Review the rotation coordinator's
caller after this change to ensure stale journal entries are retried or surfaced as
operator-visible failures.

### Phase 4: descriptor-bound store validation

Refactor protected-store reads around `fstat`, then rerun platform custody and
mutation tests. Keep this change isolated because it touches Windows and POSIX
security semantics.

## Release and rollout guidance

Before release:

- Run the full `scripts/security-check.sh` gate with secret scanning enabled.
- Run the complete test matrix on Python 3.10 through 3.14 where supported.
- Exercise real DPAPI on Windows and Secret Service on a Linux desktop session.
- Test opening stores created before the migration and rotation changes.
- Document whether the adaptive provider may migrate an existing file-backed key to
  native custody automatically. Default behavior should avoid silent key rotation.
- Treat duplicate migration detection and missing-row rotation errors as explicit
  operational events, not as recoverable “not found” fallbacks.

## Acceptance criteria

The remediation is complete when:

- `migrate_all()` is idempotent across processes and never creates duplicate modern
  records for one legacy ID.
- The adaptive provider selects the native provider for the current OS and only
  uses file custody when explicitly enabled.
- Rotation cannot mark an item complete unless exactly one row was re-sealed.
- Protected-store validation is bound to the opened file object as far as each OS
  permits.
- Existing tests remain green and new regression tests fail against the current
  implementation before each fix is applied.
- The full CI/security gate passes on the supported platform matrix.

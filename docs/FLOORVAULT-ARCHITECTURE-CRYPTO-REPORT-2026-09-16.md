# FloorVault Architecture and Cryptography Report

**Reviewed commit:** `123d1b97a2ed93bcadd19853f6578e84acfcd503` plus the local search-surface removal change.

**Evidence boundary:** This report uses executable source, tests, package configuration, security scripts, and `SECURITY.md`. `README.md` was not used as evidence.

## Executive summary

FloorVault is a Python application-layer encryption library built around `FloorVault`, a contextual AES-256-SIV engine, and `VaultStore`, a structured SQLite credential store. Key custody is separate from data encryption and supports explicit environment keys, Windows DPAPI, Linux Secret Service, macOS Keychain, and an explicitly enabled weaker file fallback.

The application-level search surface has now been removed: `origin_idx`, `VaultStore.find_by_origin()`, full blind-index APIs, beacon APIs, and keyed FTS search projections are no longer part of the implementation. SQLite records are now retrieved by known identifiers or by an outer database/query layer such as SQLCipher.

## Architecture

The public package is organized into these layers:

- `core.py`: contextual encryption envelopes, AAD, nonce tracking, revision binding, and lifecycle.
- `vaultkit/vault.py`: SQLite schema, item validation, encrypted metadata/payload storage, migration, and rotation primitives.
- `providers/`: master-key resolution and protected-store handling.
- `memory.py`: unmanaged key buffers, page locking attempts, dump/fork controls, and zeroization.
- `migration.py`: non-destructive legacy Fernet/JSON migration with retirement tombstones.
- `keyring.py`: per-record key-generation selection during rotation.
- `sqlite_adapter.py`: table-bound encryption/decryption helpers.

`VaultStore` constructs an `AdaptiveKeyProvider`, resolves a master key, constructs `FloorVault`, then initializes SQLite (`src/floorvault/vaultkit/vault.py:214-226`). The database uses `secure_delete = ON`, rollback journaling, and `synchronous = FULL` (`src/floorvault/vaultkit/vault.py:228-285`). These settings reduce residue and improve durability; they are not database encryption by themselves.

The current `vault_items` table stores operational fields (`id`, `kind`, `has_otp`) and encrypted metadata/payload fields. There is no searchable index column (`src/floorvault/vaultkit/vault.py:228-277`). Existing databases containing the removed `origin_idx` column are rebuilt without it while preserving the remaining columns (`src/floorvault/vaultkit/vault.py:300-328`).

## Core functions

| Function/class | Responsibility | Source |
|---|---|---|
| `FloorVault.__init__` | Validate the 32-byte master key and derive the SIV key | `src/floorvault/core.py:147-250` |
| `FloorVault.encrypt` / `decrypt` | Context-bound authenticated encryption | `src/floorvault/core.py:270-489` |
| `associated_data` | Canonical coordinate binding | `src/floorvault/core.py:93-141` |
| `VaultStore.add_item` | Validate, normalize, encrypt, and insert items | `src/floorvault/vaultkit/vault.py:370-452` |
| `VaultStore.resolve_secret` | Decrypt and decode payloads | `src/floorvault/vaultkit/vault.py:477-500` |
| `MigratingVaultStore` | Legacy dual-read and verified migration | `src/floorvault/migration.py:54-310` |
| `KeyRing` | Select the authenticated key generation named by an envelope | `src/floorvault/keyring.py:43-171` |
| `AdaptiveKeyProvider` | Platform-aware master-key resolution | `src/floorvault/providers/adaptive.py:25-215` |
| `HardenedMemoryKey` | Key placement, locking attempts, and zeroization | `src/floorvault/memory.py:48-235` |

## Cryptographic construction

### Master key and derivation

`FloorVault` accepts raw bytes or `HardenedMemoryKey` and requires exactly 32 bytes (`src/floorvault/core.py:147-202`). It derives a 64-byte AES-SIV key with HKDF-SHA-256 and the domain string `floorvault-v1-aes-siv` (`src/floorvault/core.py:204-230`). The former separate search/index key is no longer derived.

### Envelope and AAD

The current writer emits:

```text
FLV2 || crypto_version || key_id || nonce_len || nonce || AES-SIV ciphertext
```

The header and 16-byte random nonce are authenticated associated-data components (`src/floorvault/core.py:270-334`). AAD canonically binds application instance, table, record ID, column, schema ID/version, and optional revision (`src/floorvault/core.py:93-141`). Moving a valid ciphertext to another logical coordinate fails authentication. A trusted monotonic revision is required for same-coordinate rollback detection.

The reader supports v1 and v2 envelopes, rejects malformed headers/nonce lengths/versions, authenticates the header, and maps tag failures to `DecryptionVerificationError` (`src/floorvault/core.py:346-489`).

Nonce tracking is a bounded in-process sliding window backed by `os.urandom(16)` (`src/floorvault/core.py:255-268,301-324`). It is not cross-process or cross-restart freshness state.

### Memory custody

`HardenedMemoryKey` uses an unmanaged `mmap`, attempts `mlock`/`VirtualLock`, and on Linux attempts dump/fork protections (`src/floorvault/memory.py:48-170`). `wipe()` closes first, zeros the allocation, unlocks it, and releases the mapping (`src/floorvault/memory.py:198-235`). The default is opportunistic; `required` mode fails when critical protection cannot be applied (`src/floorvault/memory.py:136-155`).

This is best-effort containment, not a proof that Python or cryptographic-library copies never exist: `get_bytes()` necessarily returns immutable bytes (`src/floorvault/memory.py:192-196`).

## Key custody

`AdaptiveKeyProvider` checks explicit environment keys first (`src/floorvault/providers/adaptive.py:49-68`). It then dispatches to Windows DPAPI, Linux Secret Service, or macOS Keychain (`src/floorvault/providers/adaptive.py:81-161`). The local-file tier is weaker and requires explicit opt-in (`src/floorvault/providers/adaptive.py:163-215`).

Protected stores use owner-only directory creation, exclusive temporary files, `fsync`, no-follow flags where available, and no-clobber publication (`src/floorvault/providers/platform_custody.py:78-166`). Reads validate the open descriptor, regular-file type, owner, size, header, payload length, and permissions before closing it (`src/floorvault/providers/platform_custody.py:169-220`).

The local-file fallback is not an independent confidentiality boundary: an attacker able to copy the file can recover the key. Native providers provide the stronger OS-user boundary.

## Migration and rotation

Legacy migration is read-only until explicit migration, creates backups, uses deterministic modern IDs, and records retirement tombstones to prevent deleted modern records from resurrecting legacy values (`src/floorvault/migration.py:109-166,186-203,248-310`).

Rotation uses authenticated v2 `key_id` values and `KeyRing` refuses unknown generations rather than trying keys opportunistically (`src/floorvault/keyring.py:101-125`). Payload, metadata, and rotation journal state are written transactionally (`src/floorvault/vaultkit/vault.py:655-753`). No search index is recomputed during rotation because no search index exists.

## Security impact of removing search

Removed surfaces:

- `origin_idx` storage and its SQLite index.
- `VaultStore.find_by_origin()`.
- `FloorVault.blind_index()` and `ContextualTable.blind_index()`.
- The standalone blind-index/beacon module and package exports.
- Inspector blind-index generation.
- Keyed FTS token projections and query generation in `SessionCrypto`.

Benefits:

- No equality/frequency leakage from full HMAC indexes.
- No coarse bucket metadata from origin beacons.
- No origin-search existence oracle through `find_by_origin()`.
- No candidate-decryption amplification from large beacon buckets.
- Fewer public cryptographic APIs with specialized leakage contracts.

Trade-off: known-ID retrieval remains available, but arbitrary origin/field search is no longer provided by FloorVault. Callers requiring database-wide query support should use a database-level encryption system such as SQLCipher, or implement a separately reviewed query layer with an explicit leakage model.

## Verification

The local suite after the removal reported `234 passed, 5 skipped`. Ruff and the curated mutation suite passed; the mutation suite reported `42 behavioural mutants killed; canary survived`. The repository includes a hygiene test asserting that the removed APIs and `origin_idx` schema column are absent (`tests/test_repository_hygiene.py:87-96`).

## Remaining deployment limitations

1. Same-coordinate replay requires a trusted revision; AES-SIV alone does not provide freshness.
2. Memory hardening is optional unless callers select `memory_mode="required"`.
3. Local-file key custody remains weaker than native OS custody.
4. The inspection CLI prints decrypted values and must be treated as secret-bearing output (`src/floorvault/inspector.py:89-121`).
5. SQLite journaling and secure-delete settings do not replace database-wide encryption if the database file itself must hide schema and operational metadata.

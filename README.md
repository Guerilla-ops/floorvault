<p>
  <img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/floorvault-hero.svg" width="100%" alt="FloorVault. Contextual field encryption. The key and context must match to decrypt.">
</p>

# FloorVault

**Encrypt application data. Bind each field to its context.**

FloorVault is a Python library for field encryption in existing databases. It uses
AES-256-SIV with authenticated context to detect ciphertext moved to the wrong
record, column, table, schema, or application instance.

[Install](#install) · [Quickstart](#quickstart) · [Context binding](#context-binding) ·
[Databases](#databases) · [Key custody](#key-custody) · [Limits](#security-boundaries) ·
[Documentation](#documentation)

**Beta.** The project does not claim a completed independent security audit.
Read the [security model](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md) and [audit packet](https://github.com/Guerilla-ops/floorvault/blob/main/docs/AUDIT-PACKET.md)
before deciding whether it fits your deployment.

| Context | Encryption | Key custody |
| --- | --- | --- |
| The caller supplies the expected record coordinates. Decryption authenticates those values. | Selected fields are stored as authenticated ciphertext. Other database content remains visible. | Choose an OS-backed provider or an explicit key source. Hardware custody is not provided by default. |

## Install

Python 3.10 or newer:

```bash
python -m pip install floorvault
```

In a uv project, use `uv add floorvault`.

FloorVault does not require SQLCipher or a modified database engine. It uses the
`cryptography` package, which includes native components. Availability of binary
wheels determines whether your environment needs a compiler for dependencies.

**This README follows `main`.** PostgreSQL/MySQL adapters and the importable RFC 5297
testing helpers were added after release `0.1.0`. Install from source for those APIs;
pin a reviewed tag or commit when deploying:

```bash
git clone https://github.com/Guerilla-ops/floorvault.git
cd floorvault
python -m pip install .
# Optional drivers for the source-only database adapters:
python -m pip install ".[postgres,mysql]"
```

| Extra | Adds |
| --- | --- |
| `macos` | macOS Keychain bindings; applies on macOS |
| `linux` | Linux Secret Service client |
| `sqlalchemy` | SQLAlchemy ORM adapter |
| `libsql` | Synchronous libSQL driver |
| `postgres` | Psycopg driver; install from source for the adapter |
| `mysql` | MySQL Connector/Python driver; install from source for the adapter |
| `dev` | Development and verification tools |

For example, use `python -m pip install "floorvault[macos]"` for Keychain support.
The base install does not make every OS key store available.

## Quickstart

This in-memory example uses a fresh demonstration key. It needs no database server
or key-store configuration. **Do not generate a new key on every start for persistent
data:** retain the original key through an appropriate custody provider.

```python
from secrets import token_bytes

from floorvault import DecryptionVerificationError, FloorVault

master_key = token_bytes(32)  # Ephemeral demo key, not a persistence strategy.

with FloorVault(master_key, app_instance_id="my-app") as crypto:
    ciphertext = crypto.encrypt(
        "secret value",
        table="credentials", record_id="user-123", column="api_key",
    )
    assert crypto.decrypt(
        ciphertext,
        table="credentials", record_id="user-123", column="api_key",
    ) == "secret value"

    try:
        crypto.decrypt(
            ciphertext,
            table="credentials", record_id="user-456", column="api_key",
        )
    except DecryptionVerificationError:
        print("Different record: authentication rejected.")
    else:
        raise AssertionError("Wrong-context ciphertext was accepted")
```

Exiting the context closes the engine and wipes its managed key buffers. It does
not erase the caller's `master_key` bytes or all copies made by dependencies.

## Context binding

<img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/context-binding.svg" width="100%" alt="The same key and record context return plaintext. With the same key but a different record ID, authentication fails. Context is caller-supplied data, not proof of permission.">

A 32-byte master key is expanded with HKDF-SHA256 into the 64-byte key required by
AES-256-SIV. Each encrypted field is written in an `FLV2` envelope using a random
16-byte nonce. Its authenticated context contains:

| Value | Supplied by |
| --- | --- |
| `app_instance_id` | The application when creating its `FloorVault` engine |
| `table`, `record_id`, `column` | The caller or database adapter |
| `schema_id`, `schema_version` | The caller or adapter's configured defaults |
| `revision`, when used | The caller's expected record revision |

The key and expected context must match the encrypted record. Changing an
authenticated coordinate causes verification to fail. Those coordinates are not
an identity check: FloorVault does not establish who the caller is or whether a
requested operation is allowed. Resolve identity and permission in your application.

Replaying an older ciphertext under the **same** context is not detected by default.
An expected `revision` helps only when an attacker cannot roll that expected value
back with the ciphertext. For SQLite and libSQL tables, the opt-in
`floorvault.freshness.FreshnessAnchor` keeps a keyed digest of the anchored tables
outside the database and refuses one that was rolled back or whose rows were replayed,
deleted, or added — as long as the anchor store sits where the attacker cannot roll it
back too ([SPEC §14.3](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md)). AES-SIV misuse resistance does not make nonce reuse
harmless: repetition of the same key, nonce, context, and plaintext can reveal equality.

## Databases

FloorVault encrypts individual values before the adapter writes them. It does not
create your application schema or own your commits, and it encrypts the entire
database only for local libSQL files opened with `connect_encrypted` (below).

| Integration | Surface | Application responsibility |
| --- | --- | --- |
| SQLite | `EncryptedSQLiteTable` | Create rows and encrypted `BLOB` columns; commit writes |
| libSQL | `EncryptedLibSqlTable`, `connect_encrypted` | Supply a synchronous connection; configure any replica or remote service |
| PostgreSQL | `EncryptedPostgresTable` on `main` | Supply a synchronous DB-API connection and a `BYTEA` column |
| MySQL | `EncryptedMySQLTable` on `main` | Supply a synchronous DB-API connection and a binary column |
| SQLAlchemy | `SqlAlchemyEncryption` | Configure mapped identity and ciphertext fields; use its guarded session factory |

A self-contained SQLite example:

```python
import sqlite3
from secrets import token_bytes

from floorvault import EncryptedSQLiteTable, FloorVault

connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, token_cipher BLOB)")
connection.execute("INSERT INTO users (id) VALUES (?)", ("u1",))

with FloorVault(token_bytes(32), app_instance_id="sqlite-demo") as crypto:
    fields = EncryptedSQLiteTable(connection, crypto, "users", id_column="id")
    fields.store("u1", "token_cipher", "secret-token")
    connection.commit()
    assert fields.load("u1", "token_cipher") == "secret-token"

connection.close()
```

The table adapters validate identifiers, parameterise record IDs, and require a
write to match exactly one existing row. They also provide `store_fields()`,
`load_fields()`, and binary-read variants. Use the same schema version and revision
when reading as when writing. See the [adapter contracts](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md) and
[SQLite](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/sqlite_adapter.py), [libSQL](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/libsql_adapter.py),
[PostgreSQL/MySQL](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/dbapi_adapter.py), and
[SQLAlchemy](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/sqlalchemy_adapter.py) implementations.

### Whole-file encryption for local libSQL

Field encryption leaves the schema, indexes, WAL, and unprotected columns readable to
anyone holding the file. For a local libSQL file, `connect_encrypted` adds libSQL's
native page cipher underneath, keyed by a subkey derived from the same master key:

```python
from floorvault import AdaptiveKeyProvider, EncryptedLibSqlTable, FloorVault, connect_encrypted

master_key = AdaptiveKeyProvider(service_name="my-app").resolve_key()
connection = connect_encrypted("app.db", master_key)  # local files only; creates app.db encrypted
connection.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, api_token_cipher BLOB)")
connection.execute("INSERT OR IGNORE INTO users (id) VALUES (?)", ("u1",))

fields = EncryptedLibSqlTable(connection, FloorVault(master_key, app_instance_id="my-app"), "users")
fields.store("u1", "api_token_cipher", "secret-token")
connection.commit()
assert fields.load("u1", "api_token_cipher") == "secret-token"
```

It refuses remote URLs (a remote server ignores the key), replica options, `:memory:`,
and existing unencrypted files (libSQL cannot encrypt in place). The page cipher hides
the file but does not authenticate it; integrity still comes from FloorVault's field
envelopes. See [SPEC §14.2](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md).

## Key custody

`AdaptiveKeyProvider` checks explicit environment keys first, then the native OS
provider, then an opt-in local file. An unavailable backend and an installed but
unusable backend are different cases; a custody error must not silently become a
weaker store.

| Source | Requirement or limit |
| --- | --- |
| Environment | `FLOOR_VAULT_KEY` or `VAULT_MASTER_KEY`: 64 hexadecimal characters. Plaintext environment custody; refused with `strict=True`. |
| macOS Keychain | Requires the `macos` extra and a usable Keychain. It does not imply Secure Enclave storage. |
| Windows DPAPI | Uses the Windows account boundary and a shared store path, rather than a service-scoped Keychain entry. |
| Linux Secret Service | Requires the `linux` extra and an accessible Secret Service. |
| Local file | Disabled by default. `allow_disk_fallback=True` opts in; an attacker who copies the key file can recover the key. Add `passphrase=` to wrap it under scrypt + AES-SIV so a copy alone is not enough; `protect_key_file()` converts an existing raw file. |
| Vault Transit | Separate `VaultTransitProvider`. A remote key wraps the application master key; the unwrapped master key is used locally. |

For OS-backed custody, construct
`AdaptiveKeyProvider(service_name="my-app", strict=True)` and resolve its key.
It refuses environment-key custody and local-file fallback. `allow_create=False`
resolves existing keys without creating one. Legacy environment names and key-store
adoption require their own explicit opt-ins.

Key custody policy and process-memory hardening are separate settings. The default
memory mode is opportunistic; required mode rejects failures of the checks it
enforces. Where supported, key-handle construction attempts to disable core dumps
process-wide. Neither memory mode establishes a boundary against an attacker who
controls the running process, account, or host.

See [provider behaviour](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/providers/adaptive.py),
[Vault Transit setup](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md), and
[hardware custody design](https://github.com/Guerilla-ops/floorvault/blob/main/docs/HARDWARE-CUSTODY.md). The hardware guide is a proposed
design, not a shipped PKCS#11 provider or a FloorKey integration.

## Security boundaries

| Property | Boundary |
| --- | --- |
| Confidentiality at rest | Protects encrypted fields when an attacker obtains ciphertext without the key. Unencrypted columns, schema, row counts, ciphertext lengths, and access patterns are not hidden. |
| Context integrity | Detects ciphertext authenticated under different expected coordinates. The caller remains responsible for choosing trustworthy coordinates. |
| Freshness | No whole-database rollback protection. A trusted external expected revision is needed to reject older same-context records. |
| Memory | Managed buffers can be wiped; Python objects, plaintext, provider copies, and dependency internals can retain other copies. |
| Search | Optional beacons enable equality lookups but expose equality/bucket information and statistical structure. Decrypt candidates to confirm a match. |
| Migration | Encryption does not remove the plaintext source. Cleanup can reduce residue in SQLite pages and WAL files; deletion alone does not guarantee erasure from snapshots, backups, or storage media. |
| Application control | Does not authorise agent actions, isolate processes, prevent plaintext logging, or supply hardware trust. |

Protect keys, backups, and endpoints as part of the deployment. Read
[SECURITY.md](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md) for the full threat model and platform limitations.

## Additional APIs

| Capability | Entry points and guidance |
| --- | --- |
| Custom record binding | `RecordBinding`, `ContextualSQLite`; [specification](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md) |
| Equality search | `BeaconIndexer`, `derive_beacon_key`, `suggest_beacon_bits` in [beacons.py](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/beacons.py). Choose width for the dataset and its leakage budget. |
| Plaintext migration | `migrate_plaintext_column`, `verify_encrypted_column`, `drop_plaintext_column`; [implementation](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/sqlite_migration.py) |
| Rotation | `KeyRing`, `rotate_vault_store`; [rotation contract](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/vault_rotation.py). Make the new key resolvable, retain both generations when resuming, and rebuild stores on the new engine. |
| Recovery | `wrap_master_key`, `recover_master_key`; [recovery contract](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/key_recovery.py). Keep the recovery key separate and protected. |
| Conformance testing | `floorvault.testing.siv_reference` on `main`; [reference API](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/testing/siv_reference.py). Raw AES-SIV helpers are test support, not the application envelope API. |

`floorvault inspect` opens an existing SQLite database read-only and **decrypts**
the selected field. Output is redacted by default; `--reveal` prints plaintext.
Match the original service/key source and application instance. Inspection does not
create a missing key. See the [CLI](https://github.com/Guerilla-ops/floorvault/blob/main/src/floorvault/inspector.py).

## Evidence and releases

The [CI configuration](https://github.com/Guerilla-ops/floorvault/blob/main/.github/workflows/ci.yml) defines Linux Python 3.10–3.14 jobs
and macOS/Windows Python 3.10 and 3.13 jobs. A workflow configuration is not evidence
that every platform's native custody path was exercised successfully; consult the
individual run results and [platform findings](https://github.com/Guerilla-ops/floorvault/blob/main/docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md).

The [release workflow](https://github.com/Guerilla-ops/floorvault/blob/main/.github/workflows/release.yml) checks repeat builds on the
same runner and includes provenance-attestation and publishing steps. That is not
a guarantee of identical artifacts across platforms or proof of any particular
download's provenance. Follow the [release verification guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RELEASING.md)
for the artifact and version you use.

The [September 2026 benchmark](https://github.com/Guerilla-ops/floorvault/blob/main/docs/COMPARATIVE-BENCHMARK-2026-09-15.md) records one
host, payload, and workload. It does not establish universal performance superiority
or the cost of database I/O. Use the included harness for your workload.

## Documentation

- [Security model and reporting](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md)
- [Protocol, context encoding, and adapter contracts](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md)
- [Record envelope format](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RECORD-FORMAT-2026-09-15.md)
- [External audit orientation](https://github.com/Guerilla-ops/floorvault/blob/main/docs/AUDIT-PACKET.md)
- [Vault Transit](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md)
- [Proposed hardware custody](https://github.com/Guerilla-ops/floorvault/blob/main/docs/HARDWARE-CUSTODY.md)
- [Release process](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RELEASING.md)

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Guerilla-ops/floorvault/security/advisories/new)
or **floorbond@pm.me**. Keep security reports out of public issues and pull requests.

## Development

```bash
uv sync --extra dev
uv run pytest
bash scripts/security-check.sh
```

The full gate also needs its external scanning tools; see the script for requirements.
FloorVault is dual-licensed under [MIT](https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE-MIT) or [Apache 2.0](https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE-APACHE),
at your option.

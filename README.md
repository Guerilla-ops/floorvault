# FloorVault

[![PyPI](https://img.shields.io/pypi/v/floorvault.svg)](https://pypi.org/project/floorvault/)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)

Contextual, misuse-resistant encryption for SQLite and local application data.

FloorVault adds authenticated field-level encryption to ordinary Python `sqlite3` databases. Ciphertext is bound to the table, record, column, schema, and application instance where it belongs—without SQLCipher, a custom SQLite build, or a C extension.

> Beta software. Review the [security model](SECURITY.md) before using FloorVault for production secrets.

## Why FloorVault?

- AES-256-SIV authenticated encryption (RFC 5297)
- Context binding that rejects ciphertext relocation
- HKDF-SHA256 key derivation
- Best-effort hardened key memory with strict failure options
- Native key custody for macOS, Windows, and Linux
- Safe SQLite field storage and plaintext-to-encrypted migration
- Resumable vault key rotation
- Authenticated master-key recovery bundles
- Standard-library-friendly integration with existing SQLite applications

## Install

```bash
pip install floorvault
```

With `uv`:

```bash
uv add floorvault
```

macOS Keychain support is optional:

```bash
uv add "floorvault[macos]"
```

## Quickstart

```python
from floorvault import AdaptiveKeyProvider, FloorVault

master_key = AdaptiveKeyProvider(service_name="my-app").resolve_key()
crypto = FloorVault(master_key, app_instance_id="my-app-instance")

ciphertext = crypto.encrypt(
    "secret value",
    table="credentials",
    record_id="user-123",
    column="api_key",
)

plaintext = crypto.decrypt(
    ciphertext,
    table="credentials",
    record_id="user-123",
    column="api_key",
)

assert plaintext == "secret value"
```

The same ciphertext will not decrypt successfully when supplied with a different table, record ID, column, schema, or application instance.

Never hard-code a production master key in source code. Use an OS-backed provider or an external secret source.

## Existing SQLite tables

FloorVault does not own your schema or transactions. Add an encrypted column to an existing table, then use the adapter:

```python
import sqlite3

from floorvault import AdaptiveKeyProvider, EncryptedSQLiteTable, FloorVault

connection = sqlite3.connect("app.db")
master_key = AdaptiveKeyProvider(service_name="my-app").resolve_key()
crypto = FloorVault(master_key, app_instance_id="my-app")

fields = EncryptedSQLiteTable(
    connection,
    crypto,
    "users",
    id_column="id",
)

fields.store("user-123", "api_token_cipher", "secret-token")
connection.commit()

token = fields.load("user-123", "api_token_cipher")
```

Table and column identifiers are validated before SQL is constructed. Record IDs and values remain bound parameters or cryptographic inputs. A missing record is an error; the adapter never inserts one accidentally.

## Migrate existing plaintext columns

Migrate into a new encrypted column without deleting the original source:

```python
from floorvault import migrate_plaintext_column, verify_encrypted_column

migrate_plaintext_column(
    connection,
    crypto,
    table_name="users",
    id_column="id",
    source_column="api_token",
    destination_column="api_token_cipher",
)
connection.commit()

assert verify_encrypted_column(
    connection,
    crypto,
    table_name="users",
    id_column="id",
    source_column="api_token",
    destination_column="api_token_cipher",
)
```

The migration validates identifiers, refuses a populated destination, binds each value to its real record ID, and rolls back on failure. Remove the plaintext column only after independent verification and an appropriate backup policy.

## Key custody

`AdaptiveKeyProvider` selects an available custody tier rather than silently weakening an explicitly requested one:

- macOS Keychain
- Windows DPAPI
- Linux Secret Service
- protected local fallback where permitted

The local fallback is protected by the filesystem and OS-account boundary; it is not equivalent to hardware-backed or OS-managed secret custody. If a native backend is present but unusable, FloorVault can fail closed with `CustodyDowngradeError`.

## Rotation and recovery

Rotate a store under a new key with resumable progress and post-rotation verification:

```python
from floorvault import KeyRing, rotate_vault_store

rotate_vault_store(
    store,
    source_ring=KeyRing({0: old_crypto}),
    new_vault=new_crypto,
    new_key_id=1,
)
```

Create an authenticated recovery bundle using a separately protected recovery key:

```python
from floorvault import recover_master_key, wrap_master_key

bundle = wrap_master_key(master_key, recovery_key)
recovered = recover_master_key(bundle, recovery_key)
```

The recovery bundle is not a substitute for protecting the recovery key. Keep that key separate from the vault and its backups.

## Security boundaries

FloorVault protects against:

- database or ciphertext theft;
- accidental cryptographic misuse;
- moving ciphertext to another authenticated context;
- some forms of key-memory exposure, where platform hardening succeeds.

FloorVault does not provide:

- process isolation against same-user malware;
- endpoint compromise protection;
- hardware-backed trust by itself;
- whole-database freshness or rollback protection;
- protection from plaintext copies created by Python, OpenSSL, or other dependencies.

For replay protection, bind encryption to a caller-controlled revision that an attacker cannot roll back with the database.

## Performance

A measured macOS benchmark using five independent 10,000-iteration runs and a 1,019-byte payload reported:

| Operation | FloorVault | Fernet |
|---|---:|---:|
| Encrypt | 0.00583 ms | 0.00700 ms |
| Decrypt | 0.00517 ms | 0.00629 ms |

These are workload-specific measurements, not universal performance claims. The benchmark includes contextual AAD and envelope handling but no database I/O.

Reproduce it with:

```bash
uv run python scripts/benchmark_compare.py --iterations 10000 --json /tmp/floorvault-fernet.json
```

See [`docs/COMPARATIVE-BENCHMARK-2026-09-15.md`](docs/COMPARATIVE-BENCHMARK-2026-09-15.md) for methodology and limits.

## CLI

Inspect an encrypted field without exposing its plaintext:

```bash
floorvault inspect local_vault.db users user-123 api_token_cipher
```

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The project tests on Linux, macOS, and Windows across supported Python versions. Security-gate details and cross-platform findings are documented in [`SECURITY.md`](SECURITY.md) and [`docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md`](docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md).

## Documentation

- [`SECURITY.md`](SECURITY.md) — security model, limitations, and reporting guidance
- [`docs/COMPARATIVE-BENCHMARK-2026-09-15.md`](docs/COMPARATIVE-BENCHMARK-2026-09-15.md) — benchmark methodology
- [`docs/PERFORMANCE-HARDENING-COST-REVIEW-2026-09-15.md`](docs/PERFORMANCE-HARDENING-COST-REVIEW-2026-09-15.md) — hardening trade-offs
- [`docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md`](docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md) — platform-specific findings

## License

FloorVault is dual-licensed under:

- [MIT](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

Copyright © Scott Lee.

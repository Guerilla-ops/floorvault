<div align="center">
  <img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/floorvault-hero.svg" width="100%" alt="FloorVault — Your data. Its place. Cryptographically bound.">
  <h1>FloorVault</h1>
  <p><strong>Your data. Its place. Cryptographically bound.</strong><br>
  Context-bound, misuse-resistant field encryption for SQLite — AES-256-SIV (RFC 5297), no SQLCipher, no C extension.</p>
  <p><a href="#quickstart">Quickstart</a> · <a href="#how-it-works">How it works</a> · <a href="#install">Install</a> · <a href="#existing-sqlite-tables">SQLite adapter</a> · <a href="#security-boundaries">Boundaries</a> · <a href="https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md">Security model</a> · <a href="#documentation">Docs</a></p>
  <p><a href="https://pypi.org/project/floorvault/"><img src="https://img.shields.io/pypi/v/floorvault.svg" alt="PyPI version"></a> <a href="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml"><img src="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status on main"></a> <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg" alt="Python 3.10 and newer"></a> <a href="https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/status-beta-f0a45d.svg" alt="Project status: beta"></a> <a href="https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg" alt="MIT or Apache 2.0 license"></a></p>
</div>

> **Beta — no external security audit.** Review the [security model](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md) before using FloorVault for production secrets.

| Bound to its place | Your existing SQLite | Fail-closed key custody |
| --- | --- | --- |
| Every ciphertext authenticates against its table, record, column, schema, and application instance — moved or replayed under different coordinates, verification fails instead of returning wrong plaintext. | Field-level encryption for ordinary `sqlite3` databases — plus an opt-in SQLAlchemy adapter — with no SQLCipher or custom SQLite build. | macOS Keychain, Windows DPAPI, Linux Secret Service, or Vault Transit — never a silent downgrade to a weaker store. |

## Quickstart

`resolve_key()` uses whatever custody tier is available on the host and fails closed when none applies — see
[Key custody](#key-custody). The wrong-context decrypt at the end is the point of the library: a different
table, record, column, schema, or app instance fails authentication rather than returning wrong plaintext.

```python
from floorvault import AdaptiveKeyProvider, DecryptionVerificationError, FloorVault

master_key = AdaptiveKeyProvider(service_name="my-app").resolve_key()
crypto = FloorVault(master_key, app_instance_id="my-app-instance")

ciphertext = crypto.encrypt("secret value", table="credentials", record_id="user-123", column="api_key")
assert crypto.decrypt(ciphertext, table="credentials", record_id="user-123", column="api_key") == "secret value"

try:
    crypto.decrypt(ciphertext, table="credentials", record_id="user-456", column="api_key")
except DecryptionVerificationError:
    pass
else:
    raise AssertionError("ciphertext accepted under the wrong context")
```

Never hard-code a production master key in source — use an OS-backed provider or an external secret source.

## How it works

<img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/context-binding.svg" width="100%" alt="Diagram: a ciphertext sealed for users/u1/api_key verifies under those coordinates; under users/u2/api_key it is rejected.">

FloorVault authenticates each value against the place it belongs. Every envelope's associated data binds five
coordinates — `table`, `record_id`, `column`, `schema_id`/`schema_version`, and the `app_instance_id` of the
writer — so ciphertext moved to another row, column, schema, or application instance fails verification rather
than decrypting. The master key derives an AES-SIV key with HKDF-SHA256; each field is sealed with
AES-256-SIV (RFC 5297) into an `FLV2` envelope in an ordinary `BLOB` column. An optional caller-held `revision`
can bind a per-record version into the same context — replay detection, not whole-database rollback protection.

## Install

```bash
pip install floorvault
uv add floorvault
```

Published artifacts are reproducible and carry Sigstore provenance — see
[Verifying a download](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RELEASING.md#verifying-a-download).

Add extras as needed — `floorvault[macos]`, `floorvault[macos,sqlalchemy]`, …:

| Extra | Enables |
| --- | --- |
| `macos` | macOS Keychain custody tier |
| `linux` | Linux Secret Service custody tier |
| `sqlalchemy` | `SqlAlchemyEncryption` ORM adapter |
| `libsql` | `EncryptedLibSqlTable` — same contract over libSQL (local files, embedded replicas, Turso) |
| `dev` | Test, lint, and security-gate toolchain |

A stock install does not provide an OS key store on every host: the `macos`/`linux` extras enable Keychain and
Secret Service, Windows uses built-in DPAPI, and the local-file tier stays off unless you opt in. With no
usable provider, `resolve_key()` fails closed with a `KeyProviderError` naming the remedies — no unprotected key file.

## Existing SQLite tables

FloorVault does not own your schema or transactions. Add an encrypted `BLOB` column to an existing table, then use the adapter:

```python
import sqlite3

from floorvault import AdaptiveKeyProvider, EncryptedSQLiteTable, FloorVault

connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, api_token_cipher BLOB)")
connection.execute("INSERT INTO users (id) VALUES (?)", ("u1",))

master_key = AdaptiveKeyProvider(service_name="my-app").resolve_key()
crypto = FloorVault(master_key, app_instance_id="my-app")
fields = EncryptedSQLiteTable(connection, crypto, "users", id_column="id")

fields.store("u1", "api_token_cipher", "secret-token")
connection.commit()

assert fields.load("u1", "api_token_cipher") == "secret-token"
```

Table and column identifiers are validated before SQL is constructed; record IDs and values stay bound
parameters or cryptographic inputs. A missing record is an error — the adapter never inserts one accidentally.

## Key custody

`AdaptiveKeyProvider` resolves an available custody tier rather than silently weakening an explicitly requested
one — an environment variable first (`FLOOR_VAULT_KEY`, `VAULT_MASTER_KEY`, or the legacy `APPSTATE_KEY`, 64 hex
characters), then the OS-native tier (**macOS Keychain**, needs the `macos` extra; **Windows DPAPI**, built in,
a store outside the user profile is refused; **Linux Secret Service**, needs the `linux` extra), and only then
a **0600 local file** (Tier 3, off unless `allow_disk_fallback=True`; `strict=True` forbids it outright).
Resolving a key with no OS store — macOS without its extra, or a headless container — fails closed with a
`KeyProviderError` that names the remedies (resolution options in the custody guide below).

**Custody caveats.** The 0600 local file is protected by the filesystem and OS-account boundary only — not
equivalent to hardware-backed or OS-managed custody, and anyone who can copy it recovers the key. A present but
unusable native backend raises `CustodyDowngradeError` instead of downgrading. Constructing a key handle sets
`RLIMIT_CORE` to 0 process-wide and never restores it — a core dump would write the held master key to disk.
Live CI coverage exists for Windows DPAPI only; the macOS and Linux tiers are unit-tested but not
live-verified — per-tier status in [`SECURITY.md`](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md).

## Security boundaries

| Protects against | Does not provide |
| --- | --- |
| Database or ciphertext theft; accidental cryptographic misuse; moving ciphertext to another authenticated context; some forms of key-memory exposure where platform hardening succeeds. | Process isolation against same-user malware; endpoint compromise protection; hardware-backed trust by itself; whole-database freshness or rollback protection; protection from plaintext copies created by Python, OpenSSL, or other dependencies. |

For replay protection, bind encryption to a caller-controlled `revision` an attacker cannot roll back with the database — full statement: [`SECURITY.md`](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md).

## Guides

<details>
<summary><strong>SQLAlchemy ORM adapter</strong> — plaintext attributes encrypt at assignment; bulk writes refused</summary>

With the `sqlalchemy` extra installed, `SqlAlchemyEncryption` binds encrypted fields onto mapped classes:
plaintext-facing attributes are descriptors that encrypt at assignment, and writes that cannot bind per-record
coordinates are refused.

```python
from sqlalchemy import Column, LargeBinary, String, create_engine
from sqlalchemy.orm import DeclarativeBase

from floorvault import AdaptiveKeyProvider, FloorVault, SqlAlchemyEncryption

crypto = FloorVault(AdaptiveKeyProvider(service_name="my-app").resolve_key(), app_instance_id="my-app")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    tenant = Column(String, nullable=False)
    ssn_ct = Column(LargeBinary, nullable=True)


engine = create_engine("sqlite://")
Base.metadata.create_all(engine)

vault = SqlAlchemyEncryption(crypto, schema_id="my-app.v1")
vault.protect(User, id_attr="id", tenant_attr="tenant", fields={"ssn": "ssn_ct"})
Session = vault.session_factory(bind=engine)

with Session() as session:
    user = User(id="u1", tenant="acme")  # identity attrs first — binding needs them
    user.ssn = "123-45-6789"  # encrypts here; only ciphertext is mapped
    session.add(user)
    session.commit()
    assert session.get(User, "u1").ssn == "123-45-6789"
```

Fail-closed invariants (full contract: [SPEC.md §14.1](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md)):

- `obj.ssn_ct = b"plaintext"` is refused at assignment — only envelope-shaped values may occupy a ciphertext column.
- `session.execute(insert(User).values(ssn_ct=...))`, executemany sets, `Query.update`, and the legacy bulk APIs (`bulk_insert_mappings`/`bulk_update_mappings`/`bulk_save_objects`) on ciphertext columns or protected classes raise `UnsupportedWriteError`.
- `tenant_attr` binds the tenant into the record coordinate, so a ciphertext cannot be replayed across tenants; `revision_attr` binds a per-record revision (same-coordinate replay detection, not whole-database rollback protection).

</details>

<details>
<summary><strong>Migrate existing plaintext columns</strong> — atomic, verified, residue-aware</summary>

Encrypt a plaintext column into an existing destination column without deleting the source. This continues
the [existing-tables example](#existing-sqlite-tables) (`crypto`) on its own in-memory table:

```python
import sqlite3

from floorvault import migrate_plaintext_column, verify_encrypted_column

connection = sqlite3.connect(":memory:")
connection.execute(
    "CREATE TABLE users (id TEXT PRIMARY KEY, private_value TEXT, private_value_cipher BLOB)"
)
connection.execute("INSERT INTO users (id, private_value) VALUES (?, ?)", ("u1", "plain-secret"))

migrate_plaintext_column(
    connection, crypto, table="users", id_column="id",
    source_column="private_value", destination_column="private_value_cipher",
)
connection.commit()

assert verify_encrypted_column(
    connection, crypto, table="users", id_column="id",
    source_column="private_value", destination_column="private_value_cipher",
) == 1
```

The migration validates identifiers, refuses a populated destination, binds each value to its real record ID,
and rolls back on failure. Remove the plaintext column only after independent verification and a backup policy —
`drop_plaintext_column()` arms `PRAGMA secure_delete`, checkpoints the WAL, and optionally `VACUUM`s, but
filesystem residue can survive; destroying the file is the only complete guarantee.

</details>

<details>
<summary><strong>Searchable beacons (opt-in)</strong> — exact-match lookup with an explicit leakage trade</summary>

Exact-match lookups over an encrypted column need an indexed value beside the ciphertext. Storing one leaks
something, so this is opt-in and a trade made deliberately. The snippet is self-contained after `crypto` and
`master_key` from the [existing-tables example](#existing-sqlite-tables);
`tests/test_searchable_beacons.py` executes the same workflow.

```python
import sqlite3

from floorvault.beacons import BeaconIndexer, derive_beacon_key, suggest_beacon_bits

connection = sqlite3.connect(":memory:")
connection.execute(
    "CREATE TABLE contacts (id TEXT PRIMARY KEY, email_cipher BLOB, email_beacon BLOB)"
)
connection.execute("CREATE INDEX contacts_email_beacon ON contacts (email_beacon)")

record_id, email = "c1", "alice@example.com"

# Size the width to the table, don't pick a constant: the anonymity a beacon
# gives is roughly one bucket's occupancy.
indexer = BeaconIndexer(derive_beacon_key(master_key), bits=suggest_beacon_bits(200_000))

# On write: store the ciphertext and the beacon in an indexed column.
connection.execute(
    "INSERT INTO contacts (id, email_cipher, email_beacon) VALUES (?, ?, ?)",
    (record_id, crypto.encrypt(email, table="contacts", record_id=record_id, column="email_cipher"),
     indexer.beacon(email, scope="contacts.email")),
)
connection.commit()

# On read: the bucket narrows candidates; decryption confirms the match.
bucket = indexer.beacon(email, scope="contacts.email")
for candidate_id, ciphertext in connection.execute(
    "SELECT id, email_cipher FROM contacts WHERE email_beacon = ?", (bucket,)
):
    if crypto.decrypt(ciphertext, table="contacts", record_id=candidate_id, column="email_cipher") == email:
        break  # confirmed
else:
    raise AssertionError("beacon lookup found no matching record")
```

What this costs: equal values produce equal beacons, so unequal beacons prove unequal values; bucket occupancy
still tracks the plaintext distribution, so a skewed column shows a skewed beacon histogram. Truncation makes
the index non-injective — it does not make the data uniform — so size the width to the row count, and do not
beacon a low-cardinality column or one you never look up by equality. Widths are byte-aligned (4 and 8 bits are
the same index); `BeaconIndexer` rejects a width it cannot store rather than rounding it. A beacon hit is not
proof of equality — always confirm by decrypting. Full statement: [SECURITY.md §5](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md).

</details>

<details>
<summary><strong>Key-custody options and Vault Transit</strong> — resolving a key when no OS store applies</summary>

Three ways to satisfy `resolve_key()`:

```python
import os

from floorvault import AdaptiveKeyProvider, FloorVault

# 1. Explicit key, 64 hex characters, from your own secret source.
crypto = FloorVault(bytes.fromhex(os.environ["APPSTATE_KEY"]), app_instance_id="my-app")

# 2. A 0600 local key file, created on first use and reused afterwards. This is
#    Tier 3: anyone who can copy the file can recover the key.
crypto = FloorVault(
    AdaptiveKeyProvider(service_name="my-app", allow_disk_fallback=True).resolve_key(),
    app_instance_id="my-app",
)

# 3. Install the OS-native tier for the platform (floorvault[macos] on macOS).
crypto = FloorVault(AdaptiveKeyProvider(service_name="my-app").resolve_key(), app_instance_id="my-app")
```

`VaultTransitProvider` is a fourth option: it keeps the master key wrapped by a HashiCorp Vault Transit key
instead of a local file; the wrapped blob lives in a governed on-disk generation store
([SPEC.md §10.6–10.7](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md)):

```python
from floorvault.providers.vault_transit import VaultTransitProvider

provider = VaultTransitProvider(
    vault_addr="https://vault.internal:8200",
    token=os.environ["VAULT_TOKEN"],  # Transit datakey/decrypt/rewrap perms
    key_name="floorvault-master",
    store_dir="/var/lib/myapp/floorvault",  # 0700; holds store.id + generations
    app_instance_id="my-app",
)
crypto = FloorVault(provider.resolve_key(), app_instance_id="my-app")

# Rewrap under a new Transit KEK version (CAS-publishes a new generation):
provider.rewrap()
```

Every Vault failure raises `CustodyDowngradeError`; a configured provider never silently falls back to file
custody. HTTPS only, verified TLS, bounded timeouts/retries, redirects refused unless a standby host is
trusted. The resolved key is cached briefly (300 s default) — that bounds Transit latency, not revocation
protection. Full setup: [`docs/VAULT-TRANSIT.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md).

</details>

<details>
<summary><strong>Rotation and recovery</strong> — resumable re-keying, authenticated recovery bundles</summary>

Rotate a store under a new key with resumable progress and post-rotation verification:

```python
from floorvault import AdaptiveKeyProvider, FloorVault, KeyRing, rotate_vault_store

# VaultStore is the structured item store this rotation operates on; it is not
# re-exported at the top level.
from floorvault.vaultkit import VaultStore
from pathlib import Path

# VaultStore does NOT expand "~" -- a literal tilde would become a directory
# named "~" relative to the working directory. Expand it explicitly.
VAULT_DIR = Path("~/.floor/vault").expanduser()

old_crypto = FloorVault(AdaptiveKeyProvider(service_name="my-app").resolve_key(), app_instance_id="my-app")
store = VaultStore(VAULT_DIR, crypto=old_crypto)

# A new_master_key from your key provider, wrapped in its own engine.
new_crypto = FloorVault(new_master_key, app_instance_id="my-app")

# default_key_id=0 attributes v1 envelopes (which carry no key id in their
# header) to the old key; without it a legacy v1 record is refused.
rotate_vault_store(store, source_ring=KeyRing({0: old_crypto}, default_key_id=0), new_vault=new_crypto, new_key_id=1)

# If the call above was interrupted, resume with BOTH generations in the ring:
# items already committed under key_id 1 can't be read by a ring holding only the old key.
# rotate_vault_store(store, source_ring=KeyRing({0: old_crypto, 1: new_crypto}, default_key_id=0),
#                    new_vault=new_crypto, new_key_id=1)

# REQUIRED: the `store` above was built on old_crypto and CANNOT read the
# re-sealed records -- rotation sealed every envelope under the NEW master key.
# Rebuild the store on the new key and repoint every holder of the old one.
store = VaultStore(VAULT_DIR, crypto=new_crypto)
```

**When rotating to different key material, rebuild the original `store`.** Its convenience reads cannot
authenticate records sealed under the new master: `resolve_secret`, `get_meta`, and `list_items` raise
`DecryptionVerificationError`, while `has_items()` does not decrypt and cannot surface the mismatch. Rotation is
durable and verified — if the process exits before rebuilding and the provider still resolves the old key, the
store stays unreadable across restarts. Rebuild the store rather than mutating it, and make the new key
resolvable before you rotate. To read a store spanning generations, use `KeyRing` with `read_sealed_item`.

Create an authenticated recovery bundle using a separately protected recovery key — keep it separate from the
vault and its backups. This recipe requires `master_key` and `recovery_key` as distinct 32-byte `bytes` or
`bytearray` values from your secret source, not the `HardenedMemoryKey` handle returned by `resolve_key()`:

```python
from floorvault import recover_master_key, wrap_master_key

bundle = wrap_master_key(master_key, recovery_key)
recovered = recover_master_key(bundle, recovery_key)
```

The recovery bundle is not a substitute for protecting the recovery key.

</details>

## Performance

A measured macOS benchmark using five independent 10,000-iteration runs and a 1,019-byte payload reported
(methodology and limits: [`docs/COMPARATIVE-BENCHMARK-2026-09-15.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/COMPARATIVE-BENCHMARK-2026-09-15.md)):

| Operation | FloorVault | Fernet |
| --- | ---: | ---: |
| Encrypt | 0.00583 ms | 0.00700 ms |
| Decrypt | 0.00517 ms | 0.00629 ms |

Workload-specific measurements, not universal claims; includes contextual AAD and envelope handling, no database I/O. Reproduce with `uv run python scripts/benchmark_compare.py --iterations 10000 --json /tmp/floorvault-fernet.json`.

## CLI

`floorvault inspect` **decrypts** a field and reports it — the value is `<redacted>` by default; pass
`--reveal` to print the plaintext (treat that output as secret):
`floorvault inspect local_vault.db users user-123 private_value_cipher --service-name my-app --app-instance my-app --reveal`.
The flags must match how the record was written: the CLI resolves the key under `--service-name` and binds
decryption to `--app-instance`. Defaults are `floorvault` and `default`, so records written under those
defaults need no flags. `--service-name` selects the key only when custody comes from the OS store tiers
(macOS Keychain, Linux Secret Service, or the local file key): records written under `FLOOR_VAULT_KEY`/
`VAULT_MASTER_KEY` need that same environment variable set for `inspect` instead, and Windows DPAPI keys
are machine-bound rather than service-scoped. The target must be a real SQLite database — the tool refuses
non-database and non-regular paths — and it opens it read-only. Inspection never creates keys — a mistyped
service name fails with an error rather than minting a new custody entry.

## Reporting a vulnerability

Do not report security issues in public GitHub issues or pull requests. Use GitHub private vulnerability
reporting on this repository (preferred), or email **floorbond@pm.me** — [`SECURITY.md`](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md) has scope and PGP details.

## Documentation

- [`SECURITY.md`](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md) — security model, limitations, and reporting
- [`docs/SPEC.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md) — full protocol and adapter contracts
- [`docs/VAULT-TRANSIT.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md) — Vault Transit custody setup
- [`docs/RECORD-FORMAT-2026-09-15.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RECORD-FORMAT-2026-09-15.md) — `FLV2` envelope format
- [`docs/COMPARATIVE-BENCHMARK-2026-09-15.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/COMPARATIVE-BENCHMARK-2026-09-15.md) — benchmark methodology
- [`docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md`](https://github.com/Guerilla-ops/floorvault/blob/main/docs/CROSS-PLATFORM-CI-FINDINGS-2026-09-15.md) — platform findings

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src/ tests/ scripts/ fuzz/
uv run ruff format --check src/ tests/ scripts/ fuzz/
uv run bandit -q -r src/ scripts/ fuzz/
bash scripts/security-check.sh   # full gate; also needs gitleaks and semgrep on PATH
```

CI tests on Linux, macOS, and Windows across supported Python versions.

## License

FloorVault is dual-licensed under [MIT](https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE-MIT) or [Apache License 2.0](https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE-APACHE), at your option.

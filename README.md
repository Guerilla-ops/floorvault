# FloorVault

**Encrypt application data. Bind each field to its context.**

FloorVault is a Python library for field encryption in existing databases and
local credential stores. It uses AES-256-SIV with authenticated context to detect
ciphertext moved to the wrong record, column, table, schema or application.

Keep your database engine and choose which fields to protect. Use OS-backed key
custody, an explicit key source, or an explicitly enabled passphrase-wrapped file.
Optional features include equality search and external freshness anchors.

**Beta.** No completed independent code audit or security certification is claimed.
Read [SECURITY.md](SECURITY.md) before choosing a deployment. Package and
on-disk format versions are independent; the package currently declares `0.2.0`.

## Install

Requires Python 3.10 or newer:

```bash
python -m pip install floorvault
```

Examples describe the repository source. Some APIs were added after the published
`0.1.0` release; install a reviewed source checkout when using those features:

```bash
git clone https://github.com/Guerilla-ops/floorvault.git
cd floorvault
python -m pip install .
```

Before unmerged changes land, check out the reviewed branch or commit before
installing. Pin that commit or a release for deployment. The distribution,
Python package and CLI are all named `floorvault`.

| Optional extra | Adds |
| --- | --- |
| `macos` | macOS Keychain bindings |
| `linux` | Linux Secret Service client |
| `sqlalchemy` | SQLAlchemy integration |
| `libsql` | Synchronous libSQL driver |
| `postgres` | Psycopg driver |
| `mysql` | MySQL Connector/Python driver |
| `dev` | Development and verification tools |

For example, run `python -m pip install ".[linux]"` from a source checkout.
The base install does not enable every native key store. FloorVault ships Python
code; its `cryptography` dependency contains native components. Dependency wheel
availability determines whether compilation is needed.

## Quickstart

This example uses an ephemeral key and needs no external key store. For persistent
records, retain the original key through a custody provider: generating a new key
at each start makes existing data unreadable.

```python
from secrets import token_bytes

from floorvault import DecryptionVerificationError, FloorVault

with FloorVault(token_bytes(32), app_instance_id="example-app") as crypto:
    ciphertext = crypto.encrypt(
        "secret value", table="credentials", record_id="user-123", column="token"
    )
    assert crypto.decrypt(
        ciphertext, table="credentials", record_id="user-123", column="token"
    ) == "secret value"

    try:
        crypto.decrypt(
            ciphertext, table="credentials", record_id="user-456", column="token"
        )
    except DecryptionVerificationError:
        print("Different record: authentication rejected.")
    else:
        raise AssertionError("Wrong-context ciphertext was accepted")
```

Closing the engine wipes its managed buffers. It does not erase all key or
plaintext copies held by callers, Python, providers or cryptographic dependencies.

## Context binding and freshness

A 32-byte master key is expanded with HKDF-SHA256 into the 64-byte AES-256-SIV key.
Fields use versioned `FLV2` envelopes with fresh 16-byte random nonces. The expected
application ID, table, record ID, column, schema ID, schema version and optional
revision are authenticated during decryption.

Context is caller-supplied data, not identity or permission. Your application must
choose trustworthy expected coordinates and authorise access before decrypting.

Same-context replay is accepted by ordinary decryption. A revision only helps if
its expected value cannot be rolled back with the ciphertext. For selected
SQLite/libSQL tables, opt-in `floorvault.freshness.FreshnessAnchor` keeps keyed state
outside the database. Use its verified transaction path and place the anchor where
an attacker cannot roll it back together with the database. A crash during commit
can require deliberate recovery. Neither the credential store nor the plugin
turns freshness protection on automatically.

AES-SIV is misuse-resistant, but repeating the same key, nonce, context and
plaintext can reveal equality.

## Database adapters

Table adapters encrypt selected values and leave schema creation and commits to
the application. Writes must match exactly one existing row.

| Integration | API | Application setup |
| --- | --- | --- |
| SQLite | `EncryptedSQLiteTable` | Existing rows and encrypted `BLOB` columns |
| libSQL | `EncryptedLibSqlTable` | Synchronous connection |
| PostgreSQL | `EncryptedPostgresTable` | Synchronous DB-API connection and `BYTEA` columns |
| MySQL | `EncryptedMySQLTable` | Synchronous DB-API connection and binary columns |
| SQLAlchemy | `SqlAlchemyEncryption` | Mapped fields and its guarded session factory |

```python
import sqlite3
from secrets import token_bytes

from floorvault import EncryptedSQLiteTable, FloorVault

connection = sqlite3.connect(":memory:")
connection.execute("CREATE TABLE users (id TEXT PRIMARY KEY, token_cipher BLOB)")
connection.execute("INSERT INTO users (id) VALUES (?)", ("u1",))

with FloorVault(token_bytes(32), app_instance_id="sqlite-demo") as crypto:
    fields = EncryptedSQLiteTable(connection, crypto, "users", id_column="id")
    fields.store("u1", "token_cipher", "demo-token")
    connection.commit()
    assert fields.load("u1", "token_cipher") == "demo-token"

connection.close()
```

For local libSQL files, `connect_encrypted` optionally adds native page encryption
under a derived key. It refuses remote URLs, replica options, `:memory:` and
existing plaintext files. The page cipher does not authenticate the whole file;
field integrity still comes from the FloorVault envelopes.

## Credential stores

`floorvault.vaultkit.VaultStore` manages a local credential database, including
its schema and operation transactions. It supports generic, login and payment
items. Use an explicit directory and crypto engine when integrating:

```python
from pathlib import Path
from secrets import token_bytes
from tempfile import TemporaryDirectory

from floorvault import FloorVault
from floorvault.vaultkit import VaultStore

with TemporaryDirectory() as directory:
    with FloorVault(token_bytes(32), app_instance_id="store-demo") as crypto:
        store = VaultStore(Path(directory), crypto=crypto, seal_listing_metadata=True)
        item = store.add_item(
            kind="generic", label="Demo token", secret={"value": "demo-secret"}
        )
        assert store.resolve_secret(item.id) == {"value": "demo-secret"}
```

Listing metadata sealing is opt-in. Converting an existing unsealed listing also
requires `migrate_listing_metadata=True`. Item counts, IDs and ciphertext lengths
remain visible, and historical pages or backups may retain earlier metadata.
`floorvault.get_vault_store()` preserves the existing default location: a
`floor_constants.get_floor_home()` host directory when available, otherwise
`~/.floor/vault`. Its new `auto_migrate` argument defaults to true and exposes a
migration-aware facade when legacy `vault.json.enc` and `vault.key` files exist.
Use an explicit directory and `auto_migrate=False` for modern-store-only access.
The older `floorvault.vaultkit.get_vault_store()` remains a plain store factory.

Legacy Fernet migration is separate from upgrading FloorVault's own records.
`MigratingVaultStore.list_items()` can lazily migrate every legacy item it lists,
writing modern records and retirement tombstones. It is not a read-only operation.
Back up legacy data first; use `migrate_all()` for backed-up bulk conversion and
verify migrated items before retiring the source. Original source files remain.

## Hermes Agent integration

The optional plugin in [`plugins/hermesvault`](plugins/hermesvault) resolves local
FloorVault items into Hermes Agent environment variables. FloorVault remains the
library and package name.

Install FloorVault into the Python environment used by the host, then register the
plugin through that host's plugin mechanism. The library wheel does not include or
register the plugin. The checkout's `vendor` link depends on the repository layout;
copying the plugin directory alone is not a self-contained installation. A compatible
host secret-source API is required; host integration tests are skipped when that
checkout is absent.

Once installed and registered with a compatible Hermes host, the plugin maps
references to existing items into the host's environment:

```yaml
secrets:
  hermesvault:
    enabled: true
    env:
      SERVICE_TOKEN: hv:vault_service:value
```

References use `hv:<item_id>[:<field>]`. Without a field, the source uses `value`
or the item's sole nonempty field. Multi-field items otherwise need an explicit
field. Its agent-secret directory defaults to `<profile-home>/agent-vault`,
separate from the browser-fill `<profile-home>/vault`; plugin reads disable
legacy browser-vault migration. Directory separation alone does not prove
independent keys or access control.

The plugin supplies `hermes hvault` management commands. Prefer `add --stdin`
over passing secret values as command arguments. `show` reports field counts or status; its current
`--reveal` mode also masks values rather than printing plaintext.
The current `put` path removes then recreates an item; it needs an atomic update
before use with critical data. The library wheel alone does not install or
register the plugin. The source accepts a configured bootstrap key through
`token_env` (default `HERMES_VAULT_KEY`); this integration setting does not change
the core provider's environment-key defaults. Match the same bootstrap settings
when provisioning and reading a store. Credentials returned to the host are
plaintext; this integration does not provide a separate authorisation broker.

## Key custody

`AdaptiveKeyProvider` checks explicit environment keys, then native OS custody,
then an explicitly enabled local-file fallback. A present but unusable backend
must fail instead of silently downgrading custody.

| Source | Requirements and limits |
| --- | --- |
| Environment | `FLOOR_VAULT_KEY` or `VAULT_MASTER_KEY`: 64 hex characters encoding a 32-byte key. Plaintext custody; refused in strict mode. |
| macOS Keychain | Requires the `macos` extra and usable Keychain. Does not imply Secure Enclave storage. |
| Windows DPAPI | Bound to the Windows account; default secondary entropy is a public label, not another secret. |
| Linux Secret Service | Requires the `linux` extra and an accessible Secret Service. |
| Local file | Disabled by default. `allow_disk_fallback=True` opts in; copying an unwrapped file can reveal the key. |
| Wrapped local file | Add `passphrase=` to file custody for scrypt + AES-SIV wrapping. Security depends on the passphrase and its custody. |
| Vault Transit | Separate provider wraps the master key remotely; unwrapped key use and field encryption remain local. |

Use `AdaptiveKeyProvider(service_name="my-app", strict=True)` for explicit OS-only
custody. `resolve_key(allow_create=False)` resolves an existing key without creating
one. Legacy environment names and old key-store adoption require explicit opt-ins.
Existing file custody and OS-tier markers guard against accidentally minting a
different key when backend availability changes.

Preserve the original custody service, account, path, key and application context
when reopening an existing store. Keep recovery material securely backed up.
Memory-hardening settings are separate from key-custody settings.

## Security boundaries

| Property | Limit |
| --- | --- |
| Confidentiality | Only encrypted fields are protected by default. Other columns, schema, counts, lengths and access patterns remain visible. |
| Context integrity | The caller must provide trustworthy expected coordinates. Context does not establish permission. |
| Freshness | Opt-in revisions or external anchors require trusted state outside the attacker's rollback control. |
| Equality search | Optional beacons reveal bucket, frequency and access-pattern information. Decrypt candidates to confirm matches. |
| Memory | Managed buffers can be wiped; other copies may persist. Page locking and anti-dump measures do not create an enclave. |
| Migration | Deletion does not guarantee erasure from WAL, pages, backups, snapshots or storage media. |
| Agent access | A compromised or prompt-injected authorised caller can request genuine plaintext. The library does not supply a policy broker. |

## Compatibility

This update retains the existing `floorvault` imports, CLI, `FLRV`/`FLV2` envelopes,
`floorvault-v1-*` derivation labels and original custody/recovery identities. Existing
FloorVault data does not require re-encryption solely to use this branch. Regression
fixtures produced by the earlier `main` revision cover records, recovery bundles,
beacon keys, sealed metadata and retirement records.

Experimental data written by the temporary package/protocol rename in earlier PR
#53 commits is a separate format and is not automatically converted. Keep the
creating revision, original keys and configuration available when recovering that
data. Do not infer compatibility from the unchanged package version alone.

## Additional APIs and documentation

- `RecordBinding` and `ContextualSQLite`: custom record binding.
- `floorvault.beacons`: opt-in equality indexes; choose width for the dataset and leakage budget.
- `migrate_plaintext_column`, `verify_encrypted_column`, `drop_plaintext_column`: SQLite migration helpers.
- `KeyRing` and `rotate_vault_store`: staged rotation with retained key generations.
- `wrap_master_key` and `recover_master_key`: recovery using separately protected material.
- `floorvault.testing.siv_reference`: conformance helpers, not an application encryption API.

`floorvault inspect` opens an existing SQLite database read-only and decrypts a
selected field. Output is redacted unless `--reveal` is supplied. Match the
original custody service and application context; inspection creates no missing key.

Read the [security policy](SECURITY.md), [protocol specification](docs/SPEC.md),
[record format](docs/RECORD-FORMAT-2026-09-15.md), [audit packet](docs/AUDIT-PACKET.md),
[Vault Transit guide](docs/VAULT-TRANSIT.md) and [release guide](docs/RELEASING.md).
The [hardware custody guide](docs/HARDWARE-CUSTODY.md) is a proposal, not a shipped
hardware provider. Historical reviews and benchmarks apply to their stated revisions
and workloads; they are not certification of the current source.

## Development

```bash
uv sync --extra dev
uv run pytest
bash scripts/security-check.sh
```

The standalone local gate also requires external scanning tools. CI runs the full
suite on four PR cells: Ubuntu Python 3.10/3.14 and macOS/Windows Python 3.13.
Weekly, version-tag and expanded manual runs cover all declared Python versions
on Ubuntu plus Python 3.10/3.13 on macOS/Windows. Shared lint/build/scans run once;
full mutations run on Linux, with platform subsets on macOS/Windows. Dependency
audits resolve optional dependencies separately on each OS.

Plugin tests need a compatible
Hermes checkout through `HERMES_AGENT_SRC`; otherwise they skip. Passing library
tests do not demonstrate host integration. Check actual CI results and skip reasons
before making platform or custody claims. Maintainers should keep the
[required check names](docs/CI.md) aligned with the workflow.

Report vulnerabilities through [private GitHub reporting](https://github.com/Guerilla-ops/floorvault/security/advisories/new)
or **floorbond@pm.me**. Keep security reports and live secrets out of public issues.

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

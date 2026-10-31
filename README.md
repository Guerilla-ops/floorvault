<p>
  <img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/floorvault-v0.2.8.webp" width="100%" alt="FloorVault v0.2.8: encrypt the field, bind it in place. Ciphertext moved to another row, column, table or app does not decrypt. Four parts: context binding, the AES-256-SIV envelope engine, key custody, and agent secrets.">
</p>

# FloorVault

**Encrypt the field. Bind it in place.**

<p>
  <a href="https://pypi.org/project/floorvault/"><img src="https://img.shields.io/pypi/v/floorvault.svg" alt="PyPI version"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml"><img src="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status on main"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg" alt="Python 3.10 and newer"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/status-beta-f0a45d.svg" alt="Project status: beta"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

FloorVault is a Python library that encrypts individual fields in the database
you already have, and keeps local credential stores. Every value is bound to
where it belongs: ciphertext moved to another row, column, table, schema or
application does not decrypt.

[Install](#install) · [Quickstart](#quickstart) · [Context binding](#01--context-binding) ·
[Envelope engine](#02--envelope-engine) · [Key custody](#03--key-custody) ·
[Agent secrets](#04--agent-secrets) · [Limits](#security-boundaries) ·
[Documentation](#documentation)

**Beta.** No completed independent code audit or security certification is claimed.
Read [SECURITY.md](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md)
before choosing a deployment.

## Install

Requires Python 3.10 or newer:

```bash
python -m pip install floorvault
```

| Optional extra | Adds |
| --- | --- |
| `macos` | macOS Keychain bindings |
| `linux` | Linux Secret Service client |
| `sqlalchemy` | SQLAlchemy integration |
| `libsql` | Synchronous libSQL driver |
| `postgres` | Psycopg driver |
| `mysql` | MySQL Connector/Python driver |
| `hermes` | PyYAML, for `floorvault secrets import --hermes --remove-from-env` |
| `dev` | Development and verification tools |

For example, `python -m pip install "floorvault[linux]"`. The base install does
not enable every native key store. To work from the repository instead, clone
and `python -m pip install .`; the distribution, package and CLI are all named
`floorvault`.

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

## 01 / Context binding

**Bound data.** Every encrypted field is authenticated together with its
coordinates: application instance, table, record, column, schema ID and schema
version. Decryption rebuilds them from what the caller expects, so a value moved
to another row or column fails with `DecryptionVerificationError`, even under the
right key.

<img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/context-binding.svg" width="100%" alt="The same key and record context return plaintext. With the same key but a different record ID, authentication fails. Context is caller-supplied data, not proof of permission.">

Binding alone does not catch an old value written back to the same place.
Opt-in revisions and external freshness anchors detect that rollback, given state
kept outside the attacker's reach.

> **Context is not permission.** Your application chooses the expected coordinates
> and decides who may read them.

[Context binding and freshness](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#context-binding-and-freshness)

## 02 / Envelope engine

**AES-256-SIV.** A misuse-resistant AEAD (RFC 5297) in a versioned `FLV2`
envelope. HKDF-SHA256 derives a separate subkey for each purpose (field
encryption, search beacons, libSQL file encryption, freshness anchors) from one
32-byte master key. The coordinates, the envelope header and the nonce are all
authenticated as associated data.

- **Database adapters:** SQLite, libSQL, PostgreSQL, MySQL and SQLAlchemy table
  integrations, plus opt-in libSQL page encryption.
- **Checked against:** the RFC 5297 test vectors, Project Wycheproof's AES-SIV
  vectors, fixed wire-format vectors, and fuzzing in CI.
- **`floorvault inspect`** checks one encrypted SQLite field from the command line.

[Protocol specification](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md) ·
[Database adapters](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#database-adapters)

## 03 / Key custody

**Keep the key.** The master key comes from a custody provider and is never
stored in the database it protects:

| Source | Notes |
| --- | --- |
| macOS Keychain | `macos` extra |
| Windows DPAPI | Bound to the Windows account |
| Linux Secret Service | `linux` extra |
| HashiCorp Vault Transit | Wraps the master key remotely; encryption stays local |
| Environment or an explicit key | `FLOOR_VAULT_KEY`, or bytes you supply |
| Local file | Off by default; can be passphrase-wrapped |

A configured key source that fails is an error, never a silent downgrade to a
weaker one. Key material is held in buffers that can be wiped after use.

> **Lose the key, lose the data.** Keep recovery material backed up, and reopen a
> store with the same key, service and application context it was created with.

[Key custody](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#key-custody) ·
[Vault Transit guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md)

## 04 / Agent secrets

**No secrets in `.env`.** `floorvault run` starts any command, such as an agent,
an MCP server or a script, with `fv:` references filled in from an encrypted local
store. Configs and `.env` files then hold only references, which are safe to sync
or commit:

```bash
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "OpenAI" --id openai --stdin; unset KEY
echo 'OPENAI_API_KEY=fv:openai' > .env
floorvault run --env-file .env -- python agent.py
```

- `floorvault secrets import .env` previews moving an existing file's values into
  the store; add `--write` to store them and rewrite the file to references.
- `floorvault secrets allow` binds an item to the command lines it may reach, and
  `run --require-binding` refuses items that have no binding.
- The store is `VaultStore`, a local credential database with optional sealed
  listing metadata, also usable directly from Python.
- A [Hermes Agent plugin](https://github.com/Guerilla-ops/floorvault/tree/main/plugins/hermesvault)
  in this repository loads vault items into Hermes' environment at startup.

> **The process you start sees plaintext,** and so can other code running as you.

The [walkthrough](https://github.com/Guerilla-ops/floorvault/tree/main/examples/agent-secrets)
has a references-only `.env`, an MCP client config, and what this does and does
not protect.

[Run any command with vault secrets](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#run-any-command-with-vault-secrets) ·
[Credential stores](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#credential-stores) ·
[Hermes Agent](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#hermes-agent-integration)

## Security boundaries

Beta, unaudited, no policy broker, and search beacons leak equality. In detail:

| Property | Limit |
| --- | --- |
| Confidentiality | Only encrypted fields are protected by default. Other columns, schema, counts, lengths and access patterns remain visible. |
| Context integrity | The caller must provide trustworthy expected coordinates. Context does not establish permission. |
| Freshness | Opt-in revisions or external anchors require trusted state outside the attacker's rollback control. |
| Equality search | Optional beacons reveal bucket, frequency and access-pattern information. Decrypt candidates to confirm matches. |
| Memory | Managed buffers can be wiped; other copies may persist. Page locking and anti-dump measures do not create an enclave. |
| Migration | Deletion does not guarantee erasure from WAL, pages, backups, snapshots or storage media. |
| Agent access | A compromised or prompt-injected authorised caller can request genuine plaintext. The library does not supply a policy broker. |

## Documentation

- [Usage guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md) — adapters, stores, custody, plugin, compatibility
- [Security policy](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md)
- [Protocol specification](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md)
- [Record format](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RECORD-FORMAT-2026-09-15.md)
- [Audit packet](https://github.com/Guerilla-ops/floorvault/blob/main/docs/AUDIT-PACKET.md)
- [Vault Transit guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/VAULT-TRANSIT.md)
- [Release guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/RELEASING.md)

The [hardware custody guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/HARDWARE-CUSTODY.md)
is a proposal, not a shipped hardware provider. Historical reviews and benchmarks
apply to their stated revisions and workloads; they are not certification of the
current source.

## Development

```bash
uv sync --extra dev
uv run pytest
bash scripts/security-check.sh
```

CI covers Ubuntu/macOS/Windows across the supported Python range; see
[docs/CI.md](https://github.com/Guerilla-ops/floorvault/blob/main/docs/CI.md) and
the [development notes](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#development).

Report vulnerabilities through [private GitHub reporting](https://github.com/Guerilla-ops/floorvault/security/advisories/new)
or **floorbond@pm.me**. Keep security reports and live secrets out of public issues.

Licensed under the [MIT License](https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE).

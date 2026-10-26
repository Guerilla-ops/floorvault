<p>
  <img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/groundwork-v0.2.0.png" width="100%" alt="FloorVault Groundwork v0.2.0 — stronger foundations, safer data. Keep the original key. Detect restored data. Refuse ambiguous updates.">
</p>

# FloorVault

**Encrypt application data. Bind each field to its context.**

<p>
  <a href="https://pypi.org/project/floorvault/"><img src="https://img.shields.io/pypi/v/floorvault.svg" alt="PyPI version"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml"><img src="https://github.com/Guerilla-ops/floorvault/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status on main"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg" alt="Python 3.10 and newer"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/status-beta-f0a45d.svg" alt="Project status: beta"></a>
  <a href="https://github.com/Guerilla-ops/floorvault/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

FloorVault is a Python library for field encryption in existing databases and
local credential stores. It uses AES-256-SIV with authenticated context to detect
ciphertext moved to the wrong record, column, table, schema or application.

Keep your database engine and choose which fields to protect. Use OS-backed key
custody, an explicit key source, or an explicitly enabled passphrase-wrapped file.

[Install](#install) · [Quickstart](#quickstart) · [Context binding](#context-binding) ·
[Features](#features) · [Limits](#security-boundaries) · [Documentation](#documentation)

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
| `gui` | `floorvault-gui` desktop window (PySide6-Essentials) — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#desktop-window-beta) |
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

## Context binding

<img src="https://raw.githubusercontent.com/Guerilla-ops/floorvault/main/docs/assets/context-binding.svg" width="100%" alt="The same key and record context return plaintext. With the same key but a different record ID, authentication fails. Context is caller-supplied data, not proof of permission.">

Every encrypted field carries its expected coordinates — application, table,
record, column and schema version. Decryption authenticates them: a ciphertext
moved to a different row or column fails verification even under the right key.

Context is caller-supplied data, not identity or permission. Your application
chooses the expected coordinates and authorises access. Details, freshness
options and replay limits live in the
[usage guide](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#context-binding-and-freshness).

## Features

| Surface | What it provides |
| --- | --- |
| Field encryption | AES-256-SIV `FLV2` envelopes with authenticated context; details in [SPEC.md](https://github.com/Guerilla-ops/floorvault/blob/main/docs/SPEC.md) |
| Database adapters | SQLite, libSQL, PostgreSQL, MySQL and SQLAlchemy table integrations; opt-in libSQL page encryption — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#database-adapters) |
| Credential stores | `VaultStore` local credential database with opt-in sealed listing metadata and legacy migration — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#credential-stores) |
| Key custody | Environment, macOS Keychain, Windows DPAPI, Linux Secret Service, opt-in file custody, Vault Transit — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#key-custody) |
| Hermes Agent | Optional plugin resolving vault items into host environment variables — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#hermes-agent-integration) |
| Freshness | Opt-in revisions and external anchors for rollback detection — [usage](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md#context-binding-and-freshness) |

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

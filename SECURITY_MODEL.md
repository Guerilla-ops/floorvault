# FloorVault threat model

Scope: `Guerilla-ops/floorvault` (main, 0.4.2). No infrastructure repository: FloorVault is a Python library + CLI (`floorvault` → `floorvault.inspector:main`) published to PyPI, plus the optional Hermes Agent plugin. Built on the maintainers' own policy in [`SECURITY.md`](SECURITY.md) (System and scope, Threat model and trust boundaries, Security invariants, Design limits) — that file is the maintainers' statement of the model; sections below marked *(SECURITY.md)* restate it, everything else is inferred from the code.

## System overview and trust boundaries

FloorVault runs in the caller's process. It has no network listener; its only IPC endpoint is the key agent's owner-only Unix socket, and its own outbound network call is HTTPS to a Vault server for Transit custody. `EncryptedLibSqlTable` also issues queries over the caller-provided libSQL connection, which may be a remote URL or embedded replica; that transport is the caller's.

Trust boundaries:
1. **Storage ↔ process** — databases, `vault.db`, ciphertext, metadata and backups are untrusted at rest; plaintext is released only after AES-SIV authentication against caller-supplied expected context.
2. **Other local users ↔ this user** — enforced by file modes (0600/0700), owner checks, and `SO_PEERCRED`/`LOCAL_PEERCRED` on the key-agent socket.
3. **Same-user code ↔ key / bindings** — SECURITY.md calls command bindings, decrypt-only agent mode and `--only` scoping guardrails, but **the maintainer decided (2026-11-27) these controls must hold against same-user code**: a realistic bypass is a real finding. The key itself must not leave custody (the agent never hands out the key).
4. **Configuration ↔ resolution** — `.env`/MCP config and Hermes profile config choose which items are resolved and into which child; untrusted config can name any item.
5. **Vault server ↔ client** — verified TLS only (`https://` enforced, `ssl.create_default_context`, optional `VAULT_CACERT`).
6. **Source ↔ released artifact** — GitHub Actions release with pinned actions, Sigstore attestation, PyPI Trusted Publishing.

## Components

| Component | Code |
|---|---|
| **Envelope core** | `src/floorvault/core.py`, `records.py`, `beacons.py`, `freshness.py`, `memory.py`, `vaultkit/` |
| **DB adapters** | `sqlite_adapter.py`, `dbapi_adapter.py`, `sqlalchemy_adapter.py`, `libsql_adapter.py`, `migration.py`, `sqlite_migration.py` |
| **Key custody** | `providers/` (adaptive, linux_keyring, windows_dpapi, platform_custody, passphrase_store, generation_store, vault_transit), `key_file.py`, `passphrase_custody.py`, `transit_custody.py`, `systemd_creds.py`, `keyring.py`, `key_recovery.py`, `custody_rotation.py`, `vault_rotation.py`, `platform_support.py`, `_filelock.py` |
| **Credential store** | `store.py`, `agentenv.py`, `binding_record.py`, `hermes_config.py` |
| **CLI** | `inspector.py`, `agent_cli.py` (`secrets`, `run`, `unlock`/`lock`, `import`, `protect`, `allow`) |
| **Key agent** | `key_agent.py` |
| **Hermes plugin** | `plugins/hermesvault/` (`source.py`, `cli.py`, `binding_guard.py`) |
| **Build & release** | `.github/workflows/`, `scripts/`, `pyproject.toml`, `uv.lock`, `fuzz/`, `.clusterfuzzlite/` |

## Entry points and who can reach them

- **Library API** (`FloorVault.encrypt/decrypt*`, adapters, `VaultStore`) — the embedding application; inputs include attacker-controllable stored ciphertext/rows.
- **CLI** — the local user (and anything running as them, e.g. an agent); reads `.env`/MCP config, env vars (`FLOOR_VAULT_KEY`, `VAULT_ADDR`, `VAULT_TOKEN`, `FLOOR_VAULT_REQUIRE_RECORD`, …), stdin, key files.
- **`floorvault run`** — resolves `fv:` refs and `execve`s the operator's command with plaintext in its environment, after binding checks.
- **Key agent socket** — `$XDG_RUNTIME_DIR/floorvault` or `<store>/agent`; same-uid peers only; JSON requests for status/lock/encrypt/decrypt.
- **Hermes plugin** — Hermes host calls the secret source at startup; `hermes hvault` CLI for setup/allow/bind.
- **Vault Transit** — outbound HTTPS from the client.
- **CI/release** — GitHub events on the repo.

## Assets and sensitivity *(SECURITY.md)*

All weighted equally for triage (maintainer decision). Master and derived keys; recovery material; credential values in `vault.db`; protected metadata; expected record coordinates (context); trusted freshness state; command-binding records; Vault tokens; release artifacts' integrity.

## Attacker profiles

- **Storage attacker** *(SECURITY.md, primary)* — can read/copy/modify databases, ciphertext, metadata and backups without the key. Must not obtain plaintext, cross-context acceptance, or key material.
- **Other local user** — unprivileged account on the same host; must not reach the agent socket, key files, store or binding records. **Maintainer: FloorVault runs on single-user dev workstations / agent hosts**, so findings whose only attacker is another local account are low priority.
- **Same-user code / prompt-injected agent** — **in scope per the maintainer**: it must not bypass the key agent's decrypt-only default, `--write`/`--bindings` opt-ins or `--only` scoping, command bindings in `run`/Hermes (including the out-of-store binding record, and `run`'s code-loading env var refusal; Hermes has already started and cannot check the variables that steer what it loads *(SECURITY.md)*), or extract the key. Still accepted *(SECURITY.md)*: it can request authentic plaintext the host and bindings allow, and read a started child's environment.
- **Untrusted configuration author** — supplies `.env`/MCP/Hermes config; documented that it can name any item; defects that let config redirect keys, overwrite bootstrap variables or escape directories are in scope.
- **Network attacker** — between client and Vault; must be stopped by verified TLS.
- **Supply-chain attacker** — malicious PR/dependency/action targeting CI or release.

## Existing controls

- AES-256-SIV envelopes (`FLV2`) authenticating `[context, header, nonce]`; canonical context encoding (`associated_data`, `canonical_json_bytes`); domain-separated HKDF labels.
- `AdaptiveKeyProvider` anti-fork guards (`master.key.ostier` marker, read-only OS tier when a file key exists, refuse on missing OS key); `strict=True` refuses env/file fallback.
- Identifier allow-listing and quoting (`_safe_identifier`, `_quoted_identifier`, `_quote_all`) with parameterised values; exact single-row update checks.
- Key agent: 0700 owner-checked socket dir, peer uid check, decrypt-only default, `--write`/`--bindings` opt-ins, `--only` scoping, owner-only use log, `PR_SET_DUMPABLE=0`/`PT_DENY_ATTACH`, hardened memory.
- `run`: strips key variables and Transit token from the child, binding enforcement with out-of-store fingerprint record, code-loading env var refusal (`LD_PRELOAD`, `NODE_OPTIONS`, …), refuses group/other-writable key files.
- Hermes: key from the `token_env` variable (default `HERMES_VAULT_KEY`, exactly 64 hex) when set, otherwise from configured custody (OS store, `key_file`, systemd-creds, Vault Transit); the process-wide `FLOOR_VAULT_KEY`/`VAULT_MASTER_KEY`/`FLOOR_VAULT_KEY_FILE` are not read by default (`token_env` is read from the fetch-scoped environment Hermes supplies, per profile under multiplex; config validation checks only that it is a valid variable name, so naming a legacy variable changes the lookup name, not its profile scope); bootstrap overwrite protection; post-resolve binding re-check; `bind --stdin` 64 KiB cap.
- systemd-creds: fixed system helper path, list argv, pipes, `--refuse-null` on 259+.
- Supply chain: SHA-pinned actions, gitleaks, semgrep, dependency audit, fuzzing, mutation tests, Sigstore provenance, Trusted Publishing.

## Security invariants

Concrete forms of SECURITY.md's invariants 1–9.

- **Authenticated decryption / cross-context (CWE-347, CWE-345).** `FloorVault.decrypt`/`decrypt_bytes` in `core.py` must authenticate before returning anything; header parsing (`envelope_header`, `_parse_envelope`) never establishes trust; context (app, schema, table, record, column, revision) goes through `associated_data` canonical encoding only. Anti-pattern: any path returning plaintext from a header-only parse, ad-hoc string concatenation of context, or falling back to a legacy `FLRV` vector for a `FLV2` record.
- **Nonce / protocol (CWE-323).** New writes use fresh 16-byte random nonces (`_track_nonce`); purpose labels and header bytes are protocol constants changed only via versioned migration. Repetition reveals equality only — judge accordingly.
- **Custody identity, no downgrade or key fork (CWE-636, CWE-1188).** `providers/adaptive.py` must refuse rather than mint when a marker/file key/sdcred exists or an OS key goes missing; configured custody failing (Transit, systemd-creds, key_file, OS) is reported, never replaced by another (`agent_cli._custody_key`, `hermesvault/source._open_store`). Transit never re-mints a missing wrapped key.
- **Strict custody / env key names (CWE-15).** `strict=True` and the Hermes source (with its default `token_env`) must not read `FLOOR_VAULT_KEY`, `VAULT_MASTER_KEY`, `FLOOR_VAULT_KEY_FILE`; legacy `APPSTATE_KEY` adoption stays off in `VaultStore`.
- **SQL injection (CWE-89).** Adapters build SQL only from identifiers passed through `_safe_identifier`/`_safe_column`/`_quoted_identifier` (sqlite) or `_quote_all` (DB-API) and bind values with `?`/`%s`; the `# nosec B608` f-strings are safe only while that holds. Anti-pattern: an identifier or record id reaching an f-string without the allow-list.
- **Command execution (CWE-78, CWE-426).** `run` uses `os.execve`/`subprocess.Popen` with list argv and no shell (`_launch`, `_spawn_and_wait`); `_find_command` resolution must match what bindings compare against (absolute path). `systemd_creds._run` uses only the system helper path. Anti-pattern: `shell=True`, PATH-relative resolution that differs from the bound path, or env vars that steer loading passing the check.
- **Secret flow to children (CWE-200, CWE-526).** `_prepare_environment` must strip every key variable and key-file pointer before exec, and refs onto those names are refused. `_without_transit_token` strips the Vault token (and copies of its value) from the collected environment, before secret resolution adds values, and only when the store uses Transit custody; a store with other custody, or a run given `--key-env`/`--key-file`, passes it through by design so `run -- vault ...` works. Hermes must not let a mapped secret overwrite bootstrap names.
- **Local IPC & file permissions (CWE-276, CWE-59, CWE-367).** Agent socket dir is re-checked (real dir, owner, 0700, no symlink) before every bind/connect; peer uid checked per connection; `vault.db` 0600; key files refused if other-owned or group/other-writable; markers owner-only; lock files under `$XDG_RUNTIME_DIR/floorvault` or `~/.cache/floorvault`. Anti-pattern: following symlinks, check-then-open races on key/marker files, world-readable creation before chmod.
- **Agent authorisation (CWE-862, CWE-863).** `key_agent` serves encrypt only with `--write`, binding-column writes only with `--bindings`, and refuses items outside `--only`; it never returns key bytes.
- **Binding integrity (CWE-345).** `run` and Hermes compare the sealed binding with the out-of-store `binding_record` fingerprint and refuse rolled-back/cleared bindings. In `run`, `FLOOR_VAULT_REQUIRE_RECORD=1` makes losing a previously established record fatal (first use is not affected); Hermes only warns when the record is lost and then checks bindings from the store alone.
- **TLS to Vault (CWE-295, CWE-319).** `providers/vault_transit.py` accepts only `https://` and a default-verified `ssl` context; redirects must stay on https; tokens never logged.
- **Diagnostics (CWE-532, CWE-209).** Errors, warnings and the agent use log never include values or keys; CLI `secrets` commands print no values; `secrets put` and `secrets add --stdin` take values from the prompt/stdin, while positional `secrets add field=value` arguments are visible to `ps` (documented in its help).
- **Migration/rotation (CWE-404-adjacent integrity).** Source preserved until verification, retired records never resurrected, old key generations kept through staged rotation.
- **Deserialization / parsing.** Agent messages are parsed with stdlib `json` only; recovery bundles (`key_recovery.py`) are a binary `FVRB1` header, bundle id and authenticated envelope; no `pickle`/`yaml.load` of untrusted input.
- **Supply chain (CWE-829, CWE-494).** Workflows pin actions by SHA, use least `permissions`, no `pull_request_target` with checkout of PR code; release builds are attested and published via Trusted Publishing.

## Out of scope / accepted risk *(SECURITY.md)*

Attacks premised only on full host, process or account compromise, root, physical access, unspecified timing differences, unclaimed features, and denial of service. Documented design limits: same-user code reading `run` children's environment or using the agent as a decryption oracle; unwrapped key file copies; visible metadata and beacon leakage; opt-in freshness/same-context replay; account-based OS custody and public default DPAPI entropy; plaintext residue in pages/WAL/backups; migration writing during listing; libSQL page encryption not authenticating the whole DB. Defects that exceed these limits or give a less-privileged caller new access remain in scope.

## Maintainer decisions (2026-11-27)

- Deployment: single-user dev workstations / agent hosts (not shared multi-user hosts, CI-only, or production app servers).
- Same-user code bypassing key-agent scoping or command bindings: **in scope**.
- Asset priority: all assets weighted equally.
- Hermes plugin: same priority as the core library.
- Finding tags: Component, Invariant, CWE, CVE.

## Open questions

- None outstanding.

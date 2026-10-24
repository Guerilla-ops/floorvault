# FloorVault usage guide

Detailed behaviour and limits. The [README](../README.md) is the short overview;
this guide carries the full notes on each surface.

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

## Run any command with vault secrets

`floorvault run` fills `fv:` references into environment variables and then
starts a command. Configs and `.env` files hold only references, so the
plaintext stays in the encrypted store.

```bash
# Store a secret (read from the terminal, never from argv).
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "OpenAI" --id openai --stdin; unset KEY

# Reference it. This file holds no secret.
echo 'OPENAI_API_KEY=fv:openai' > .env
floorvault run --env-file .env -- python agent.py
```

MCP clients work the same way. Point the server's command at `floorvault run`
and put the reference in its `env` block. Claude Desktop, Cursor and Claude
Code use this shape:

```json
{
  "mcpServers": {
    "github": {
      "command": "/absolute/path/to/floorvault",
      "args": ["run", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "fv:github-pat",
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

GUI clients often start servers with a minimal `PATH`. Use the absolute path
that `command -v floorvault` prints, and set `PATH` in the `env` block so `run`
can find the command (`npx` here); plain values there are passed through
unchanged. `run` looks the command up on the `PATH` it was started with.

**Install the key-store support for your platform.** A plain
`pip install floorvault` has no OS key store on macOS or Linux, and without
one `run` and `secrets add` refuse rather than fall back to a key file. Install
`floorvault[macos]` (Keychain) or `floorvault[linux]` (Secret Service) into the
same environment whose `floorvault` the client starts. Windows uses DPAPI with
no extra.

**Headless Linux, servers and containers.** Without a Secret Service (no
desktop session, a server, a container), give the key in a file with
`--key-file PATH` or `$FLOOR_VAULT_KEY_FILE`, rather than putting the master
key itself in `FLOOR_VAULT_KEY` or an MCP config, where it unlocks every item.

```sh
mkdir -p ~/.config/floorvault
(umask 077; python3 -c "import secrets; print(secrets.token_hex(32))" \
  > ~/.config/floorvault/master.key)
export FLOOR_VAULT_KEY_FILE=~/.config/floorvault/master.key
# Creates the store under that key; no OS key store is used.
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "OpenAI" --id openai --stdin; unset KEY
floorvault run -e OPENAI_API_KEY=fv:openai -- python agent.py
```

The file holds the 64-hex master key; surrounding whitespace is ignored. It
must be a regular file. On Linux and macOS it must also be owned by you or root
and not writable by group or others, since a replaceable key file would let someone choose the key new items
are sealed under. A file readable by others is used with a warning. Symlinks are
followed, so a Kubernetes secret volume works. Like `--key-env`, the key is used
directly and nothing is created elsewhere. `--key-file` and `--key-env` cannot
be combined, and `$FLOOR_VAULT_KEY_FILE` is ignored when `--key-env` is given.

In a container, mount the key as an orchestrator secret and point
`FLOOR_VAULT_KEY_FILE` at it. With Docker Compose:

```yaml
services:
  agent:
    environment:
      FLOOR_VAULT_KEY_FILE: /run/secrets/floorvault_key
    secrets: [floorvault_key]
secrets:
  floorvault_key:
    file: ./floorvault.key   # mode 600, outside the build context
```

In Kubernetes, mount a Secret as a volume with `defaultMode: 0440` and an
`fsGroup` the container runs in, or `0400` if it runs as the file's owner.

The key file is plaintext at rest, protected only by its permissions; it keeps
the key out of configs, shell history and the command's environment, not away
from root or from code running as you. The command started by `run` runs as the
same user and can read the file if it knows the path, so keep the file outside
the command's working directory.

**References.** `fv:<item_id>[:<field>]`. In `-e` and env files `hv:` is
accepted too, so a Hermes `secrets.hermesvault.env` mapping can be reused; in
the inherited environment only `fv:` is filled in, because an `hv:` value there
may belong to another tool. Without a field, `run` uses the
item's `value` field or its only field; other multi-field items need a field. A
value that starts with `fv:` or `hv:` but is malformed is an error, never
passed on as text.

**Sources**, lowest precedence first:

1. Inherited variables whose value is an `fv:` reference (turn off with
   `--no-inherit-refs`).
2. Each `--env-file`, in order. Lines are `[export ]NAME=value`, blank or
   `# comment`; one pair of matching quotes is removed; there is no
   interpolation. A `#` after a value is part of the value (`A=x # y` sets
   `x # y`), not a comment. Plain values are passed through unchanged.
3. Each `-e NAME=fv:ref`.

**Failure.** Every reference resolves or the command is not started. Errors go
to stderr and name the variable and item, never a value. Exit status: `125`
when `run` itself fails (usage, an env file, a reference, the vault or its key),
`127` when the command is not found, `126` when it cannot be started, and
otherwise the command's own status. `125` follows GNU `env`, so `run`'s own
failures never look like the command's `1` or `2`.

**Behaviour.** `run` writes nothing to stdout, which belongs to the command
(MCP servers speak JSON-RPC there). On Linux and macOS it replaces itself with
the command. On Windows it starts the command, waits, and exits with its
status; the command shares the console, so Ctrl+C reaches it directly. Because
`run` stays alive on Windows, the resolved values remain in its memory until
the command exits (Python strings cannot be wiped). A bare name such as `npx`
finds `npx.cmd` through `PATHEXT`; Windows runs `.cmd` and `.bat` files through
`cmd.exe`, whose quoting rules differ from a normal program's, so pass such
commands only arguments you wrote yourself. If nothing needs resolving, no
vault is opened.

**Store and key.** The store is `--vault DIR`, else `$FLOOR_VAULT_DIR`, else
`~/.floorvault/agent-vault`. The key uses the same custody as the Hermes plugin
(service `floor-vault`, application context `floor-agent`), or `--key-env NAME`
for a 64-hex key in a named variable, or `--key-file PATH` (default
`$FLOOR_VAULT_KEY_FILE`) for one in a file. `--key-env` and `--key-file` use
that key directly, as the plugin's `token_env` does; it does not pass through `AdaptiveKeyProvider`, so
it never creates or looks up a key elsewhere. `--vault "$HERMES_HOME/agent-vault"
--key-env HERMES_VAULT_KEY` reads a Hermes store set up with `token_env`. Only
`floorvault secrets add` and `secrets import --write` create a store or a key;
`run` and the other commands open an existing store and fail if the key is
missing. The command never receives `FLOOR_VAULT_KEY`, `VAULT_MASTER_KEY`,
`HERMES_VAULT_KEY`, `FLOOR_VAULT_KEY_FILE` or the `--key-env` variable, nor any
other variable holding a copy of one of their values or of the key file's key,
and no reference may target those names or `APPSTATE_KEY`. A program that needs one of those variables itself, such as
Hermes with `token_env`, should be started directly rather than through `run`.

On macOS and Linux the default custody keeps one master key per user and
service: the Keychain or Secret Service entry `floor-vault` / `default-v1`.
Every store opened with the defaults, including the Hermes plugin's
`agent-vault` and `run`'s store, uses that one key; the stores are separate
files, not separate keys. On Windows the DPAPI-protected key file lives in each
store's directory, so each store has its own key. The command is looked up
on `run`'s own `PATH`; a `PATH` set in an env file or with `-e` reaches the
command but does not choose which binary starts.

The commands use the existing `vault.db` format (schema version 3, unchanged
since 0.2.1), so a store shared with the Hermes plugin stays readable by both.

**Managing items.** `floorvault secrets add | put | list | show | rm | ref | import`.
`put` prompts for the value. `show` reports how many fields are set, or whether one named field is set. `ref` prints
the reference to paste (`--env NAME` prints `NAME=fv:…`). These commands never
print a value, and `add` and `put` refuse values containing a NUL byte, which
no environment variable can hold. Not printing values is a convenience, not a
control: `run` is the one way a value leaves the vault, whatever it starts can
print what it receives (`floorvault run -e X=fv:id -- printenv X`), and
`floorvault inspect --reveal` prints a decrypted field by design.

**Moving an existing `.env` into the vault.** `floorvault secrets import .env`
prints a plan and changes nothing. When the vault already exists, the dry run
unlocks it to compare values with existing items, so it needs the key:

```text
OPENAI_API_KEY -> fv:openai_api_key (new item)
DEBUG: left as is (--skip)
FLOOR_VAULT_KEY: left as is (a vault key variable cannot be stored in the vault it unlocks)
dry run: nothing changed. Re-run with --write to store and rewrite .env.
```

`--write` stores each plaintext value as an item, then replaces the file in
place with `fv:` references. The replacement is atomic, keeps the file's
comments, line endings and permissions, and makes no backup, because a backup
would be a second plaintext copy.
- **Item ids** are the lowercased variable names. `--prefix myapp.` namespaces them.
- **Selecting:** `--only NAME` and `--skip NAME` choose what moves.
- **Left as is:** empty values, existing references and vault key variables.
- **Re-running** is safe. An item that already holds the same value is reused, and one with different contents stops the import before anything changes.
- **Old copies:** earlier copies of the plaintext can survive in backups, editor swap files or git history. Rotate any key that was ever committed or shared.
- **Symlinks:** `--write` refuses a symlinked file.

**What the rewritten file works with.** After `--write` the file holds `fv:`
references, not values, so it works only for programs started with
`floorvault run --env-file .env -- <command>`. `run` puts the real values in
the environment before the program starts. Then:
- **A loader that keeps existing variables still works.** That covers python-dotenv's `load_dotenv()` and most dotenv libraries by default.
- **Anything that reads the file and lets it win breaks.** That covers a loader set to override, Docker Compose `env_file`, and Hermes Agent. It gets the `fv:` text and fails to authenticate. Nothing leaks, but it doesn't work.
- **MCP clients are unaffected.** They take secrets from the `env` block in their own config, not from `.env`.

**Hermes Agent.** Hermes loads `$HERMES_HOME/.env` with override, after its
environment is set, so fv: references there would replace the real values.
`secrets import` recognises a Hermes `.env`: `$HERMES_HOME`, `~/.hermes`,
`%LOCALAPPDATA%\hermes`, a `profiles/<name>` directory, or a directory with
Hermes' `state.db` and `config.yaml`. It warns on a dry run and refuses
`--write`. For Hermes, use the [plugin](#hermes-agent-integration):
1. Store each key with `hermes hvault add`.
2. Delete its line from `.env`.
3. Map it under `secrets.hermesvault.env` (`hermes hvault env <item> <NAME>` prints the mapping).

Protection is at rest. The started command, and code running as your user, can
read the resolved values: `run` keeps secrets out of files, not away from the
process that uses them.

**Untrusted configuration.** References name items by guessable ids
(`fv:openai`, `fv:github-pat`), and whatever configuration `run` reads decides
which items are resolved. A cloned repository's `.env` and the program it
starts, or an MCP server entry pasted from elsewhere, can name any item in your
vault and receive it. Only run `floorvault run` on configuration and commands
you have reviewed. When the command itself is untrusted, pass
`--no-inherit-refs` and give only the references it needs with `-e`, so
references already in the environment are not filled in for it.

## Hermes Agent integration

The optional plugin in [`plugins/hermesvault`](../plugins/hermesvault) resolves local
FloorVault items into Hermes Agent environment variables. FloorVault remains the
library and package name.

Install it with Hermes' plugin manager:

```bash
hermes plugins install Guerilla-ops/floorvault/plugins/hermesvault
hermes plugins enable hermesvault
```

The plugin directory is self-contained. Its `plugin.yaml` declares
`floorvault>=0.2.1,<0.3` and the platform keyring packages, which Hermes installs
from PyPI after asking for consent. The library wheel does not include or register
the plugin. See the [plugin README](../plugins/hermesvault/README.md) for
configuration, the `hermes hvault` commands and what the plugin reads and writes.

Once enabled, the plugin maps references to existing items into the host's
environment:

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
`put` replaces a field inside one immediate SQLite transaction, preserving the
existing item if validation or encryption fails. Hermes runs `hermes hvault` only
under the default `plugins.isolation: in_process`; under `host` isolation the
secret source still works but plugin CLI commands are skipped. On Linux without a
usable Secret Service, key resolution fails closed unless you supply an explicit
key. The source accepts a configured bootstrap key through
`token_env` (default `HERMES_VAULT_KEY`); this integration setting does not change
the core provider's environment-key defaults. Match the same bootstrap settings
when provisioning and reading a store. The plugin uses the authenticated
application context `floor-agent`; preserve it and the same custody settings
when reopening an existing store. Credentials returned to the host are
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

On macOS and Linux, constructing `HardenedMemoryKey` attempts to set the
process-wide `RLIMIT_CORE` soft and hard limits to zero. This setting is
permanent for the process and prevents the OS from writing process memory to a
core-dump file after a crash. Applications that depend on core dumps for
diagnostics should account for this side effect before opening a vault.

## Additional APIs

- `RecordBinding` and `ContextualSQLite`: custom record binding.
- `floorvault.beacons`: opt-in equality indexes; choose width for the dataset and leakage budget.
- `migrate_plaintext_column`, `verify_encrypted_column`, `drop_plaintext_column`: SQLite migration helpers.
- `KeyRing` and `rotate_vault_store`: staged rotation with retained key generations.
- `wrap_master_key` and `recover_master_key`: recovery using separately protected material.
- `floorvault.testing.siv_reference`: conformance helpers, not an application encryption API.

`floorvault inspect` opens an existing SQLite database read-only and decrypts a
selected field. Output is redacted unless `--reveal` is supplied. Match the
original custody service and application context; inspection creates no missing key.

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

Plugin tests need a compatible Hermes checkout through `HERMES_AGENT_SRC`;
otherwise they skip. Passing library tests do not demonstrate host integration.
Check actual CI results and skip reasons before making platform or custody claims.
Maintainers should keep the [required check names](CI.md) aligned with the workflow.

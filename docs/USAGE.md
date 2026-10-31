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
desktop session, a server, a container) there are two routes, and neither puts
the master key itself in `FLOOR_VAULT_KEY` or an MCP config, where it unlocks
every item. On a host with systemd 256 or newer, prefer
[systemd-creds](#headless-host-with-systemd-creds): the key is sealed to the
machine and your user. In a container, or where systemd-creds is not available,
give the key in a file with `--key-file PATH` or `$FLOOR_VAULT_KEY_FILE`.

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

### Headless host with systemd-creds

`floorvault secrets init --custody systemd-creds` creates a random master key
and seals it with `systemd-creds encrypt --user`. The sealed credential lives
beside the vault as `master.key.sdcred`; `run` and `secrets` find it there and
unseal it with `systemd-creds decrypt --user`, with no prompt and nothing in an
environment variable, an MCP config or a key file.

```sh
floorvault secrets init --custody systemd-creds      # new store only
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "OpenAI" --id openai --stdin; unset KEY
floorvault run -e OPENAI_API_KEY=fv:openai -- python agent.py
```

- **What binds the key.** The credential is tied to your numeric UID, your
  username and the machine-id, so another user, or the file copied to another
  machine, cannot unseal it. Beyond that, systemd's automatic selection decides:
  per its documentation it uses the TPM2 chip when it finds one (outside a
  container) and the host key (a root-only file under `/var/lib/systemd`) when that
  directory is on persistent media, and fails when neither is available.
  **floorvault cannot choose or check which one it used.** For an unprivileged
  caller `systemd-creds encrypt` passes no key choice to systemd (it ignores
  `--with-key`, and refuses `tpm2` alone with `--user`), so `init` offers no
  `--with-key`. Do not assume hardware binding: on a machine without a TPM2 the
  credential may be bound to the host key alone. It never asks for systemd's
  `null` key, which has no confidentiality or authentication.
- **What it does not stop.** Code running as you can ask `systemd-creds` to unseal
  the key just as `run` does, and root can too. A copied credential, without the
  host's secrets, cannot be opened elsewhere. With the host key alone, a full disk
  image holds the credential and the key that opens it; a TPM2 binding would add
  the hardware, but you must confirm that your host provides it, because
  floorvault does not.
- **Fails closed.** It needs Linux and systemd 256 or newer (`--user` arrived in
  256). Without that, `init`, `run` and `secrets` stop with a message; nothing
  falls back to the OS key store, a key file or `$FLOOR_VAULT_KEY`. A store with
  a `master.key.sdcred` takes its key from there and ignores `$FLOOR_VAULT_KEY`
  and `$FLOOR_VAULT_KEY_FILE`; `--key-env` and `--key-file` still override, which
  is the recovery route if you hold a copy of the key.
- **The helper.** `systemd-creds` is looked for only in `/usr/bin`, `/bin`,
  `/usr/sbin`, `/sbin` and `/run/current-system/sw/bin`, never on `$PATH` or
  through a variable, and runs with a minimal environment. The key reaches it
  and comes back through pipes, never argv. From systemd 259 decryption also
  passes `--refuse-null`; on 256 to 258 the only check against a planted
  credential is that the file is yours and not writable by others.
- **New stores only.** `init` refuses when `vault.db` already exists, and when
  `master.key.sdcred` does (it is never replaced). Moving an existing store's key
  into systemd-creds is not supported yet. Back up what the vault holds: losing
  the credential or the keys that open it loses the data.
- **No second key.** With a credential beside it, the default key provider
  (`AdaptiveKeyProvider`, which the Hermes plugin uses) refuses to create an OS or
  file key for that directory instead of forking it. An explicit key
  (`FLOOR_VAULT_KEY`, `--key-env`) is still honoured. The Hermes plugin opens such
  a store with `secrets.hermesvault.custody: systemd-creds` (plugin 0.2.8, with
  floorvault 0.2.8); its `hermes hvault setup` can also create the credential for
  a new store.

**Checked and not checked.** Tested against a stand-in for `systemd-creds` that
enforces the documented command contract (`--user`, the credential name,
`--refuse-null` only from 259, the key never in argv). That stand-in cannot show what
systemd's automatic selection binds the key to. `init` also unseals the
credential once from your shell before it writes anything. **Not checked on a real
host:** unsealing from a service, a cron job or an SSH session with no login (the
case this exists for), which distributions ship systemd 256 or newer, which key systemd's automatic
selection used on your host, and whether your cloud image offers a TPM2. Ubuntu 24.04 LTS ships systemd 255, which is too
old. Try `init` and a `run` from the kind of session you will use before relying
on it.

[`scripts/check_systemd_creds_host.sh`](../scripts/check_systemd_creds_host.sh)
does that for you, with a throwaway store under `$HOME` that it deletes on exit. It
reports the systemd version, whether a TPM2 is usable and whether linger is on,
then checks that the key unseals from your shell, from a cron-like bare
environment, and from a user service. With `--with-sudo` it also tries a system
service running as you outside any login session; with `--with-cron` a real cron
job (a marked crontab line, removed afterwards); and with `--with-ssh` a
non-interactive `ssh localhost`. Run it as the user that will own the vault. It
exits 0 when every context that ran passed, 1 when one failed, and 2 when the host
cannot run the check.

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
   `x # y`), not a comment. Plain values are passed through unchanged. Lines
   end only at LF, CR or CRLF; a line holding any other line-break character
   (form feed, vertical tab, U+0085, U+2028, U+2029, U+001C–U+001E) is refused,
   so a file means the same to `run` as it shows in an editor or `grep`.
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
status; the command shares the console, so Ctrl+C and Ctrl+Break reach it
directly while `run` ignores them and keeps waiting. Because
`run` stays alive on Windows, the resolved values remain in its memory until
the command exits (Python strings cannot be wiped). A bare name such as `npx`
finds `npx.cmd` through `PATHEXT`. Only the `PATH` entries are searched, never
the current directory first (unlike `shutil.which` and `cmd.exe`), and empty
entries are skipped. Windows runs `.cmd` and `.bat` files through
`cmd.exe`, whose quoting rules differ from a normal program's, so pass such
commands only arguments you wrote yourself. Windows variable names are not
case-sensitive, so `run` merges them that way there: `Path=` in an env file
replaces the inherited `PATH` (the command sees it upper-cased). If nothing
needs resolving, no vault is opened.

**Store and key.** The store is `--vault DIR`, else `$FLOOR_VAULT_DIR`, else
`~/.floorvault/agent-vault`. The key comes from the first of these that applies:
`--key-env NAME` (a 64-hex key in a named variable), `--key-file PATH`, the
`master.key.sdcred` beside the store (made by `secrets init --custody
systemd-creds`), `$FLOOR_VAULT_KEY_FILE`, and otherwise `AdaptiveKeyProvider` with
the Hermes plugin's service and context (`floor-vault`, `floor-agent`): the OS key
store, after `$FLOOR_VAULT_KEY` or `$VAULT_MASTER_KEY` when one is set (the plugin
itself reads neither; see below). The first four
use their key directly, as the plugin's `token_env` does. They do not pass
through `AdaptiveKeyProvider`, so they never create or look up a key elsewhere.
`--vault "$HERMES_HOME/agent-vault"
--key-env HERMES_VAULT_KEY` reads a Hermes store set up with `token_env`. Only
`floorvault secrets add`, `secrets import --write` and `secrets init` create a store or a key;
`run` and the other commands open an existing store and fail if the key is
missing. The command never receives `FLOOR_VAULT_KEY`, `VAULT_MASTER_KEY`,
`HERMES_VAULT_KEY`, `FLOOR_VAULT_KEY_FILE` or the `--key-env` variable, nor any
other variable holding a copy of one of their values (in either hex case) or of the
key from a key file or sealed credential (a sealed credential is unsealed, and so
its copies looked for, only when the command uses a reference),
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

**Rotated stores.** There is no `secrets rotate` command; a store is rotated
through the library (`rotate_vault_store`). Once a rotation has finished, put
the new key where `run` and `secrets` read it (OS key store, `--key-file`,
`--key-env`) and they open the store as before. A rotation that stopped
part-way leaves items under both keys, which no single key opens: every command
that opens the store (`run` with references, and the `secrets` commands that
read or change items) refuses it, says so, and changes nothing. `run` with no
references opens no store and starts the command as usual. Finish the rotation
with the library first.

The commands use the existing `vault.db` format (schema version 3, unchanged
since 0.2.1), so a store shared with the Hermes plugin stays readable by both.

**Sealed listing metadata.** By default `vault.db` shows each item's kind and
OTP flag in cleartext. `floorvault secrets seal-listing` seals them (after
checking the key opens every item), so the file shows only item ids. The
commands open a sealed store without options. To have them also refuse a store
whose kinds are cleartext again, which anyone who can write `vault.db` can do,
set `FLOOR_VAULT_SEALED_LISTING=1` or pass `--sealed-listing`; with it, a new
store is sealed from its first item. floorvault 0.2.8 and earlier, and the
`hermesvault` plugin, cannot open a sealed store, so do not seal a store the
plugin uses.

**Managing items.** `floorvault secrets add | put | list | show | rm | ref | import | allow | init | seal-listing`.
`put` prompts for the value. `show` reports how many fields are set, or whether one named field is set. `ref` prints
the reference to paste (`--env NAME` prints `NAME=fv:…`), and only one `run` can
resolve: for an item with several fields it asks for `--field`, and it refuses a
field the item does not have. These commands never print a value. `add` and
`put` refuse values that are blank or contain a NUL byte, field names a
reference cannot name (blank, a leading `:`, a NUL or newline), and `add`
refuses labels with a tab, newline or other control character. Before writing
to an existing store, `add` and `import --write` check that the key opens the
items already there, so a wrong key fails instead of leaving a store sealed
under two keys. Not printing values is a convenience, not a
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
`--write`. For Hermes, use `--hermes`, which moves the keys into the
[plugin](#hermes-agent-integration)'s store instead of rewriting the file:

```bash
floorvault secrets import --hermes                       # dry run on $HERMES_HOME/.env
floorvault secrets import --hermes --write --skip DEBUG  # store the items; .env is untouched
# add the printed secrets.hermesvault.env block to config.yaml, then:
floorvault secrets import --hermes --write --skip DEBUG --remove-from-env
```

1. **Dry run** (the default) prints each `NAME -> hv:<item>` and the
   `secrets.hermesvault.env` block to paste into `config.yaml`, and changes
   nothing. It lists every assignment, settings included: keep plain settings
   (a `DEBUG` flag, a model name) in `.env` with `--skip NAME` or `--only NAME`.
2. **`--write`** stores each value as a generic item in the plugin's store,
   `<home>/agent-vault` (pass `--vault DIR` when `secrets.hermesvault.dir` names
   another), under a key the plugin can use: the key in `$HERMES_VAULT_KEY` when
   that variable is set (or the variable `--key-env` names), else `--key-file`
   (the plugin's `custody: key_file`), else the systemd-creds credential beside the
   store (`custody: systemd-creds`), else the OS key store (`custody: os`). The
   printed block includes the `custody` and `key_file` lines to match.
   `$FLOOR_VAULT_KEY`, `$VAULT_MASTER_KEY` and `$FLOOR_VAULT_KEY_FILE` are ignored
   here (the plugin does not read them, so a store keyed by them would be
   unreadable to Hermes), and `--key-file` beside a sealed credential is refused,
   since it would create the store under a second key. It does not touch `.env`. Re-running reuses items
   that already hold the same value and stops on one that differs.
3. **`--write --remove-from-env`** deletes the imported lines from `.env`, but
   only after it has re-read each item, parsed `config.yaml` beside the `.env`,
   confirmed `secrets.hermesvault.enabled: true` and each nested mapping, checked
   the configured vault directory, and decrypted the imported values through
   the plugin's prospective key route. Otherwise it removes nothing.
   Removal is atomic, keeps the file's mode, comments and other lines, makes no
   backup (a backup would be a second plaintext copy) and refuses a symlink or a
   file that changed during the import.

`FILE` defaults to `$HERMES_HOME/.env`, else `~/.hermes/.env`; one profile per
run, by path (`profiles/<name>/.env` uses that profile's own `agent-vault`). A
directory that is not a Hermes home needs an explicit `--vault`. Vault key
variables in the file are left as they are.

The removal check requires the optional `hermes` extra (`floorvault[hermes]`,
which installs PyYAML). Without it removal fails with installation guidance;
dry runs and store-only imports still work. Duplicate YAML keys (including
overlapping merges), malformed YAML, disabled sources and mismatched mappings
are refused. The known `max_turns`/`agent` shape that makes Hermes use fallback
configuration is also refused. This guard does not run Hermes' full version-specific
normalization or managed overlays; unrelated configuration errors can still cause
Hermes to use its fallback, so review the rest of the profile and check with Hermes
after restart. Quoted keys, flow mappings and non-overlapping YAML merges work.
Relative `secrets.hermesvault.dir` paths resolve under the profile home.

The key check overlays the remaining profile `.env` values on the importing
process environment, then takes the plugin's own route: `token_env` (default
`HERMES_VAULT_KEY`), else `secrets.hermesvault.custody`: the OS key store with no
environment tier and no prompt (`os`), the file `key_file` names (relative paths
from the profile home), or the systemd-creds credential beside the store.
`$FLOOR_VAULT_KEY`, `$VAULT_MASTER_KEY` and `$FLOOR_VAULT_KEY_FILE` are not read,
as the plugin does not read them. For `key_file` and `systemd-creds` it also reads
the version of the plugin installed in the profile
(`<home>/plugins/hermesvault/plugin.yaml`) and refuses removal unless it is 0.2.8
or newer: an older plugin ignores `custody` and could not open the store. A custom `token_env` must remain available; it cannot itself be
removed. The check verifies decryption, not just matching variable names.
A changed config detected before replacement also prevents removal.

This does not prove that a separately launched Hermes process has the same
environment or OS key-store session. Run `hermes hvault doctor`, restart Hermes,
and verify the service before relying on the migration. Earlier plaintext
copies in backups, editor swap files and git history are not removed.

**What changes in Hermes once the lines are gone.** Checked against Hermes
`fab9b01` with `hermes chat` in a scratch home: with the key only in the vault,
the request carried the same key as with the key in `.env`. Two other commands
misreport, because they read the `.env` text rather than the environment:
`hermes doctor` warns "No API key found in .env", and `hermes status` can name a
different provider (it listed AWS Bedrock where it listed OpenAI before). Both are
display only in that test. Not tested: the messaging gateway, cron, the terminal
UI, several profiles, an OS key store as the key source, newer Hermes versions.
Two behaviours come from reading Hermes' source, not from a run: secret sources
fail open, so if Hermes cannot open the vault (a service without access to the OS
key store, a wrong key) it starts without these keys and fails at its first API
call, not at startup; and Hermes commands that save keys, such as `hermes setup`,
can write plaintext back into `.env`.

**The master key.** A store opened through `token_env` needs `HERMES_VAULT_KEY`
in the environment, and `.env` is where Hermes reads it from. Left there, anyone
who can read `.env` and `vault.db` can open the vault, so the move mostly keeps
keys out of what Hermes and its tools read as plain text. A store whose key is
held by the OS key store gains real protection at rest.

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

**Binding items to commands.** `floorvault secrets allow` binds an item to the
exact command lines `run` may start with it:

```bash
floorvault secrets allow github-pat -- npx -y @modelcontextprotocol/server-github
floorvault secrets show github-pat            # lists the bound command lines
floorvault secrets allow github-pat --remove -- npx -y @modelcontextprotocol/server-github
floorvault secrets allow github-pat --clear   # unbind: resolves for any command again
```

- **What must match:** the program's absolute path as found on `PATH` (symlinks
  are not followed, so a link to the same interpreter does not count), and then
  exactly the same arguments. Run `secrets allow` with the `PATH` the client
  uses; when they differ, `run` prints the command line it saw.
- **On a mismatch** `run` exits `125` naming the variable and item, and the
  command does not start. Items without a binding behave as before.
- **Variables that steer the program.** While a bound item is being resolved,
  `run` refuses to start if the command's environment sets a variable that can
  change what it loads: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`,
  `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`,
  `PYTHONUSERBASE`, `PERL5OPT`, `RUBYOPT`, `BASH_ENV`, `JAVA_TOOL_OPTIONS`,
  package-index variables for pip and uv, and npm's registry, config-file and
  TLS settings (`agentenv.CODE_INJECTION_ENV_NAMES` has the full list). Unset
  them for that command. The list is best effort: `HOME`, `PATH` and a
  program's own configuration files can steer it too.
- **Removing the last command line** is refused; use `--clear`, so widening an
  item to every command is always explicit.
- **Interpreters and launchers.** Binding `npx -y <package>` or
  `python /abs/path/agent.py` pins the arguments, not what they load: `npx`
  fetches the package when it runs, and a script can be edited. Give scripts as
  absolute paths; `secrets allow` warns about relative ones, which resolve
  against whatever directory the command starts in.
- **Not a boundary against your own user, or against anyone who can write
  `vault.db`.** The binding is sealed under the item's id, so it cannot be moved
  to another item or replaced with new command lines without the key. It can,
  however, be removed without the key (an item whose binding column is empty
  counts as unbound), or rolled back to an older sealed binding of the same
  item ([#97](https://github.com/Guerilla-ops/floorvault/issues/97)). Code
  running as you can also clear it, read the key from your key store, or read
  the started command's environment. It protects against mistakes and against
  a configuration that names an item for a command you did not choose. It does
  not fix which variable the value lands in.
- **Requiring a binding.** `floorvault run --require-binding`, or
  `FLOOR_VAULT_REQUIRE_BINDING=1` where `run` starts (for example in an MCP
  client's `env` block), refuses every item that has no binding. A binding
  cleared in `vault.db` then blocks the item instead of releasing it. The
  requirement lives outside the store, which is why it holds; a stored flag
  could be cleared the same way. It does not stop an older, wider binding of the
  same item being written back; only a record of the store kept outside it
  (`floorvault.freshness`) detects that.
- **Who enforces it:** only `floorvault run` from this release on. Older
  `floorvault` versions and the Hermes plugin ignore bindings.

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
`floorvault>=0.2.2,<0.3` and the platform keyring packages, which Hermes installs
from PyPI after asking for consent. The library wheel does not include or register
the plugin. See the [plugin README](../plugins/hermesvault/README.md) for
configuration, the `hermes hvault` commands and what the plugin reads and writes.
Run `hermes hvault setup` once per profile: it creates the store and its key and
may unlock the OS key store (a prompt), or, with `custody: systemd-creds`, seals a
new key beside a new store; with `custody: key_file` it uses the existing file. The secret source itself never prompts
and never creates anything, so Hermes startup cannot block on it; a missing store,
a missing key or a locked Secret Service collection is reported and startup goes
on without those variables.

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
custody. `environ=` chooses where the environment tier reads its variables (`{}`
for none, as the Hermes plugin does, or a per-configuration view in a process that
serves several), and `interactive=False` keeps the Linux Secret Service tier from
prompting: no unlock, no collection or key creation, a locked or missing key is
an error instead. On macOS it asks the Keychain to fail rather than show a dialog
(`kSecUseAuthenticationUIFail`) and creates no key; that is checked against a
stand-in for the Security framework, not a real Keychain. On Linux the
first key created for a service/account is serialized across processes of the
user, and two entries that hold different keys are refused, not chosen between. `resolve_key(allow_create=False)` resolves an existing key without creating
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
selected field. Output is redacted unless `--reveal` is supplied (a binary value
is then printed as hex). Match the original custody service and application
context; inspection creates no missing key. It tries the table and column names
as given and then ASCII-lower-cased, as `EncryptedSQLiteTable` binds them;
`--id-column` names the record id column (default `id`), `--revision` the
revision a record was written at, and `--schema-id` / `--schema-version` a
non-default schema coordinate. It refuses qualified column names and an id
that more than one row holds.

The key comes from the same options as `run` and `secrets`, in the same order:
`--key-env NAME`, `--key-file PATH` (default `$FLOOR_VAULT_KEY_FILE`), or
`--key-dir DIR`, the directory holding a systemd-creds credential sealed by
`secrets init --custody systemd-creds` (for an agent-secret store, its store
directory). Without a credential there, the default custody for
`--service-name` is used, with `DIR` as its key-file directory. Giving both
`--key-env` and `--key-file` exits 2.

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

The standalone local gate also requires external scanning tools. It needs
Python 3.11 or newer: `pip-audit` is installed by the dev extra only there,
because its `filelock` dependency has no patched release for 3.10 (the fixes for
the six advisories published on 2026-10-23 need 3.11), so on 3.10 the gate fails
closed with "Required gate tool not found: pip-audit". CI runs the audit on 3.13.
CI runs the full suite on four PR cells: Ubuntu Python 3.10/3.14 and macOS/Windows
Python 3.13.
Weekly, version-tag and expanded manual runs cover all declared Python versions
on Ubuntu plus Python 3.10/3.13 on macOS/Windows. Shared lint/build/scans run once;
full mutations run on Linux, with platform subsets on macOS/Windows. Dependency
audits resolve optional dependencies separately on each OS.

Plugin tests need a compatible Hermes checkout through `HERMES_AGENT_SRC`;
otherwise they skip. Passing library tests do not demonstrate host integration.
Check actual CI results and skip reasons before making platform or custody claims.
Maintainers should keep the [required check names](CI.md) aligned with the workflow.

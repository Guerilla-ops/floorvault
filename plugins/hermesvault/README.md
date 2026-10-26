# hermesvault: FloorVault secret source for Hermes Agent

`hermesvault` is a [Hermes Agent](https://github.com/NousResearch/hermes-agent)
secret-source plugin. At startup it resolves the environment variables you map
in `secrets.hermesvault.env` from a local [FloorVault](https://github.com/Guerilla-ops/floorvault)
store (AES-256-SIV, context-bound records). It also adds a `hermes hvault`
command for managing that store.

It holds agent credentials only. The browser-fill login vault at
`<profile-home>/vault` is never opened or migrated.

## Install

```bash
hermes plugins install Guerilla-ops/floorvault/plugins/hermesvault
hermes plugins enable hermesvault
```

Hermes asks for consent to install the plugin's Python dependencies, which come
from PyPI:
- `floorvault>=0.2.2,<0.3` (`custody: key_file` and `custody: systemd-creds` need
  0.2.8 or newer; with 0.2.2 they report that and open nothing);
- `secretstorage` on Linux;
- `pyobjc-framework-Security` on macOS.

The plugin directory contains no copy of FloorVault. Restart Hermes after
enabling the plugin, then create the store once per profile:

```bash
hermes hvault setup
```

`setup` creates the store and its key (in the OS key store, where it may show the
unlock prompt, or as a systemd-creds credential; see [Key custody](#key-custody)).
Nothing else does: the secret source runs at Hermes startup and never prompts,
unlocks, or creates a key, a credential or a store. If the store is missing, the
key is missing, or the Linux Secret Service collection is locked, the source
reports an error and Hermes starts without those variables.

Check an install with `hermes plugins doctor hermesvault`.

## Configure

```yaml
# ~/.hermes/config.yaml
secrets:
  hermesvault:
    enabled: true
    env:
      SERVICE_TOKEN: hv:vault_service        # the item's `value` field, or its only field
      DB_PASSWORD: hv:vault_db:password      # a named field
    # dir: agent-vault                       # default <profile-home>/agent-vault
    # token_env: HERMES_VAULT_KEY            # bootstrap key variable (64 hex chars)
    # custody: os                            # os, key_file or systemd-creds
    # key_file: /run/secrets/hermes-vault    # with custody: key_file
    # override_existing: false
```

A reference has the form `hv:<item_id>[:<field>]`. An item with several
fields needs an explicit field. A reference that can't be resolved is skipped
with a warning; it never sets an empty value.

**Remove each mapped key from `.env`.** Hermes loads `<profile-home>/.env`
before secret sources run. With `override_existing: false` (the default), a
variable that `.env` already sets keeps its `.env` value, and the vault value is
skipped without an error. Leaving a key in both places therefore keeps using the
plaintext copy. After mapping a key, delete its line from `.env`; `hermes status`
then counts it in `FloorVault: applied N secret(s)`. Setting
`override_existing: true` makes the vault win instead, but the plaintext copy
stays on disk.

`floorvault secrets import` will not rewrite a Hermes `.env` to references:
Hermes reads that file itself, so references there would replace the real
values. Move Hermes keys with `floorvault secrets import --hermes` instead. It
stores each value in this plugin's store, prints the `secrets.hermesvault.env`
block to add to `config.yaml`, and with `--write --remove-from-env` deletes the
imported lines from `.env` once enabled YAML mappings, the configured store and
plugin-key decryption have been verified (afterwards `hermes doctor`
warns that no API key is in `.env`, and `hermes status` can name a different
provider; chat uses the vault key). See
[USAGE](../../docs/USAGE.md#run-any-command-with-vault-secrets). Or move keys one
at a time with `hermes hvault` as above.

The companion removal check requires `floorvault[hermes]` (PyYAML). The
`floorvault secrets` command line is not in a published release yet (the plugin's
`floorvault>=0.2.2` dependency does not include it); run it from a FloorVault
source checkout until it is.

## Manage items

```bash
hermes hvault setup                          # once: create the store and key (may prompt)
hermes hvault add "Service token" --stdin    # field=value lines on stdin
hermes hvault put <item_id> <field>          # prompts for the value
hermes hvault list                           # metadata only
hermes hvault doctor                         # check mappings, custody and precedence
hermes hvault show hv:<item_id>              # field names and status; never plaintext
hermes hvault env <item_id> SERVICE_TOKEN    # prints the config.yaml mapping
hermes hvault rm <item_id>
```

Prefer `--stdin` or `put` to `field=value` arguments, which show up in process
listings. A malformed line is reported by its number (`stdin line 3`), never
echoed, since it may be the secret itself. `put` replaces one field inside a single SQLite transaction.

`hermes hvault doctor` checks the active profile's configuration and existing
store, attempts to resolve each mapping, and reports variables shadowed by the
current environment or protected as the bootstrap key. Exit status is 0 when
all configured mappings resolve without these issues, 1 for operational issues
(including a disabled source or no mappings), and 2 for malformed configuration.
It never prints credential values and does not create a missing vault. It opens
the store exactly as the secret source does at startup: no prompt, no key or store
created. With `override_existing: true` it reports that
existing values will be replaced; it does not remove plaintext files. Restart
Hermes and verify the actual service after changes: the command checks its own
process environment, not a running gateway or another profile.

CLI commands reject malformed IDs/environment names before opening the store.
`env` safely quotes its YAML output but does not verify that an item exists;
use `doctor` after merging that output into the profile configuration. Configuration
load errors or Hermes' `FailedConfigRead` fallback stop commands instead of
silently selecting the default store.

`hermes hvault` is a Hermes CLI subcommand, so it is available under the
default `plugins.isolation: in_process`. Under `plugins.isolation: host`, Hermes
skips plugin CLI commands; the secret source itself still works.

## Key custody

The store's master key is the 64-hex-character key in the variable named by
`token_env`, read from the environment Hermes gives this source for the profile
being fetched (under the multiplex gateway, that profile's scope, not the launch
environment). Without it, the key comes from the custody the profile sets in
`custody`:

| `custody` | Where the key is | Use it for |
|---|---|---|
| `os` (default) | the OS key store (macOS Keychain, Windows DPAPI, Linux Secret Service) through FloorVault's `AdaptiveKeyProvider`, with its environment tier turned off | desktops and laptops |
| `key_file` | the file named by `key_file` (absolute, or relative to the profile home), holding 64 hex characters | containers and servers with an orchestrator secret mount (Docker/Kubernetes secret on tmpfs) |
| `systemd-creds` | `master.key.sdcred` beside the store, sealed by `systemd-creds encrypt --user` and unsealed with `systemd-creds decrypt --user` | Linux servers with systemd 256 or newer and no Secret Service |

`FLOOR_VAULT_KEY`, `VAULT_MASTER_KEY` and `FLOOR_VAULT_KEY_FILE` are never read,
so a key in another profile's environment never unlocks this store. The source
also declares them, besides `token_env`, as protected, so a mapped secret can
never overwrite them. A configured custody that fails is reported and nothing
falls back to another one; `key_file` is refused unless `custody: key_file`.

**`key_file`.** The file is checked as `floorvault run --key-file` checks it:
symlinks (Kubernetes `..data`) must lead to a regular file, owned by you or root
and not writable by group or others. A file readable by others is used, with a
warning. `hermes hvault setup` creates the store under that key; it never
creates or changes the key file. The file is as strong as its permissions: on
a host's disk it protects against other users, not against code running as you
or against a copy of the disk.

**`systemd-creds`.** `hermes hvault setup` creates a random key, seals it to this
user and machine with `systemd-creds encrypt --user`, checks that it unseals,
and creates the store. It does this for a new store only: beside an existing
store it refuses, because a new key would fork the store's key. Setup does the
same as `floorvault secrets init --custody systemd-creds`, so a store made either
way opens either way. At startup the source runs `systemd-creds decrypt --user`
(found only in system directories, with a minimal environment, the key passed
through a pipe) and never creates a credential. Without systemd 256 or newer it
fails closed. **Not checked on a real host:** unsealing from a service or a
session with no login, which is how Hermes often runs. Restart Hermes and run
`hermes hvault doctor` in the same kind of session before relying on it. See
FloorVault's [docs/USAGE.md](https://github.com/Guerilla-ops/floorvault/blob/main/docs/USAGE.md)
for what systemd's automatic key selection does and does not protect.

On Linux every store using `os` custody shares one Secret Service entry
(`floor-vault` / `default-v1`). The first key for it is created under a per-user
lock (`$XDG_RUNTIME_DIR/floorvault`, else `~/.cache/floorvault`), so two stores set
up at the same time get the same key; if two entries with different keys exist
anyway (for example made by an older version), opening is refused rather than one
being picked, and no entry is overwritten or removed. On a host with no usable OS
key store and no `token_env` key, `os` custody fails closed; use `key_file` or
`systemd-creds` there. A store holding a systemd-creds credential is refused
under `os` custody with a message naming `custody: systemd-creds`.

`floorvault secrets import --hermes` stores under the same key: `$HERMES_VAULT_KEY`
(or `--key-env`), else `--key-file` (then set `custody: key_file` and `key_file`
to that file), else a credential beside the store (`custody: systemd-creds`),
else the OS key store; the mapping it prints includes the `custody` lines. With
`--remove-from-env` it deletes the `.env` lines only after opening the store the
way the plugin will, and, for `key_file` or `systemd-creds`, only if the plugin
installed in the profile (`<profile-home>/plugins/hermesvault`) is 0.2.8 or newer.
Keep the same custody settings and the `floor-agent` application context when
reopening an existing store. See FloorVault's
[SECURITY.md](https://github.com/Guerilla-ops/floorvault/blob/main/SECURITY.md)
for the custody model and its limits.

Command bindings set with `floorvault secrets allow` are enforced only by
`floorvault run`. This plugin ignores them and resolves a bound item like any
other.

## What this plugin does on your machine

- **Reads** a FloorVault store under `<profile-home>/agent-vault` (or
  `secrets.hermesvault.dir`) at startup, and only reads. `hermes hvault` commands
  write to it; `hermes hvault setup` creates it.
- **Reads its own master key** from the `token_env` variable, else from the custody
  configured in `custody`: the OS key store (service `floor-vault`, the default),
  the file named by `key_file`, or the systemd-creds credential beside the store. It never reads other tools' credential stores, `.env`
  files or Hermes' `auth.json`. Any other FloorVault `VaultStore` on the same
  account that uses default custody (for example an app built on
  `floorvault.vaultkit`, whose default store is `~/.floor/vault`) uses the same
  key-store entry and application context, so those stores are separated by
  directory, not by key. Set `token_env` to give the agent vault its own key.
  Hermes' own browser-fill vault is a separate implementation with its own key.
- **Returns plaintext secrets** to Hermes, which places them in the agent's
  environment. Hermes applies them; the plugin never writes `os.environ`.
- **Starts one subprocess, only with `custody: systemd-creds`:** the system's own
  `systemd-creds` (`decrypt --user` at startup; `encrypt` and `decrypt` during
  `hermes hvault setup`), as an argument list with no shell and a minimal
  environment. Otherwise no subprocesses.
- **No network calls**, no shell commands, no background processes, no telemetry.

## Develop

From a FloorVault checkout, with a Hermes checkout at `HERMES_AGENT_SRC`:

```bash
HERMES_AGENT_SRC=~/hermes-agent pytest tests/test_hermes_plugin.py \
  tests/test_hermes_plugin_packaging.py
hermes plugins validate plugins/hermesvault --install-deps
```

The tests that need Hermes skip without a checkout, and a skip proves nothing
about host compatibility.

## License

MIT, the same as FloorVault.

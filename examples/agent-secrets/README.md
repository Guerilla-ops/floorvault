# Keep agent secrets out of `.env`

AI agents and MCP servers usually read API keys from `.env` files or from the
`env` block of an MCP client config. Those files get synced, backed up, pasted
into issues and committed. Here they hold only `fv:` references. The values stay
in an encrypted local store, and `floorvault run` fills them into the command's
environment when it starts.

Everything below needs only `python -m pip install floorvault` and, for the
master key, your OS key store (`floorvault[macos]` or `floorvault[linux]`) or one
of the [headless options](../../docs/USAGE.md#run-any-command-with-vault-secrets).

## 1. Store the secrets

Values are read from standard input, never from the command line:

```bash
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "OpenAI" --id openai --stdin; unset KEY
read -rs KEY && printf 'value=%s\n' "$KEY" | floorvault secrets add "GitHub" --id github-pat --stdin; unset KEY
read -rs PW && printf 'user=app\npassword=%s\n' "$PW" | floorvault secrets add "App DB" --id app-db --stdin; unset PW
floorvault secrets list            # ids, kinds and labels; never a value
```

Already have a `.env` full of keys? `floorvault secrets import .env` shows what
it would move and changes nothing; `--write` stores the values and rewrites the
file to references. It keeps no backup, because a backup would be a second
plaintext copy, so old copies may still exist in editor swap files, backups or
git history.

## 2. Bind each item to its command

`floorvault run` hands an item only to the command lines it is bound to, and
refuses one with no binding, so say which command may receive each item:

```bash
floorvault secrets allow openai -- python ~/agent.py
floorvault secrets allow app-db -- python ~/agent.py
floorvault secrets allow github-pat -- python ~/agent.py
```

A binding is the program's absolute path as found on `PATH`, plus exactly these
arguments; `secrets allow` resolves the path and warns about relative ones.
`run` then refuses the item for any other command line. It also refuses an item
whose binding was cleared or replaced in the store file behind its back, for
example an older copy written back. `run --allow-unbound` resolves unbound items
for any command, as releases before 0.3.0 did.

## 3. Reference them

[`app.env`](app.env) holds references and ordinary settings, and is safe to commit:

```bash
floorvault run --env-file app.env -- python ~/agent.py
```

`fv:<item>` takes the item's `value` field (or its only field), and
`fv:<item>:<field>` takes a named one. If any reference does not resolve, the
command is not started.

## 4. MCP servers

[`mcp.json`](mcp.json) is the shape Claude Desktop, Cursor and Claude Code use.
The client starts `floorvault run`, which resolves the reference in `env` and
starts the server. Use the absolute path that `command -v floorvault` prints:
GUI clients often have a minimal `PATH`. Bind the server's item (step 2) with
the `PATH` from its `env` block, so `npx` resolves to the same file:
`PATH=/usr/local/bin:/usr/bin:/bin floorvault secrets allow github-pat -- npx -y @modelcontextprotocol/server-github`.

## What this protects, and what it does not

- **Protected:** the values at rest. Configs, `.env` files and their copies hold
  only references, so leaking them leaks no secret.
- **Not protected:** the started command can read its environment, and so can
  code running as your user, which can also ask the key store for the master
  key. A binding guards against mistakes and untrusted configuration, not
  against someone who can write the store file.

The [usage guide](../../docs/USAGE.md#run-any-command-with-vault-secrets) has
the details: key custody, headless hosts, Hermes Agent, and every option.

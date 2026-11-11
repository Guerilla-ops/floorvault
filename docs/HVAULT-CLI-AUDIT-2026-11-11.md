# `hermes hvault` CLI audit (2026-11-11)

An audit of the hermesvault plugin's operator CLI (`plugins/hermesvault/cli.py`)
and the parts of the secret source it calls (`source.py`, `binding_guard.py`), on
`main` at 257510a. A companion to [CLI-AUDIT-2026-10-26.md](CLI-AUDIT-2026-10-26.md),
which covered `floorvault run`, `secrets` and `inspect`.

**Method.** One full read of `cli.py` and two independent read-only reviews.
Every finding below was reproduced against throwaway stores, using the plugin's
own code and a Hermes checkout (NousResearch/hermes-agent at a867bb03, where
`tests/test_hermes_plugin.py` passes 141/141). Each fixed finding has a
regression test named after it in `tests/test_hermes_cli_audit.py`. All of those
tests fail on 257510a, except the ones marked *guard* below, which pin behaviour
that must not change.

**Result.** 21 findings, all fixed here.

## Findings

| ID | Severity | Command | Finding | Fix |
| --- | --- | --- | --- | --- |
| HV-2 | High | bind, put, add, fetch | A value containing a NUL byte was stored and returned by `fetch`. Hermes publishes resolved values with `os.environ[name] = value`, which raises `ValueError: embedded null byte`. `_apply_external_secret_sources` does not catch it, so Hermes failed at startup. | Refused at write time, as `floorvault secrets add`/`put` do. `fetch` skips a stored NUL value with a warning. |
| HV-12 | High | bind, doctor, status | `doctor` and `status` compared bindings with their own process (`hermes hvault …`), which no binding names. So `bind`'s default flow (bind to the gateway line, then run doctor) exited 1 with "resolved 0/1" and told the operator to rebind an item that was bound correctly. | `fetch_for(cfg, home, None)` runs every startup check except that comparison: the tamper record, unreadable bindings, `require_binding`, decryption. Each bound mapping is listed as information. |
| HV-11 | High | allow | `allow ITEM` with no command could only refuse: it dropped captured lines containing "hvault", and both `sys.argv` and `sys.orig_argv` of a real `hermes hvault allow` contain it. The help and README described a default that could not happen. | The no-command default binds the gateway line, the same line `bind` uses. Where there is none (Windows) it asks for the line after `--`. |
| HV-1 | Medium | bind --stdin | A value piped from a CRLF file kept a trailing `\r`. It is ASCII, so it passes Hermes' sanitiser, and the provider then rejects it as an invalid key. | Line endings (`\r\n`, `\n`) are removed. |
| HV-5 | Medium | show, put | Any store, key or decryption failure was reported as "item … not found". | Only a missing item is "not found". Other failures reach the redacted handler and its custody hint. *Guard:* a missing item is still "not found". |
| HV-13 | Medium | fetch, doctor, status | An `env` key that YAML reads as a non-string (`1:`) raised `TypeError` in Hermes' `is_valid_env_name`, at startup and in `doctor`. Errors from bare `hermes hvault` were prefixed "hvault None:". | Non-string names are skipped with a warning; the prefix is "hvault:". |
| HV-14 | Medium | bind, env, fetch | Hermes' name check matches with `$`, so `FOO\n` passed. It was written to config.yaml and echoed as a forged line. | Strict `fullmatch` name check (`valid_env_name`) in the CLI and the source. *Guard:* names Hermes already refused still fail. |
| HV-8 | Medium | add --stdin | Unlike `bind --stdin`, `add --stdin` read from a terminal, so the values were echoed on screen. | Refuses a terminal. |
| HV-3 | Medium | add | A blank value printed "created …" for an item with no usable field. | Refused with the argument or line number, exit 2. |
| HV-18 | Low | show, allow, bind | Bound command lines were printed raw, so a bound argument could carry terminal escapes (OSC/CSI). | Printed through `_printable`, as `list` already does. |
| HV-6 | Low | put, add, bind, show | Field names accepted C1 controls (0x9b is a CSI) and U+2028/2029, and are echoed back. | All `Cc`, `Zl` and `Zp` characters are refused. |
| HV-15 | Low | doctor, status, fetch | `env: null` made `doctor` exit 2 while `fetch` and `status` treated it as empty. `env: [K]` showed "0 mapping(s)" in `status`. | One rule in `validate_config`: null means no mappings, and any other non-map is refused everywhere. |
| HV-17 | Low | all | Every `ValueError`, including a bad key (`VaultError`), exited 2, which is the exit code for input errors. `status` exited 0 when resolving failed. | 2 is only for typed or configured input; runtime failures exit 1, and so does a failed resolve in `status`. |
| HV-4 | Low | add --id | An existing id gave "operation failed (IntegrityError)". | "item … already exists", with the `put` command to use instead. |
| HV-7 | Low | rm | Mappings to the removed item were left behind silently. Hermes then skips them at every startup. | Prints a warning with the number of mappings left; the names are not echoed. *Guard:* no warning when nothing maps to the item. |
| HV-9 | Low | add --stdin | `line.strip()` removed trailing whitespace from values, so a passphrase ending in a space lost it. | Only the line ending is removed. |
| HV-10 | Low | put | A blank value said "update failed (VaultError); check item and key custody". | "empty value; nothing changed", exit 2. |
| HV-16 | Low | status, doctor, setup | When the token variable was set but empty, the output said "key: the token_env variable", but `_open_store` ignores an empty value and falls back to custody. | Tests the value, not the name. |
| HV-19 | Low | allow --remove | A line whose program had been deleted could not be removed, because the program was resolved first. The only way out was `--clear`, which unbinds the item entirely. | `--remove` takes an absolute path as stored. |
| HV-20 | Low | allow | A lone `[` (the `/usr/bin/[` program) was parsed as a JSON command line and refused. | A lone `[` is a program. |
| HV-21 | Docs | show | The README said `show` prints field names; it prints counts. | README corrected. |

## Behaviour changes

- `allow ITEM` with no `--` binds the gateway line. It used to refuse in every real invocation.
- `doctor` passes for an item bound to lines other than its own process, and lists the item's bindings.
- Exit code 1, not 2, for store, key and custody failures. `status` returns 1 when resolving fails.
- `bind`, `put` and `add` refuse NUL bytes and blank values. `add --stdin` refuses a terminal and keeps values as written.
- `env:` that is neither a map nor null is a configuration error for `fetch`, `doctor` and `status` alike.

## Not covered

- **CI never runs the plugin tests.** It has no Hermes checkout, so `tests/test_hermes_plugin*.py` and `tests/test_hermes_cli_audit.py` skip there. They were run locally against hermes-agent a867bb03. A CI job that checks out a pinned Hermes would close this gap.
- The CLI was driven through `hvault_command` with Hermes' config reader stubbed, as the existing tests do. A full `hermes hvault …` run through Hermes' argument parser was not done.
- Windows: no default line for `allow` (HV-11), as for `bind`. Not run on Windows.

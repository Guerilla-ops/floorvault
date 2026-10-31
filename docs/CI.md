# CI and required checks

Ordinary pull requests run the full suite on Ubuntu Python 3.10/3.14 and
macOS/Windows Python 3.13. Weekly, version-tag and expanded manual runs add the
remaining declared Ubuntu interpreters and Python 3.10 on macOS/Windows.

Lint/build, static analysis, history scanning and the complete mutation roster
run in shared jobs. macOS/Windows also run platform mutation controls. Dependency
audits resolve all extras on each OS so platform-marked dependencies are covered.
The standalone `scripts/security-check.sh` remains a complete local gate.

## How the mutation controls are split

Each curated mutant runs the whole test suite, so the roster is sharded across
parallel jobs (`scripts/mutation_check.py --shard INDEX/COUNT`; every mutant runs
in exactly one shard, and the equivalent canary runs in all of them):

- **Linux:** `Linux mutants N/10` jobs, about 25 minutes each.
- **macOS and Windows:** `Platform mutants <os> N/6` jobs for the platform roster.
- **The required checks keep their names.** `Full mutation controls (Linux)` and
  the four `<os> / py<version>` cells are small gate jobs that pass only when
  every job behind them passed. Branch protection does not change when shards are
  added or removed. A shard that was skipped on a change that needs it fails the
  gate; skipping is accepted only for the case below.
- **Documentation-only pull requests skip the mutation jobs.** Mutation results
  depend on code and tests, so a pull request that changes only `*.md`, `docs/`,
  `examples/`, `LICENSE` or the repository templates runs the test, lint, SAST,
  audit and scan jobs but not the shards. Any other path, and every push to
  `main`, merge queue run, tag and scheduled run, runs everything.
- **Shard counts** (`linux`, `platform`) are set once, in the `Classify changes`
  job, and read by every shard job. Raise them as the roster grows: the harness
  refuses more shards than mutants. `tests/test_ci_workflow.py` guards the names
  and the single source of the counts.

Windows test jobs set `TEMP` and `TMP` to a unique directory under the user's
`LOCALAPPDATA\Temp` (inside the DPAPI provider's profile boundary), with a protected,
inheritable ACL for the owner, SYSTEM and Administrators, matching Python 3.13's
`mkdir(mode=0o700)` descriptor. Python before
3.13 ignores `mkdir(mode=0o700)` on Windows, so its temporary directories would
otherwise inherit extra account permissions from the hosted runner. Production
key-store ACL verification remains unchanged and continues to refuse those
permissions.

## Required checks on main

The repository's [floorvault branch governance ruleset](https://github.com/Guerilla-ops/floorvault/rules/24341865)
requires named checks. When changing the workflow matrix, update those names in
Settings → Rules → Rulesets as well. A deleted job cannot satisfy an old required
check, even when every emitted job passes.

For the reduced PR workflow, require these exact contexts:

```text
ubuntu-latest / py3.10
ubuntu-latest / py3.14
macos-latest / py3.13
windows-latest / py3.13
Lint and build
Full mutation controls (Linux)
SAST (Bandit, Semgrep CE)
secret scan (history)
Dependency CVE audit (all extras) (ubuntu-latest)
Dependency CVE audit (all extras) (macos-latest)
Dependency CVE audit (all extras) (windows-latest)
vault transit (live dev server)
fuzz (code-change)
```

Retire these seven contexts from the previous PR configuration:

```text
ubuntu-latest / py3.11
ubuntu-latest / py3.12
ubuntu-latest / py3.13
macos-latest / py3.10
windows-latest / py3.10
Pinned gitleaks history scan
Windows native DPAPI and NTFS custody
```

The five extra interpreter cells still run in expanded CI. The shared history
scan replaces the duplicate gitleaks job. Native Windows DPAPI remains in the
Windows full test suite. Requiring the new build, mutation and audit jobs preserves
controls previously embedded in each platform's full gate.

Keep review-thread resolution, linear history and non-fast-forward protection
unchanged. This document is a settings checklist; committing it does not modify
the hosted ruleset.

## Merge queue

"Require branches to be up to date before merging" makes every merge turn each
other open pull request stale: it must take the new `main` and run all of the
checks again, so pull requests merge one at a time. A merge queue replaces that
rule. It tests each pull request merged onto `main` (and onto the pull requests
ahead of it) once, and merges it when that passes, with no manual branch updates.

Both workflows that report required checks, `ci.yml` and `cflite.yml`, run on
`merge_group`. To switch, in the ruleset:

1. Turn off "Require branches to be up to date before merging".
2. Turn on "Require merge queue": method **squash**, "Maximum pull requests to
   build" about 3 (they are tested in parallel), "Minimum pull requests to merge"
   1, and a status-check timeout of about 90 minutes.
3. Keep the same required status checks. In the queue, the fuzz check runs in
   batch mode for the same 5 minutes (code-change mode needs a pull request
   event); its name is unchanged.

CodeQL's default setup is not part of the required checks above. If you add it as
required, confirm it reports on `merge_group` runs first, or the queue will wait
for it.

## Before publishing a release

Push the version tag and wait for its expanded CI run, or rehearse the exact
release commit with the CI workflow's manual `expanded` option. Publishing the
GitHub release starts the publishing workflow; follow [RELEASING.md](RELEASING.md).

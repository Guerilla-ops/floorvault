# CI and required checks

Ordinary pull requests run the full suite on Ubuntu Python 3.10/3.14 and
macOS/Windows Python 3.13. Weekly, version-tag and expanded manual runs add the
remaining declared Ubuntu interpreters and Python 3.10 on macOS/Windows.

Lint/build, static analysis, history scanning and the complete mutation roster
run in shared jobs. macOS/Windows also run platform mutation controls. Dependency
audits resolve all extras on each OS so platform-marked dependencies are covered.
The standalone `scripts/security-check.sh` remains a complete local gate.

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

Keep up-to-date branch checking, review-thread resolution, linear history and
non-fast-forward protection unchanged. This document is a settings checklist;
committing it does not modify the hosted ruleset.

## Before publishing a release

Push the version tag and wait for its expanded CI run, or rehearse the exact
release commit with the CI workflow's manual `expanded` option. Publishing the
GitHub release starts the publishing workflow; follow [RELEASING.md](RELEASING.md).

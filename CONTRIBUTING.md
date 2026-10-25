# Contributing to FloorVault

Thanks for your interest in FloorVault. It is a cryptographic library, so
reviews here are security reviews first and style reviews second. This guide
explains how to propose changes so they can be reviewed and merged quickly.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

**Do not open a public issue, pull request or discussion for a vulnerability.**
Follow [SECURITY.md](SECURITY.md): use
[GitHub private vulnerability reporting](https://github.com/Guerilla-ops/floorvault/security/advisories/new)
or email **floorbond@pm.me** with a subject beginning `SECURITY:`.

## Issues

- Search [existing issues](https://github.com/Guerilla-ops/floorvault/issues)
  before opening a new one.
- Use the bug report or feature request template. Include the FloorVault
  version or commit, Python version, OS and the key-custody tier in use.
- Never paste keys, passphrases, key-store files, ciphertext from production
  systems or other people's data.

## Development setup

FloorVault uses [uv](https://docs.astral.sh/uv/) and supports Python 3.10+.

```bash
git clone https://github.com/Guerilla-ops/floorvault
cd floorvault
uv sync --extra dev            # add --extra macos on macOS, --extra linux on Linux
```

## Checks to run before opening a pull request

These mirror the required CI checks (see [docs/CI.md](docs/CI.md)):

```bash
uv run --no-sync ruff check src/ tests/ scripts/ fuzz/
uv run --no-sync ruff format --check src/ tests/ scripts/ fuzz/
uv run --no-sync pytest -q tests/
uv run --no-sync python -u scripts/mutation_check.py --mode curated
```

`scripts/security-check.sh` is the complete local security gate (gitleaks,
pip-audit, Bandit, Semgrep CE and more). It fails closed when a gate tool is
missing; set `FLOORVAULT_STRICT=0` only if you deliberately accept skipping one.
Run it on Python 3.11 or newer: the dev extra installs `pip-audit` only there
(see [the usage guide](docs/USAGE.md#development)), so on 3.10 the gate stops at
"Required gate tool not found: pip-audit".

## Pull request guidelines

- Branch from `main` and keep each pull request focused on one change.
  `main` requires linear history, so pull requests are squash- or
  rebase-merged.
- Use [Conventional Commits](https://www.conventionalcommits.org/) style
  titles, e.g. `fix(custody): ...`, `feat(security): ...`, `docs(readme): ...`.
- Add or update tests for every behavior change. New security guards need a
  curated mutant in `scripts/mutation_check.py`.
- Update documentation in the same pull request. Wrong docs are treated as
  bugs (see `docs/SPEC.md` §17).
- All review threads must be resolved and required checks green before merge.

### Security-sensitive rules

Changes that touch the following need extra care and will be reviewed
strictly. The full list lives in
[.github/copilot-instructions.md](.github/copilot-instructions.md).

- **On-disk formats are a contract.** Any byte-level change to an envelope,
  record or store format requires a version bump, a spec update in
  `docs/SPEC.md`, new test vectors, and a reader for every previously
  published version.
- **Never weaken authentication or validation.** Every cleartext envelope
  field stays inside the AEAD associated data, and the rejection rules in
  `docs/SPEC.md` §4.3/§16 are normative, including their order.
- **Nonces** are 16 bytes from `os.urandom`, fresh per field.
- **No custody downgrades.** A broken or refused key-custody tier must raise,
  never silently fall through to a weaker one.
- **SQL identifiers** must pass `_safe_identifier` and be interpolated via
  `_quoted_identifier`.
- **Errors are honest.** No swallowed exceptions or checks masked behind
  other checks.
- **Public API.** The public surface is pinned by `tests/test_public_api.py`;
  changes to it must be deliberate. See [docs/RELEASING.md](docs/RELEASING.md)
  for the versioning and deprecation policy.

## License

FloorVault is licensed under the [MIT License](LICENSE). Unless you explicitly
state otherwise, any contribution you intentionally submit for inclusion in
FloorVault is licensed under the same MIT terms, without any additional terms
or conditions.

## Summary

<!-- What does this change and why? Link related issues (e.g. "Fixes #123"). -->

## Test plan

<!-- How was this verified? -->

- [ ] `uv run --no-sync ruff check src/ tests/ scripts/ fuzz/` and `ruff format --check` pass
- [ ] `uv run --no-sync pytest -q tests/` passes
- [ ] `uv run --no-sync python -u scripts/mutation_check.py --mode curated` passes (security guards changed or added)

## Checklist

- [ ] Tests added or updated for every behavior change
- [ ] Documentation updated (wrong docs are bugs)
- [ ] No on-disk / wire-format change, **or** version bump + `docs/SPEC.md` + vectors + readers for every published version
- [ ] No weakening of authentication, validation, nonce discipline or key custody
- [ ] Public API unchanged, **or** `tests/test_public_api.py` updated deliberately
- [ ] No secrets, keys or production data in code, tests or logs

<!-- Security vulnerabilities: do not open a public PR. See SECURITY.md. -->

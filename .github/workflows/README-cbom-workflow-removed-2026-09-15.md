# Crypto Bill of Materials workflow — removed 2026-09-15

The `.github/workflows/main.yml` "Create Crypto Bill of Materials" workflow,
added in commit `7ca3499`, was removed in `18de92f` (this file's parent).

**Reason.** The workflow consumed `advanced-security/cbom-action@v1`, which
internally uses the now-deprecated `actions/upload-artifact: v3`. GitHub
auto-blocks requests to that deprecated action, so every matrix-analysis job
(and therefore the whole workflow) failed on every run, including the first
run after the workflow was added and again on the push that included this
removal. The failure was in the third-party action's own machinery, not in
anything `vaultfloor/floorvault` ships.

**What the workflow did.** It used the GitHub Advanced Security CBOM action to
build a crypto bill of materials across a matrix of public Python ecosystem
repositories (`coveragepy`, `cryptography`, `ruff`, `packaging`, `pytest`,
`pyobjc`, etc.), not floorvault's own dependencies in any actionable sense.

**What was already covering the real gate.** FloorVault's secret scan is
gitleaks in `.github/workflows/ci.yml` (CI job `secret scan (history)`), which
runs on every push to `main` and must pass for the push to be considered
gate-clean. The CBOM workflow was informational only and was never part of the
pre-push gate.

**Status.** Removed. No replacement is in place; if a crypto bill of materials
is wanted in future it should use a maintained action whose dependencies do not
include a deprecated artifact-action version.

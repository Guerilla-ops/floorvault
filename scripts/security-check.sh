#!/usr/bin/env bash
# scripts/security-check.sh for floorvault
#
# Single source of truth for the security gates: run locally before pushing,
# and by CI on every supported OS and Python version.
#
# Behaviour knobs:
#   FLOORVAULT_STRICT=0            allow a missing gate tool to be skipped (warn)
#                                  rather than failing the gate. Default is 1:
#                                  fail closed, so a missing tool can never be
#                                  mistaken for a passing check.
#   FLOORVAULT_SKIP_SECRET_SCAN=1  skip the gitleaks history scan
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

STRICT="${FLOORVAULT_STRICT:-1}"

echo "============================================================"
echo "    STARTING LOCAL SECURITY & CRYPTOGRAPHIC VERIFICATION    "
echo "============================================================"

# Ensure virtualenv binaries are prioritized. The venv layout differs between
# Windows (Scripts/) and POSIX (bin/), so probe both.
for candidate in "$REPO_DIR/.venv/bin" "$REPO_DIR/.venv/Scripts"; do
    if [ -d "$candidate" ]; then
        export PATH="$candidate:$PATH"
    fi
done

require_tool() {
    # Fail closed by default: a gate that silently skips a missing tool reports
    # success it did not earn (a missing pip-audit once removed the dependency
    # CVE audit from this gate entirely). Opting out is deliberate and explicit.
    if ! command -v "$1" >/dev/null 2>&1; then
        if [ "$STRICT" = "1" ]; then
            echo "[FAIL] Required gate tool not found: $1" >&2
            echo "       Install it, or set FLOORVAULT_STRICT=0 to run without this check." >&2
            exit 1
        fi
        echo "[WARN] $1 not found. Skipping (FLOORVAULT_STRICT=0)."
        return 1
    fi
    return 0
}

echo ""
echo "=== 1. Scanning Repository History & Staged Changes (Gitleaks) ==="
if [ "${FLOORVAULT_SKIP_SECRET_SCAN:-0}" = "1" ]; then
    echo "[SKIP] Secret scan disabled (FLOORVAULT_SKIP_SECRET_SCAN=1)."
elif require_tool gitleaks; then
    gitleaks git --verbose --redact
    echo "[PASS] Gitleaks: Zero secrets or private keys detected."
fi

echo ""
echo "=== 2. Auditing Python Dependencies for CVEs (pip-audit) ==="
if require_tool pip-audit; then
    pip-audit --desc on --skip-editable
    echo "[PASS] pip-audit: Zero vulnerable dependencies detected."
fi

echo ""
echo "=== 3. Running Static Analysis & Linting (Ruff) ==="
ruff check src/ tests/
ruff format --check src/ tests/
echo "[PASS] Ruff: Zero lint or code quality violations."

echo ""
echo "=== 4. Verifying Official RFC 5297 (AES-SIV) & RFC 5869 Test Vectors ==="
pytest -q tests/test_rfc_vectors.py
echo "[PASS] RFC Test Vectors: 100% byte-for-byte mathematical alignment."

echo ""
echo "=== 5. Testing Hardware Memory Custody & Zeroization (mlock) ==="
pytest -q tests/test_memory_custody.py
echo "[PASS] Memory Custody: Page locking, anti-dumping, and zeroization verified."

echo ""
echo "=== 6. Running Core Crypto & Splicing Immunity Tests ==="
pytest -q tests/test_crypto_core.py tests/test_sqlite_integration.py
echo "[PASS] Core Crypto: Contextual AAD anti-splicing verified."

echo ""
echo "=== 7. Running Agent-Optimized Drop-in Adapter Tests ==="
pytest -q tests/test_vaultkit_adapter.py tests/test_adaptive_provider.py
echo "[PASS] Adapter: Vault storage and session encryption verified."

echo ""
echo "=== 8. Running Deterministic Fuzz Harness (adversarial crypto invariants) ==="
pytest -q tests/test_fuzz.py
echo "[PASS] Fuzz: round-trip, splice-immunity, and malformed-envelope invariants verified."

echo ""
echo "=== 9. Running the Full Test Suite ==="
# Step 5-8 above cover the security-critical paths with readable labels, but the
# gate MUST also run everything else: the enumerated subsets previously missed
# test_platform_providers.py, test_protected_store_safety.py and others, so a
# regression could pass CI while the suite failed locally.
pytest -q tests/
echo "[PASS] Full suite: every test file under tests/ passed."

echo ""
echo "=== 10. Verifying Universal Wheel Build (Zero-C Compilation) ==="
rm -rf dist/
uv build
python scripts/verify_wheel.py dist
echo "[PASS] Wheel Build: Successfully packaged a universal (py3-none-any) wheel."

# Report the artifact digests. The gate builds the wheel and sdist, verifies
# their shape, and would otherwise discard them leaving no record of which
# bytes this run produced - which makes reproducibility unprovable rather than
# merely unproven. Every leg prints these, so the logs from all three operating
# systems can be compared against each other, and a release note can carry the
# digests for anyone checking a download against a build from source.
# Computed in Python rather than with sha256sum/shasum: the gate runs under bash
# on Windows too, where neither tool is guaranteed to exist.
python - <<'DIGESTS'
import gzip  # noqa: F401  (documents that the sdist is gzip-compressed)
import hashlib
import pathlib
import tarfile
import zipfile

dist = pathlib.Path("dist")
wheels = sorted(dist.glob("*.whl"))
sdists = sorted(dist.glob("*.tar.gz"))
if not wheels or not sdists:
    raise SystemExit("[FAIL] expected both a wheel and an sdist in dist/")

for artifact in wheels + sdists:
    print(f"[DIGEST] sha256 {hashlib.sha256(artifact.read_bytes()).hexdigest()} {artifact.name}")

# Archive headers carry fields that vary by platform (the zip creating-system
# byte, the gzip OS byte, tar member modes) and any of them would explain a
# digest that differs between runners. Printing them turns the question into a
# reading instead of another guess: see the artifact-identity note in
# SECURITY.md, where two attributions have already been falsified by a run.
for wheel in wheels:
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        creators = sorted({info.create_system for info in infos})
        modes = sorted({info.external_attr >> 16 for info in infos})
    print(f"[ARTIFACT] {wheel.name}: create_system={creators} modes={[oct(m) for m in modes]}")

for sdist in sdists:
    with tarfile.open(sdist, "r:gz") as archive:
        tar_modes = sorted({member.mode for member in archive.getmembers()})
    print(f"[ARTIFACT] {sdist.name}: gzip_os_byte={sdist.read_bytes()[9]} tar_modes={[oct(m) for m in tar_modes]}")
DIGESTS

echo ""
echo "=== 11. Verifying the Security Tests Actually Detect Regressions (Mutation) ==="
# The suite passing proves nothing if the tests cannot fail. This runs curated
# behavioural mutants of the custody code and requires every one to be killed.
# It was previously a manual script only, so a refactor that invalidated the
# mutants' anchors (they silently reported 'pattern not found' rather than
# failing) went unnoticed by this gate.
python scripts/mutation_check.py --mode curated
echo "[PASS] Mutation: all required curated security mutants were killed; declared equivalent mutants are documented."

echo ""
echo "============================================================"
echo "    ALL STANDALONE SECURITY GATES & RFC VECTORS PASSED     "
echo "============================================================"

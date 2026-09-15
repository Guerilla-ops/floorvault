#!/usr/bin/env bash
# scripts/security-check.sh for floorvault
#
# Single source of truth for the security gates: run locally before pushing,
# and by CI on every supported OS and Python version.
#
# Behaviour knobs:
#   FLOORVAULT_STRICT=1            a missing gate tool is fatal (default: warn + skip)
#   FLOORVAULT_SKIP_SECRET_SCAN=1  skip the gitleaks history scan
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

STRICT="${FLOORVAULT_STRICT:-0}"

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
    # In strict mode (CI) a missing tool is fatal; locally it is a loud warning.
    if ! command -v "$1" >/dev/null 2>&1; then
        if [ "$STRICT" = "1" ]; then
            echo "[FAIL] Required gate tool not found: $1" >&2
            exit 1
        fi
        echo "[WARN] $1 not found. Skipping (set FLOORVAULT_STRICT=1 to fail instead)."
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
echo "=== 6. Running Core Crypto, Splicing Immunity, & Blind Index Tests ==="
pytest -q tests/test_crypto_core.py tests/test_blind_index.py tests/test_sqlite_integration.py
echo "[PASS] Core Crypto: Contextual AAD anti-splicing and B-Tree lookups verified."

echo ""
echo "=== 7. Running Agent-Optimized Drop-in Adapter Tests ==="
pytest -q tests/test_vaultkit_adapter.py tests/test_adaptive_provider.py
echo "[PASS] Adapter: Vault lookups and FTS5 split-projection verified."

echo ""
echo "=== 8. Running Deterministic Fuzz Harness (adversarial crypto invariants) ==="
pytest -q tests/test_fuzz.py
echo "[PASS] Fuzz: round-trip, splice-immunity, malformed-envelope, beacon invariants verified."

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

echo ""
echo "============================================================"
echo "    ALL STANDALONE SECURITY GATES & RFC VECTORS PASSED     "
echo "============================================================"

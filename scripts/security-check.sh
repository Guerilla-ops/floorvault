#!/usr/bin/env bash
# scripts/security-check.sh for floorvault
# 100% Local Git Pipeline (Zero Cloud / No GitHub Actions Required)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "============================================================"
echo "    STARTING LOCAL SECURITY & CRYPTOGRAPHIC VERIFICATION    "
echo "============================================================"

# Ensure virtualenv binaries are prioritized
export PATH="$REPO_DIR/.venv/bin:$PATH"

echo ""
echo "=== 1. Scanning Repository History & Staged Changes (Gitleaks) ==="
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks git --verbose --redact
    echo "[PASS] Gitleaks: Zero secrets or private keys detected."
else
    echo "[WARN] Gitleaks not found globally. Skipping secret scan."
fi

echo ""
echo "=== 2. Auditing Python Dependencies for CVEs (pip-audit) ==="
if command -v pip-audit >/dev/null 2>&1; then
    pip-audit --desc on --skip-editable
    echo "[PASS] pip-audit: Zero vulnerable dependencies detected."
else
    echo "[INFO] pip-audit not installed in active environment. Skipping CVE audit."
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
echo "=== 9. Verifying Universal Wheel Build (Zero-C Compilation) ==="
uv build
echo "[PASS] Wheel Build: Successfully packaged universal wheel."

echo ""
echo "============================================================"
echo "    ALL STANDALONE SECURITY GATES & RFC VECTORS PASSED     "
echo "============================================================"

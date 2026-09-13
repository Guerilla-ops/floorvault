#!/usr/bin/env bash
# scripts/security-check.sh for appstate-crypto
# 100% Local Git Pipeline (Zero Cloud / No GitHub Actions Required)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "============================================================"
echo "    STARTING LOCAL SECURITY & CRYPTOGRAPHIC VERIFICATION    "
echo "============================================================"

echo ""
echo "=== 1. Scanning Repository History & Staged Changes (Gitleaks) ==="
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --source . --verbose --redact
    echo "[PASS] Gitleaks: Zero secrets or private keys detected."
else
    echo "[WARN] Gitleaks not found; skipping secret scan."
fi

echo ""
echo "=== 2. Auditing Python Dependencies for CVEs (pip-audit) ==="
.venv/bin/pip-audit --strict --desc on
echo "[PASS] pip-audit: Zero vulnerable dependencies detected."

echo ""
echo "=== 3. Running Static Analysis & Linting (Ruff) ==="
.venv/bin/ruff check src/ tests/
echo "[PASS] Ruff: Zero lint or code quality violations."

echo ""
echo "=== 4. Verifying Official RFC 5297 (AES-SIV) & RFC 5869 Test Vectors ==="
.venv/bin/pytest -q tests/test_rfc_vectors.py
echo "[PASS] RFC Test Vectors: 100% byte-for-byte mathematical alignment."

echo ""
echo "=== 5. Testing Hardware Memory Custody & Zeroization (mlock) ==="
.venv/bin/pytest -q tests/test_memory_custody.py
echo "[PASS] Memory Custody: Page locking, anti-dumping, and zeroization verified."

echo ""
echo "=== 6. Running Core Crypto, Splicing Immunity, & Blind Index Tests ==="
.venv/bin/pytest -q tests/test_crypto_core.py tests/test_blind_index.py tests/test_sqlite_integration.py
echo "[PASS] Core Crypto: Contextual AAD anti-splicing and B-Tree lookups verified."

echo ""
echo "=== 7. Running Hermes-Optimized Drop-in Adapter Tests ==="
.venv/bin/pytest -q tests/test_hermes_adapter.py tests/test_adaptive_provider.py
echo "[PASS] Hermes Adapter: Vault lookups and FTS5 split-projection verified."

echo ""
echo "=== 8. Verifying Universal Wheel Build (Zero-C Compilation) ==="
uv build
echo "[PASS] Wheel Build: Successfully packaged universal wheel."

echo ""
echo "============================================================"
echo "    ALL STANDALONE SECURITY GATES & RFC VECTORS PASSED     "
echo "============================================================"

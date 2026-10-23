"""Hermes' own SecretSource conformance kit, run against HermesVaultSource.

Hermes documents green conformance (`tests/secret_sources/conformance.py` in
its repository) as the bar for a contract-compliant secret source. The kit is
loaded from the Hermes checkout at HERMES_AGENT_SRC (default ~/hermes-agent);
without one this module skips, which says nothing about host compatibility.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERMES = Path(os.environ.get("HERMES_AGENT_SRC", str(Path.home() / "hermes-agent")))
KIT = HERMES / "tests" / "secret_sources" / "conformance.py"

if not KIT.is_file():
    pytest.skip(f"Hermes conformance kit not found at {KIT}", allow_module_level=True)

sys.path.insert(0, str(ROOT / "plugins" / "hermesvault"))
sys.path.insert(0, str(HERMES))
pytest.importorskip("agent.secret_sources.base")

# Load the kit by path: this repository's own tests/ directory would shadow
# Hermes' `tests` package under a plain import.
_spec = importlib.util.spec_from_file_location("hermes_secret_source_conformance", KIT)
_kit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_kit)

from source import HermesVaultSource  # noqa: E402


class TestHermesVaultConformance(_kit.SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return HermesVaultSource()

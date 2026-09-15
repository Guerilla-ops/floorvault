"""Tests for the universal-wheel (zero-C-compilation) assertion.

FloorVault's positioning is that it ships a single pure-Python wheel
(``py3-none-any``) and never compiles native code at install time. These tests
pin that claim to an executable check so the security gate can enforce it.

``scripts/verify_wheel.py`` is a standalone script (like ``scripts/memory_probe.py``),
not an importable package member, so it is loaded here by path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_wheel.py"


def _load_verify_wheel():
    spec = importlib.util.spec_from_file_location("verify_wheel", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_wheel = _load_verify_wheel()


def test_universal_wheel_is_accepted():
    assert verify_wheel.is_universal("floorvault-0.1.0-py3-none-any.whl") is True


def test_platform_wheel_is_rejected():
    # A compiled / platform-specific wheel must never be shipped.
    assert verify_wheel.is_universal("floorvault-0.1.0-cp313-cp313-macosx_11_0_arm64.whl") is False
    assert verify_wheel.is_universal("floorvault-0.1.0-cp313-cp313-win_amd64.whl") is False
    assert (
        verify_wheel.is_universal("floorvault-0.1.0-cp313-cp313-manylinux_2_17_x86_64.whl") is False
    )


def test_non_wheel_filename_is_rejected():
    assert verify_wheel.is_universal("floorvault-0.1.0.tar.gz") is False


def test_assert_universal_accepts_a_universal_wheel():
    assert verify_wheel.assert_universal("floorvault-0.1.0-py3-none-any.whl") is None


def test_assert_universal_exits_nonzero_on_a_platform_wheel():
    with pytest.raises(SystemExit) as excinfo:
        verify_wheel.assert_universal("floorvault-0.1.0-cp313-cp313-win_amd64.whl")
    assert excinfo.value.code == 1

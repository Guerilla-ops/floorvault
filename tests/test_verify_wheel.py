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
    assert verify_wheel.is_universal("floorvault-0.2.0-py3-none-any.whl") is True


def test_platform_wheel_is_rejected():
    # A compiled / platform-specific wheel must never be shipped.
    assert verify_wheel.is_universal("floorvault-0.2.0-cp313-cp313-macosx_11_0_arm64.whl") is False
    assert verify_wheel.is_universal("floorvault-0.2.0-cp313-cp313-win_amd64.whl") is False
    assert (
        verify_wheel.is_universal("floorvault-0.2.0-cp313-cp313-manylinux_2_17_x86_64.whl") is False
    )


def test_non_wheel_filename_is_rejected():
    assert verify_wheel.is_universal("floorvault-0.2.0.tar.gz") is False


def test_assert_universal_accepts_a_universal_wheel():
    assert verify_wheel.assert_universal("floorvault-0.2.0-py3-none-any.whl") is None


def test_assert_universal_exits_nonzero_on_a_platform_wheel():
    with pytest.raises(SystemExit) as excinfo:
        verify_wheel.assert_universal("floorvault-0.2.0-cp313-cp313-win_amd64.whl")
    assert excinfo.value.code == 1


def test_cli_rejects_a_metadata_only_wheel(tmp_path):
    from zipfile import ZipFile

    wheel = tmp_path / "floorvault-0.2.0-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("floorvault-0.2.0.dist-info/METADATA", "Name: floorvault\n")
    with pytest.raises(SystemExit) as error:
        verify_wheel.main(str(tmp_path))
    assert error.value.code == 1


def test_cli_requires_the_package_core_and_entry_point(tmp_path):
    from zipfile import ZipFile

    wheel = tmp_path / "floorvault-0.2.0-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("floorvault/__init__.py", "")
        archive.writestr("floorvault/core.py", "")
    with pytest.raises(SystemExit) as error:
        verify_wheel.main(str(tmp_path))
    assert error.value.code == 1
    with ZipFile(wheel, "a") as archive:
        archive.writestr("floorvault/inspector.py", "")
    assert verify_wheel.main(str(tmp_path)) is None

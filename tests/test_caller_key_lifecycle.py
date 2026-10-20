"""Regression tests for caller-owned HardenedMemoryKey lifecycle."""

import pytest

from floorvault.core import FloorVault
from floorvault.memory import HardenedMemoryKey


def test_floorvault_preserves_caller_key_by_default() -> None:
    source = HardenedMemoryKey(b"K" * 32, mode="disabled")

    vault = FloorVault(source, memory_mode="disabled")

    assert source.get_bytes() == b"K" * 32
    ciphertext = vault.encrypt("value", table="t", record_id="r", column="c")
    assert vault.decrypt(ciphertext, table="t", record_id="r", column="c") == "value"


def test_multiple_instances_can_share_caller_key_handle() -> None:
    source = HardenedMemoryKey(b"M" * 32, mode="disabled")

    first = FloorVault(source, app_instance_id="first", memory_mode="disabled")
    second = FloorVault(source, app_instance_id="second", memory_mode="disabled")

    assert source.get_bytes() == b"M" * 32
    first_cipher = first.encrypt("one", table="t", record_id="1", column="c")
    second_cipher = second.encrypt("two", table="t", record_id="2", column="c")
    assert first.decrypt(first_cipher, table="t", record_id="1", column="c") == "one"
    assert second.decrypt(second_cipher, table="t", record_id="2", column="c") == "two"


def test_wipe_source_key_is_explicit_opt_in() -> None:
    source = HardenedMemoryKey(b"W" * 32, mode="disabled")

    FloorVault(source, memory_mode="disabled", wipe_source_key=True)

    assert source.is_wiped
    with pytest.raises(RuntimeError, match="wiped"):
        source.get_bytes()

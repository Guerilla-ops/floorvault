"""Coverage-guided fuzz target: the protected key-store reader.

Property: whatever bytes are on disk, ``read_protected`` returns a payload that
is exactly the file minus its header (32 bytes, or non-empty when the length is
opaque), or raises ``ProtectedStoreError``. It must never report an existing
store as *missing* - that is the one answer that licenses minting a new key over
the user's data - and never leak another exception type to the caller.

The first input byte selects the length mode; the rest is written verbatim to an
owner-only file. On Windows the DACL of a temp directory may be refused as too
broad; that is still a ``ProtectedStoreError``, so the property holds there too.
"""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

from floorvault.platform_support import binary_mode_flag
from floorvault.providers.platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    read_protected,
)

_HEADER = b"FVFUZZ1\x00"
_MAX_STORE_BYTES = 4096
_DIR = Path(tempfile.mkdtemp(prefix="floorvault-fuzz-store-"))
atexit.register(shutil.rmtree, _DIR, ignore_errors=True)
_STORE = _DIR / "master.key.fuzz"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _write_store(payload: bytes) -> None:
    _STORE.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_mode_flag()
    fd = os.open(_STORE, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def seed_inputs() -> list[bytes]:
    return [
        b"\x00" + _HEADER + bytes(range(32)),
        b"\x01" + _HEADER + b"opaque-dpapi-blob",
        b"\x00" + _HEADER + bytes(31),
        b"\x01" + _HEADER,
        b"\x00" + b"FVFUZZ0\x00" + bytes(32),
        b"\x01" + _HEADER + bytes(_MAX_STORE_BYTES),
        b"\x00",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    if not data:
        return
    expected_length = None if data[0] & 1 else 32
    payload = data[1:]
    _write_store(payload)
    try:
        key = read_protected(_STORE, header=_HEADER, expected_length=expected_length)
    except ProtectedStoreMissing as exc:
        raise AssertionError("an existing store was reported as missing") from exc
    except ProtectedStoreError:
        return
    _require(len(payload) <= _MAX_STORE_BYTES, "a store larger than the read buffer was accepted")
    _require(payload.startswith(_HEADER), "a store without the scheme header was accepted")
    _require(key == payload[len(_HEADER) :], "the returned key is not the stored payload")
    if expected_length is None:
        _require(bool(key), "an empty opaque payload was accepted")
    else:
        _require(len(key) == expected_length, "a key of the wrong length was accepted")


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

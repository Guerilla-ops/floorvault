"""Coverage-guided fuzz target: the file-format and record parsers.

One input byte selects the parser, the rest is its byte input:

- ``passphrase_store.unwrap``: returns a wipeable key or raises
  ``PassphraseStoreError`` - never another exception, never a short key.
- ``BindingRecord._parse``: returns ``{str: str}`` or raises
  ``BindingRecordError`` on a malformed store record.
- ``FreshnessAnchor._load``: returns ``None``/``(raw, committed, pending)`` or
  raises ``RollbackDetectedError``; a returned record is length-valid.
- ``agentenv.read_env_file``: returns an ``EnvFile`` whose assignment names all
  pass ``is_valid_env_name``, or raises ``AgentEnvError``.
"""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

from floorvault.agentenv import AgentEnvError, is_valid_env_name, read_env_file
from floorvault.binding_record import BindingRecord, BindingRecordError
from floorvault.freshness import FreshnessAnchor, RollbackDetectedError
from floorvault.platform_support import binary_mode_flag
from floorvault.providers.passphrase_store import (
    PAYLOAD_BYTES,
    PassphraseStoreError,
    unwrap,
)

_DIR = Path(tempfile.mkdtemp(prefix="floorvault-fuzz-parsers-"))
atexit.register(shutil.rmtree, _DIR, ignore_errors=True)
_ENV = _DIR / "fuzz.env"

_VAULT = _DIR / "vault"
_STATE = _DIR / "state"
_VAULT.mkdir(exist_ok=True)
_STATE.mkdir(exist_ok=True)
_RECORD = BindingRecord(_VAULT, _STATE)


class _DictStore:
    """The smallest AnchorStore: whatever bytes the fuzzer placed in ``blob``."""

    blob: bytes | None = None

    def load(self, name: str):
        return self.blob

    def compare_and_swap(self, name: str, expected, new) -> bool:  # pragma: no cover
        return False


_STORE = _DictStore()
_ANCHOR = FreshnessAnchor(b"\x00" * 32, _STORE, name="fuzz", tables={"t": "id"})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _unwrap(data: bytes) -> None:
    payload = (data + bytes(PAYLOAD_BYTES))[:PAYLOAD_BYTES]
    try:
        key = unwrap(payload, b"fuzz-passphrase")
    except PassphraseStoreError:
        return
    _require(len(key) == 32, "unwrap returned a key that is not 32 bytes")


def _record(data: bytes) -> None:
    try:
        items = _RECORD._parse(data if data else None)
    except BindingRecordError:
        return
    _require(
        all(isinstance(k, str) and isinstance(v, str) for k, v in items.items()),
        "_parse returned non-str binding entries",
    )


def _anchor(data: bytes) -> None:
    _STORE.blob = data or None
    try:
        loaded = _ANCHOR._load()
    except RollbackDetectedError:
        return
    if loaded is None:
        return
    _raw, committed, pending = loaded
    _require(len(committed) == 32, "a malformed committed digest was accepted")
    _require(
        pending is None or len(pending) == 32,
        "a malformed pending digest was accepted",
    )


def _env(data: bytes) -> None:
    _ENV.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_mode_flag()
    fd = os.open(_ENV, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)
    try:
        parsed = read_env_file(_ENV)
    except AgentEnvError:
        return
    for line in parsed.assignments():
        _require(is_valid_env_name(line.name), "an invalid env name was accepted")


_DISPATCH = (_unwrap, _record, _anchor, _env)


def seed_inputs() -> list[bytes]:
    import json

    record = json.dumps(
        {
            "format": "fv-freshness-anchor-1",
            "committed": "00" * 32,
            "pending": None,
            "mac": "00" * 32,
        }
    ).encode()
    bindings = json.dumps(
        {"format": "fv-bindings-1", "vault": str(_VAULT), "items": {"a": "b"}}
    ).encode()
    return [
        b"\x00" + bytes([15, 1, 1]) + bytes(PAYLOAD_BYTES),
        b"\x01" + bindings,
        b"\x01" + b"not json",
        b"\x02" + record,
        b"\x02" + record.replace(b'"pending":null', b'"pending":""'),
        b"\x03A=1\nexport B='two'\n# comment\n",
        b"\x03BAD LINE\nA==\n\n",
        b"\x04unhandled-selector",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    if not data:
        return
    _DISPATCH[data[0] % len(_DISPATCH)](data[1:])


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

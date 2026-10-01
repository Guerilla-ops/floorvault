"""Coverage-guided fuzz target: envelope parsing and authenticated decryption.

Property: for *any* byte string, ``envelope_header`` and ``decrypt_bytes``
either return or raise ``DecryptionVerificationError`` - never an internal error
(``IndexError``, ``struct.error``, ...) - and decryption only succeeds for one of
the genuine envelopes below. Anything else authenticating would be a forgery.

The genuine envelopes are built with fixed nonces, so they are byte-identical in
every process. The seed corpus is written by a different process (at build time)
than the one fuzzing; with random nonces its genuine seeds would authenticate
under the fixed key yet be missing from this process's set, and the forgery
check would fire on its own seeds.

Run under Atheris (ClusterFuzzLite does this): ``python fuzz/fuzz_envelope.py``.
``tests/test_fuzz_targets.py`` replays the same entry point without Atheris so
the property is also checked on every OS in the ordinary suite.
"""

from __future__ import annotations

import sys
from unittest import mock

from floorvault import FloorVault
from floorvault.core import RECORD_MAGIC, RECORD_MAGIC_V2, DecryptionVerificationError
from floorvault.core import envelope_header as parse_header

_VAULT = FloorVault(bytes(range(32)), memory_mode="disabled")
_COORDS = {"table": "t", "record_id": "r", "column": "c"}
_PLAINTEXTS = (b"seed", b"", "h\u00e9llo-\U0001f9ca".encode())


def _genuine_envelopes() -> dict[bytes, bytes]:
    """Encrypt each plaintext under a fixed, distinct nonce (deterministic output)."""
    nonces = iter(bytes([index + 1]) * 16 for index in range(len(_PLAINTEXTS)))
    with mock.patch("floorvault.core.os.urandom", side_effect=lambda size: next(nonces)):
        return {_VAULT.encrypt(plaintext, **_COORDS): plaintext for plaintext in _PLAINTEXTS}


#: The only envelopes that may authenticate. Decrypting anything else must fail.
_GENUINE = _genuine_envelopes()


def _require(condition: bool, message: str) -> None:
    # Not ``assert``: the property must still be checked under ``python -O``.
    if not condition:
        raise AssertionError(message)


def seed_inputs() -> list[bytes]:
    genuine = list(_GENUINE)
    return [
        *genuine,
        b"",
        RECORD_MAGIC,
        RECORD_MAGIC_V2 + b"\x02\x00\x10",
        RECORD_MAGIC + b"\x10" + bytes(16) + b"\x00",
        genuine[0][:-1],
        genuine[0] + b"\x00",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    try:
        header = parse_header(data)
    except DecryptionVerificationError:
        header = None
    else:
        _require(header["magic"] == data[:4], "header magic does not describe the input")

    try:
        plaintext = _VAULT.decrypt_bytes(data, **_COORDS)
    except DecryptionVerificationError:
        return
    _require(data in _GENUINE, f"forged envelope authenticated: {data.hex()}")
    _require(plaintext == _GENUINE[data], "genuine envelope decrypted to the wrong plaintext")
    _require(header is not None, "decryption succeeded on an envelope the header parser refuses")


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

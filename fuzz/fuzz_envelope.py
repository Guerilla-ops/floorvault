"""Coverage-guided fuzz target: envelope parsing and authenticated decryption.

Property: for *any* byte string, ``envelope_header`` and ``decrypt_bytes``
either return or raise ``DecryptionVerificationError`` - never an internal error
(``IndexError``, ``struct.error``, ...) - and decryption only succeeds for an
envelope this process actually produced. Anything else authenticating would be
a forgery.

Run under Atheris (ClusterFuzzLite does this): ``python fuzz/fuzz_envelope.py``.
``tests/test_fuzz_targets.py`` replays the same entry point without Atheris so
the property is also checked on every OS in the ordinary suite.
"""

from __future__ import annotations

import sys

from floorvault import FloorVault
from floorvault.core import RECORD_MAGIC, RECORD_MAGIC_V2, DecryptionVerificationError
from floorvault.core import envelope_header as parse_header

_VAULT = FloorVault(bytes(range(32)), memory_mode="disabled")
_COORDS = {"table": "t", "record_id": "r", "column": "c"}
#: Genuine envelopes from this process. Decrypting anything else must fail.
_GENUINE = {
    _VAULT.encrypt(b"seed", **_COORDS): b"seed",
    _VAULT.encrypt(b"", **_COORDS): b"",
    _VAULT.encrypt("h\u00e9llo-\U0001f9ca", **_COORDS): "h\u00e9llo-\U0001f9ca".encode(),
}


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

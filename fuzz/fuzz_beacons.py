"""Coverage-guided fuzz target: blind-index beacon encoding.

Properties:

* the ``(scope, value)`` payload is length-prefixed and decodes back to exactly
  its inputs, so a caller controlling the scope can never collide with a value
  under a twisted scope;
* ``compute_beacon`` is deterministic, returns ``beacon_bucket_bytes(bits)``
  bytes, and ``beacon_matches`` agrees with it;
* invalid widths and scopes are refused with ``ValueError`` / ``TypeError``.
"""

from __future__ import annotations

import struct
import sys

from floorvault.beacons import (
    _canonical_payload,
    beacon_bucket_bytes,
    beacon_matches,
    compute_beacon,
)

_KEY = bytes(range(32, 64))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def seed_inputs() -> list[bytes]:
    return [
        b"\x08users.email\xffalice@example.com",
        b"\x40a\xffb\x00c",
        b"\x10a\x00b\xffc",
        b"\x03s\xffv",
        b"\x41s\xffv",
        b"\x08 \xffv",
        b"\x08\xed\xa0\x80\xffv",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    if not data:
        return
    bits = data[0]
    scope_raw, _, value_raw = data[1:].partition(b"\xff")
    scope = scope_raw.decode("utf-8", "surrogateescape")
    value = value_raw.decode("utf-8", "surrogateescape")

    try:
        payload = _canonical_payload(value, scope=scope)
    except (ValueError, TypeError):
        payload = None
    else:
        (scope_len,) = struct.unpack(">I", payload[:4])
        decoded_scope = payload[4 : 4 + scope_len].decode("utf-8")
        decoded_value = payload[4 + scope_len :].decode("utf-8")
        _require((decoded_scope, decoded_value) == (scope, value), "payload is not injective")

    try:
        beacon = compute_beacon(value, scope=scope, key=_KEY, bits=bits)
    except (ValueError, TypeError):
        return
    _require(payload is not None, "a beacon was computed for a payload the encoder refuses")
    _require(len(beacon) == beacon_bucket_bytes(bits), "beacon has the wrong width")
    _require(beacon == compute_beacon(value, scope=scope, key=_KEY, bits=bits), "nondeterministic")
    _require(
        beacon_matches(value, scope=scope, key=_KEY, beacon=beacon, bits=bits),
        "beacon_matches disagrees with compute_beacon",
    )


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

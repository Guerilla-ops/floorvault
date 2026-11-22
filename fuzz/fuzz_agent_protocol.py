"""Coverage-guided fuzz target: the key agent's wire-message parsers.

Property: a length-prefixed message is either refused with the documented
``AgentError`` (or a short-read EOF) or decodes to a dict, and the decoded
request then either passes ``_coordinates`` with fully-typed output or raises
``ValueError``. Neither parser may hang, crash, or hand untyped data onward.

The first byte chooses the message-length cap (mod 4096), the next 4 the
declared length; the rest is the message body the socket would deliver.
"""

from __future__ import annotations

import json
import struct
import sys

from floorvault.key_agent import AgentError, _coordinates, _recv, _unb64


def seed_inputs() -> list[bytes]:
    def frame(obj: object, limit: int = 8) -> bytes:
        body = json.dumps(obj).encode()
        return bytes([limit]) + struct.pack(">I", len(body)) + body

    return [
        frame({"op": "encrypt", "table": "t", "record_id": "1", "column": "c",
               "schema_id": "s", "schema_version": 1, "key_id": 0,
               "plaintext": "AA=="}),
        frame({"op": "decrypt", "schema_version": -1, "key_id": True}),
        frame(["not", "a", "dict"]),
        frame({"schema_version": 1e40}),
        bytes([255]) + struct.pack(">I", 0xFFFFFFFF) + b"{}",
        bytes([0]) + struct.pack(">I", 9) + b'{"op":"x',
        b"\x04" + b"short",
        b"",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    if len(data) < 5:
        return
    limit = 1 + data[0] % 4096
    wire = memoryview(data)[1:]

    def read_exact(n: int) -> bytes:
        nonlocal wire
        if len(wire) < n:
            raise EOFError("the peer hung up")
        out = bytes(wire[:n])
        wire = wire[n:]
        return out

    try:
        message = _recv(read_exact, limit)
    except (AgentError, EOFError):
        return
    if not isinstance(message, dict):
        raise AssertionError("_recv returned a non-dict request")

    for key_id_default in (None, 0):
        try:
            coords = _coordinates(message, key_id_default=key_id_default)
        except ValueError:
            continue
        for name in ("table", "record_id", "column", "schema_id"):
            if not isinstance(coords[name], str):
                raise AssertionError(f"_coordinates returned a non-str {name}")
        if not isinstance(coords["schema_version"], int) or isinstance(
            coords["schema_version"], bool
        ):
            raise AssertionError("_coordinates returned a non-int schema_version")

    for name in ("plaintext", "ciphertext", "aad", "start_token"):
        if name in message:
            try:
                _unb64(message[name])
            except ValueError:
                pass


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

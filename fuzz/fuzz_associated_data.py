"""Coverage-guided fuzz target: canonical associated-data encoding.

Property: ``associated_data`` either refuses its input with ``ValueError`` /
``TypeError`` or returns bytes that decode back to *exactly* the coordinates it
was given, and re-encode to the same bytes. A left inverse makes the encoding
injective - two different coordinate tuples can never share an AAD, which is
what makes moving a ciphertext between rows, columns or tables detectable.

Coordinates are decoded with ``surrogateescape`` so the fuzzer can also reach
strings that are not encodable as UTF-8 (lone surrogates); those must be
refused, not encoded lossily.
"""

from __future__ import annotations

import json
import sys

from floorvault.core import associated_data, canonical_json_bytes

_FIELDS = ("table", "record_id", "column", "schema_id", "app_instance_id")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _decode(data: bytes) -> tuple[dict[str, str], int, int | None]:
    """Split the input into five strings, a schema version and an optional revision."""
    numbers = data[:5].ljust(5, b"\x00")
    parts = data[5:].split(b"\xff", len(_FIELDS) - 1)
    parts += [b""] * (len(_FIELDS) - len(parts))
    coords = {name: part.decode("utf-8", "surrogateescape") for name, part in zip(_FIELDS, parts)}
    schema_version = int.from_bytes(numbers[:2], "big", signed=True)
    revision = None if numbers[2] & 1 else int.from_bytes(numbers[3:5], "big", signed=True)
    return coords, schema_version, revision


def seed_inputs() -> list[bytes]:
    return [
        b"\x00\x01\x01\x00\x00users\xffu-1\xffemail\xfffloor.vault.v1\xffdefault",
        b"\x00\x02\x00\x00\x07t\xffr\xffc\xffs\xffa",
        b'\x00\x01\x01\x00\x00\xc3\xa9\xff\xe2\x80\xa8\xff\x00\xff"\\\xff{}',
        b"\xff\xff\x00\xff\xfft\xffr\xffc\xffs\xffa",
        b"\x00\x01\x01\x00\x00\xed\xa0\x80\xffr\xffc\xffs\xffa",
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    coords, schema_version, revision = _decode(data)
    try:
        aad = associated_data(**coords, schema_version=schema_version, revision=revision)
    except (ValueError, TypeError):
        return

    decoded = json.loads(aad.decode("utf-8"))
    expected = {**coords, "schema_version": schema_version}
    if revision is not None:
        expected["revision"] = revision
    _require(decoded == expected, f"AAD does not decode to its coordinates: {aad!r}")
    _require(canonical_json_bytes(decoded) == aad, "AAD is not in canonical form")


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

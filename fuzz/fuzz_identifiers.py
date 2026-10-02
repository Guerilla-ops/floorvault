"""Coverage-guided fuzz target: SQL identifier validation (inspector and adapters).

Identifiers cannot be bound as SQL parameters, so the library and the inspector
CLI interpolate them into query text after an allow-list check. Properties:

* the CLI's ``floorvault.inspector.safe_identifier`` and the adapters'
  ``_safe_identifier`` are the same implementation - this check keeps it that
  way if anyone re-forks the CLI validator;
* an accepted identifier is plain ASCII ``[A-Za-z0-9_$]`` with at most one dot,
  at most 128 characters, and never starts with a digit, so nothing that could
  terminate or extend a statement survives;
* ``_quoted_identifier`` wraps every accepted part in ``[...]`` so keywords and
  literals (``NULL``, ``TRUE``, ``CURRENT_TIMESTAMP``) resolve as column names
  or fail closed, never as expressions or double-quoted string literals.
"""

from __future__ import annotations

import re
import sys

from floorvault.inspector import safe_identifier
from floorvault.sqlite_adapter import _quoted_identifier, _safe_identifier

_SAFE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?", re.ASCII)
_QUOTED = re.compile(r"\[[A-Za-z_][A-Za-z0-9_$]*\](?:\.\[[A-Za-z_][A-Za-z0-9_$]*\])?", re.ASCII)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _verdict(validator, name: str) -> str | None:
    try:
        return validator(name)
    except ValueError:
        return None


def seed_inputs() -> list[bytes]:
    return [
        b"users",
        b"main.users",
        b"_t$1",
        b"1users",
        b"users; DROP TABLE users",
        b"users--",
        b"a.b.c",
        b"users\n",
        b"\xd9\xa3",
        b"x" * 129,
    ]


def TestOneInput(data: bytes) -> None:  # noqa: N802 - Atheris entry-point name
    name = data.decode("utf-8", "replace")
    cli = _verdict(safe_identifier, name)
    library = _verdict(_safe_identifier, name)
    _require(cli == library, f"validators disagree on {name!r}: cli={cli!r} library={library!r}")
    if cli is None:
        return
    _require(cli == name, "an accepted identifier was rewritten")
    _require(len(name) <= 128, "an identifier longer than 128 characters was accepted")
    _require(_SAFE.fullmatch(name) is not None, f"unsafe identifier accepted: {name!r}")
    quoted = _quoted_identifier(name)
    _require(
        _QUOTED.fullmatch(quoted) is not None,
        f"quoted form of accepted identifier is malformed: {quoted!r}",
    )


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

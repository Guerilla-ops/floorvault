"""Read a 64-hex master key from a file, such as an orchestrator secret mount.

``floorvault run`` / ``floorvault secrets`` (``--key-file``,
``$FLOOR_VAULT_KEY_FILE``) and the Hermes plugin (``custody: key_file``) use
this, so a key file is accepted or refused the same way everywhere.

Symlinks are followed (Kubernetes mounts secrets through ``..data`` links), but
the target must be a regular file and, on POSIX, owned by this user or root and
not writable by group or others: a replaceable key file would let someone else
choose the key new items are sealed under. A file readable by others is used,
with a warning passed to ``warn``. Messages name the path, never the content.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Callable, Optional

__all__ = ["KeyFileError", "MAX_KEY_FILE_BYTES", "read_key_file"]

MAX_KEY_FILE_BYTES = 4096
_HEX_KEY = re.compile(r"[0-9A-Fa-f]{64}")


class KeyFileError(Exception):
    """The key file cannot be used. The message names the path, never key material."""


def read_key_file(path: Path, *, warn: Optional[Callable[[str], None]] = None) -> bytes:
    """Return the 32-byte key held as 64 hex characters in ``path``."""
    path = Path(path).expanduser()
    # Open once and check that handle, so the file cannot be swapped between
    # the checks and the read. O_NONBLOCK keeps a FIFO from hanging the open.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path.resolve(strict=True), flags)
    except (OSError, RuntimeError) as exc:
        raise KeyFileError(f"key file {path}: cannot read ({type(exc).__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyFileError(f"key file {path} is not a regular file")
        handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        return _key_from_handle(path, handle, st, warn)


def _key_from_handle(path: Path, handle, st: os.stat_result, warn) -> bytes:
    if os.name != "nt":
        if st.st_uid not in (os.geteuid(), 0):
            raise KeyFileError(f"key file {path} is owned by another user")
        if st.st_mode & 0o022:
            raise KeyFileError(
                f"key file {path} is writable by group or others; run chmod go-w on it"
            )
        if st.st_mode & 0o004 and warn is not None:
            warn(f"key file {path} is readable by other users")
    if st.st_size > MAX_KEY_FILE_BYTES:
        raise KeyFileError(f"key file {path} is too large to hold a key")
    try:
        raw = handle.read(MAX_KEY_FILE_BYTES + 1).decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise KeyFileError(f"key file {path}: cannot read ({type(exc).__name__})") from None
    if not _HEX_KEY.fullmatch(raw):
        raise KeyFileError(f"key file {path} must hold 64 hexadecimal characters")
    return bytes.fromhex(raw)

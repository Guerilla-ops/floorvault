"""Shared file-backed master-key custody for platform-native providers.

Pure-Python, cross-platform, fail-closed:
  * Writes the protected key with O_EXCL|O_NOFOLLOW to a temp then atomically
    renames it, so the file is never group/world-readable mid-write.
  * Reads refuse symlinks (O_NOFOLLOW) and enforce 0600.
  * The stored blob header marks the protection scheme so an on-disk value can
    never be mistaken for a raw key.

Platform providers wrap this with their native boundary (Windows DPAPI
secondary entropy, Linux Secret Service) — but the file/hardening contract is
identical and testable on every OS.
"""

from __future__ import annotations

import os
from pathlib import Path


class ProtectedStoreError(Exception):
    """Raised when the protected store is missing, corrupt, or insecurely owned."""


def write_protected(key: bytes, path: Path, *, header: bytes) -> None:
    """Atomically write ``header + key`` to ``path`` with 0600. Refuses symlinks."""
    if len(key) != 32:
        raise ProtectedStoreError("master key must be exactly 32 bytes")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.urandom(6).hex()}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.write(descriptor, header + key)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_protected(path: Path, *, header: bytes) -> bytes:
    """Read and validate a protected store; return the raw 32-byte key."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ProtectedStoreError("protected store not present") from exc
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    if not raw.startswith(header):
        raise ProtectedStoreError("protected store has an unknown or missing header")
    key = raw[len(header) :]
    if len(key) != 32:
        raise ProtectedStoreError("protected store key has an unexpected length")
    mode = os.stat(path).st_mode & 0o777
    if mode != 0o600:
        raise ProtectedStoreError("protected store is not 0600")
    return key

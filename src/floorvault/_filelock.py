"""Cross-process exclusive lock on a small lock file.

Used where a check-then-write must be atomic across processes, not just
threads: the freshness anchor's compare-and-swap and Tier-3 key creation.
POSIX uses ``flock``; Windows uses ``msvcrt.locking`` on the first byte. The
lock file itself carries no data and is left in place - deleting it while
another process waits would let two holders proceed on different inodes.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

# flock is per open file description, so two threads of one process that each
# open the lock file do exclude each other; the process-wide mutex below makes
# that independent of platform lock semantics.
_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _process_lock(path: Path) -> threading.Lock:
    key = os.path.abspath(path)
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.Lock())


#: How long Windows waits when the caller names no timeout (it always polls).
_DEFAULT_WINDOWS_TIMEOUT = 30.0


@contextmanager
def exclusive_lock(path: Path, *, timeout: Optional[float] = None) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` (created 0600 if absent) for the block.

    With a ``timeout``, :class:`TimeoutError` is raised when the lock cannot be
    taken within that many seconds, on every platform, counting the wait for
    another thread of this process too. Without one, POSIX waits for as long as
    it takes (a holder may be waiting on a person: a key-store unlock prompt)
    and Windows waits 30 seconds.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    process_lock = _process_lock(path)
    if deadline is None:
        process_lock.acquire()
    elif not process_lock.acquire(timeout=max(timeout, 0.0)):
        raise TimeoutError(f"timed out waiting for lock {path}")
    try:
        # Looked up through the custody module at call time (and imported
        # lazily, to avoid an import cycle) so every non-directory open in the
        # custody paths carries the same binary-mode flag.
        from .providers import platform_custody

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | platform_custody.binary_mode_flag()
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags, 0o600)
        try:
            if os.name == "nt":  # pragma: no cover - exercised on Windows CI legs
                import msvcrt

                if deadline is None:
                    deadline = time.monotonic() + _DEFAULT_WINDOWS_TIMEOUT
                while True:
                    try:
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f"timed out waiting for lock {path}") from None
                        time.sleep(0.05)
                try:
                    yield
                finally:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                if deadline is None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                else:
                    # A blocking flock has no deadline: a holder that is stopped
                    # or hung would hang every caller that asked for a bound.
                    while True:
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"timed out waiting for lock {path}") from None
                            time.sleep(0.05)
                try:
                    yield
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
    finally:
        process_lock.release()

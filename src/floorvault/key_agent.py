"""A key agent that holds an unwrapped master key for one store (#84, step 3, part 2).

``floorvault unlock`` asks for the passphrase of a passphrase-wrapped store once,
then leaves a small background process holding the key in hardened memory until a
time limit, ``floorvault lock``, or ``SIGTERM``. This module is the agent's
*core*: its process, socket and lifetime. It answers only ``status`` and ``lock``;
it hands out no key and resolves no item. Serving ``run`` and ``secrets`` through
it is the next part of #84, and until that lands nothing in the CLI consults it.

Threat model, stated plainly:

- **Other local users**: kept out. The socket lives in a directory that is
  checked to be a real directory, owned by this user, mode 0700 (no symlink),
  before every bind and every connect, and the peer's uid is checked on every
  connection (``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED`` on macOS). The client
  also checks that the server is this user.
- **Code running as the same user**: *not* kept out. It can connect and ask, as it
  can ask ``systemd-creds`` or read a key file. ``PR_SET_DUMPABLE=0`` (Linux) and
  ``PT_DENY_ATTACH`` (macOS) make ``ptrace`` and ``/proc/<pid>/mem`` harder, no
  more; they do not stop the socket.
- **root**, and anyone who can read the process's memory by other means: not kept out.
- **Reboot**: the key is gone; it lives only in this process.

Linux and macOS only (``AF_UNIX`` with peer credentials). Windows has DPAPI custody.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from ._filelock import exclusive_lock

SUPPORTED = sys.platform in ("linux", "darwin")

DEFAULT_TTL = 8 * 3600
DEFAULT_IDLE = 3600
#: Largest request the agent reads, and how long one client may hold the agent.
MAX_MESSAGE = 4096
IO_TIMEOUT = 5.0
#: The longest socket path that fits ``sockaddr_un`` on both Linux (108) and macOS (104).
MAX_SOCKET_PATH = 100
_OPS = ("status", "lock")
_DURATION = re.compile(r"^(\d+)([smhd]?)$")


class AgentError(Exception):
    """The agent cannot be started, reached or trusted. The message is safe to print."""


class AgentNotRunning(AgentError):
    """No agent is listening for this store."""


# ------------------------------------------------------------------ durations


def parse_duration(text: str) -> int:
    """``"90"`` (seconds), ``"30s"``, ``"15m"``, ``"8h"`` or ``"2d"`` as whole seconds (> 0)."""
    match = _DURATION.fullmatch(text.strip().lower())
    if match is None:
        raise ValueError(f"not a duration: {text!r} (use 30s, 15m, 8h or 2d)")
    seconds = int(match.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    if seconds <= 0:
        raise ValueError("a duration must be longer than zero")
    return seconds


# --------------------------------------------------------------------- places


def runtime_dir(vault_dir: Path, environ: Mapping[str, str]) -> Path:
    """Where the socket lives: ``$XDG_RUNTIME_DIR/floorvault``, else ``<store>/agent``.

    Never ``/tmp``. A relative ``$XDG_RUNTIME_DIR`` is ignored.
    """
    xdg = (environ.get("XDG_RUNTIME_DIR") or "").strip()
    if xdg and os.path.isabs(xdg):
        return Path(xdg) / "floorvault"
    # Absolute: the daemon changes directory to "/", and its cleanup must name the
    # socket it bound, not a relative path resolved from somewhere else.
    return Path(os.path.abspath(vault_dir)) / "agent"


def store_id(vault_dir: Path) -> str:
    """A short id from the store's resolved path and its wrapped key file.

    A different store, or the same path with a replaced key file, gets a different
    socket, so an agent answers only for the store it was unlocked for. The file is
    read the way the key reader reads it (no FIFO, link or oversized file; owner-only),
    so a planted file cannot block or exhaust this command.
    """
    from . import passphrase_custody
    from .providers import passphrase_store
    from .providers.platform_custody import ProtectedStoreError, read_protected

    resolved = os.path.realpath(vault_dir)
    path = passphrase_custody.wrapped_path(Path(resolved))
    try:
        payload = read_protected(
            path,
            header=passphrase_store.MAGIC,
            expected_length=passphrase_store.PAYLOAD_BYTES,
        )
    except ProtectedStoreError as exc:  # ProtectedStoreMissing is a subclass
        raise AgentError(f"no usable passphrase-wrapped key beside {vault_dir}: {exc}") from None
    except OSError as exc:
        raise AgentError(
            f"no readable passphrase-wrapped key beside {vault_dir} ({type(exc).__name__})"
        ) from None
    digest = hashlib.sha256(
        resolved.encode("utf-8") + b"\0" + passphrase_store.MAGIC + payload
    ).hexdigest()
    return digest[:20]


def socket_path(vault_dir: Path, environ: Mapping[str, str]) -> Path:
    path = runtime_dir(vault_dir, environ) / f"{store_id(vault_dir)}.sock"
    if len(os.fsencode(path)) > MAX_SOCKET_PATH:
        raise AgentError(
            f"the socket path {path} is too long for a Unix socket; set $XDG_RUNTIME_DIR "
            "to a short directory you own"
        )
    return path


def check_private_dir(path: Path, *, create: bool = False) -> None:
    """Require ``path`` to be a real directory, owned by this user, with no group/other access.

    ``lstat``: a symlink is refused, however it resolves. With ``create`` a missing
    final component is made 0700 (its parent must exist).
    """
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AgentError(f"cannot create {path} ({type(exc).__name__})") from None
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise AgentError(f"cannot check {path} ({type(exc).__name__})") from None
    if not stat.S_ISDIR(info.st_mode):
        raise AgentError(f"{path} is not a real directory (a link or a file); refusing it")
    if info.st_uid != os.geteuid():
        raise AgentError(f"{path} is owned by another user; refusing it")
    if info.st_mode & 0o077:
        raise AgentError(f"{path} is accessible by group or others; run chmod 700 on it")


# ------------------------------------------------------------------- peer uid


def peer_credentials(conn: socket.socket) -> tuple[Optional[int], int]:
    """``(pid or None, uid)`` of the process at the other end of a Unix socket."""
    if sys.platform == "linux":
        pid, uid, _gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        return pid, uid
    if sys.platform == "darwin":
        # struct xucred { u_int cr_version; uid_t cr_uid; ... }, LOCAL_PEERCRED = 1 at level 0.
        buf = conn.getsockopt(0, 1, 76)
        _version, uid = struct.unpack_from("II", buf)
        return None, uid
    raise AgentError("Unix socket peer credentials are not available on this platform")


# --------------------------------------------------------------------- hardening


def harden_process() -> dict[str, bool]:
    """Best-effort limits on how this process can be inspected. Reports what took effect."""
    import ctypes
    import ctypes.util

    from .memory import disable_core_dumps

    report = {"core_dumps_off": False, "ptrace_blocked": False}
    with contextlib.suppress(Exception):
        report["core_dumps_off"] = bool(disable_core_dumps())
    libc_name = ctypes.util.find_library("c")
    if libc_name:
        with contextlib.suppress(Exception):
            libc = ctypes.CDLL(libc_name, use_errno=True)
            if sys.platform == "linux":
                report["ptrace_blocked"] = libc.prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE
            elif sys.platform == "darwin":
                report["ptrace_blocked"] = libc.ptrace(31, 0, 0, 0) == 0  # PT_DENY_ATTACH
    os.umask(0o077)
    return report


# ----------------------------------------------------------------- wire format


def _send(conn: socket.socket, message: Mapping[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body)


def _discard_pending(conn: socket.socket) -> None:
    """Drop what the peer has already sent, so closing does not reset the connection.

    Closing a Unix socket with unread data makes the peer's next read fail with a reset
    instead of returning the reply that was just sent. One non-blocking-ish read is
    enough for a request of a few bytes; this never waits for a slow peer.
    """
    with contextlib.suppress(OSError):
        conn.settimeout(0.05)
        conn.recv(MAX_MESSAGE)


def _reader(
    conn: socket.socket,
    deadline: float,
    check: Optional[Callable[[], None]] = None,
) -> Callable[[int], bytes]:
    """A ``read_exact(count)`` bounded by one absolute ``deadline`` (``time.monotonic``).

    ``settimeout`` bounds each receive, not the whole request, so a peer sending a
    byte at a time could hold a reader for hours. This slices the wait, enforces the
    one deadline, and calls ``check`` between slices (the agent uses it to notice a
    stop, a lock or the end of the key's lifetime while a read is in flight).
    """

    def read_exact(count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            if check is not None:
                check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgentError("the message did not arrive in time")
            conn.settimeout(min(remaining, 0.25))
            try:
                chunk = conn.recv(count - len(chunks))
            except socket.timeout:
                continue
            if not chunk:
                raise AgentError("the connection closed early")
            chunks.extend(chunk)
        return bytes(chunks)

    return read_exact


def _recv(read_exact: Callable[[int], bytes], limit: int) -> dict[str, Any]:
    (length,) = struct.unpack(">I", read_exact(4))
    if length > limit:
        raise AgentError("the message is too large")
    try:
        message = json.loads(read_exact(length).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError: a few thousand nested arrays fit in 4 KiB and overflow the decoder.
        raise AgentError("the message is not valid JSON") from None
    if not isinstance(message, dict):
        raise AgentError("the message is not an object")
    return message


# ----------------------------------------------------------------------- server


class Agent:
    """Holds ``key`` until ``ttl`` seconds after start, ``idle`` seconds without use, or a stop.

    ``status`` does not count as use (a monitor must not keep the key alive);
    ``lock`` stops the agent. ``clock`` and ``poll`` exist for tests.
    """

    def __init__(
        self,
        key: Any,
        sock_path: Path,
        *,
        ttl: int = DEFAULT_TTL,
        idle: int = DEFAULT_IDLE,
        clock: Callable[[], float] = time.monotonic,
        poll: float = 0.5,
        hardening: Optional[Mapping[str, bool]] = None,
        identity: Optional[tuple[int, int]] = None,
    ) -> None:
        self._key = key
        self.sock_path = Path(sock_path)
        #: (st_dev, st_ino) of the socket this agent bound; only that file is removed on exit.
        self._identity = identity
        self.ttl = ttl
        self.idle = idle
        self._clock = clock
        self._poll = poll
        self._hardening = dict(hardening or {})
        self._started = clock()
        self._last_use = self._started
        self._stop = False
        self.reason = "running"

    # -- lifetime
    def _remaining(self) -> tuple[float, float]:
        now = self._clock()
        return self._started + self.ttl - now, self._last_use + self.idle - now

    def request_stop(self, reason: str = "stopped") -> None:
        if not self._stop:
            self._stop = True
            self.reason = reason

    def _expired(self) -> Optional[str]:
        ttl_left, idle_left = self._remaining()
        if ttl_left <= 0:
            return "the time limit passed"
        if idle_left <= 0:
            return "the idle limit passed"
        return None

    def touch(self) -> None:
        """Count a use of the key (the later parts of #84); ``status`` does not."""
        self._last_use = self._clock()

    # -- serving
    def serve(self, listener: socket.socket) -> str:
        """Serve until a limit, a lock or a stop; wipe the key and remove the socket. Returns why."""
        selector = selectors.DefaultSelector()
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ)
        try:
            while not self._stop:
                expired = self._expired()
                if expired is not None:
                    self.request_stop(expired)
                    break
                ttl_left, idle_left = self._remaining()
                timeout = max(0.0, min(self._poll, ttl_left, idle_left))
                for _event, _mask in selector.select(timeout):
                    self._accept(listener)
        finally:
            selector.close()
            self._close(listener)
        return self.reason

    def _accept(self, listener: socket.socket) -> None:
        try:
            conn, _addr = listener.accept()
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return
        with conn:
            try:
                self._handle(conn)
            except (AgentError, OSError, struct.error):
                with contextlib.suppress(OSError):
                    _send(conn, {"ok": False, "error": "bad request"})

    def _handle(self, conn: socket.socket) -> None:
        try:
            _pid, uid = peer_credentials(conn)
        except (AgentError, OSError):
            _send(conn, {"ok": False, "error": "refused"})
            _discard_pending(conn)
            return
        if uid != os.geteuid():
            _send(conn, {"ok": False, "error": "refused"})  # another user: told nothing
            _discard_pending(conn)
            return
        deadline = time.monotonic() + IO_TIMEOUT
        request = _recv(_reader(conn, deadline, self._check_live), MAX_MESSAGE)
        conn.settimeout(max(0.05, deadline - time.monotonic()))
        op = request.get("op")
        if op == "status":
            ttl_left, idle_left = self._remaining()
            _send(
                conn,
                {
                    "ok": True,
                    "pid": os.getpid(),
                    "expires_in": max(0, int(ttl_left)),
                    "idle_in": max(0, int(idle_left)),
                    "protected_memory": bool(getattr(self._key, "is_locked", False)),
                    **self._hardening,
                },
            )
        elif op == "lock":
            _send(conn, {"ok": True, "locked": True})
            self.request_stop("locked")
        else:
            _send(conn, {"ok": False, "error": "unknown operation"})

    def _check_live(self) -> None:
        """Called while a request is being read: end it if the agent is stopping or out of time."""
        if self._stop:
            raise AgentError("the agent is stopping")
        expired = self._expired()
        if expired is not None:
            self.request_stop(expired)
            raise AgentError("the agent is stopping")

    def _close(self, listener: socket.socket) -> None:
        with contextlib.suppress(Exception):
            wipe = getattr(self._key, "wipe", None)
            if wipe is not None:
                wipe()
        with contextlib.suppress(OSError):
            listener.close()
        self._remove_socket()

    def _remove_socket(self) -> None:
        """Remove the socket file only if it is still the one this agent bound.

        Under the store's lifecycle lock, so it cannot interleave with another
        unlock that is probing, replacing or binding the same path.
        """
        with contextlib.suppress(Exception):
            with exclusive_lock(_lock_path(self.sock_path), timeout=5.0):
                try:
                    info = os.lstat(self.sock_path)
                except FileNotFoundError:
                    return
                if self._identity is None or (info.st_dev, info.st_ino) == self._identity:
                    os.unlink(self.sock_path)


# ------------------------------------------------------------------ client side


def _check_socket(path: Path) -> None:
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        raise AgentNotRunning(f"no agent is listening at {path}") from None
    except OSError as exc:
        raise AgentError(f"cannot check {path.parent} ({type(exc).__name__})") from None
    check_private_dir(path.parent)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise AgentNotRunning(f"no agent is listening at {path}") from None
    except OSError as exc:
        raise AgentError(f"cannot check {path} ({type(exc).__name__})") from None
    if not stat.S_ISSOCK(info.st_mode):
        raise AgentError(f"{path} is not a socket; refusing it")
    if info.st_uid != os.geteuid():
        raise AgentError(f"{path} is owned by another user; refusing it")


def request(sock_path: Path, op: str, *, timeout: float = IO_TIMEOUT) -> dict[str, Any]:
    """Send one request and return the reply. Checks the directory, the socket and the server's uid."""
    if op not in _OPS:
        raise ValueError(f"unknown operation {op!r}")
    if not SUPPORTED:
        raise AgentError("the key agent needs Linux or macOS")
    _check_socket(sock_path)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(timeout)
        try:
            client.connect(os.fspath(sock_path))
        except FileNotFoundError:
            raise AgentNotRunning(f"no agent is listening at {sock_path}") from None
        except ConnectionRefusedError:
            raise AgentNotRunning(f"{sock_path} is stale: nothing is listening") from None
        except OSError as exc:
            raise AgentError(f"cannot connect to {sock_path} ({type(exc).__name__})") from None
        _pid, uid = peer_credentials(client)
        if uid != os.geteuid():
            raise AgentError("the process at the socket is not this user; refusing it")
        try:
            _send(client, {"op": op})
        except (BrokenPipeError, ConnectionResetError):
            # The server answered and hung up without reading (it refuses some callers that
            # way); its reply is already queued, so read it rather than report a broken pipe.
            pass
        reply = _recv(_reader(client, time.monotonic() + timeout), MAX_MESSAGE)
    except (OSError, struct.error) as exc:
        raise AgentError(f"the agent did not answer ({type(exc).__name__})") from None
    finally:
        client.close()
    if not reply.get("ok"):
        raise AgentError(f"the agent refused the request ({reply.get('error', 'no reason')})")
    return reply


def status(sock_path: Path) -> dict[str, Any]:
    return request(sock_path, "status")


def lock(sock_path: Path) -> None:
    request(sock_path, "lock")


# ---------------------------------------------------------------------- starting


def _lock_path(sock_path: Path) -> Path:
    return sock_path.with_suffix(".lock")


def _socket_identity(sock_path: Path) -> tuple[int, int]:
    info = os.lstat(sock_path)
    return info.st_dev, info.st_ino


def _bind(sock_path: Path) -> socket.socket:
    """Bind a 0600 listening socket in a checked directory, replacing only a stale one.

    The probe for a live agent, the removal of a stale socket and the bind happen
    under the store's lifecycle lock, so two unlocks started together cannot both
    see a stale socket and the second replace the first's live one. Anything other
    than a clear "nothing is listening" refuses: an agent that is still starting
    answers late, and that is not permission to take its place.
    """
    check_private_dir(sock_path.parent, create=True)
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(exclusive_lock(_lock_path(sock_path), timeout=10.0))
        except Exception as exc:  # noqa: BLE001 - report the type only
            raise AgentError(
                f"cannot take the lock for {sock_path} ({type(exc).__name__})"
            ) from None
        try:
            status(sock_path)
        except AgentNotRunning as exc:
            if "stale" in str(exc):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(sock_path)
        else:
            raise AgentError(
                "an agent is already unlocked for this store; `floorvault lock` stops it"
            )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous = os.umask(0o177)
        try:
            listener.bind(os.fspath(sock_path))
        except OSError as exc:
            listener.close()
            raise AgentError(f"cannot bind {sock_path} ({type(exc).__name__})") from None
        finally:
            os.umask(previous)
        check_private_dir(sock_path.parent)  # again, after the bind: still ours and private
        os.chmod(sock_path, 0o600)
        listener.listen(8)
        return listener


def start(
    vault_dir: Path,
    key: bytes,
    *,
    ttl: int = DEFAULT_TTL,
    idle: int = DEFAULT_IDLE,
    environ: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Start a background agent holding ``key`` for ``vault_dir``; return its first status.

    The listener is bound before forking, so a refusal (a bad directory, an agent
    already running) is reported here. The agent is a daemon: a second fork after
    ``setsid``, standard streams on ``/dev/null``, core dumps off. The caller's own
    copy of ``key`` lives until the caller exits; ``bytes`` cannot be wiped.
    """
    if not SUPPORTED:
        raise AgentError("the key agent needs Linux or macOS")
    environ = os.environ if environ is None else environ
    path = socket_path(vault_dir, environ)
    listener = _bind(path)
    identity = _socket_identity(path)
    read_end, write_end = os.pipe()
    try:
        first = os.fork()
    except OSError as exc:
        listener.close()
        raise AgentError(f"cannot start the agent ({type(exc).__name__})") from None
    if first == 0:  # pragma: no cover - runs in the child
        _daemon(listener, path, key, ttl, idle, identity, read_end, write_end)
        os._exit(0)
    os.close(write_end)
    listener.close()  # the daemon owns it now
    with contextlib.suppress(ChildProcessError):
        os.waitpid(first, 0)
    try:
        with os.fdopen(read_end, "rb") as pipe:
            ready = pipe.read(1)
    except OSError:
        ready = b""
    if ready != b"1":
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise AgentError("the agent did not start; nothing is holding the key")
    return status(path)


def _daemon(  # pragma: no cover - runs in the forked child
    listener: socket.socket,
    path: Path,
    key: bytes,
    ttl: int,
    idle: int,
    identity: tuple[int, int],
    read_end: int,
    write_end: int,
) -> None:
    code = 1
    try:
        os.close(read_end)
        os.setsid()
        if os.fork() != 0:
            os._exit(0)  # the first child ends; the daemon is not a session leader
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        if devnull > 2:
            os.close(devnull)
        os.chdir("/")
        report = harden_process()
        from .memory import HardenedMemoryKey

        held = HardenedMemoryKey(bytearray(key))
        agent = Agent(held, path, ttl=ttl, idle=idle, hardening=report, identity=identity)
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, lambda *_a: agent.request_stop("signalled"))
        os.write(write_end, b"1")
        os.close(write_end)
        agent.serve(listener)
        code = 0
    except BaseException:  # noqa: BLE001 - a daemon must not raise into the caller's stack
        with contextlib.suppress(OSError):
            os.close(write_end)
    finally:
        os._exit(code)

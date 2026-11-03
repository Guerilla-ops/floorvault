"""A key agent that holds an unwrapped master key for one store (#84, step 3).

``floorvault unlock`` asks for the passphrase of a passphrase-wrapped store once,
then leaves a small background process holding the key in hardened memory until a
time limit, ``floorvault lock``, or ``SIGTERM``. While it runs, ``floorvault run``
and ``floorvault secrets`` for that store use it instead of asking for the
passphrase.

The agent **never hands out the key**. It answers ``status`` and ``lock``, and it
encrypts and decrypts for the caller: the store code (``VaultStore``) is given a
:class:`RemoteVault` whose ``encrypt`` and ``decrypt`` ask the agent, so the key stays
in the agent's protected memory and the caller sees only plaintext and ciphertext.
That is a decryption oracle for whoever may connect, which is the limit below: the
agent narrows who holds the key, it does not make a connected caller harmless.

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

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import select
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
#: Largest message either side reads (a vault item and its base64 fit), and how long one
#: client may hold the agent. The peer's uid is checked before anything is read.
MAX_MESSAGE = 4 * 1024 * 1024
IO_TIMEOUT = 5.0
#: A master key is 32 bytes; the agent reads exactly that from its starter.
KEY_BYTES = 32
#: The longest socket path that fits ``sockaddr_un`` on both Linux (108) and macOS (104).
MAX_SOCKET_PATH = 100
_OPS = ("status", "lock", "encrypt", "decrypt")
_CRYPTO_OPS = ("encrypt", "decrypt")
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
    """The agent's socket, with links in its directory's path resolved once, here.

    Every later bind and connect then uses a path with no symlink in it, so swapping a link
    cannot redirect them; the directories above it are checked by :func:`check_private_dir`.
    """
    directory = Path(os.path.realpath(runtime_dir(vault_dir, environ)))
    path = directory / f"{store_id(vault_dir)}.sock"
    if len(os.fsencode(path)) > MAX_SOCKET_PATH:
        raise AgentError(
            f"the socket path {path} is too long for a Unix socket; set $XDG_RUNTIME_DIR "
            "to a short directory you own"
        )
    return path


def check_private_dir(path: Path, *, create: bool = False) -> None:
    """Require ``path`` to be a real directory, owned by this user, with no group/other access,
    below directories that only this user (or root) can change.

    ``lstat``: a symlink is refused, however it resolves. With ``create`` a missing
    final component is made 0700 (its parent must exist); if the checks then refuse
    it, the directory this call made is removed again.
    """
    created = False
    if create:
        try:
            os.mkdir(path, 0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise AgentError(f"cannot create {path} ({type(exc).__name__})") from None
    try:
        _check_private_dir(path)
    except AgentError:
        if created:
            with contextlib.suppress(OSError):
                os.rmdir(path)
        raise


def _check_private_dir(path: Path) -> None:
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
    _check_ancestors(path)


def _group_is_only_us(gid: int) -> bool:
    """Whether ``gid`` is a group of ours that nobody else belongs to (a user-private group)."""
    if gid != os.getegid() and gid not in os.getgroups():
        return False
    try:
        import grp
        import pwd

        me = pwd.getpwuid(os.geteuid()).pw_name
        if any(member != me for member in grp.getgrgid(gid).gr_mem):
            return False
        return all(entry.pw_uid == os.geteuid() for entry in pwd.getpwall() if entry.pw_gid == gid)
    except (ImportError, KeyError, OSError):
        return False  # cannot tell: not ours alone


def _check_ancestors(path: Path) -> None:
    """Every directory above ``path`` must be one that only this user (or root) can rename entries in.

    ``lstat`` stops a link in ``path`` itself, but anyone who can write to a directory above
    it can rename it or swap a link there, and a client would connect to, or an agent bind in,
    a different place. So, along the resolved path from ``/``, each ancestor must be owned by
    this user or root, and not writable by group or others, except a sticky directory (``/tmp``:
    entries there cannot be renamed by other users) or a group that is ours alone.
    """
    resolved = Path(os.path.realpath(path))
    for ancestor in reversed(resolved.parents):
        try:
            info = os.lstat(ancestor)
        except OSError as exc:
            raise AgentError(f"cannot check {ancestor} ({type(exc).__name__})") from None
        if not stat.S_ISDIR(info.st_mode):
            raise AgentError(f"{ancestor} (above {path}) is not a directory; refusing it")
        if info.st_uid not in (0, os.geteuid()):
            raise AgentError(f"{ancestor} (above {path}) is owned by another user; refusing it")
        if info.st_mode & stat.S_ISVTX:
            continue
        if info.st_mode & stat.S_IWOTH or (
            info.st_mode & stat.S_IWGRP and not _group_is_only_us(info.st_gid)
        ):
            raise AgentError(
                f"{ancestor} (above {path}) can be changed by other users, who could swap "
                "what the path leads to; run chmod go-w on it or use a directory elsewhere"
            )


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


def _libc() -> Any:
    """The C library, or None. The running program's own symbols first: ``find_library``
    can fail (musl, minimal images) where the process already has libc loaded."""
    import ctypes
    import ctypes.util

    probe = "prctl" if sys.platform == "linux" else "ptrace"
    with contextlib.suppress(OSError, AttributeError):
        libc = ctypes.CDLL(None, use_errno=True)
        getattr(libc, probe)
        return libc
    with contextlib.suppress(OSError):
        name = ctypes.util.find_library("c")
        if name:
            return ctypes.CDLL(name, use_errno=True)
    return None


def harden_process() -> dict[str, bool]:
    """Limits on how this process can be inspected. Reports what took effect.

    Best effort here; whether the agent may run without them is decided by its starter
    (``start`` refuses unless ``allow_unhardened``).
    """
    from .memory import disable_core_dumps

    report = {"core_dumps_off": False, "ptrace_blocked": False}
    with contextlib.suppress(Exception):
        report["core_dumps_off"] = bool(disable_core_dumps())
    libc = _libc()
    if libc is not None:
        with contextlib.suppress(Exception):
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
        conn.recv(65536)


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


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValueError("not base64") from None


def _int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("expected an integer")
    return value


def _coordinates(request: Mapping[str, Any], *, key_id_default: Optional[int]) -> dict[str, Any]:
    """The context a record is bound to (table, id, column, schema, revision, key id)."""
    texts = {}
    for name in ("table", "record_id", "column", "schema_id"):
        value = request.get(name)
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        texts[name] = value
    version = _int_or_none(request.get("schema_version"))
    if version is None:
        raise ValueError("schema_version must be an integer")
    key_id = _int_or_none(request["key_id"]) if "key_id" in request else key_id_default
    return {
        **texts,
        "schema_version": version,
        "revision": _int_or_none(request.get("revision")),
        "key_id": key_id,
    }


# ----------------------------------------------------------------------- server


class _LimitClock:
    """Seconds the agent has been alive, for its total and idle limits.

    ``time.monotonic`` does not count time the machine is suspended (Linux
    ``CLOCK_MONOTONIC``; Python's macOS clock stops in sleep too), so a laptop that sleeps
    overnight would keep the key far past its limits in real time. The wall clock does
    keep going, but it can be set back. So each step advances by the larger of the two
    clocks' steps, and never backwards: a sleep counts in full, setting the wall clock
    back extends nothing, and a forward step (NTP, a person) ends the limits early,
    which is the safe direction.
    """

    def __init__(
        self,
        monotonic: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self._monotonic, self._wall = monotonic, wall
        self._last_monotonic, self._last_wall = monotonic(), wall()
        self._now = 0.0

    def __call__(self) -> float:
        monotonic, wall = self._monotonic(), self._wall()
        self._now += max(monotonic - self._last_monotonic, wall - self._last_wall, 0.0)
        self._last_monotonic, self._last_wall = monotonic, wall
        return self._now


class Agent:
    """Holds ``key`` until ``ttl`` seconds after start, ``idle`` seconds without use, or a stop.

    ``status`` does not count as use (a monitor must not keep the key alive);
    ``lock`` stops the agent; ``encrypt`` and ``decrypt`` are use, and are served by
    ``crypto`` (a ``FloorVault`` over the same key) when one is given. ``clock`` and
    ``poll`` exist for tests; the default clock keeps counting while the machine sleeps.
    """

    def __init__(
        self,
        key: Any,
        sock_path: Path,
        *,
        ttl: int = DEFAULT_TTL,
        idle: int = DEFAULT_IDLE,
        clock: Optional[Callable[[], float]] = None,
        poll: float = 0.5,
        hardening: Optional[Mapping[str, bool]] = None,
        identity: Optional[tuple[int, int]] = None,
        crypto: Any = None,
    ) -> None:
        self._key = key
        self._crypto = crypto
        self.sock_path = Path(sock_path)
        #: (st_dev, st_ino) of the socket this agent bound; only that file is removed on exit.
        self._identity = identity
        self.ttl = ttl
        self.idle = idle
        self._clock = clock if clock is not None else _LimitClock()
        clock = self._clock
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
        elif op in _CRYPTO_OPS and self._crypto is not None:
            # The limits and a stop apply when the key is used, not only while the request is
            # read: a deadline can pass between the last byte and here, and touching first
            # would restart the idle clock of an agent that should already be gone.
            self._check_live()
            self.touch()
            _send(conn, self._crypto_reply(op, request))
        else:
            _send(conn, {"ok": False, "error": "unknown operation"})

    def _crypto_reply(self, op: str, request: Mapping[str, Any]) -> dict[str, Any]:
        """Run one ``encrypt`` or ``decrypt``. A failure names its kind and never its content."""
        from .core import DecryptionVerificationError, NonceReuseError

        try:
            coords = _coordinates(request, key_id_default=0 if op == "encrypt" else None)
            if op == "encrypt":
                plaintext = _unb64(request.get("plaintext_b64"))
                cipher = self._crypto.encrypt(plaintext, **coords)
                return {"ok": True, "ciphertext_b64": base64.b64encode(cipher).decode("ascii")}
            ciphertext = _unb64(request.get("ciphertext_b64"))
            plaintext = self._crypto.decrypt(ciphertext, **coords).encode("utf-8")
            # Base64, like the request: JSON would escape non-ASCII text to six bytes a
            # character, so an item that fits an encrypt could not be read back.
            return {"ok": True, "plaintext_b64": base64.b64encode(plaintext).decode("ascii")}
        except DecryptionVerificationError:
            return {"ok": False, "kind": "verification", "error": "verification failed"}
        except NonceReuseError:
            return {"ok": False, "kind": "nonce", "error": "nonce reuse"}
        except (ValueError, TypeError):
            return {"ok": False, "kind": "value", "error": "invalid argument"}
        except Exception:  # noqa: BLE001 - the type is not worth the risk of a message
            return {"ok": False, "kind": "failed", "error": "the operation failed"}

    def _check_live(self) -> None:
        """Called while a request is being read: end it if the agent is stopping or out of time."""
        if self._stop:
            raise AgentError("the agent is stopping")
        expired = self._expired()
        if expired is not None:
            self.request_stop(expired)
            raise AgentError("the agent is stopping")

    def _close(self, listener: socket.socket) -> None:
        for holder in (self._crypto, self._key):
            with contextlib.suppress(Exception):
                wipe = getattr(holder, "wipe", None)
                if wipe is not None:
                    wipe()
        with contextlib.suppress(OSError):
            listener.close()
        self._remove_socket()

    def _remove_socket(self) -> None:
        """Remove the socket file only if it is still the one this agent bound."""
        _unlink_socket(self.sock_path, self._identity)


def _unlink_socket(sock_path: Path, identity: Optional[tuple[int, int]]) -> None:
    """Unlink ``sock_path`` only if it is still the socket with ``identity`` (``(st_dev, st_ino)``).

    Under the store's lifecycle lock, so it cannot interleave with another unlock that is
    probing, replacing or binding the same path.
    """
    with contextlib.suppress(Exception):
        with exclusive_lock(_lock_path(sock_path), timeout=5.0):
            try:
                info = os.lstat(sock_path)
            except FileNotFoundError:
                return
            if identity is None or (info.st_dev, info.st_ino) == identity:
                os.unlink(sock_path)


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


def _exchange(sock_path: Path, message: Mapping[str, Any], timeout: float) -> dict[str, Any]:
    """Send one message and return the reply as it came. Checks the directory, the socket and the server's uid."""
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
            _send(client, message)
        except (BrokenPipeError, ConnectionResetError):
            # The server answered and hung up without reading (it refuses some callers that
            # way); its reply is already queued, so read it rather than report a broken pipe.
            pass
        return _recv(_reader(client, time.monotonic() + timeout), MAX_MESSAGE)
    except (OSError, struct.error) as exc:
        raise AgentError(f"the agent did not answer ({type(exc).__name__})") from None
    finally:
        client.close()


def request(sock_path: Path, op: str, *, timeout: float = IO_TIMEOUT) -> dict[str, Any]:
    """Send one ``status`` or ``lock`` request and return the reply."""
    if op not in ("status", "lock"):
        raise ValueError(f"unknown operation {op!r}")
    reply = _exchange(sock_path, {"op": op}, timeout)
    if not reply.get("ok"):
        raise AgentError(f"the agent refused the request ({reply.get('error', 'no reason')})")
    return reply


class RemoteVault:
    """``encrypt`` and ``decrypt`` through a running key agent: the key never leaves it.

    Offers the two methods ``VaultStore`` calls on its crypto object, with the same
    arguments and the same exceptions, so a store opened with one behaves as one
    opened with the key. Every call asks the agent, which counts it as use of the key.
    """

    def __init__(self, sock_path: Path, *, timeout: float = IO_TIMEOUT) -> None:
        self.sock_path = Path(sock_path)
        self._timeout = timeout

    def _ask(self, message: dict[str, Any]) -> dict[str, Any]:
        from .core import DecryptionVerificationError, NonceReuseError

        reply = _exchange(self.sock_path, message, self._timeout)
        if reply.get("ok"):
            return reply
        kind = reply.get("kind")
        if kind == "verification":
            raise DecryptionVerificationError("authentication of the stored value failed")
        if kind == "nonce":
            raise NonceReuseError("the agent refused to reuse a nonce")
        if kind == "value":
            raise ValueError("the agent rejected an argument")
        raise AgentError(f"the agent refused the request ({reply.get('error', 'no reason')})")

    def encrypt(
        self,
        plaintext: Any,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: Optional[int] = None,
        key_id: int = 0,
    ) -> bytes:
        if isinstance(plaintext, str):
            data = plaintext.encode("utf-8")
        elif isinstance(plaintext, (bytes, bytearray, memoryview)):
            data = bytes(plaintext)
        else:
            raise TypeError(
                "plaintext must be str, bytes, bytearray, or memoryview, "
                f"got {type(plaintext).__name__}"
            )
        reply = self._ask(
            {
                "op": "encrypt",
                "plaintext_b64": base64.b64encode(data).decode("ascii"),
                "table": table,
                "record_id": record_id,
                "column": column,
                "schema_id": schema_id,
                "schema_version": schema_version,
                "revision": revision,
                "key_id": key_id,
            }
        )
        return _unb64(reply.get("ciphertext_b64"))

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        table: str,
        record_id: str,
        column: str,
        schema_id: str = "floor.vault.v1",
        schema_version: int = 1,
        revision: Optional[int] = None,
        key_id: Optional[int] = None,
    ) -> str:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes")
        reply = self._ask(
            {
                "op": "decrypt",
                "ciphertext_b64": base64.b64encode(bytes(ciphertext)).decode("ascii"),
                "table": table,
                "record_id": record_id,
                "column": column,
                "schema_id": schema_id,
                "schema_version": schema_version,
                "revision": revision,
                "key_id": key_id,
            }
        )
        try:
            return _unb64(reply.get("plaintext_b64")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise AgentError("the agent's reply was not understood") from None

    def wipe(self) -> None:
        """Nothing is held here; the agent keeps the key."""


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


class PendingAgent:
    """A forked agent that is bound, protected and waiting for its key.

    The agent is forked **before** the passphrase is asked for, and receives the key over a
    pipe into a buffer it zeroes after copying, so nothing the caller held while prompting
    (the typed passphrase, the derived wrapping key, the unwrapped key) is in the agent's
    memory image. ``send_key`` delivers the key; ``cancel`` (or a closed pipe) makes the
    agent exit and remove its socket.
    """

    def __init__(self, path: Path, key_fd: int, ready_fd: int) -> None:
        self.path = path
        self._key_fd = key_fd
        self._ready_fd = ready_fd
        self._done = (
            False  # the key was delivered (or the agent was cancelled): nothing left to undo
        )

    def _close_key(self) -> None:
        if self._key_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self._key_fd)
            self._key_fd = -1

    def _finish(self) -> None:
        self._close_key()
        if self._ready_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self._ready_fd)
            self._ready_fd = -1

    def send_key(self, key: bytes) -> dict[str, Any]:
        """Hand the agent its key and return its first status."""
        if self._done:
            raise AgentError("the agent was already given its key or cancelled")
        try:
            if len(key) != KEY_BYTES:
                raise AgentError(f"the key must be {KEY_BYTES} bytes")
            try:
                os.write(self._key_fd, key)
            except OSError:
                raise AgentError("the agent went away before it was given the key") from None
            self._close_key()
            if _read_ready(self._ready_fd, 1) != b"1":
                raise AgentError("the agent did not start; nothing is holding the key")
        except BaseException:
            self.cancel()
            raise
        self._done = True
        self._finish()
        return status(self.path)

    def cancel(self) -> None:
        """Stop the agent without a key and wait until its socket is gone.

        Does nothing once the key was delivered: from then on ``lock`` is how it stops.
        """
        if self._done:
            return
        self._done = True
        self._close_key()
        if self._ready_fd >= 0:
            _read_ready(self._ready_fd, 1, until_eof=True)
        self._finish()
        info = None
        with contextlib.suppress(OSError):
            info = os.lstat(self.path)
        if info is not None and stat.S_ISSOCK(info.st_mode):
            with contextlib.suppress(OSError):
                os.unlink(self.path)  # the agent died before it could remove it


def _read_ready(fd: int, count: int, *, until_eof: bool = False, timeout: float = 15.0) -> bytes:
    """Up to ``count`` bytes from a pipe (all of it, then EOF, with ``until_eof``), or b"" on a timeout."""
    deadline = time.monotonic() + timeout
    data = b""
    while until_eof or len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return data
        ready, _w, _x = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, max(count - len(data), 1) if not until_eof else 64)
        if not chunk:
            break
        data += chunk
    return data


def prepare(
    vault_dir: Path,
    *,
    ttl: int = DEFAULT_TTL,
    idle: int = DEFAULT_IDLE,
    environ: Optional[Mapping[str, str]] = None,
    app_context: str,
    allow_unhardened: bool = False,
) -> PendingAgent:
    """Bind the socket, fork the agent, and have it protect itself; it then waits for its key.

    ``app_context`` is the application context the store's records were sealed under; the
    agent encrypts and decrypts with it, so it must be the CLI's own (``APP_CONTEXT``).

    The agent refuses to run unless it could turn core dumps off and block debuggers
    from reading its memory (a same-user process could otherwise take the key itself, which
    outlives the agent); ``allow_unhardened`` runs it anyway, and ``status`` still reports
    what took effect. That is decided here, before anyone is asked for a passphrase.

    The listener is bound before forking, so a refusal (a bad directory, an agent
    already running) is reported here. The agent is a daemon: a second fork after
    ``setsid``, standard streams on ``/dev/null``, core dumps off.
    """
    if not SUPPORTED:
        raise AgentError("the key agent needs Linux or macOS")
    environ = os.environ if environ is None else environ
    path = socket_path(vault_dir, environ)
    listener = _bind(path)
    identity = _socket_identity(path)
    key_read, key_write = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        first = os.fork()
    except OSError as exc:
        for fd in (key_read, key_write, ready_read, ready_write):
            os.close(fd)
        listener.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise AgentError(f"cannot start the agent ({type(exc).__name__})") from None
    if first == 0:  # pragma: no cover - runs in the child
        os.close(key_write)
        os.close(ready_read)
        _daemon(
            listener,
            path,
            ttl,
            idle,
            identity,
            app_context,
            allow_unhardened,
            key_read,
            ready_write,
        )
        os._exit(0)
    os.close(key_read)
    os.close(ready_write)
    listener.close()  # the daemon owns it now
    with contextlib.suppress(ChildProcessError):
        os.waitpid(first, 0)
    pending = PendingAgent(path, key_write, ready_read)
    verdict = _read_ready(ready_read, 1)
    if verdict == b"H":
        flags = _read_ready(ready_read, 2)
        pending.cancel()
        missing = [
            what
            for what, flag in (("turn core dumps off", flags[:1]), ("block debuggers", flags[1:2]))
            if flag != b"1"
        ]
        raise AgentError(
            f"the agent could not {' or '.join(missing)}, so a process running as you could "
            "read the key out of its memory; nothing is holding the key. Pass "
            "--allow-unhardened to start it anyway"
        )
    if verdict != b"K":
        pending.cancel()
        raise AgentError("the agent did not start; nothing is holding the key")
    return pending


def start(
    vault_dir: Path,
    key: bytes,
    *,
    ttl: int = DEFAULT_TTL,
    idle: int = DEFAULT_IDLE,
    environ: Optional[Mapping[str, str]] = None,
    app_context: str,
    allow_unhardened: bool = False,
) -> dict[str, Any]:
    """Start a background agent holding ``key`` for ``vault_dir``; return its first status.

    For a caller that already has the key (the CLI uses :func:`prepare` so that the agent is
    forked before the passphrase is asked for). The caller's own copy of ``key`` lives
    until the caller exits; ``bytes`` cannot be wiped.
    """
    pending = prepare(
        vault_dir,
        ttl=ttl,
        idle=idle,
        environ=environ,
        app_context=app_context,
        allow_unhardened=allow_unhardened,
    )
    return pending.send_key(key)


def _close_inherited_descriptors(keep: set[int]) -> None:
    """Close every descriptor but the standard streams and ``keep``.

    A daemon forked from a caller holds that caller's descriptors until it exits, which
    for an agent is hours: a pipe the caller was reading to the end (a test runner, a
    shell substitution, a supervisor) would never see end-of-file.
    """
    listing = None
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            listing = [int(name) for name in os.listdir(directory)]
            break
        except (OSError, ValueError):
            continue
    for fd in listing if listing is not None else range(3, 1024):
        if fd > 2 and fd not in keep:
            with contextlib.suppress(OSError):
                os.close(fd)


def _read_key_into_buffer(fd: int) -> Optional[bytearray]:  # pragma: no cover - child
    """Exactly ``KEY_BYTES`` from the pipe, read straight into a mutable buffer (no ``bytes``
    copy), or None if the pipe closed first."""
    buffer = bytearray(KEY_BYTES)
    view = memoryview(buffer)
    got = 0
    try:
        while got < KEY_BYTES:
            count = os.readv(fd, [view[got:]])
            if count == 0:
                break
            got += count
    finally:
        view.release()
    if got != KEY_BYTES:
        buffer[:] = bytes(KEY_BYTES)
        return None
    return buffer


def _daemon(  # pragma: no cover - runs in the forked child
    listener: socket.socket,
    path: Path,
    ttl: int,
    idle: int,
    identity: tuple[int, int],
    app_context: str,
    allow_unhardened: bool,
    key_read: int,
    ready_write: int,
) -> None:
    code = 1
    served = False
    try:
        os.setsid()
        if os.fork() != 0:
            os._exit(0)  # the first child ends; the daemon is not a session leader
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        if devnull > 2:
            os.close(devnull)
        os.chdir("/")
        _close_inherited_descriptors({listener.fileno(), key_read, ready_write})
        report = harden_process()
        if not allow_unhardened and not (report["core_dumps_off"] and report["ptrace_blocked"]):
            flags = (b"1" if report["core_dumps_off"] else b"0") + (
                b"1" if report["ptrace_blocked"] else b"0"
            )
            os.write(ready_write, b"H" + flags)
        else:
            os.write(ready_write, b"K")  # protected, bound, and waiting for the key
            from .core import FloorVault
            from .memory import HardenedMemoryKey

            key = _read_key_into_buffer(key_read)
            os.close(key_read)
            if key is not None:
                held = HardenedMemoryKey(key)  # copies the key and zeroes the buffer it was given
                del key
                crypto = FloorVault(held, app_instance_id=app_context)
                agent = Agent(
                    held,
                    path,
                    ttl=ttl,
                    idle=idle,
                    hardening=report,
                    identity=identity,
                    crypto=crypto,
                )
                for number in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(number, lambda *_a: agent.request_stop("signalled"))
                os.write(ready_write, b"1")
                os.close(ready_write)
                ready_write = -1
                served = True
                agent.serve(listener)  # wipes the key and removes the socket when it ends
                code = 0
    except BaseException:  # noqa: BLE001 - a daemon must not raise into the caller's stack
        pass
    finally:
        if not served:
            # Refused, cancelled or failed before serving: close the listener and remove the
            # socket this process bound.
            with contextlib.suppress(Exception):
                listener.close()
            _unlink_socket(path, identity)
        if ready_write >= 0:
            with contextlib.suppress(OSError):
                os.close(ready_write)
        os._exit(code)

"""The key agent core (#84, step 3, part 2): `floorvault unlock` / `lock` and `floorvault.key_agent`.

The agent is exercised in a thread with a fake clock for its limits and its
protocol, and as a real forked daemon for starting, status, lock and expiry.
Nothing here reaches a terminal or another user: a peer of a different uid is
simulated by replacing the peer-credential lookup (the sandbox runs as root).
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from floorvault import key_agent, passphrase_custody
from floorvault.inspector import main
from floorvault.memory import HardenedMemoryKey
from floorvault.providers import passphrase_store

pytestmark = pytest.mark.skipif(not key_agent.SUPPORTED, reason="Linux or macOS only")

PHRASE = "correct horse battery staple"


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)


@pytest.fixture()
def base():
    """A short directory: Unix socket paths are limited to about 100 bytes."""
    path = Path(tempfile.mkdtemp(prefix="fa", dir="/tmp" if os.path.isdir("/tmp") else None))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture()
def vault(base):
    directory = base / "v"
    passphrase_custody.create_wrapped_key(directory, PHRASE)
    return directory


@pytest.fixture()
def env(base):
    run = base / "r"
    run.mkdir(mode=0o700)
    return {"XDG_RUNTIME_DIR": str(run), "HOME": str(base)}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Running:
    """An Agent served from a thread against a real socket."""

    def __init__(self, vault, env, clock, *, ttl=3600, idle=600):
        self.path = key_agent.socket_path(vault, env)
        self.listener = key_agent._bind(self.path)
        self.key = HardenedMemoryKey(bytearray(b"k" * 32))
        self.agent = key_agent.Agent(
            self.key, self.path, ttl=ttl, idle=idle, clock=clock, poll=0.02
        )
        self.thread = threading.Thread(target=self.agent.serve, args=(self.listener,))
        self.thread.start()

    def join(self, timeout=5):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "the agent did not stop"

    def stop(self):
        self.agent.request_stop("test over")
        self.thread.join(5)


@pytest.fixture()
def running(vault, env):
    made = []

    def make(clock=None, **kwargs):
        item = Running(vault, env, clock or FakeClock(), **kwargs)
        made.append(item)
        return item

    yield make
    for item in made:
        item.stop()


# ------------------------------------------------------------------ pure helpers


def test_parse_duration():
    assert key_agent.parse_duration("90") == 90
    assert key_agent.parse_duration("30s") == 30
    assert key_agent.parse_duration("15m") == 900
    assert key_agent.parse_duration("8H") == 8 * 3600
    assert key_agent.parse_duration(" 2d ") == 2 * 86400
    for bad in ("", "0", "0s", "-5", "1.5h", "h", "10 minutes", "5w"):
        with pytest.raises(ValueError):
            key_agent.parse_duration(bad)


def test_the_socket_directory_follows_xdg_and_never_tmp(vault, base):
    xdg = {"XDG_RUNTIME_DIR": str(base / "x")}
    assert key_agent.runtime_dir(vault, xdg) == base / "x" / "floorvault"
    # Not absolute, empty or missing: beside the store, not in a shared directory.
    for environ in ({"XDG_RUNTIME_DIR": "relative/dir"}, {"XDG_RUNTIME_DIR": " "}, {}):
        assert key_agent.runtime_dir(vault, environ) == vault / "agent"


def test_the_store_id_follows_the_path_and_the_wrapped_key(base):
    one, two = base / "one", base / "two"
    passphrase_custody.create_wrapped_key(one, PHRASE)
    passphrase_custody.create_wrapped_key(two, PHRASE)
    first = key_agent.store_id(one)
    assert first == key_agent.store_id(one)
    assert first != key_agent.store_id(two)  # another store, another socket
    # The same path with a replaced key file is another store too.
    (one / "master.key.fvpw").unlink()
    passphrase_custody.create_wrapped_key(one, PHRASE)
    assert key_agent.store_id(one) != first
    with pytest.raises(key_agent.AgentError, match="no readable passphrase-wrapped key"):
        key_agent.store_id(base / "missing")


def test_a_socket_path_too_long_for_unix_is_refused(vault, base):
    environ = {"XDG_RUNTIME_DIR": str(base / ("d" * 120))}
    with pytest.raises(key_agent.AgentError, match="too long"):
        key_agent.socket_path(vault, environ)


def test_the_socket_directory_must_be_private_and_ours(base, monkeypatch):
    good = base / "good"
    good.mkdir(mode=0o700)
    key_agent.check_private_dir(good)
    # Created with 0700 on request, and only the last component.
    fresh = base / "fresh"
    key_agent.check_private_dir(fresh, create=True)
    assert stat.S_IMODE(os.stat(fresh).st_mode) == 0o700
    with pytest.raises(key_agent.AgentError, match="cannot create"):
        key_agent.check_private_dir(base / "no" / "parent", create=True)
    # Group or other access.
    open_dir = base / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o750)
    with pytest.raises(key_agent.AgentError, match="group or others"):
        key_agent.check_private_dir(open_dir)
    # A link is refused however it resolves.
    link = base / "link"
    link.symlink_to(good)
    with pytest.raises(key_agent.AgentError, match="not a real directory"):
        key_agent.check_private_dir(link)
    (base / "file").write_text("x")
    with pytest.raises(key_agent.AgentError, match="not a real directory"):
        key_agent.check_private_dir(base / "file")
    # Owned by someone else.
    monkeypatch.setattr(key_agent.os, "geteuid", lambda: os.stat(good).st_uid + 1)
    with pytest.raises(key_agent.AgentError, match="owned by another user"):
        key_agent.check_private_dir(good)


# ----------------------------------------------------------------- agent in a thread


def test_status_reports_the_agent_and_does_not_count_as_use(running):
    clock = FakeClock()
    item = running(clock, ttl=10_000, idle=600)
    info = key_agent.status(item.path)
    assert info["ok"] and info["pid"] == os.getpid()
    assert info["expires_in"] == 10_000 and info["idle_in"] == 600
    assert info["protected_memory"] in (True, False)
    # A monitor polling status must not keep the key alive.
    clock.advance(400)
    assert key_agent.status(item.path)["idle_in"] == 200
    clock.advance(201)
    item.join()
    assert item.agent.reason == "the idle limit passed"
    assert item.key.is_wiped and not item.path.exists()


def test_the_total_time_limit_stops_the_agent(running):
    clock = FakeClock()
    item = running(clock, ttl=100, idle=10_000)
    clock.advance(101)
    item.join()
    assert item.agent.reason == "the time limit passed"
    assert item.key.is_wiped and not item.path.exists()


def test_lock_wipes_the_key_removes_the_socket_and_stops(running):
    item = running()
    key_agent.lock(item.path)
    item.join()
    assert item.agent.reason == "locked"
    assert item.key.is_wiped and not item.path.exists()
    with pytest.raises(key_agent.AgentNotRunning):
        key_agent.status(item.path)


def test_another_users_connection_is_refused_and_learns_nothing(running):
    item = running()
    real = key_agent.peer_credentials

    def other_user_on_the_server(conn):
        pid, uid = real(conn)
        if threading.current_thread() is item.thread:
            return pid, uid + 1
        return pid, uid

    with mock.patch.object(key_agent, "peer_credentials", other_user_on_the_server):
        with pytest.raises(key_agent.AgentError, match="refused the request .*refused"):
            key_agent.status(item.path)
        with pytest.raises(key_agent.AgentError, match="refused"):
            key_agent.lock(item.path)  # and it did not obey
    assert item.thread.is_alive() and not item.key.is_wiped
    assert key_agent.status(item.path)["ok"]


def test_the_client_refuses_a_server_that_is_not_this_user(running):
    item = running()
    real = key_agent.peer_credentials

    def other_user_on_the_client(conn):
        pid, uid = real(conn)
        if threading.current_thread() is not item.thread:
            return pid, uid + 1
        return pid, uid

    with mock.patch.object(key_agent, "peer_credentials", other_user_on_the_client):
        with pytest.raises(key_agent.AgentError, match="not this user"):
            key_agent.status(item.path)


def raw_exchange(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3)
        conn.connect(os.fspath(path))
        conn.sendall(payload)
        try:
            return key_agent._recv(conn, 65536)
        except (key_agent.AgentError, OSError):
            return None


def test_bad_requests_get_an_error_and_do_not_stop_the_agent(running):
    item = running()
    huge = struct.pack(">I", 10_000_000)
    assert raw_exchange(item.path, huge) == {"ok": False, "error": "bad request"}
    junk = b"not json"
    assert raw_exchange(item.path, struct.pack(">I", len(junk)) + junk) == {
        "ok": False,
        "error": "bad request",
    }
    array = b"[1,2]"
    assert raw_exchange(item.path, struct.pack(">I", len(array)) + array) == {
        "ok": False,
        "error": "bad request",
    }
    unknown = b'{"op":"key"}'
    assert raw_exchange(item.path, struct.pack(">I", len(unknown)) + unknown) == {
        "ok": False,
        "error": "unknown operation",
    }
    assert item.thread.is_alive() and not item.key.is_wiped
    assert key_agent.status(item.path)["ok"]


def test_a_client_that_says_nothing_cannot_hold_the_agent(running, monkeypatch):
    monkeypatch.setattr(key_agent, "IO_TIMEOUT", 0.2)
    item = running()
    stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stalled.connect(os.fspath(item.path))
        started = time.monotonic()
        assert key_agent.status(item.path)["ok"]
        assert time.monotonic() - started < 3
    finally:
        stalled.close()


def test_the_client_checks_the_directory_and_the_socket(running, base, env):
    item = running()
    run_dir = item.path.parent
    os.chmod(run_dir, 0o755)
    with pytest.raises(key_agent.AgentError, match="group or others"):
        key_agent.status(item.path)
    os.chmod(run_dir, 0o700)
    key_agent.status(item.path)
    # Something that is not a socket at the path.
    plain = run_dir / "plain.sock"
    plain.write_text("x")
    with pytest.raises(key_agent.AgentError, match="not a socket"):
        key_agent.status(plain)
    with pytest.raises(key_agent.AgentNotRunning):
        key_agent.status(run_dir / "absent.sock")
    # No directory at all yet (nothing has ever been unlocked): not running, not an error.
    with pytest.raises(key_agent.AgentNotRunning):
        key_agent.status(base / "never" / "made" / "x.sock")


def test_binding_creates_a_private_directory_and_a_private_socket(vault, env):
    path = key_agent.socket_path(vault, env)
    assert not path.parent.exists()
    listener = key_agent._bind(path)
    try:
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_ISSOCK(os.stat(path).st_mode)
    finally:
        listener.close()
        os.unlink(path)


def test_a_stale_socket_is_replaced_and_a_live_one_is_not(vault, env, running):
    path = key_agent.socket_path(vault, env)
    stale = key_agent._bind(path)
    stale.close()  # the file stays, nothing listens
    with pytest.raises(key_agent.AgentNotRunning, match="stale"):
        key_agent.status(path)
    fresh = key_agent._bind(path)
    fresh.close()
    os.unlink(path)
    item = running()
    with pytest.raises(key_agent.AgentError, match="already unlocked"):
        key_agent._bind(item.path)
    assert key_agent.status(item.path)["ok"]


# --------------------------------------------------------------------- real daemon


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except OSError:
        return True


def wait_until(condition, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_a_real_agent_starts_answers_and_locks(vault, env):
    info = key_agent.start(vault, b"k" * 32, ttl=3600, idle=600, environ=env)
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        assert pid != os.getpid() and alive(pid)
        assert info["expires_in"] > 3500 and info["idle_in"] > 500
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        with pytest.raises(key_agent.AgentError, match="already unlocked"):
            key_agent.start(vault, b"k" * 32, environ=env)
        key_agent.lock(path)
        assert wait_until(lambda: not path.exists())
        assert wait_until(lambda: not alive(pid))
    finally:
        if alive(pid):
            os.kill(pid, 9)


def test_a_real_agent_stops_itself_at_its_time_limit(vault, env):
    info = key_agent.start(vault, b"k" * 32, ttl=1, idle=600, environ=env)
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        assert wait_until(lambda: not path.exists(), 15)
        assert wait_until(lambda: not alive(pid))
    finally:
        if alive(pid):
            os.kill(pid, 9)


# --------------------------------------------------------------------------- the CLI


def cli(args, env, answers=()):
    answers = list(answers)
    asked = []

    def prompt(text="Passphrase: ", *, confirm=False):
        asked.append(text)
        return answers.pop(0)

    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", *args]),
        mock.patch.object(passphrase_custody, "prompt_passphrase", prompt),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue(), asked


def test_unlock_status_and_lock_from_the_command_line(vault, env):
    args = ["--vault", str(vault)]
    code, out, err, asked = cli(["unlock", *args], env, [PHRASE])
    assert code == 0, err
    assert "unlocked: an agent" in out and "protected memory:" in out
    assert "answers status and lock only" in err and PHRASE not in out + err
    assert len(asked) == 1
    pid = key_agent.status(key_agent.socket_path(vault, env))["pid"]
    try:
        code, out, _err, _ = cli(["unlock", "--status", *args], env)
        assert code == 0 and f"pid {pid}" in out
        code, _out, err, asked = cli(["unlock", *args], env, [PHRASE])
        assert code == 1 and "already unlocked" in err and asked == []
        code, out, err, _ = cli(["lock", *args], env)
        assert code == 0 and "locked" in out
        assert wait_until(lambda: not alive(pid))
        code, _out, err, _ = cli(["lock", *args], env)
        assert code == 1 and "no agent is listening" in err
        code, _out, err, _ = cli(["unlock", "--status", *args], env)
        assert code == 1 and "no agent is listening" in err
    finally:
        if alive(pid):
            os.kill(pid, 9)


def test_unlock_needs_a_wrapped_key_a_right_passphrase_and_sane_limits(base, vault, env):
    code, _out, err, asked = cli(["unlock", "--vault", str(base / "nothing")], env)
    assert code == 1 and "no passphrase-wrapped key" in err and asked == []
    code, _out, err, _ = cli(["unlock", "--vault", str(vault)], env, ["a wrong passphrase"])
    assert code == 1 and "wrong passphrase" in err
    assert not key_agent.socket_path(vault, env).exists()
    code, _out, err, asked = cli(["unlock", "--vault", str(vault), "--ttl", "soon"], env)
    assert code == 2 and "not a duration" in err and asked == []
    code, _out, err, asked = cli(["unlock", "--vault", str(vault), "--idle", "0"], env)
    assert code == 2 and asked == []


def test_unlock_refuses_a_raw_key_beside_the_wrapped_key_before_asking(vault, env):
    (vault / "master.key").write_bytes(b"\x00" * 32)
    code, _out, err, asked = cli(["unlock", "--vault", str(vault)], env, [PHRASE])
    assert code == 1 and "plaintext copy" in err and asked == []

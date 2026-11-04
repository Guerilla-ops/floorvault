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
import re
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
from floorvault.agent_cli import APP_CONTEXT
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
            self.key,
            self.path,
            ttl=ttl,
            idle=idle,
            clock=clock,
            poll=0.02,
            identity=key_agent._socket_identity(self.path),
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
    with pytest.raises(key_agent.AgentError, match="no usable passphrase-wrapped key"):
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
    # The directory's own message, not one about a directory above it (which would also be
    # raised, for an ordinary user's tree, if this directory's own check were missing).
    with pytest.raises(key_agent.AgentError, match=re.escape(f"{good} is owned by another user")):
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


def test_a_reply_sent_before_the_server_hung_up_is_still_read(base, monkeypatch):
    """A server that answers and closes without reading must show its reply, not a broken pipe."""
    path = base / "rst" / "x.sock"
    listener = key_agent._bind(path)
    answered = threading.Event()

    def refuse_and_hang_up():
        conn, _ = listener.accept()
        key_agent._send(conn, {"ok": False, "error": "refused"})
        conn.close()
        answered.set()

    thread = threading.Thread(target=refuse_and_hang_up, daemon=True)
    thread.start()
    real = key_agent.peer_credentials

    def after_the_server_has_hung_up(conn):
        result = real(conn)
        assert answered.wait(5)  # the client sends only once the server is gone
        return result

    monkeypatch.setattr(key_agent, "peer_credentials", after_the_server_has_hung_up)
    try:
        with pytest.raises(key_agent.AgentError, match="refused the request .*refused"):
            key_agent.status(path)
    finally:
        thread.join(5)
        listener.close()


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
            return key_agent._recv(key_agent._reader(conn, time.monotonic() + 3), 65536)
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
    if not os.path.isdir("/proc/self"):
        return True  # no /proc (macOS): a signal that found the process is all there is to go on
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except FileNotFoundError:
        return False  # a zombie that was reaped between the two looks
    except OSError:
        return True


def force_kill(pid):
    """SIGKILL, for cleanup: the process may have exited since it was last looked at."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, 9)


def wait_until(condition, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_a_real_agent_starts_answers_and_locks(vault, env):
    info = key_agent.start(
        vault, b"k" * 32, ttl=3600, idle=600, environ=env, app_context=APP_CONTEXT
    )
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        assert pid != os.getpid() and alive(pid)
        assert info["expires_in"] > 3500 and info["idle_in"] > 500
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        with pytest.raises(key_agent.AgentError, match="already unlocked"):
            key_agent.start(vault, b"k" * 32, environ=env, app_context=APP_CONTEXT)
        key_agent.lock(path)
        assert wait_until(lambda: not path.exists())
        assert wait_until(lambda: not alive(pid))
    finally:
        if alive(pid):
            force_kill(pid)


def test_the_daemon_does_not_keep_the_callers_descriptors(vault, env):
    """A pipe its caller reads to the end must reach end-of-file: the agent must not hold it."""
    import select

    reader, writer = os.pipe()
    info = key_agent.start(
        vault, b"k" * 32, ttl=3600, idle=600, environ=env, app_context=APP_CONTEXT
    )
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        os.close(writer)
        ready, _, _ = select.select([reader], [], [], 5)
        assert ready and os.read(reader, 1) == b""  # end-of-file: no other copy of the write end
    finally:
        os.close(reader)
        with contextlib.suppress(key_agent.AgentError):
            key_agent.lock(path)
        if alive(pid):
            assert wait_until(lambda: not alive(pid))


def test_a_real_agent_stops_itself_at_its_time_limit(vault, env):
    info = key_agent.start(vault, b"k" * 32, ttl=1, idle=600, environ=env, app_context=APP_CONTEXT)
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        assert wait_until(lambda: not path.exists(), 15)
        assert wait_until(lambda: not alive(pid))
    finally:
        if alive(pid):
            force_kill(pid)


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
    assert "use the agent now" in err and PHRASE not in out + err
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
            force_kill(pid)


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


# ------------------------------------------------------- review findings on #125


def test_a_planted_fifo_or_link_for_the_wrapped_key_cannot_block_or_exhaust(base):
    import signal

    def hang(*_a):
        raise AssertionError("store_id blocked")

    old = signal.signal(signal.SIGALRM, hang)
    try:
        signal.alarm(8)
        fifo_dir = base / "fifo"
        fifo_dir.mkdir(mode=0o700)
        os.mkfifo(fifo_dir / "master.key.fvpw")
        with pytest.raises(key_agent.AgentError, match="no usable passphrase-wrapped key"):
            key_agent.store_id(fifo_dir)
        link_dir = base / "link"
        link_dir.mkdir(mode=0o700)
        (link_dir / "master.key.fvpw").symlink_to("/dev/zero")
        with pytest.raises(key_agent.AgentError, match="no usable passphrase-wrapped key"):
            key_agent.store_id(link_dir)
        big_dir = base / "big"
        big_dir.mkdir(mode=0o700)
        (big_dir / "master.key.fvpw").write_bytes(b"FVPW1" + b"x" * 100_000)
        os.chmod(big_dir / "master.key.fvpw", 0o600)
        with pytest.raises(key_agent.AgentError, match="no usable passphrase-wrapped key"):
            key_agent.store_id(big_dir)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def trickle(path, stop, interval=0.05):
    """A client that announces a request and then sends it a byte at a time, for as long as it can."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(os.fspath(path))
        conn.sendall(struct.pack(">I", 3000))
        while not stop.is_set():
            try:
                conn.sendall(b"x")
            except OSError:
                return
            time.sleep(interval)


def test_a_client_trickling_bytes_cannot_hold_the_agent_past_the_request_deadline(
    running, monkeypatch
):
    monkeypatch.setattr(key_agent, "IO_TIMEOUT", 0.6)
    item = running()
    stop = threading.Event()
    worker = threading.Thread(target=trickle, args=(item.path, stop))
    worker.start()
    try:
        started = time.monotonic()
        assert key_agent.status(
            item.path,
        )["ok"]  # served once the trickler is cut off
        assert time.monotonic() - started < 3
    finally:
        stop.set()
        worker.join(5)


def test_the_key_lifetime_and_a_stop_cut_off_a_request_in_flight(running, monkeypatch):
    monkeypatch.setattr(key_agent, "IO_TIMEOUT", 60.0)  # the deadline alone would not do
    clock = FakeClock()
    item = running(clock, ttl=100, idle=10_000)
    stop = threading.Event()
    worker = threading.Thread(target=trickle, args=(item.path, stop))
    worker.start()
    try:
        time.sleep(0.3)  # the agent is now inside the trickler's request
        clock.advance(101)
        item.join(5)
        assert item.agent.reason == "the time limit passed"
        assert item.key.is_wiped and not item.path.exists()
    finally:
        stop.set()
        worker.join(5)


def test_a_stop_request_ends_an_agent_that_is_reading(running, monkeypatch):
    monkeypatch.setattr(key_agent, "IO_TIMEOUT", 60.0)
    item = running(ttl=10_000)
    stop = threading.Event()
    worker = threading.Thread(target=trickle, args=(item.path, stop))
    worker.start()
    try:
        time.sleep(0.3)
        item.agent.request_stop("signalled")  # what the SIGTERM handler does
        item.join(5)
        assert item.key.is_wiped and not item.path.exists()
    finally:
        stop.set()
        worker.join(5)


def test_two_unlocks_started_together_cannot_both_take_the_socket(vault, env, monkeypatch):
    monkeypatch.setattr(key_agent, "IO_TIMEOUT", 0.5)
    path = key_agent.socket_path(vault, env)
    stale = key_agent._bind(path)
    stale.close()  # a stale socket file: both unlocks will see it

    def real_status(
        sock_path,
    ):  # the default 5 s wait on the loser's probe would only slow this down
        return key_agent.request(sock_path, "status", timeout=0.5)

    seen_stale = threading.Barrier(2)

    def slow_after_seeing_stale(sock_path):
        try:
            return real_status(sock_path)
        except key_agent.AgentNotRunning:
            # Without the lifecycle lock both unlocks get here: they meet, and the one that
            # arrived second then dawdles until the first has bound, and removes *its* socket.
            # With the lock only one gets here, and the wait just times out.
            try:
                late = seen_stale.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                late = 0
            if late:
                time.sleep(0.4)
            raise

    monkeypatch.setattr(key_agent, "status", slow_after_seeing_stale)
    barrier = threading.Barrier(2)
    results = []

    def attempt():
        barrier.wait()
        try:
            results.append(key_agent._bind(path))
        except key_agent.AgentError as exc:
            results.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    winners = [r for r in results if isinstance(r, socket.socket)]
    try:
        losers = [r for r in results if isinstance(r, key_agent.AgentError)]
        assert len(winners) == 1 and len(losers) == 1
        assert path.exists()  # the loser did not remove the winner's socket
    finally:
        for winner in winners:
            winner.close()


def test_an_agent_that_exits_never_removes_a_socket_it_did_not_bind(running):
    item = running()
    original = item.path
    # The socket this agent bound is replaced (it was removed and another process bound again).
    os.unlink(original)
    replacement = key_agent._bind(original)
    try:
        item.agent.request_stop("test over")
        item.join()
        assert original.exists()
    finally:
        replacement.close()
        os.unlink(original)


def test_a_relative_vault_path_gives_an_absolute_socket_path(base, monkeypatch):
    passphrase_custody.create_wrapped_key(base / "rel", PHRASE)
    monkeypatch.chdir(base)
    assert key_agent.runtime_dir(Path("rel"), {}).is_absolute()
    path = key_agent.socket_path(Path("rel"), {})
    # Compare resolved paths: on macOS /tmp is a link to /private/tmp, and the working
    # directory comes back with the real prefix.
    assert path.is_absolute() and path.parent.resolve() == (base / "rel" / "agent").resolve()


def test_deeply_nested_json_is_a_bad_request_not_the_end_of_the_agent(running, monkeypatch):
    item = running()
    body = b'{"op":"status","x":' + b"[" * 1500 + b"]" * 1500 + b"}"
    assert len(body) < key_agent.MAX_MESSAGE
    real = key_agent.json.loads

    def overflowing(text, *args, **kwargs):
        # What CPython's decoder does on versions where this much nesting overflows it.
        if text.count("[") > 1000:
            raise RecursionError("maximum recursion depth exceeded")
        return real(text, *args, **kwargs)

    monkeypatch.setattr(key_agent.json, "loads", overflowing)
    assert raw_exchange(item.path, struct.pack(">I", len(body)) + body) == {
        "ok": False,
        "error": "bad request",
    }
    assert item.thread.is_alive()
    assert key_agent.status(item.path)["ok"]


# ------------------------------------------- limits across sleep and hardening policy


def test_the_limit_clock_counts_a_sleep_ignores_a_clock_set_back_and_never_goes_back():
    monotonic, wall = FakeClock(), FakeClock()
    clock = key_agent._LimitClock(monotonic, wall, suspend_inclusive=None)
    assert clock() == 0.0
    monotonic.advance(10), wall.advance(10)
    assert clock() == 10.0  # ordinary running
    wall.advance(50_000)  # asleep: only the wall clock moved
    assert clock() == 50_010.0
    monotonic.advance(5), wall.advance(-7_200)  # the wall clock set back while 5 s pass
    assert clock() == 50_015.0
    monotonic.advance(1), wall.advance(1)  # carries on normally from the wrong time: no rewind
    assert clock() == 50_016.0
    wall.advance(3_600)  # a forward step (NTP, a person) counts in full: limits end early
    assert clock() == 53_616.0


def test_an_agent_that_slept_past_its_limits_wipes_its_key_when_the_machine_wakes(vault, env):
    monotonic, wall = FakeClock(), FakeClock()
    item = Running(
        vault,
        env,
        key_agent._LimitClock(monotonic, wall, suspend_inclusive=None),
        ttl=8 * 3600,
        idle=3600,
    )
    try:
        assert key_agent.status(item.path)["ok"]
        wall.advance(14 * 3600)  # the machine slept overnight: the monotonic clock stood still
        item.join(10)
        assert item.key.is_wiped and not item.path.exists()
        assert item.agent.reason == "the time limit passed"
    finally:
        item.stop()


def test_an_agent_without_a_clock_of_its_own_uses_the_limit_clock(monkeypatch):
    made = []

    class Spy:
        def __init__(self):
            made.append(self)

        def __call__(self):
            return 0.0

    monkeypatch.setattr(key_agent, "_LimitClock", Spy)
    key_agent.Agent(object(), Path("/tmp/not-used.sock"))
    assert len(made) == 1


def test_the_c_library_is_found_even_where_find_library_fails(monkeypatch):
    import ctypes.util

    monkeypatch.setattr(ctypes.util, "find_library", lambda name: None)
    libc = key_agent._libc()
    assert libc is not None and hasattr(libc, "prctl" if sys.platform == "linux" else "ptrace")


@pytest.mark.parametrize(
    ("report", "named"),
    [
        ({"core_dumps_off": True, "ptrace_blocked": False}, "block debuggers"),
        ({"core_dumps_off": False, "ptrace_blocked": True}, "turn core dumps off"),
        (
            {"core_dumps_off": False, "ptrace_blocked": False},
            "turn core dumps off or block debuggers",
        ),
    ],
)
def test_the_agent_refuses_to_start_unprotected_and_holds_nothing(
    vault, env, monkeypatch, report, named
):
    monkeypatch.setattr(key_agent, "harden_process", lambda: dict(report))
    with pytest.raises(key_agent.AgentError, match=f"could not {named}") as raised:
        key_agent.start(vault, b"k" * 32, environ=env, app_context=APP_CONTEXT)
    assert "--allow-unhardened" in str(raised.value) and "nothing is holding the key" in str(
        raised.value
    )
    path = key_agent.socket_path(vault, env)
    assert not path.exists()
    with pytest.raises(key_agent.AgentNotRunning):
        key_agent.status(path)


def test_allow_unhardened_starts_the_agent_and_status_says_what_is_missing(vault, env, monkeypatch):
    monkeypatch.setattr(
        key_agent, "harden_process", lambda: {"core_dumps_off": False, "ptrace_blocked": False}
    )
    info = key_agent.start(
        vault, b"k" * 32, environ=env, app_context=APP_CONTEXT, allow_unhardened=True
    )
    path = key_agent.socket_path(vault, env)
    pid = info["pid"]
    try:
        assert info["core_dumps_off"] is False and info["ptrace_blocked"] is False
        key_agent.lock(path)
        assert wait_until(lambda: not alive(pid))
    finally:
        if alive(pid):
            force_kill(pid)


def test_unlock_refuses_an_unprotected_agent_unless_told_otherwise(vault, env, monkeypatch):
    monkeypatch.setattr(
        key_agent, "harden_process", lambda: {"core_dumps_off": True, "ptrace_blocked": False}
    )
    args = ["--vault", str(vault)]
    code, out, err, asked = cli(["unlock", *args], env, [PHRASE])
    assert code == 1 and "could not block debuggers" in err and "--allow-unhardened" in err
    assert PHRASE not in out + err and asked == []  # refused before anyone typed anything
    assert not key_agent.socket_path(vault, env).exists()
    code, out, err, _ = cli(["unlock", "--allow-unhardened", *args], env, [PHRASE])
    pid = key_agent.status(key_agent.socket_path(vault, env))["pid"]
    try:
        assert code == 0 and "ptrace blocked: no" in out
        assert "WARNING" in err and "not fully protected" in err
    finally:
        cli(["lock", *args], env)
        if not wait_until(lambda: not alive(pid)) and alive(pid):
            force_kill(pid)


# ----------------------------- the agent is forked before the passphrase, and gets only the key


def test_the_agent_is_forked_before_the_passphrase_is_asked_for(base, vault, env):
    """Whatever the starting process holds while prompting is in the agent's memory if it forked later."""
    state = {"typed": False, "active": True}
    log = base / "forks.log"

    def note_fork():  # runs in each child the agent's start makes
        if state["active"]:
            with open(log, "a") as handle:
                handle.write("T" if state["typed"] else "F")

    os.register_at_fork(after_in_child=note_fork)

    def prompt(text="Passphrase: ", *, confirm=False):
        state["typed"] = True
        return PHRASE

    out, err = io.StringIO(), io.StringIO()
    try:
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(sys, "argv", ["floorvault", "unlock", "--vault", str(vault)]),
            mock.patch.object(passphrase_custody, "prompt_passphrase", prompt),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = main()
    finally:
        state["active"] = False
    pid = key_agent.status(key_agent.socket_path(vault, env))["pid"]
    try:
        assert code == 0, err.getvalue()
        assert state["typed"]  # the prompt ran ...
        assert log.read_text() == "FF"  # ... after both of the agent's forks
    finally:
        cli(["lock", "--vault", str(vault)], env)
        if not wait_until(lambda: not alive(pid)) and alive(pid):
            os.kill(pid, 9)


def test_a_prepared_agent_waits_for_its_key_and_then_serves(vault, env):
    pending = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    path = pending.path
    pid = None
    try:
        assert path.exists()
        info = pending.send_key(b"k" * 32)
        pid = info["pid"]
        assert info["ok"] and alive(pid)
        with pytest.raises(key_agent.AgentError, match="already given its key or cancelled"):
            pending.send_key(b"k" * 32)
        pending.cancel()  # too late to cancel: the live agent and its socket are left alone
        assert path.exists() and key_agent.status(path)["ok"]
        key_agent.lock(path)
        assert wait_until(lambda: not path.exists())
    finally:
        pending.cancel()
        if pid is not None and alive(pid):
            os.kill(pid, 9)


def test_a_prepared_agent_that_is_cancelled_or_abandoned_leaves_nothing(vault, env):
    pending = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    path = pending.path
    pending.cancel()
    assert not path.exists()
    with pytest.raises(key_agent.AgentNotRunning):
        key_agent.status(path)
    # A starter that dies (its end of the key pipe closes) is the same as a cancel.
    pending = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    os.close(pending._key_fd)
    pending._key_fd = -1
    assert wait_until(lambda: not path.exists())
    pending.cancel()


def test_a_key_of_the_wrong_size_is_refused_and_the_agent_goes_away(vault, env):
    pending = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    path = pending.path
    with pytest.raises(key_agent.AgentError, match="key must be 32 bytes"):
        pending.send_key(b"short")
    assert not path.exists()


def test_the_key_is_read_into_a_buffer_that_a_short_write_does_not_fill():
    reader, writer = os.pipe()
    try:
        os.write(writer, b"x" * 32)
        os.close(writer)
        assert key_agent._read_key_into_buffer(reader) == bytearray(b"x" * 32)
    finally:
        os.close(reader)
    reader, writer = os.pipe()
    try:
        os.write(writer, b"y" * 10)
        os.close(writer)
        assert key_agent._read_key_into_buffer(reader) is None  # the pipe closed too soon
    finally:
        os.close(reader)


def test_a_second_unlock_while_the_first_waits_for_its_key_does_not_take_its_place(vault, env):
    first = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    try:
        with pytest.raises(key_agent.AgentError):  # it answers late, which is not "nothing listens"
            key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
        assert first.path.exists()
    finally:
        first.cancel()


UNLOCK_IN_A_FRESH_PROCESS = """
import contextlib, io, os, sys
sys.path.insert(0, {src!r})
from unittest import mock
from floorvault import passphrase_custody
from floorvault.inspector import main
from floorvault.providers import passphrase_store
passphrase_store.DEFAULT_LOG2_N = passphrase_store.MIN_LOG2_N
phrase_file, vault = sys.argv[1], sys.argv[2]
def prompt(*args, **kwargs):
    return open(phrase_file).read()   # the passphrase enters this process only here
out = io.StringIO()
with mock.patch.object(sys, "argv", ["floorvault", "unlock", "--vault", vault]), \\
     mock.patch.object(passphrase_custody, "prompt_passphrase", prompt), \\
     contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
    sys.exit(main())
"""


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: -1)() != 0 or not os.path.isdir("/proc/self"),
    reason="reads another process's memory",
)
def test_neither_the_typed_passphrase_nor_a_copy_of_the_key_is_in_the_agent_memory(base, env):
    """A root scan of /proc/<pid>/mem (CI runs as an ordinary user, so it skips).

    The unlock runs in a fresh interpreter so that nothing here (this test holds both the
    passphrase and the key) is in the agent's inherited memory.
    """
    import re
    import subprocess

    canary = "CANARY-PASSPHRASE-" + "q7x2m9" * 4
    vault = base / "scan"
    passphrase_custody.create_wrapped_key(vault, canary)
    key = passphrase_custody.read_key(vault, canary)
    phrase_file = base / "phrase"
    phrase_file.write_text(canary)
    src = str(Path(key_agent.__file__).resolve().parent.parent)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            UNLOCK_IN_A_FRESH_PROCESS.format(src=src),
            str(phrase_file),
            str(vault),
        ],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    pid = key_agent.status(key_agent.socket_path(vault, env))["pid"]
    found = {"passphrase": 0, "key": 0}
    try:
        with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
            for line in maps:
                match = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
                lo, hi, perms, name = int(match[1], 16), int(match[2], 16), match[3], match[4]
                if "r" not in perms or name.strip() in ("[vvar]", "[vsyscall]", "[vdso]"):
                    continue
                try:
                    mem.seek(lo)
                    data = mem.read(hi - lo)
                except OSError:
                    continue
                found["passphrase"] += data.count(canary.encode())
                if "/dev/zero" not in name:  # the protected mapping holds the key by design
                    found["key"] += data.count(key)
    finally:
        cli(["lock", "--vault", str(vault)], env)
        if not wait_until(lambda: not alive(pid)) and alive(pid):
            os.kill(pid, 9)
    assert found == {"passphrase": 0, "key": 0}


# ------------------------------------------- the directories above the socket directory


def nested(base, *names):
    """base/n1/n2/..., each 0700, and the deepest path."""
    path = base
    for name in names:
        path = path / name
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    return path


def test_a_directory_above_the_socket_directory_that_others_can_change_is_refused(base):
    final = nested(base, "top", "mid", "floorvault")
    key_agent.check_private_dir(final)
    top = base / "top"
    os.chmod(top, 0o777)
    with pytest.raises(key_agent.AgentError, match="can be changed by other users") as raised:
        key_agent.check_private_dir(final)
    assert str(top) in str(raised.value) and "chmod go-w" in str(raised.value)
    os.chmod(top, 0o1777)  # sticky, like /tmp: other users cannot rename what is ours
    key_agent.check_private_dir(final)
    os.chmod(top, 0o700)
    key_agent.check_private_dir(final)


def test_a_group_writable_directory_is_accepted_only_for_a_group_that_is_ours_alone(
    base, monkeypatch
):
    final = nested(base, "top", "mid", "floorvault")
    os.chmod(base / "top", 0o775)
    monkeypatch.setattr(key_agent, "_group_is_only_us", lambda gid: False)
    with pytest.raises(key_agent.AgentError, match="can be changed by other users"):
        key_agent.check_private_dir(final)
    monkeypatch.setattr(key_agent, "_group_is_only_us", lambda gid: True)
    key_agent.check_private_dir(final)


def test_which_groups_are_ours_alone(monkeypatch):
    import grp
    import pwd
    from types import SimpleNamespace

    me, gid = os.geteuid(), os.getegid()
    mine = SimpleNamespace(pw_name="me", pw_uid=me, pw_gid=gid)
    other = SimpleNamespace(pw_name="other", pw_uid=me + 1, pw_gid=gid)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: mine)
    monkeypatch.setattr(grp, "getgrgid", lambda g: SimpleNamespace(gr_mem=[]))
    monkeypatch.setattr(pwd, "getpwall", lambda: [mine])
    assert key_agent._group_is_only_us(gid) is True
    monkeypatch.setattr(pwd, "getpwall", lambda: [mine, other])  # someone else has it as primary
    assert key_agent._group_is_only_us(gid) is False
    monkeypatch.setattr(pwd, "getpwall", lambda: [mine])
    monkeypatch.setattr(grp, "getgrgid", lambda g: SimpleNamespace(gr_mem=["me", "other"]))
    assert key_agent._group_is_only_us(gid) is False  # someone else is a listed member
    monkeypatch.setattr(grp, "getgrgid", lambda g: SimpleNamespace(gr_mem=["me"]))
    assert key_agent._group_is_only_us(gid) is True
    monkeypatch.setattr(os, "getgroups", lambda: [])
    assert key_agent._group_is_only_us(gid + 1000) is False  # not a group of ours at all
    monkeypatch.setattr(grp, "getgrgid", lambda g: (_ for _ in ()).throw(KeyError(g)))
    assert key_agent._group_is_only_us(gid) is False  # cannot tell


def test_a_directory_above_owned_by_someone_else_is_refused(base, monkeypatch):
    final = nested(base, "top", "mid", "floorvault")
    target = os.fspath(os.path.realpath(base / "top"))
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == target:
            fields = list(info)
            fields[4] = os.geteuid() + 424242  # st_uid: not us, and not root
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(key_agent.os, "lstat", lstat)
    with pytest.raises(key_agent.AgentError, match="above .* is owned by another user"):
        key_agent.check_private_dir(final)


def test_links_in_the_path_are_resolved_and_what_they_lead_through_is_judged(base):
    real = nested(base, "real")
    os.chmod(real, 0o700)
    nested(base, "real", "floorvault")
    (base / "link").symlink_to(real)
    # socket_path resolves the link once, so later binds and connects name no link at all.
    vault = base / "v"
    passphrase_custody.create_wrapped_key(vault, PHRASE)
    path = key_agent.socket_path(vault, {"XDG_RUNTIME_DIR": str(base / "link")})
    assert path.parent == Path(os.path.realpath(real / "floorvault"))
    assert not any(part.is_symlink() for part in [path.parent, *path.parent.parents])
    # A link into a place others can change is refused for what it leads through.
    open_dir = nested(base, "open")
    inside = nested(base, "open", "floorvault")
    os.chmod(open_dir, 0o777)
    (base / "link2").symlink_to(open_dir)
    with pytest.raises(key_agent.AgentError, match="can be changed by other users"):
        key_agent.check_private_dir(base / "link2" / "floorvault")
    os.chmod(open_dir, 0o700)
    key_agent.check_private_dir(inside)


def test_a_refused_directory_is_not_left_behind_by_a_create(base):
    top = nested(base, "top")
    os.chmod(top, 0o777)
    with pytest.raises(key_agent.AgentError, match="can be changed by other users"):
        key_agent.check_private_dir(top / "floorvault", create=True)
    assert not (top / "floorvault").exists()


def test_the_client_will_not_connect_through_a_directory_others_can_change(running):
    item = running()
    assert key_agent.status(item.path)["ok"]
    runtime = item.path.parent.parent
    os.chmod(runtime, 0o777)
    try:
        with pytest.raises(key_agent.AgentError, match="can be changed by other users"):
            key_agent.status(item.path)
    finally:
        os.chmod(runtime, 0o700)
    assert key_agent.status(item.path)["ok"]


def test_the_agent_will_not_bind_below_a_directory_others_can_change(base, vault):
    runtime = nested(base, "shared")
    os.chmod(runtime, 0o777)
    path = key_agent.socket_path(vault, {"XDG_RUNTIME_DIR": str(runtime)})
    with pytest.raises(key_agent.AgentError, match="can be changed by other users"):
        key_agent._bind(path)
    assert not path.exists() and not path.parent.exists()


def test_a_suspend_inclusive_clock_counts_a_sleep_even_if_the_wall_clock_is_corrected_back():
    awake, wall, suspended = FakeClock(), FakeClock(), FakeClock()
    clock = key_agent._LimitClock(awake, wall, suspend_inclusive=suspended)
    awake.advance(1800), wall.advance(1800), suspended.advance(1800)  # 30 minutes awake
    assert clock() == 1800.0
    # 45 minutes asleep: only the suspend-inclusive clock moves ... and on waking the wall clock
    # is corrected back an hour, so its step over the sleep is -900 s. The fallback would lose
    # the whole sleep (deltas 0 and -900); this does not.
    suspended.advance(2700), wall.advance(2700 - 3600)
    assert clock() == 4500.0


def test_the_idle_limit_ends_an_agent_that_slept_through_a_clock_correction():
    awake, wall, suspended = FakeClock(), FakeClock(), FakeClock()
    clock = key_agent._LimitClock(awake, wall, suspend_inclusive=suspended)
    agent = key_agent.Agent(
        object(), Path("/tmp/not-used.sock"), ttl=8 * 3600, idle=3600, clock=clock
    )
    awake.advance(1800), wall.advance(1800), suspended.advance(1800)
    assert agent._expired() is None  # 30 minutes in: well inside the idle hour
    suspended.advance(2700), wall.advance(-900)  # 45 minutes asleep, clock corrected back an hour
    assert agent._expired() == "the idle limit passed"  # 75 minutes without use


def test_the_platforms_suspend_inclusive_clock_is_the_one_chosen(monkeypatch):
    import time as time_module

    expected = "CLOCK_BOOTTIME" if sys.platform == "linux" else "CLOCK_MONOTONIC_RAW"
    wanted = getattr(time_module, expected)

    def fake_clock_gettime(clock_id):
        return 5000.0 if clock_id == wanted else 100.0

    monkeypatch.setattr(time_module, "clock_gettime", fake_clock_gettime)
    clock = key_agent._suspend_inclusive_clock()
    assert clock is not None and clock() == 5000.0
    monkeypatch.delattr(time_module, expected)
    assert key_agent._suspend_inclusive_clock() is None  # no such clock here: the fallback is used

    def failing(clock_id):
        raise OSError("not supported")

    monkeypatch.undo()
    monkeypatch.setattr(time_module, "clock_gettime", failing)
    assert key_agent._suspend_inclusive_clock() is None


def stale_socket(path):
    """A socket file with nobody listening: bound, then closed."""
    leftover = socket.socket(socket.AF_UNIX)
    leftover.bind(str(path))
    leftover.close()
    return key_agent._socket_identity(path)


def test_unlinking_removes_a_stale_socket_and_nothing_else(base):
    path = base / "s.sock"
    identity = stale_socket(path)
    key_agent._unlink_socket(path, identity)
    assert not path.exists()
    key_agent._unlink_socket(path, identity)  # already gone: nothing to do, no error
    stale_socket(path)
    key_agent._unlink_socket(path, None)  # no identity known: a stale socket is removed
    assert not path.exists()


def test_unlinking_leaves_a_live_socket_alone_even_if_it_has_the_same_inode(base):
    path = base / "live.sock"
    live = socket.socket(socket.AF_UNIX)
    live.bind(str(path))
    live.listen(1)
    try:
        # The identity matches exactly (inode numbers get reused, so a match proves little) ...
        key_agent._unlink_socket(path, key_agent._socket_identity(path))
        assert path.exists()  # ... but somebody is listening, so it is not the stale one
    finally:
        live.close()


def test_unlinking_leaves_a_socket_with_another_identity_and_a_non_socket_alone(base, monkeypatch):
    path = base / "other.sock"
    stale_socket(path)
    key_agent._unlink_socket(path, (0, 0))  # not the socket that was bound
    assert path.exists()
    path.unlink()
    path.write_text("not a socket")
    # What a connect to a regular file reports differs by OS (refused on Linux, ENOTSOCK on
    # macOS), so say outright that nobody is listening: the type check alone must keep the file.
    monkeypatch.setattr(key_agent, "_nobody_listens", lambda sock_path: True)
    key_agent._unlink_socket(path, None)
    assert path.read_text() == "not a socket"


def test_a_refused_start_never_removes_a_socket_another_agent_bound_since(vault, env, monkeypatch):
    monkeypatch.setattr(
        key_agent, "harden_process", lambda: {"core_dumps_off": False, "ptrace_blocked": False}
    )
    path = key_agent.socket_path(vault, env)
    real_waitpid = os.waitpid
    replacements = []

    def waitpid_then_a_newer_agent_binds(pid, flags):
        result = real_waitpid(pid, flags)
        with contextlib.suppress(
            FileNotFoundError
        ):  # the refused agent may have removed it already
            os.unlink(path)  # its socket is stale; a concurrent unlock replaces it
        newer = socket.socket(socket.AF_UNIX)
        newer.bind(str(path))
        newer.listen(1)
        replacements.append(newer)
        return result

    monkeypatch.setattr(key_agent.os, "waitpid", waitpid_then_a_newer_agent_binds)
    try:
        with pytest.raises(key_agent.AgentError, match="could not"):
            key_agent.start(vault, b"k" * 32, environ=env, app_context=APP_CONTEXT)
        assert path.exists()  # the newer agent's socket was not taken for the refused one's
    finally:
        for newer in replacements:
            newer.close()
        with contextlib.suppress(OSError):
            os.unlink(path)


def test_cancelling_a_prepared_agent_never_removes_a_newer_agents_socket(vault, env):
    pending = key_agent.prepare(vault, environ=env, app_context=APP_CONTEXT)
    path = pending.path
    os.close(pending._key_fd)  # the agent sees its starter go away and removes its own socket ...
    pending._key_fd = -1
    assert wait_until(lambda: not path.exists())
    newer = socket.socket(socket.AF_UNIX)  # ... and a newer agent has bound the path since
    newer.bind(str(path))
    newer.listen(1)
    try:
        pending.cancel()
        assert path.exists()
    finally:
        newer.close()
        with contextlib.suppress(OSError):
            os.unlink(path)

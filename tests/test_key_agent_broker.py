"""The key agent as a broker (#84, step 3, part 3): `run` and `secrets` use it.

The agent holds the key and encrypts and decrypts for its caller; `RemoteVault` is the
caller's end. These tests check that a store behaves the same through it as with the
key, that the key never leaves the agent, that its use counts against the idle limit,
and, end to end, that `floorvault run` and `floorvault secrets` in a process with no
terminal and no key of its own work against a real forked agent and stop working when
it is locked.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from floorvault import key_agent, passphrase_custody
from floorvault.agent_cli import APP_CONTEXT
from floorvault.core import DecryptionVerificationError, FloorVault
from floorvault.inspector import main
from floorvault.memory import HardenedMemoryKey
from floorvault.providers import passphrase_store

pytestmark = pytest.mark.skipif(not key_agent.SUPPORTED, reason="Linux or macOS only")

PHRASE = "correct horse battery staple"
VALUE = "broker-fixture-secret"
ROOT = Path(__file__).resolve().parent.parent
KEY = b"k" * 32


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)


@pytest.fixture()
def base():
    path = Path(tempfile.mkdtemp(prefix="fb", dir="/tmp" if os.path.isdir("/tmp") else None))
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


class Broker:
    """An Agent with a crypto engine over KEY, served from a thread."""

    def __init__(self, vault, env, clock=None, *, idle=600, with_crypto=True):
        self.path = key_agent.socket_path(vault, env)
        self.listener = key_agent._bind(self.path)
        self.key = HardenedMemoryKey(bytearray(KEY))
        self.crypto = FloorVault(self.key, app_instance_id=APP_CONTEXT) if with_crypto else None
        self.agent = key_agent.Agent(
            self.key,
            self.path,
            ttl=3600,
            idle=idle,
            clock=clock or time.monotonic,
            poll=0.02,
            identity=key_agent._socket_identity(self.path),
            crypto=self.crypto,
        )
        self.thread = threading.Thread(target=self.agent.serve, args=(self.listener,))
        self.thread.start()

    def stop(self):
        self.agent.request_stop("test over")
        self.thread.join(5)


@pytest.fixture()
def broker(vault, env):
    made = []

    def make(*args, **kwargs):
        item = Broker(vault, env, *args, **kwargs)
        made.append(item)
        return item

    yield make
    for item in made:
        item.stop()


def coords(**over):
    return {"table": "items", "record_id": "r1", "column": "secret", **over}


# ----------------------------------------------------------- the crypto interface


def test_a_remote_vault_and_the_key_read_each_others_records(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    local = FloorVault(HardenedMemoryKey(bytearray(KEY)), app_instance_id=APP_CONTEXT)
    sealed_remotely = remote.encrypt("héllo wörld", **coords(revision=3, key_id=0))
    assert isinstance(sealed_remotely, bytes) and b"llo" not in sealed_remotely
    assert local.decrypt(sealed_remotely, **coords(revision=3)) == "héllo wörld"
    sealed_locally = local.encrypt(b"\x00bytes", **coords(schema_version=2))
    assert remote.decrypt(sealed_locally, **coords(schema_version=2)) == local.decrypt(
        sealed_locally, **coords(schema_version=2)
    )


def test_a_wrong_context_or_a_changed_record_fails_as_a_verification_error(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("plain-sealed-text", **coords())
    for wrong in (coords(record_id="r2"), coords(column="other"), coords(revision=9)):
        with pytest.raises(DecryptionVerificationError) as raised:
            remote.decrypt(sealed, **wrong)
        assert "plain-sealed-text" not in str(raised.value)
    tampered = bytearray(sealed)
    tampered[-1] ^= 1
    with pytest.raises(DecryptionVerificationError):
        remote.decrypt(bytes(tampered), **coords())
    assert remote.decrypt(sealed, **coords()) == "plain-sealed-text"  # the agent carried on


def test_bad_arguments_are_refused_without_echoing_them(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    with pytest.raises(ValueError):
        remote.encrypt("v", **coords(key_id=999))
    with pytest.raises(ValueError):
        remote.encrypt("v", **coords(schema_version="1"))
    sealed = remote.encrypt("fine", **coords())
    good = {
        "op": "decrypt",
        "ciphertext_b64": base64.b64encode(sealed).decode(),
        **coords(),
        "schema_id": "floor.vault.v1",
        "schema_version": 1,
        "revision": None,
        "key_id": None,
    }
    # The unchanged message works, so each case below fails for its one fault.
    assert key_agent._exchange(item.path, good, 3) == {
        "ok": True,
        "plaintext_b64": base64.b64encode(b"fine").decode(),
    }
    faults = {
        "non-strict base64": {"ciphertext_b64": "AA==!!"},
        "ciphertext not a string": {"ciphertext_b64": 5},
        "table not a string": {"table": 1},
        "schema_version a string": {"schema_version": "1"},
        "schema_version a bool": {"schema_version": True},
        "key_id a string": {"key_id": "0"},
        "revision a float": {"revision": 1.5},
    }
    for name, change in faults.items():
        reply = key_agent._exchange(item.path, {**good, **change}, 3)
        assert reply == {"ok": False, "kind": "value", "error": "invalid argument"}, name
    for name in ("table", "record_id", "column", "schema_id", "schema_version", "ciphertext_b64"):
        missing = {k: v for k, v in good.items() if k != name}
        reply = key_agent._exchange(item.path, missing, 3)
        assert reply["ok"] is False and reply["kind"] == "value", name
    assert remote.decrypt(sealed, **coords()) == "fine"  # and the agent carried on


def test_an_agent_without_a_crypto_engine_does_not_encrypt(broker):
    item = broker(with_crypto=False)
    reply = key_agent._exchange(item.path, {"op": "encrypt", "plaintext_b64": "AA=="}, 3)
    assert reply == {"ok": False, "error": "unknown operation"}


def test_a_large_item_round_trips_and_an_oversize_message_is_refused(broker, monkeypatch):
    item = broker()
    remote = key_agent.RemoteVault(item.path, timeout=20)
    big = "x" * (1 << 20)
    assert remote.decrypt(remote.encrypt(big, **coords()), **coords()) == big
    monkeypatch.setattr(key_agent, "MAX_MESSAGE", 1024)
    with pytest.raises(key_agent.AgentError):
        remote.encrypt("y" * 5000, **coords())


def test_no_reply_carries_the_key(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    seen = [
        json.dumps(key_agent._exchange(item.path, {"op": "status"}, 3)),
        base64.b64encode(remote.encrypt(KEY.decode(), **coords())).decode(),
        json.dumps(key_agent._exchange(item.path, {"op": "decrypt", **coords()}, 3)),
    ]
    for text in seen:
        assert KEY.decode() not in text and KEY.hex() not in text
        assert base64.b64encode(KEY).decode() not in text


# ------------------------------------------------------------- limits and who may ask


def test_encrypting_and_decrypting_count_as_use_but_status_does_not(broker):
    clock = FakeClock()
    item = broker(clock, idle=600)
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("v", **coords())
    clock.advance(500)
    assert remote.decrypt(sealed, **coords()) == "v"  # use: the idle clock restarts
    clock.advance(500)
    key_agent.status(item.path)  # not use
    assert remote.decrypt(sealed, **coords()) == "v"  # 500 s since the last use: still up
    clock.advance(601)
    deadline = time.monotonic() + 5
    while item.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not item.thread.is_alive() and item.key.is_wiped
    with pytest.raises(key_agent.AgentNotRunning):
        remote.decrypt(sealed, **coords())


def test_lock_wipes_the_engine_and_the_key(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("v", **coords())
    key_agent.lock(item.path)
    item.thread.join(5)
    assert not item.thread.is_alive()
    assert item.key.is_wiped and item.crypto._closed
    with pytest.raises(key_agent.AgentNotRunning):
        remote.decrypt(sealed, **coords())


def test_another_users_encrypt_and_decrypt_are_refused_and_learn_nothing(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("secret-value", **coords())
    real = key_agent.peer_credentials

    def other_user_on_the_server(conn):
        pid, uid = real(conn)
        if threading.current_thread() is item.thread:
            return pid, uid + 1
        return pid, uid

    with mock.patch.object(key_agent, "peer_credentials", other_user_on_the_server):
        with pytest.raises(key_agent.AgentError, match="refused"):
            remote.decrypt(sealed, **coords())
        with pytest.raises(key_agent.AgentError, match="refused"):
            remote.encrypt("x", **coords())
    assert remote.decrypt(sealed, **coords()) == "secret-value"


def test_a_remote_vault_refuses_a_server_that_is_not_this_user(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    real = key_agent.peer_credentials

    def other_user_on_the_client(conn):
        pid, uid = real(conn)
        if threading.current_thread() is not item.thread:
            return pid, uid + 1
        return pid, uid

    with mock.patch.object(key_agent, "peer_credentials", other_user_on_the_client):
        with pytest.raises(key_agent.AgentError, match="not this user"):
            remote.encrypt("never sent", **coords())


# ------------------------------------------- the CLI against a real agent, no terminal


def in_process(args, env, answers=()):
    answers = list(answers)

    def prompt(text="Passphrase: ", *, confirm=False):
        return answers.pop(0)

    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env, clear=True),
        mock.patch.object(sys, "argv", ["floorvault", *args]),
        mock.patch.object(sys, "stdin", io.StringIO(f"value={VALUE}\n")),
        mock.patch.object(passphrase_custody, "prompt_passphrase", prompt),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


LAUNCH = (
    "import sys; sys.path.insert(0, {src!r}); "
    "from floorvault.inspector import main; sys.exit(main())"
)


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


def test_run_and_secrets_use_a_real_agent_with_no_terminal_and_stop_when_it_is_locked(
    base, env, tmp_path
):
    vault = base / "v2"
    code, _out, err = in_process(
        ["secrets", "init", "--custody", "passphrase", "--vault", str(vault)], env, [PHRASE]
    )
    assert code == 0, err
    code, _out, err = in_process(
        ["secrets", "add", "Token", "--id", "tok", "--stdin", "--vault", str(vault)],
        env,
        [PHRASE],
    )
    assert code == 0, err
    code, out, err = in_process(["unlock", "--vault", str(vault)], env, [PHRASE])
    assert code == 0, err
    pid = key_agent.status(key_agent.socket_path(vault, env))["pid"]

    dump = tmp_path / "dump.py"
    dump.write_text("import json, os, sys\nsys.stdout.write(json.dumps(dict(os.environ)))\n")
    child_env = {
        **{k: v for k, v in os.environ.items() if not k.startswith(("FLOOR_VAULT", "HERMES"))},
        **env,
        "FLOOR_VAULT_STATE_DIR": str(base / "state"),
        "FLOOR_VAULT_ALLOW_UNBOUND": "1",
    }

    def floorvault(*args, stdin=None):
        # A new session has no controlling terminal, so a passphrase prompt cannot work:
        # whatever succeeds here succeeded through the agent.
        return subprocess.run(
            [sys.executable, "-c", LAUNCH.format(src=str(ROOT / "src")), *args],
            capture_output=True,
            text=True,
            env=child_env,
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            start_new_session=True,
            timeout=120,
        )

    try:
        listed = floorvault("secrets", "list", "--vault", str(vault))
        assert listed.returncode == 0, listed.stderr
        assert listed.stdout.split()[0] == "tok"
        shown = floorvault("secrets", "show", "tok", "--vault", str(vault))
        assert shown.returncode == 0 and "1 set" in shown.stdout
        assert VALUE not in shown.stdout + shown.stderr
        # A write through the agent: sealed by the agent, read back with the key by the library.
        added = floorvault(
            "secrets", "add", "Second", "--id", "two", "--stdin", "--vault", str(vault),
            stdin="value=written-through-the-agent\n",
        )  # fmt: skip
        assert added.returncode == 0, added.stderr
        ran = floorvault(
            "run", "--vault", str(vault), "-e", "A=fv:tok", "--", sys.executable, str(dump)
        )
        assert ran.returncode == 0, ran.stderr
        child = json.loads(ran.stdout)
        assert child["A"] == VALUE
        ran_two = floorvault(
            "run", "--vault", str(vault), "-e", "B=fv:two", "--", sys.executable, str(dump)
        )
        assert json.loads(ran_two.stdout)["B"] == "written-through-the-agent"
        # The child got the value and nothing that would open the store.
        assert KEY.hex() not in ran.stdout and "master.key" not in ran.stdout
        assert not (vault / "master.key").exists()

        locked = floorvault("lock", "--vault", str(vault))
        assert locked.returncode == 0, locked.stderr
        assert wait_until(lambda: not alive(pid))
        again = floorvault("secrets", "list", "--vault", str(vault))
        assert again.returncode == 1
        assert "no terminal to ask for the passphrase" in again.stderr
        assert VALUE not in again.stdout + again.stderr
    finally:
        if alive(pid):
            force_kill(pid)


def test_an_agent_that_is_there_but_unusable_stops_everything(base, env, vault):
    """A listener that answers nothing sensible is not a reason to ask for the passphrase instead."""
    path = key_agent.socket_path(vault, env)
    listener = key_agent._bind(path)
    held = []

    def garbage():
        conn, _ = listener.accept()
        conn.sendall(b"\x00\x00\x00\x02no")
        held.append(conn)

    thread = threading.Thread(target=garbage, daemon=True)
    thread.start()
    try:
        code, _out, err = in_process(["secrets", "list", "--vault", str(vault)], env, [PHRASE])
        assert code == 1
        assert "cannot be used" in err and "Nothing was opened" in err
    finally:
        thread.join(5)
        for conn in held:
            conn.close()
        listener.close()


def test_a_stale_socket_is_not_an_agent_and_the_passphrase_is_asked_as_before(base, env, vault):
    path = key_agent.socket_path(vault, env)
    key_agent._bind(path).close()  # a socket file nothing listens on
    code, _out, err = in_process(["secrets", "list", "--vault", str(vault)], env, [PHRASE])
    assert code in (0, 1) and "cannot be used" not in err


def test_key_options_and_other_custody_are_never_replaced_by_an_agent(base, env, vault):
    item = Broker(vault, env)
    try:
        # A store with an item in it, written through the agent, so a refusal below is
        # about the key option and not about a missing store.
        code, _out, err = in_process(
            ["secrets", "add", "Token", "--id", "tok", "--stdin", "--vault", str(vault)], env
        )
        assert code == 0, err
        code, out, err = in_process(["secrets", "list", "--vault", str(vault)], env)
        assert code == 0 and out.split()[0] == "tok"
        code, _out, err = in_process(
            ["secrets", "list", "--vault", str(vault), "--key-env", "NO_SUCH_KEY_VAR"], env
        )
        assert code == 1 and "NO_SUCH_KEY_VAR is not set" in err
        code, _out, err = in_process(
            ["secrets", "list", "--vault", str(vault), "--key-file", str(base / "nofile")], env
        )
        assert code == 1 and "nofile" in err
        (vault / "master.key").write_bytes(b"\x00" * 32)
        code, _out, err = in_process(["secrets", "list", "--vault", str(vault)], env)
        assert code == 1 and "plaintext copy" in err
    finally:
        item.stop()


def test_a_credential_beside_the_wrapped_key_is_refused_even_with_an_agent_running(
    base, env, vault
):
    item = Broker(vault, env)
    try:
        (vault / "master.key.sdcred").write_bytes(b"x")
        code, _out, err = in_process(["secrets", "list", "--vault", str(vault)], env)
        assert code == 1 and "forked" in err
    finally:
        item.stop()


# ------------------------------------------------- review findings on #126


def test_the_input_types_are_checked_as_the_library_checks_them(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    local = FloorVault(HardenedMemoryKey(bytearray(KEY)), app_instance_id=APP_CONTEXT)
    for bad in (10, [1, 2, 3], None, 1.5):
        with pytest.raises(TypeError, match="plaintext must be"):
            remote.encrypt(bad, **coords())
        with pytest.raises(TypeError):
            local.encrypt(bad, **coords())
    for fine in ("text", b"bytes", bytearray(b"ba"), memoryview(b"mv")):
        sealed = remote.encrypt(fine, **coords())
        assert (
            remote.decrypt(sealed, **coords())
            == bytes(fine if not isinstance(fine, str) else fine.encode()).decode()
        )
    sealed = remote.encrypt("ok", **coords())
    assert remote.decrypt(bytearray(sealed), **coords()) == "ok"
    for bad in (memoryview(sealed), list(sealed), "text", None):
        with pytest.raises(TypeError, match="Ciphertext must be bytes"):
            remote.decrypt(bad, **coords())
        with pytest.raises(TypeError):
            local.decrypt(bad, **coords())


def test_text_that_json_would_expand_still_reads_back(broker):
    item = broker()
    remote = key_agent.RemoteVault(item.path, timeout=60)
    # 3 bytes a character stored; JSON would make the reply 6 bytes a character (over the limit).
    text = "界" * 800_000
    assert remote.decrypt(remote.encrypt(text, **coords()), **coords()) == text


def test_a_request_completed_after_the_limit_passed_is_not_served(broker, monkeypatch):
    clock = FakeClock()
    item = broker(clock, idle=600)
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("v", **coords())
    served = []
    real_decrypt = item.crypto.decrypt
    monkeypatch.setattr(
        item.crypto, "decrypt", lambda *a, **k: served.append(1) or real_decrypt(*a, **k)
    )
    real_recv = key_agent._recv

    def read_then_run_out_of_time(reader, limit):
        message = real_recv(reader, limit)
        if threading.current_thread() is item.thread and message.get("op") == "decrypt":
            clock.advance(10_000)  # the last byte arrived just as the idle limit passed
        return message

    monkeypatch.setattr(key_agent, "_recv", read_then_run_out_of_time)
    with pytest.raises(key_agent.AgentError):
        remote.decrypt(sealed, **coords())
    assert served == []
    item.thread.join(5)
    assert not item.thread.is_alive() and item.key.is_wiped


def test_a_request_completed_after_a_stop_is_not_served(broker, monkeypatch):
    item = broker()
    remote = key_agent.RemoteVault(item.path)
    sealed = remote.encrypt("v", **coords())
    served = []
    real_decrypt = item.crypto.decrypt
    monkeypatch.setattr(
        item.crypto, "decrypt", lambda *a, **k: served.append(1) or real_decrypt(*a, **k)
    )
    real_recv = key_agent._recv

    def read_then_get_signalled(reader, limit):
        message = real_recv(reader, limit)
        if threading.current_thread() is item.thread and message.get("op") == "decrypt":
            item.agent.request_stop("signalled")  # what the SIGTERM handler does
        return message

    monkeypatch.setattr(key_agent, "_recv", read_then_get_signalled)
    with pytest.raises(key_agent.AgentError):
        remote.decrypt(sealed, **coords())
    assert served == []

"""systemd-creds custody: `secrets init --custody systemd-creds` and how `run` / `secrets` use it.

This sandbox-friendly suite runs against a fake ``systemd-creds`` script that
enforces the contract the real tool documents: ``--user`` is required, the
credential name is checked on decrypt, ``--refuse-null`` is unknown before
systemd 259, and nothing is accepted that carries the key in argv. The real
program is not exercised here; unattended decryption on a real host is checked
by hand (docs/USAGE.md).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from floorvault import systemd_creds as sdc
from floorvault.providers.adaptive import AdaptiveKeyProvider
from floorvault.providers.base import KeyProviderError

ROOT = Path(__file__).resolve().parents[1]
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="systemd-creds is Linux only")

FAKE = textwrap.dedent(
    """\
    #!{python}
    import base64, json, os, sys

    here = os.path.dirname(os.path.abspath(__file__))
    cfg = json.load(open(os.path.join(here, "fake.json")))
    args = sys.argv[1:]
    with open(os.path.join(here, "calls.log"), "a") as log:
        log.write(json.dumps(args) + "\\n")
    with open(os.path.join(here, "env.log"), "a") as log:
        log.write(json.dumps(sorted(os.environ)) + "\\n")
    version = cfg.get("version", 257)
    if args[:1] == ["--version"]:
        print(f"systemd {{version}} ({{version}}.1)" if version else "garbage")
        sys.exit(0 if version else 1)
    verb, rest = args[0], args[1:]
    flags = [a for a in rest if a.startswith("-") and a != "-"]
    if "--user" not in flags:
        sys.stderr.write("refusing: system-scoped credential\\n"); sys.exit(1)
    name = next((f.split("=", 1)[1] for f in flags if f.startswith("--name=")), "")
    if rest[-2:] != ["-", "-"]:
        sys.stderr.write("expected - - (stdin to stdout)\\n"); sys.exit(1)
    data = sys.stdin.buffer.read()
    if verb == "encrypt":
        mode = cfg.get("mode")
        if mode == "encrypt-fails":
            sys.stdout.write("SENTINEL-FROM-STDOUT")
            sys.stderr.write("No TPM2 and /var/lib/systemd is not persistent\\n"); sys.exit(1)
        body = json.dumps({{"name": name, "uid": os.getuid(), "data": base64.b64encode(data).decode(),
                           "flags": flags}})
        sys.stdout.write("FAKECRED1." + base64.b64encode(body.encode()).decode())
    elif verb == "decrypt":
        if "--refuse-null" in flags and version < 259:
            sys.stderr.write("unrecognized option '--refuse-null'\\n"); sys.exit(1)
        if cfg.get("mode") == "decrypt-fails":
            sys.stdout.write("SENTINEL-FROM-STDOUT")
            sys.stderr.write("Failed to unseal: TPM2 not available\\n"); sys.exit(1)
        text = data.decode()
        if not text.startswith("FAKECRED1."):
            sys.stderr.write("not a credential\\n"); sys.exit(1)
        body = json.loads(base64.b64decode(text[len("FAKECRED1."):]))
        if body["name"] != name:
            sys.stderr.write("credential name mismatch\\n"); sys.exit(1)
        if body["uid"] != os.getuid():
            sys.stderr.write("credential belongs to another user\\n"); sys.exit(1)
        out = base64.b64decode(body["data"])
        if cfg.get("mode") == "decrypt-differs":
            out = b"0" * 64 + b"\\n"
        if cfg.get("mode") == "decrypt-garbage":
            out = b"not a key\\n"
        sys.stdout.buffer.write(out)
    else:
        sys.exit(2)
    """
)


class Fake:
    def __init__(self, directory: Path):
        self.dir = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.binary = directory / "systemd-creds"
        self.binary.write_text(FAKE.format(python=sys.executable), encoding="utf-8")
        self.binary.chmod(0o755)
        self.configure()

    def configure(self, **cfg):
        (self.dir / "fake.json").write_text(json.dumps(cfg), encoding="utf-8")

    @property
    def calls(self) -> list[list[str]]:
        log = self.dir / "calls.log"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]


@pytest.fixture()
def fake(tmp_path):
    return Fake(tmp_path / "sdbin")


@pytest.fixture()
def vault(tmp_path):
    return tmp_path / "vault"


# ------------------------------------------------------------------ the module


@linux_only
def test_create_then_read_round_trips_and_keeps_the_key_out_of_argv(fake, vault):
    path = sdc.create_credential(vault, binary=str(fake.binary))
    assert path == vault / "master.key.sdcred"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(vault.stat().st_mode) == 0o700
    key = sdc.read_key(vault, binary=str(fake.binary))
    assert isinstance(key, bytes) and len(key) == 32
    flat = json.dumps(fake.calls)
    assert key.hex() not in flat
    encrypt = next(c for c in fake.calls if c[0] == "encrypt")
    assert encrypt[1:] == ["--user", "--name=floorvault.master-key", "-", "-"]
    decrypt = next(c for c in fake.calls if c[0] == "decrypt")
    assert decrypt[:3] == ["decrypt", "--user", "--name=floorvault.master-key"]
    assert decrypt[-2:] == ["-", "-"]


@linux_only
def test_the_helper_runs_with_a_minimal_environment(fake, vault, monkeypatch):
    monkeypatch.setenv("FV_TEST_CANARY", "secret-looking-value")
    monkeypatch.setenv("FLOOR_VAULT_KEY", "ab" * 32)
    sdc.create_credential(vault, binary=str(fake.binary))
    sdc.read_key(vault, binary=str(fake.binary))
    seen = {
        name
        for line in (fake.dir / "env.log").read_text().splitlines()
        for name in json.loads(line)
    }
    assert "PATH" in seen
    assert "FV_TEST_CANARY" not in seen and "FLOOR_VAULT_KEY" not in seen
    assert seen <= {"PATH", "LANG", "LC_ALL", "LC_CTYPE"}


@linux_only
def test_creating_twice_makes_different_keys_and_never_replaces(fake, tmp_path):
    first = sdc.create_credential(tmp_path / "a", binary=str(fake.binary))
    second = sdc.create_credential(tmp_path / "b", binary=str(fake.binary))
    assert sdc.read_key(first.parent, binary=str(fake.binary)) != sdc.read_key(
        second.parent, binary=str(fake.binary)
    )
    before = first.read_bytes()
    with pytest.raises(sdc.SystemdCredsError, match="already exists"):
        sdc.create_credential(first.parent, binary=str(fake.binary))
    assert first.read_bytes() == before


@linux_only
def test_encrypt_makes_no_key_choice(fake, tmp_path):
    # An unprivileged `systemd-creds encrypt` ignores --with-key (it asks systemd to
    # encrypt without one) and refuses `tpm2` with --user, so none is ever passed.
    sdc.create_credential(tmp_path / "v", binary=str(fake.binary))
    encrypt = next(c for c in fake.calls if c[0] == "encrypt")
    assert encrypt == ["encrypt", "--user", "--name=floorvault.master-key", "-", "-"]


def test_no_key_choice_is_part_of_the_module_interface():
    assert not hasattr(sdc, "WITH_KEY_CHOICES")
    with pytest.raises(TypeError):
        sdc.create_credential(Path("v"), with_key="host")  # type: ignore[call-arg]


def test_credential_present_matches_the_provider_guard(tmp_path, monkeypatch):
    assert sdc.credential_present(tmp_path) is False
    (tmp_path / "master.key.sdcred").write_text("FAKECRED1.x")
    assert sdc.credential_present(tmp_path) is True
    real = os.lstat

    def lstat(path, *a, **k):
        if str(path).endswith("master.key.sdcred"):
            raise PermissionError("denied")
        return real(path, *a, **k)

    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setattr(os, "lstat", lstat)
    assert sdc.credential_present(other) is True


@linux_only
@pytest.mark.parametrize("version, refuses", [(256, False), (258, False), (259, True), (262, True)])
def test_refuse_null_is_passed_only_where_systemd_has_it(fake, vault, version, refuses):
    fake.configure(version=version)
    sdc.create_credential(vault, binary=str(fake.binary))
    sdc.read_key(vault, binary=str(fake.binary))
    decrypts = [c for c in fake.calls if c[0] == "decrypt"]
    assert decrypts and all(("--refuse-null" in c) is refuses for c in decrypts)


@linux_only
@pytest.mark.parametrize("version", [0, 200, 255])
def test_a_helper_older_than_256_fails_closed_and_writes_nothing(fake, vault, version):
    fake.configure(version=version)
    with pytest.raises(sdc.SystemdCredsError) as info:
        sdc.create_credential(vault, binary=str(fake.binary))
    message = str(info.value)
    assert ("256" in message and str(version) in message) or "did not report" in message
    assert not vault.exists()
    assert [c for c in fake.calls if c[0] in {"encrypt", "decrypt"}] == []


@linux_only
def test_missing_helper_names_the_directories_and_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(sdc, "SEARCH_DIRS", (str(tmp_path / "empty"),))
    with pytest.raises(sdc.SystemdCredsError) as info:
        sdc.create_credential(tmp_path / "v")
    assert "systemd-creds not found" in str(info.value)
    assert "never falls back" in str(info.value)
    assert not (tmp_path / "v").exists()


def test_other_platforms_are_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(sdc.SystemdCredsError, match="Linux only"):
        sdc.create_credential(tmp_path / "v")
    assert not (tmp_path / "v").exists()


@linux_only
def test_the_helper_is_not_found_through_path_or_the_environment(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f"{fake.dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FLOORVAULT_SYSTEMD_CREDS", str(fake.binary))
    monkeypatch.setattr(sdc, "SEARCH_DIRS", (str(tmp_path / "nowhere"),))
    with pytest.raises(sdc.SystemdCredsError, match="not found"):
        sdc.create_credential(tmp_path / "v")
    assert fake.calls == []


@linux_only
def test_encrypt_failure_reports_stderr_only_and_writes_nothing(fake, vault):
    fake.configure(mode="encrypt-fails")
    with pytest.raises(sdc.SystemdCredsError) as info:
        sdc.create_credential(vault, binary=str(fake.binary))
    assert "No TPM2 and /var/lib/systemd is not persistent" in str(info.value)
    assert "SENTINEL-FROM-STDOUT" not in str(info.value)
    assert not (vault / "master.key.sdcred").exists()


@linux_only
def test_a_credential_that_does_not_unseal_to_the_same_key_is_not_written(fake, vault):
    fake.configure(mode="decrypt-differs")
    with pytest.raises(sdc.SystemdCredsError, match="nothing written"):
        sdc.create_credential(vault, binary=str(fake.binary))
    assert not (vault / "master.key.sdcred").exists()


@linux_only
def test_read_key_is_none_without_a_credential_and_an_error_when_unsealing_fails(fake, vault):
    assert sdc.read_key(vault, binary=str(fake.binary)) is None
    sdc.create_credential(vault, binary=str(fake.binary))
    fake.configure(mode="decrypt-fails")
    with pytest.raises(sdc.SystemdCredsError) as info:
        sdc.read_key(vault, binary=str(fake.binary))
    assert "Failed to unseal: TPM2 not available" in str(info.value)
    assert "SENTINEL-FROM-STDOUT" not in str(info.value)
    fake.configure(mode="decrypt-garbage")
    with pytest.raises(sdc.SystemdCredsError, match="not 64 hexadecimal") as garbage:
        sdc.read_key(vault, binary=str(fake.binary))
    assert "not a key" not in str(garbage.value)


@linux_only
def test_a_credential_for_another_name_or_user_does_not_unseal(fake, vault):
    path = sdc.create_credential(vault, binary=str(fake.binary))
    # Re-label the sealed body, as if it had been made for a different purpose.
    import base64

    text = path.read_text()
    body = json.loads(base64.b64decode(text[len("FAKECRED1.") :]))
    body["name"] = "something.else"
    path.write_text("FAKECRED1." + base64.b64encode(json.dumps(body).encode()).decode())
    with pytest.raises(sdc.SystemdCredsError, match="name mismatch"):
        sdc.read_key(vault, binary=str(fake.binary))
    body["name"] = "floorvault.master-key"
    body["uid"] = os.getuid() + 1
    path.write_text("FAKECRED1." + base64.b64encode(json.dumps(body).encode()).decode())
    with pytest.raises(sdc.SystemdCredsError, match="another user"):
        sdc.read_key(vault, binary=str(fake.binary))


@linux_only
def test_unsafe_credential_files_are_refused_before_the_helper_runs(fake, vault, tmp_path):
    path = sdc.create_credential(vault, binary=str(fake.binary))
    calls_before = len(fake.calls)
    path.chmod(0o620)
    with pytest.raises(sdc.SystemdCredsError, match="writable by group or others"):
        sdc.read_key(vault, binary=str(fake.binary))
    path.chmod(0o600)
    path.write_bytes(b"x" * (20 * 1024))
    with pytest.raises(sdc.SystemdCredsError, match="too large"):
        sdc.read_key(vault, binary=str(fake.binary))
    path.unlink()
    target = tmp_path / "elsewhere"
    target.write_text("FAKECRED1.x")
    path.symlink_to(target)
    with pytest.raises(sdc.SystemdCredsError, match="cannot open"):
        sdc.read_key(vault, binary=str(fake.binary))
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(sdc.SystemdCredsError, match="not a regular file"):
        sdc.read_key(vault, binary=str(fake.binary))
    assert len(fake.calls) == calls_before


# ---------------------------------------------------- the store-key fork guard


def _provider(directory: Path) -> AdaptiveKeyProvider:
    return AdaptiveKeyProvider(service_name="fv-test", fallback_dir=directory)


def test_default_custody_refuses_to_mint_a_second_key_beside_a_credential(tmp_path, monkeypatch):
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "master.key.sdcred").write_text("FAKECRED1.x")
    for allow_create in (True, False):
        with pytest.raises(KeyProviderError) as info:
            _provider(tmp_path).resolve_key(allow_create=allow_create)
        assert "systemd-creds" in str(info.value) and "fork" in str(info.value)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["master.key.sdcred"]


def test_an_explicit_environment_key_is_still_honoured(tmp_path, monkeypatch):
    (tmp_path / "master.key.sdcred").write_text("FAKECRED1.x")
    monkeypatch.setenv("FLOOR_VAULT_KEY", "ab" * 32)
    assert _provider(tmp_path).resolve_key() is not None


def test_a_lookup_that_cannot_rule_the_credential_out_counts_as_present(tmp_path, monkeypatch):
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    real = os.lstat

    def lstat(path, *a, **k):
        if str(path).endswith("master.key.sdcred"):
            raise PermissionError("denied")
        return real(path, *a, **k)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(KeyProviderError, match="systemd-creds"):
        _provider(tmp_path).resolve_key()


def test_no_credential_means_the_guard_does_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOOR_VAULT_KEY", "cd" * 32)
    assert _provider(tmp_path).resolve_key() is not None


# ------------------------------------------------------- through the command line

LAUNCH = (
    "import os, sys; sys.path.insert(0, {src!r}); import floorvault.systemd_creds as m; "
    "m.SEARCH_DIRS = (os.environ['FV_TEST_SDC_DIR'],); "
    "from floorvault.inspector import main; sys.exit(main())"
)


@pytest.fixture()
def cli(tmp_path, fake, vault):
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FLOOR_VAULT", "HERMES"))}
    env.pop("VAULT_MASTER_KEY", None)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "FLOOR_VAULT_DIR": str(vault),
            "FV_TEST_SDC_DIR": str(fake.dir),
            # A key variable that must be ignored for a vault whose key is sealed.
            "FLOOR_VAULT_KEY": os.urandom(32).hex(),
        }
    )

    def run(args, *, extra_env=None, stdin=None):
        return subprocess.run(
            [sys.executable, "-c", LAUNCH.format(src=str(ROOT / "src")), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env={**env, **(extra_env or {})},
            cwd=ROOT,
            timeout=120,
        )

    run.env = env
    return run


def _dump(tmp_path):
    script = tmp_path / "dump.py"
    script.write_text("import json, os, sys\nsys.stdout.write(json.dumps(dict(os.environ)))\n")
    return [sys.executable, str(script)]


@linux_only
def test_init_then_add_list_show_and_run_use_the_sealed_key(tmp_path, cli, fake, vault):
    result = cli(["secrets", "init", "--custody", "systemd-creds"])
    assert result.returncode == 0, result.stderr
    assert f"created {vault / 'master.key.sdcred'}" in result.stdout
    assert "--with-key" not in result.stdout
    assert "systemd chooses what else the key is bound to" in result.stderr
    assert "do not assume hardware binding" in result.stderr
    assert "Not checked: unsealing from a service" in result.stderr
    assert stat.S_IMODE((vault / "master.key.sdcred").stat().st_mode) == 0o600
    assert not [p for p in vault.iterdir() if p.name != "master.key.sdcred"]

    added = cli(["secrets", "add", "Token", "--id", "tok", "--stdin"], stdin="value=s3cret-value\n")
    assert added.returncode == 0, added.stderr
    assert cli(["secrets", "list"]).stdout.split()[0] == "tok"
    assert "1 field(s): 1 set" in cli(["secrets", "show", "tok"]).stdout
    # No OS key store and no key file were created for this vault.
    assert sorted(p.name for p in vault.iterdir()) == ["master.key.sdcred", "vault.db"]

    ran = cli(["run", "-e", "A=fv:tok", "--", *_dump(tmp_path)])
    assert ran.returncode == 0, ran.stderr
    child = json.loads(ran.stdout)
    assert child["A"] == "s3cret-value"
    key_hex = sdc.read_key(vault, binary=str(fake.binary)).hex()
    assert key_hex not in ran.stdout and key_hex not in json.dumps(fake.calls)
    assert not {k for k in child if k.startswith("FLOOR_VAULT_KEY")}


@linux_only
def test_a_sealed_store_ignores_floor_vault_key_and_other_key_sources(tmp_path, cli, fake, vault):
    assert cli(["secrets", "init", "--custody", "systemd-creds"]).returncode == 0
    assert cli(["secrets", "add", "T", "--id", "t", "--stdin"], stdin="value=v\n").returncode == 0
    other = tmp_path / "other.key"
    other.write_text(os.urandom(32).hex(), encoding="ascii")
    other.chmod(0o600)
    ran = cli(
        ["run", "-e", "A=fv:t", "--", *_dump(tmp_path)],
        extra_env={"FLOOR_VAULT_KEY": "00" * 32, "FLOOR_VAULT_KEY_FILE": str(other)},
    )
    assert ran.returncode == 0, ran.stderr
    assert json.loads(ran.stdout)["A"] == "v"


@linux_only
def test_when_the_helper_is_unusable_everything_fails_closed(tmp_path, cli, fake, vault):
    assert cli(["secrets", "init", "--custody", "systemd-creds"]).returncode == 0
    assert cli(["secrets", "add", "T", "--id", "t", "--stdin"], stdin="value=v\n").returncode == 0
    marker = tmp_path / "ran"
    script = tmp_path / "marker.py"
    script.write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    for mode_cfg in ({"version": 255}, {"mode": "decrypt-fails"}):
        fake.configure(**mode_cfg)
        ran = cli(["run", "-e", "A=fv:t", "--", sys.executable, str(script)])
        assert ran.returncode == 125, ran.stderr
        assert "systemd" in ran.stderr and ran.stdout == ""
        assert not marker.exists()
        listed = cli(["secrets", "list"])
        assert listed.returncode == 1 and "systemd" in listed.stderr
    # The ambient FLOOR_VAULT_KEY did not stand in for the sealed key.
    assert (vault / "master.key.sdcred").is_file()


@linux_only
def test_run_without_references_never_touches_the_helper(tmp_path, cli, fake, vault):
    assert cli(["secrets", "init", "--custody", "systemd-creds"]).returncode == 0
    fake.configure(version=100)
    ran = cli(["run", "--", *_dump(tmp_path)])
    assert ran.returncode == 0, ran.stderr


@linux_only
def test_an_explicit_key_file_wins_so_a_backup_key_can_recover_the_store(
    tmp_path, cli, fake, vault
):
    assert cli(["secrets", "init", "--custody", "systemd-creds"]).returncode == 0
    assert cli(["secrets", "add", "T", "--id", "t", "--stdin"], stdin="value=v\n").returncode == 0
    recovered = tmp_path / "recovered.key"
    recovered.write_text(sdc.read_key(vault, binary=str(fake.binary)).hex(), encoding="ascii")
    recovered.chmod(0o600)
    fake.configure(version=100)  # the sealed route is broken now
    ran = cli(["run", "--key-file", str(recovered), "-e", "A=fv:t", "--", *_dump(tmp_path)])
    assert ran.returncode == 0, ran.stderr
    assert json.loads(ran.stdout)["A"] == "v"


@linux_only
def test_init_refuses_an_existing_vault_a_second_init_and_key_options(tmp_path, cli, fake, vault):
    key = os.urandom(32).hex()
    made = cli(
        ["secrets", "add", "T", "--id", "t", "--stdin"],
        stdin="value=v\n",
        extra_env={"FLOOR_VAULT_KEY": key},
    )
    assert made.returncode == 0, made.stderr
    existing = cli(["secrets", "init", "--custody", "systemd-creds"])
    assert existing.returncode == 2 and "a vault already exists" in existing.stderr
    assert not (vault / "master.key.sdcred").exists()

    fresh = tmp_path / "fresh"
    first = cli(["secrets", "init", "--custody", "systemd-creds", "--vault", str(fresh)])
    assert first.returncode == 0, first.stderr
    sealed = (fresh / "master.key.sdcred").read_bytes()
    again = cli(["secrets", "init", "--custody", "systemd-creds", "--vault", str(fresh)])
    assert again.returncode == 1 and "already exists" in again.stderr
    assert (fresh / "master.key.sdcred").read_bytes() == sealed

    for flag in (["--key-env", "FLOOR_VAULT_KEY"], ["--key-file", str(tmp_path / "k")]):
        refused = cli(
            ["secrets", "init", "--custody", "systemd-creds", *flag, "--vault", str(tmp_path / "x")]
        )
        assert refused.returncode == 2 and "takes no --key-env or --key-file" in refused.stderr
    assert not (tmp_path / "x").exists()


@linux_only
def test_init_needs_a_custody_and_offers_no_key_choice(tmp_path, cli, vault):
    assert cli(["secrets", "init"]).returncode == 2
    for value in ("null", "host", "tpm2", "host+tpm2"):
        bad = cli(["secrets", "init", "--custody", "systemd-creds", "--with-key", value])
        assert bad.returncode == 2 and "unrecognized arguments: --with-key" in bad.stderr
    assert not vault.exists()


@linux_only
def test_init_on_an_old_systemd_says_so_and_creates_nothing(tmp_path, cli, fake, vault):
    fake.configure(version=255)
    result = cli(["secrets", "init", "--custody", "systemd-creds"])
    assert result.returncode == 1
    assert "systemd 255 found" in result.stderr and "never falls back" in result.stderr
    assert not vault.exists()


@linux_only
def test_the_default_store_is_unchanged_without_a_credential(tmp_path, cli, vault):
    added = cli(["secrets", "add", "T", "--id", "t", "--stdin"], stdin="value=v\n")
    assert added.returncode == 0, added.stderr  # FLOOR_VAULT_KEY from the environment
    assert not (vault / "master.key.sdcred").exists()
    ran = cli(["run", "-e", "A=fv:t", "--", *_dump(tmp_path)])
    assert ran.returncode == 0 and json.loads(ran.stdout)["A"] == "v"


# ----------------------------------------------- Hermes import into a sealed store

HERMES_ENV_TEXT = "OPENAI_API_KEY=sk-test-openai\nDEBUG=1\n"
HERMES_MAPPING = 'secrets:\n  hermesvault:\n    enabled: true\n    env:\n      OPENAI_API_KEY: "hv:openai_api_key"\n'
SEALED_MAPPING = HERMES_MAPPING.replace(
    "enabled: true\n", "enabled: true\n    custody: systemd-creds\n"
)


def _sealed_hermes_home(tmp_path, cli, config=HERMES_MAPPING):
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "state.db").write_bytes(b"")
    (home / "config.yaml").write_text(config, encoding="utf-8")
    (home / ".env").write_text(HERMES_ENV_TEXT, encoding="utf-8")
    store = home / "agent-vault"
    made = cli(["secrets", "init", "--custody", "systemd-creds", "--vault", str(store)])
    assert made.returncode == 0, made.stderr
    return home, store


def _plugin_manifest(home, version):
    directory = home / "plugins" / "hermesvault"
    directory.mkdir(parents=True)
    (directory / "plugin.yaml").write_text(f'version: "{version}"\n', encoding="utf-8")


def _tree(path: Path) -> dict:
    return {
        str(p.relative_to(path)): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()
    }


@linux_only
def test_hermes_import_stores_under_the_sealed_key_and_suggests_its_custody(tmp_path, cli):
    home, store = _sealed_hermes_home(tmp_path, cli)
    flags = [str(home / ".env"), "--only", "OPENAI_API_KEY"]
    dry = cli(["secrets", "import", "--hermes", *flags])
    assert dry.returncode == 0, dry.stderr
    assert "    custody: systemd-creds\n" in dry.stdout
    assert not (store / "vault.db").exists()
    written = cli(["secrets", "import", "--hermes", *flags, "--write"])
    assert written.returncode == 0, written.stderr
    assert (home / ".env").read_text() == HERMES_ENV_TEXT
    # $FLOOR_VAULT_KEY is set in the fixture; the store opens under the sealed key.
    shown = cli(["secrets", "list", "--vault", str(store)])
    assert shown.returncode == 0 and "openai_api_key" in shown.stdout


@linux_only
@pytest.mark.parametrize(
    "config, version, message",
    [
        (SEALED_MAPPING, "0.2.8", None),
        (SEALED_MAPPING, "0.2.1", "Update the plugin first"),
        (HERMES_MAPPING, "0.2.8", "plugin key cannot decrypt"),
    ],
)
def test_hermes_remove_from_a_sealed_store_follows_the_plugin_custody(
    tmp_path, cli, config, version, message
):
    home, store = _sealed_hermes_home(tmp_path, cli, config=config)
    _plugin_manifest(home, version)
    result = cli(
        ["secrets", "import", "--hermes", str(home / ".env"), "--only", "OPENAI_API_KEY",
         "--write", "--remove-from-env"]
    )  # fmt: skip
    if message is None:
        assert result.returncode == 0, result.stderr
        assert (home / ".env").read_text() == "DEBUG=1\n"
    else:
        assert result.returncode == 2 and message in result.stderr
        assert (home / ".env").read_text() == HERMES_ENV_TEXT


@linux_only
def test_hermes_import_refuses_a_key_file_beside_a_sealed_credential(tmp_path, cli):
    home, store = _sealed_hermes_home(tmp_path, cli)
    key_file = tmp_path / "k"
    key_file.write_text("ab" * 32 + "\n")
    key_file.chmod(0o600)
    before = _tree(home)
    result = cli(
        [
            "secrets", "import", "--hermes", str(home / ".env"), "--write",
            "--vault", str(store), "--key-file", str(key_file),
        ]
    )  # fmt: skip
    assert result.returncode == 2 and "--key-file names another" in result.stderr
    assert "Nothing was stored and .env is unchanged" in result.stderr
    assert _tree(home) == before


@linux_only
def test_hermes_import_still_works_with_the_plugins_own_key_variable(tmp_path, cli):
    home, store = _sealed_hermes_home(tmp_path, cli)
    result = cli(
        ["secrets", "import", "--hermes", str(home / ".env"), "--only", "OPENAI_API_KEY"],
        extra_env={"HERMES_VAULT_KEY": "cd" * 32},
    )
    assert result.returncode == 0, result.stderr
    assert "using the key in $HERMES_VAULT_KEY" in result.stderr
    assert "dry run: nothing changed" in result.stdout


@linux_only
def test_hermes_import_without_a_credential_is_unaffected(tmp_path, cli):
    home = tmp_path / "plain-home"
    home.mkdir()
    (home / "state.db").write_bytes(b"")
    (home / "config.yaml").write_text("model: x\n", encoding="utf-8")
    (home / ".env").write_text(HERMES_ENV_TEXT, encoding="utf-8")
    result = cli(
        ["secrets", "import", "--hermes", str(home / ".env"), "--only", "OPENAI_API_KEY"],
        extra_env={"FLOOR_VAULT_KEY": "ef" * 32},
    )
    assert result.returncode == 0, result.stderr
    assert "dry run: nothing changed" in result.stdout


@linux_only
def test_inspect_reads_the_key_from_a_credential_in_key_dir(
    fake, vault, tmp_path, monkeypatch, capsys
):
    """`inspect --key-dir` uses a sealed credential, as run and secrets do (#100)."""
    import sqlite3

    from floorvault import FloorVault
    from floorvault.inspector import main

    sdc.create_credential(vault, binary=str(fake.binary))
    key = sdc.read_key(vault, binary=str(fake.binary))
    db = tmp_path / "app.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE t (id TEXT, c BLOB)")
        conn.execute(
            "INSERT INTO t VALUES ('1', ?)",
            (FloorVault(key).encrypt("sealed-secret", table="t", record_id="1", column="c"),),
        )
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sdc, "SEARCH_DIRS", (str(fake.dir),))
    code = main(["inspect", str(db), "t", "1", "c", "--key-dir", str(vault), "--reveal"])
    out = capsys.readouterr()
    assert code == 0, out.err
    assert "Decrypted value: sealed-secret" in out.out

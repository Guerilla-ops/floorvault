"""hermesvault plugin tests — real store, real SecretSource contract.

The plugin modules are imported from ``plugins/hermesvault`` and the Hermes
``agent.secret_sources`` contract from a Hermes checkout (HERMES_AGENT_SRC,
default ~/hermes-agent). ``floorvault`` itself is resolved through the
installed/editable package or this repo's ``src`` via pytest pythonpath.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "hermesvault"))
sys.path.insert(0, os.environ.get("HERMES_AGENT_SRC", str(Path.home() / "hermes-agent")))

pytest.importorskip("floorvault")
secret_base = pytest.importorskip("agent.secret_sources.base")

from agent.secret_sources.base import ErrorKind, FetchResult, is_valid_env_name  # noqa: E402
from source import HermesVaultSource, parse_ref, resolve_base_dir  # noqa: E402

import floorvault  # noqa: E402

KEY = "00" * 32


@pytest.fixture()
def vault_home(tmp_path, monkeypatch):
    """A hermes home with a populated agent-vault store (env-var key custody)."""
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setenv("FLOOR_VAULT_KEY", KEY)
    store = floorvault.get_vault_store(tmp_path / "agent-vault", auto_migrate=False)
    store.add_item(
        kind="generic",
        label="openai key",
        secret={"value": "sk-test-123"},
        item_id="vault_testopenai",
    )
    store.add_item(
        kind="generic",
        label="two fields",
        secret={"user": "u1", "token": "tok-abc"},
        item_id="vault_multi",
    )
    return tmp_path


def fetch(home, cfg=None):
    cfg = {"enabled": True, "env": {}, **(cfg or {})}
    return HermesVaultSource().fetch(cfg, home)


def test_ref_parsing():
    assert parse_ref("hv:vault_abc123") == ("vault_abc123", None)
    assert parse_ref("hv:vault_abc123:token") == ("vault_abc123", "token")
    assert parse_ref("op://x") == (None, None)
    assert parse_ref("hv:") == (None, None)
    assert parse_ref("hv:bad id!") == (None, None)
    assert parse_ref(42) == (None, None)


def test_fetch_resolves_single_field_and_value(vault_home):
    result = fetch(vault_home, {"env": {"OPENAI_API_KEY": "hv:vault_testopenai"}})
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk-test-123"}


def test_fetch_named_field(vault_home):
    result = fetch(
        vault_home, {"env": {"TG_TOKEN": "hv:vault_multi:token", "TG_USER": "hv:vault_multi:user"}}
    )
    assert result.secrets == {"TG_TOKEN": "tok-abc", "TG_USER": "u1"}


def test_fetch_multi_field_without_name_warns(vault_home):
    result = fetch(vault_home, {"env": {"X": "hv:vault_multi"}})
    assert result.secrets == {} and result.ok
    assert any("vault_multi" in w and "field" in w for w in result.warnings)


def test_fetch_missing_item_warns_and_keeps_others(vault_home):
    result = fetch(vault_home, {"env": {"GONE": "hv:vault_nope", "HERE": "hv:vault_testopenai"}})
    assert result.secrets == {"HERE": "sk-test-123"}
    assert any("GONE" in w for w in result.warnings)


def test_fetch_bad_env_name_and_bad_ref_warn(vault_home):
    result = fetch(vault_home, {"env": {"1BAD": "hv:vault_testopenai", "OK_NAME": "not-a-ref"}})
    assert result.secrets == {}
    assert len(result.warnings) == 2


def test_fetch_malformed_env_section_fails_closed(vault_home):
    result = fetch(vault_home, {"env": "OPENAI_API_KEY=hv:x"})
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED


def test_fetch_empty_or_disabled_is_noop(vault_home):
    assert fetch(vault_home).ok and fetch(vault_home).secrets == {}
    assert fetch(vault_home, {"env": {}}).secrets == {}


def test_store_never_uses_login_vault_dir(vault_home):
    # The agent-secret store defaults to <home>/agent-vault, NOT <home>/vault —
    # auto_migrate=False additionally guarantees legacy vault.json.enc files are
    # never adopted into this store.
    assert resolve_base_dir({}, vault_home) == vault_home / "agent-vault"
    assert resolve_base_dir({"dir": "custom/secrets"}, vault_home) == vault_home / "custom/secrets"
    assert resolve_base_dir({"dir": "/abs/path"}, vault_home) == Path("/abs/path")


FLOORVAULT_KEYS = {"FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"}


def test_bootstrap_key_and_floorvault_key_variables_are_protected():
    source = HermesVaultSource()
    assert source.protected_env_vars({}) == frozenset({"HERMES_VAULT_KEY", *FLOORVAULT_KEYS})
    assert source.protected_env_vars({"token_env": "MY_KEY"}) == frozenset(
        {"MY_KEY", *FLOORVAULT_KEYS}
    )


def test_source_contract_surface():
    source = HermesVaultSource()
    assert source.name == "hermesvault" and source.scheme == "hv" and source.shape == "mapped"
    assert source.api_version == secret_base.SECRET_SOURCE_API_VERSION
    assert is_valid_env_name("HERMES_VAULT_KEY")
    assert isinstance(source.fetch({}, Path("/nonexistent-home")), FetchResult)


def test_register_wires_source_and_cli():
    sys.path.insert(0, str(ROOT / "plugins"))
    import hermesvault  # noqa: PLC0415 — the plugin package itself

    calls = []
    ctx = type(
        "Ctx",
        (),
        {
            "register_secret_source": lambda self, s: calls.append(("source", s.name)),
            "register_cli_command": lambda self, **kw: calls.append(("cli", kw["name"])),
        },
    )()
    hermesvault.register(ctx)
    assert calls == [("source", "hermesvault"), ("cli", "hvault")]


def test_put_uses_atomic_store_update(monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as hermesvault_cli

    calls = []

    class Store:
        def get_meta(self, item_id):
            return object()

        def update_generic_field(self, item_id, field, value):
            calls.append((item_id, field, value))
            return True

        def resolve_secret(self, *_args):
            raise AssertionError("put must not read-modify-delete-recreate an item")

        def remove_item(self, *_args):
            raise AssertionError("put must preserve the existing item")

        def add_item(self, **_kwargs):
            raise AssertionError("put must preserve the existing item")

    monkeypatch.setattr(hermesvault_cli, "_store", lambda: Store())
    monkeypatch.setattr(hermesvault_cli.getpass, "getpass", lambda _prompt: "new-value")
    assert hermesvault_cli._cmd_put(SimpleNamespace(item_id="vault_a", field="token")) == 0
    assert calls == [("vault_a", "token", "new-value")]
    assert "updated vault_a.token" in capsys.readouterr().out


def test_wrong_key_fails_closed_not_silent(tmp_path, monkeypatch):
    """A vault sealed under one key must not open under another."""
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setenv("FLOOR_VAULT_KEY", KEY)
    store = floorvault.get_vault_store(tmp_path / "agent-vault", auto_migrate=False)
    store.add_item(kind="generic", label="k", secret={"value": "v"}, item_id="vault_a")
    monkeypatch.setenv("HERMES_VAULT_KEY", "ff" * 32)
    result = HermesVaultSource().fetch({"enabled": True, "env": {"X": "hv:vault_a"}}, tmp_path)
    assert result.ok and result.secrets == {}
    assert result.warnings, "ciphertext under a different key must not resolve"


def test_store_written_by_the_plugin_opens_under_floorvault_run(tmp_path, monkeypatch):
    """Interop: an item added through the plugin's own _open_store is readable by
    `floorvault run`, from both the token_env key and the core FLOOR_VAULT_KEY."""
    import subprocess

    from source import _open_store

    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    store = _open_store({}, tmp_path, setup=True)
    store.add_item(kind="generic", label="k", secret={"value": "sk-hermes"}, item_id="vault_i")

    base = {k: v for k, v in os.environ.items() if k not in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY")}
    base["PYTHONPATH"] = str(ROOT / "src")
    base["FLOOR_VAULT_STATE_DIR"] = str(tmp_path / "state")
    base["FLOOR_VAULT_ALLOW_UNBOUND"] = "1"
    probe = [sys.executable, "-c", "import os; print(os.environ['A'])"]
    for extra, flags in (
        ({"HERMES_VAULT_KEY": KEY}, ["--key-env", "HERMES_VAULT_KEY"]),
        ({"FLOOR_VAULT_KEY": KEY}, []),
    ):
        result = subprocess.run(
            [sys.executable, "-m", "floorvault.inspector", "run"]
            + ["--vault", str(tmp_path / "agent-vault"), *flags, "-e", "A=hv:vault_i", "--"]
            + probe,
            capture_output=True,
            text=True,
            env={**base, **extra},
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "sk-hermes"


@pytest.fixture
def plugin_cli():
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli

    return cli


def test_doctor_resolves_without_printing_secrets(plugin_cli, vault_home, monkeypatch, capsys):
    monkeypatch.setattr(plugin_cli, "get_hermes_home", lambda: vault_home)
    monkeypatch.setattr(
        plugin_cli,
        "_secrets_cfg",
        lambda: {"enabled": True, "env": {"TOKEN": "hv:vault_testopenai"}},
    )
    assert plugin_cli.hvault_command(SimpleNamespace(hvault_command="doctor")) == 0
    out = capsys.readouterr()
    assert "1/1" in out.out
    assert "sk-test-123" not in out.out + out.err


@pytest.mark.parametrize(
    "cfg,existing",
    [
        ({"enabled": False, "env": {"TOKEN": "hv:vault_testopenai"}}, False),
        ({"enabled": True, "env": {"TOKEN": "hv:missing"}}, False),
        ({"enabled": True, "env": {"TOKEN": "hv:vault_testopenai"}}, True),
        ({"enabled": True, "env": {"HERMES_VAULT_KEY": "hv:vault_testopenai"}}, False),
    ],
)
def test_doctor_reports_unusable_or_shadowed_mappings(
    plugin_cli, vault_home, monkeypatch, capsys, cfg, existing
):
    monkeypatch.setattr(plugin_cli, "get_hermes_home", lambda: vault_home)
    monkeypatch.setattr(plugin_cli, "_secrets_cfg", lambda: cfg)
    if existing:
        monkeypatch.setenv("TOKEN", "existing-secret")
    assert plugin_cli.hvault_command(SimpleNamespace(hvault_command="doctor")) == 1
    out = capsys.readouterr()
    assert "sk-test-123" not in out.out + out.err
    assert "existing-secret" not in out.out + out.err


def test_doctor_missing_store_does_not_create_it(plugin_cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(plugin_cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(
        plugin_cli, "_secrets_cfg", lambda: {"enabled": True, "env": {"TOKEN": "hv:x"}}
    )
    assert plugin_cli.hvault_command(SimpleNamespace(hvault_command="doctor")) == 1
    assert not (tmp_path / "agent-vault").exists()
    assert "does not exist" in capsys.readouterr().err


@pytest.mark.parametrize(
    "command,attrs",
    [
        ("env", {"item_id": "valid", "env_name": "BAD-NAME", "field": None}),
        ("env", {"item_id": "bad\nitem", "env_name": "TOKEN", "field": None}),
        ("show", {"ref": "hv:bad id", "reveal": False}),
        ("add", {"label": "x", "fields": ["value=x"], "stdin": False, "item_id": "bad id"}),
        ("put", {"item_id": "bad id", "field": "value"}),
        ("rm", {"item_id": "bad id"}),
    ],
)
def test_cli_rejects_invalid_identifiers_before_opening_store(
    plugin_cli, monkeypatch, capsys, command, attrs
):
    calls = []
    monkeypatch.setattr(plugin_cli, "_store", lambda: calls.append("opened"))
    assert plugin_cli.hvault_command(SimpleNamespace(hvault_command=command, **attrs)) == 2
    assert not calls


def test_env_output_round_trips_yaml_special_fields(plugin_cli, capsys):
    import yaml

    field = 'token"\\suffix'
    assert plugin_cli._cmd_env(SimpleNamespace(item_id="item", env_name="TOKEN", field=field)) == 0
    assert (
        yaml.safe_load(capsys.readouterr().out)["secrets"]["hermesvault"]["env"]["TOKEN"]
        == f"hv:item:{field}"
    )


def test_cli_errors_never_echo_secret_input(plugin_cli, capsys, monkeypatch):
    secret = "unique-sensitive-fixture"
    args = SimpleNamespace(
        hvault_command="add", label="x", fields=[secret], stdin=False, item_id=None
    )
    assert plugin_cli.hvault_command(args) == 2
    assert secret not in str(capsys.readouterr())

    def fail():
        raise RuntimeError(secret)

    monkeypatch.setattr(plugin_cli, "_store", fail)
    assert plugin_cli.hvault_command(SimpleNamespace(hvault_command="list")) == 1
    assert secret not in str(capsys.readouterr())


def test_config_load_errors_do_not_fall_back_to_default_store(plugin_cli, monkeypatch):
    import types

    module = types.ModuleType("hermes_cli.config")

    def fail():
        raise RuntimeError("private config payload")

    module.load_config = fail
    monkeypatch.setitem(sys.modules, "hermes_cli.config", module)
    with pytest.raises(ValueError, match="configuration"):
        plugin_cli._secrets_cfg()


def test_source_open_error_redacts_exception(monkeypatch, tmp_path):
    import source

    def fail(*args):
        raise RuntimeError("private-key-payload")

    monkeypatch.setattr(source, "_open_store", fail)
    result = fetch(tmp_path, {"env": {"TOKEN": "hv:x"}})
    assert not result.ok
    assert "private-key-payload" not in result.error


@pytest.mark.parametrize(
    "cfg", [{"dir": 123}, {"token_env": ["KEY"]}, {"override_existing": "false"}]
)
def test_source_rejects_malformed_settings(vault_home, cfg):
    result = fetch(vault_home, {"env": {"TOKEN": "hv:vault_testopenai"}, **cfg})
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED


def test_cli_rejects_bad_yaml_even_when_host_returns_defaults(plugin_cli, tmp_path, monkeypatch):
    import types

    config = tmp_path / "config.yaml"
    config.write_text("secrets: [broken\n", encoding="utf-8")
    module = types.ModuleType("hermes_cli.config")
    module.get_config_path = lambda: config
    module.load_config = lambda: {}
    monkeypatch.setitem(sys.modules, "hermes_cli.config", module)
    with pytest.raises(ValueError, match="configuration"):
        plugin_cli._secrets_cfg()


def test_cli_rejects_host_fallback_config(plugin_cli, tmp_path, monkeypatch):
    import types

    config = tmp_path / "config.yaml"
    config.write_text("agent: broken\nmax_turns: 4\n", encoding="utf-8")

    class Fallback(dict):
        read_error = ValueError("private config value")

    module = types.ModuleType("hermes_cli.config")
    module.get_config_path = lambda: config
    module.load_config = lambda: Fallback()
    monkeypatch.setitem(sys.modules, "hermes_cli.config", module)
    with pytest.raises(ValueError, match="configuration"):
        plugin_cli._secrets_cfg()


# --- review of pin 6fc8132e: scope, prompts, creation, error text ---------------


def test_an_empty_fetch_scope_does_not_unlock_with_the_ambient_key(vault_home):
    """Under multiplex the process environment is another profile's: ignore it."""
    from agent.secret_sources.base import reset_source_environment, set_source_environment

    token = set_source_environment({})  # this profile's scope: no key at all
    try:
        result = fetch(vault_home, {"env": {"OPENAI_API_KEY": "hv:vault_testopenai"}})
    finally:
        reset_source_environment(token)
    # os.environ holds FLOOR_VAULT_KEY and HERMES_VAULT_KEY (the fixture); neither unlocks.
    assert not result.ok and result.secrets == {}
    assert result.error_kind == ErrorKind.AUTH_FAILED


def test_the_scoped_token_env_key_is_used(vault_home, monkeypatch):
    from agent.secret_sources.base import reset_source_environment, set_source_environment

    monkeypatch.delenv("HERMES_VAULT_KEY")
    monkeypatch.delenv("FLOOR_VAULT_KEY")
    token = set_source_environment({"HERMES_VAULT_KEY": KEY})
    try:
        result = fetch(vault_home, {"env": {"OPENAI_API_KEY": "hv:vault_testopenai"}})
    finally:
        reset_source_environment(token)
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk-test-123"}


def test_fetch_resolves_os_custody_read_only_and_without_prompts(vault_home, monkeypatch):
    """No token_env key: the OS tier is asked without prompts, creation or env tier."""
    import floorvault.providers.adaptive as adaptive

    monkeypatch.delenv("HERMES_VAULT_KEY")
    seen = {}

    class Spy(adaptive.AdaptiveKeyProvider):
        def __init__(self, *args, **kwargs):
            seen["init"] = kwargs
            super().__init__(*args, **kwargs)

        def resolve_key(self, *, allow_create=True):
            seen["allow_create"] = allow_create
            return super().resolve_key(allow_create=allow_create)

    monkeypatch.setattr(adaptive, "AdaptiveKeyProvider", Spy)
    result = fetch(vault_home, {"env": {"OPENAI_API_KEY": "hv:vault_testopenai"}})
    assert seen["init"]["interactive"] is False and seen["init"]["environ"] == {}
    assert seen["init"]["service_name"] == "floor-vault"
    assert seen["allow_create"] is False
    # FLOOR_VAULT_KEY is still in os.environ, yet it is not what opened the store.
    assert not result.ok and result.secrets == {}


def test_fetch_creates_nothing_when_the_store_is_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    result = fetch(tmp_path, {"env": {"A": "hv:vault_a"}})
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED
    assert "hermes hvault setup" in result.error
    assert not (tmp_path / "agent-vault").exists()


def test_setup_creates_the_store_that_fetch_then_reads(tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as hermesvault_cli

    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setattr(hermesvault_cli, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(hermesvault_cli, "_secrets_cfg", lambda: {})
    assert hermesvault_cli.hvault_command(SimpleNamespace(hvault_command="setup")) == 0
    assert f"store ready at {tmp_path / 'agent-vault'}" in capsys.readouterr().out
    assert (tmp_path / "agent-vault" / "vault.db").is_file()
    assert fetch(tmp_path, {"env": {"A": "hv:vault_a"}}).ok


def test_add_on_a_missing_store_points_to_setup(tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as hermesvault_cli

    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setattr(hermesvault_cli, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(hermesvault_cli, "_secrets_cfg", lambda: {})
    args = SimpleNamespace(hvault_command="add", label="x", fields=["value=v"], stdin=False,
                           item_id=None)  # fmt: skip
    assert hermesvault_cli.hvault_command(args) == 1
    assert "hermes hvault setup" in capsys.readouterr().err
    assert not (tmp_path / "agent-vault").exists()


@pytest.mark.parametrize(
    "fields, stdin, where",
    [
        (["sk-live-SECRET-no-equals"], "", "argument 1"),
        (["value=ok", "=sk-live-SECRET"], "", "argument 2"),
        ([], "# comment\nvalue=ok\nsk-live-SECRET-no-equals\n", "stdin line 3"),
    ],
)
def test_malformed_field_lines_are_reported_without_their_text(
    monkeypatch, capsys, fields, stdin, where
):
    import io

    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as hermesvault_cli

    def no_store(**_kw):
        raise AssertionError("a malformed line must stop the command before the store opens")

    monkeypatch.setattr(hermesvault_cli, "_store", no_store)
    monkeypatch.setattr(hermesvault_cli.sys, "stdin", io.StringIO(stdin))
    args = SimpleNamespace(hvault_command="add", label="x", fields=fields, stdin=bool(stdin),
                           item_id=None)  # fmt: skip
    assert hermesvault_cli.hvault_command(args) == 2
    captured = capsys.readouterr()
    assert f"{where} is not in field=value form" in captured.err
    assert "SECRET" not in captured.out + captured.err


def test_an_older_floorvault_fails_closed_with_a_clear_message(vault_home, monkeypatch):
    import floorvault.providers.adaptive as adaptive

    monkeypatch.delenv("HERMES_VAULT_KEY")

    class Old:
        def __init__(self, service_name="floorvault", account_name="default-v1", *,
                     fallback_dir=None):  # fmt: skip
            raise AssertionError("must not be reached with the old signature")

    monkeypatch.setattr(adaptive, "AdaptiveKeyProvider", Old)
    result = fetch(vault_home, {"env": {"A": "hv:vault_testopenai"}})
    assert not result.ok and "upgrade the floorvault package" in result.error


# ------------------------------------------------- custody: key_file, systemd-creds

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="systemd-creds is Linux only")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
OTHER_KEY = "11" * 32


def _store_under(directory: Path, key_hex: str):
    from floorvault.vaultkit import VaultStore

    store = VaultStore(
        directory,
        crypto=floorvault.FloorVault(bytes.fromhex(key_hex), app_instance_id="floor-agent"),
    )
    store.add_item(kind="generic", label="k", secret={"value": "sk-file"}, item_id="vault_k")
    return store


@pytest.fixture()
def file_home(tmp_path, monkeypatch):
    """A profile whose store is keyed by a 0600 key file, with no key variable set."""
    for name in ("HERMES_VAULT_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    key_file = tmp_path / "secrets" / "vault.key"
    key_file.parent.mkdir()
    key_file.write_text(OTHER_KEY + "\n")
    key_file.chmod(0o600)
    _store_under(tmp_path / "agent-vault", OTHER_KEY)
    return tmp_path


def test_custody_key_file_opens_the_store_from_the_configured_file(file_home):
    cfg = {"env": {"A": "hv:vault_k"}, "custody": "key_file", "key_file": "secrets/vault.key"}
    result = fetch(file_home, cfg)
    assert result.ok and result.secrets == {"A": "sk-file"} and result.warnings == []


def test_custody_key_file_ignores_floor_vault_key_file(file_home, monkeypatch):
    """The process-wide $FLOOR_VAULT_KEY_FILE never names the plugin's key."""
    monkeypatch.setenv("FLOOR_VAULT_KEY_FILE", str(file_home / "secrets" / "vault.key"))
    result = fetch(file_home, {"env": {"A": "hv:vault_k"}})  # custody: os (default)
    assert not result.ok and result.secrets == {}


@posix_only
def test_custody_key_file_refuses_a_replaceable_file(file_home):
    (file_home / "secrets" / "vault.key").chmod(0o620)
    cfg = {"env": {"A": "hv:vault_k"}, "custody": "key_file", "key_file": "secrets/vault.key"}
    result = fetch(file_home, cfg)
    assert not result.ok and result.error_kind == ErrorKind.AUTH_FAILED
    assert "writable by group or others" in result.error and OTHER_KEY not in result.error


@posix_only
def test_custody_key_file_readable_by_others_is_used_with_a_warning(file_home):
    (file_home / "secrets" / "vault.key").chmod(0o644)
    cfg = {"env": {"A": "hv:vault_k"}, "custody": "key_file", "key_file": "secrets/vault.key"}
    result = fetch(file_home, cfg)
    assert result.ok and result.secrets == {"A": "sk-file"}
    assert any("readable by other users" in warning for warning in result.warnings)


def test_custody_key_file_does_not_fall_back_when_the_file_is_missing(file_home, monkeypatch):
    import floorvault.providers.adaptive as adaptive

    def no_os_tier(*args, **kwargs):
        raise AssertionError("a configured key file must not fall back to OS custody")

    monkeypatch.setattr(adaptive, "AdaptiveKeyProvider", no_os_tier)
    cfg = {"env": {"A": "hv:vault_k"}, "custody": "key_file", "key_file": "secrets/missing.key"}
    result = fetch(file_home, cfg)
    assert not result.ok and result.error_kind == ErrorKind.AUTH_FAILED
    assert "cannot read" in result.error


def test_the_scoped_token_env_key_wins_over_the_configured_custody(file_home):
    from agent.secret_sources.base import reset_source_environment, set_source_environment

    _store_under(file_home / "other-vault", KEY)
    token = set_source_environment({"HERMES_VAULT_KEY": KEY})
    try:
        cfg = {"env": {"A": "hv:vault_k"}, "dir": "other-vault", "custody": "key_file",
               "key_file": "secrets/vault.key"}  # fmt: skip
        result = fetch(file_home, cfg)
    finally:
        reset_source_environment(token)
    assert result.ok and result.secrets == {"A": "sk-file"}


@pytest.mark.parametrize(
    "cfg, message",
    [
        ({"custody": "vault"}, "custody must be one of"),
        ({"custody": "key_file"}, "needs a key_file path"),
        ({"custody": "key_file", "key_file": "  "}, "needs a key_file path"),
        ({"key_file": "secrets/vault.key"}, "only with custody: key_file"),
        ({"custody": "systemd-creds", "key_file": "x"}, "only with custody: key_file"),
    ],
)
def test_custody_settings_are_validated(file_home, cfg, message):
    result = fetch(file_home, {"env": {"A": "hv:vault_k"}, **cfg})
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED
    assert message in result.error


def test_custody_without_floorvault_support_names_the_version(file_home, monkeypatch):
    monkeypatch.setitem(sys.modules, "floorvault.key_file", None)  # an import of it fails
    cfg = {"env": {"A": "hv:vault_k"}, "custody": "key_file", "key_file": "secrets/vault.key"}
    result = fetch(file_home, cfg)
    assert not result.ok and "floorvault 0.2.8 or newer" in result.error


@pytest.fixture()
def sdc_fake(tmp_path, monkeypatch):
    from test_systemd_creds import Fake

    import floorvault.systemd_creds as sdc

    fake = Fake(tmp_path / "sdbin")
    monkeypatch.setattr(sdc, "SEARCH_DIRS", (str(fake.dir),))
    for name in ("HERMES_VAULT_KEY", "FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    return fake


def _hvault(monkeypatch, home, cfg, command, **extra):
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as hermesvault_cli

    monkeypatch.setattr(hermesvault_cli, "get_hermes_home", lambda: str(home))
    monkeypatch.setattr(hermesvault_cli, "_secrets_cfg", lambda: cfg)
    return hermesvault_cli.hvault_command(SimpleNamespace(hvault_command=command, **extra))


@linux_only
def test_setup_seals_the_key_and_fetch_unseals_it_without_creating(
    sdc_fake, tmp_path, monkeypatch, capsys
):
    cfg = {"enabled": True, "custody": "systemd-creds", "env": {"A": "hv:vault_a"}}
    result = fetch(tmp_path, cfg)
    assert not result.ok and "hermes hvault setup" in result.error
    assert not (tmp_path / "agent-vault").exists() and sdc_fake.calls == []

    assert _hvault(monkeypatch, tmp_path, cfg, "setup") == 0
    out = capsys.readouterr()
    assert "key: custody systemd-creds" in out.out and "Not checked" in out.err
    credential = tmp_path / "agent-vault" / "master.key.sdcred"
    assert credential.is_file() and (tmp_path / "agent-vault" / "vault.db").is_file()
    assert _hvault(monkeypatch, tmp_path, cfg, "add", label="a", fields=["value=v-1"],
                   stdin=False, item_id="vault_a") == 0  # fmt: skip

    before = len(sdc_fake.calls)
    result = fetch(tmp_path, cfg)
    assert result.ok and result.secrets == {"A": "v-1"}
    assert [call[0] for call in sdc_fake.calls[before:]] == ["--version", "decrypt"]


@linux_only
def test_fetch_never_creates_a_credential_for_an_existing_store(sdc_fake, vault_home, monkeypatch):
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    cfg = {"custody": "systemd-creds", "env": {"A": "hv:vault_testopenai"}}
    result = fetch(vault_home, cfg)
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED
    assert not (vault_home / "agent-vault" / "master.key.sdcred").exists()
    assert sdc_fake.calls == []


@linux_only
def test_setup_does_not_seal_a_new_key_beside_an_existing_store(
    sdc_fake, vault_home, monkeypatch, capsys
):
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    cfg = {"custody": "systemd-creds"}
    assert _hvault(monkeypatch, vault_home, cfg, "setup") == 1
    assert "setup seals the key of a new store only" in capsys.readouterr().err
    assert not (vault_home / "agent-vault" / "master.key.sdcred").exists()
    assert sdc_fake.calls == []


@linux_only
def test_an_unusable_credential_fails_closed(sdc_fake, tmp_path, monkeypatch):
    cfg = {"custody": "systemd-creds", "env": {"A": "hv:vault_a"}}
    assert _hvault(monkeypatch, tmp_path, cfg, "setup") == 0
    sdc_fake.configure(mode="decrypt-fails")
    result = fetch(tmp_path, cfg)
    assert not result.ok and result.error_kind == ErrorKind.AUTH_FAILED


@linux_only
def test_os_custody_on_a_sealed_store_names_the_custody_setting(sdc_fake, tmp_path, monkeypatch):
    cfg = {"custody": "systemd-creds", "env": {"A": "hv:vault_a"}}
    assert _hvault(monkeypatch, tmp_path, cfg, "setup") == 0
    result = fetch(tmp_path, {"env": {"A": "hv:vault_a"}})
    assert not result.ok and result.error_kind == ErrorKind.AUTH_FAILED
    assert "custody: systemd-creds" in result.error


# ------------------------------------------------------------ command bindings
#
# `floorvault secrets allow` binds an item to command lines. Inside Hermes the
# command is Hermes itself, so the plugin compares what Hermes was started with
# to the item's bindings. The environment variable below is the plugin's own
# store key; the store lives in the `vault_home` fixture.

HERMES = os.path.abspath("/opt/hermes/bin/hermes")


def _as_started(monkeypatch, argv, orig_argv=None, executable="/usr/bin/python3"):
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(sys, "orig_argv", orig_argv or [executable, *argv], raising=False)
    monkeypatch.setattr(sys, "executable", executable)


def _bind(home, item_id, *lines):
    store = floorvault.get_vault_store(home / "agent-vault", auto_migrate=False)
    assert store.set_allowed_commands(item_id, [list(line) for line in lines])


def _clear_binding_in_the_db(home, item_id):
    import contextlib
    import sqlite3

    with contextlib.closing(sqlite3.connect(home / "agent-vault" / "vault.db")) as db:
        db.execute("UPDATE vault_items SET allowed_commands = NULL WHERE id = ?", (item_id,))
        db.commit()


ENV = {"OPENAI_API_KEY": "hv:vault_testopenai", "ALSO": "hv:vault_multi:token"}


def test_a_bound_item_is_resolved_for_the_command_hermes_was_started_with(vault_home, monkeypatch):
    _as_started(monkeypatch, [HERMES, "gateway", "run"])
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    result = fetch(vault_home, {"env": ENV})
    assert result.ok
    assert result.secrets == {"OPENAI_API_KEY": "sk-test-123", "ALSO": "tok-abc"}
    assert result.warnings == []


def test_a_bound_item_is_not_resolved_for_another_command(vault_home, monkeypatch):
    _as_started(monkeypatch, [HERMES, "chat"])
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    result = fetch(vault_home, {"env": ENV})
    # Only the bound item is skipped; the unbound one still resolves.
    assert result.secrets == {"ALSO": "tok-abc"}
    (warning,) = result.warnings
    assert warning.startswith("Skipped OPENAI_API_KEY: vault item vault_testopenai is bound to ")
    assert shlex.join([HERMES, "chat"]) in warning and "floorvault secrets allow" in warning
    assert "sk-test-123" not in warning


def test_arguments_must_match_exactly(vault_home, monkeypatch):
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    for argv in ([HERMES], [HERMES, "gateway"], [HERMES, "gateway", "run", "--debug"]):
        _as_started(monkeypatch, argv)
        assert "OPENAI_API_KEY" not in fetch(vault_home, {"env": ENV}).secrets, argv


def test_the_interpreter_command_line_can_be_what_was_bound(vault_home, monkeypatch):
    python = os.path.abspath("/opt/hermes/venv/bin/python")
    original = [python, "-m", "hermes_cli", "gateway", "run"]
    _as_started(
        monkeypatch,
        ["/opt/hermes/lib/hermes_cli/__main__.py", "gateway", "run"],
        orig_argv=original,
        executable=python,
    )
    _bind(vault_home, "vault_testopenai", original)
    assert fetch(vault_home, {"env": ENV}).secrets["OPENAI_API_KEY"] == "sk-test-123"
    # Binding the module path instead of the interpreter line also works.
    _bind(
        vault_home, "vault_testopenai", ["/opt/hermes/lib/hermes_cli/__main__.py", "gateway", "run"]
    )
    assert fetch(vault_home, {"env": ENV}).secrets["OPENAI_API_KEY"] == "sk-test-123"


def test_an_item_bound_to_several_lines_resolves_for_any_of_them(vault_home, monkeypatch):
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"], [HERMES, "chat"])
    for argv in ([HERMES, "gateway", "run"], [HERMES, "chat"]):
        _as_started(monkeypatch, argv)
        assert "OPENAI_API_KEY" in fetch(vault_home, {"env": ENV}).secrets
    _as_started(monkeypatch, [HERMES, "doctor"])
    assert "OPENAI_API_KEY" not in fetch(vault_home, {"env": ENV}).secrets


def test_unbound_items_resolve_unless_a_binding_is_required(vault_home, monkeypatch):
    _as_started(monkeypatch, [HERMES, "chat"])
    assert fetch(vault_home, {"env": ENV}).secrets == {
        "OPENAI_API_KEY": "sk-test-123",
        "ALSO": "tok-abc",
    }
    result = fetch(vault_home, {"env": ENV, "require_binding": True})
    assert result.secrets == {}
    assert len(result.warnings) == 2
    assert all("require_binding" in w and "floorvault secrets allow" in w for w in result.warnings)
    _bind(vault_home, "vault_testopenai", [HERMES, "chat"])
    assert fetch(vault_home, {"env": ENV, "require_binding": True}).secrets == {
        "OPENAI_API_KEY": "sk-test-123"
    }


def test_a_binding_cleared_in_vault_db_blocks_the_item_only_when_required(vault_home, monkeypatch):
    _as_started(monkeypatch, [HERMES, "chat"])
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    assert "OPENAI_API_KEY" not in fetch(vault_home, {"env": ENV}).secrets
    # Someone who can write vault.db clears the binding without the key (#97).
    _clear_binding_in_the_db(vault_home, "vault_testopenai")
    # Documented limit: unbound again, so it resolves ...
    assert "OPENAI_API_KEY" in fetch(vault_home, {"env": ENV}).secrets
    # ... unless Hermes' own configuration requires a binding.
    assert "OPENAI_API_KEY" not in fetch(vault_home, {"env": ENV, "require_binding": True}).secrets


def test_a_binding_that_cannot_be_read_blocks_the_item(vault_home, monkeypatch):
    import contextlib
    import sqlite3

    _as_started(monkeypatch, [HERMES, "chat"])
    _bind(vault_home, "vault_testopenai", [HERMES, "chat"])
    with contextlib.closing(sqlite3.connect(vault_home / "agent-vault" / "vault.db")) as db:
        db.execute(
            "UPDATE vault_items SET allowed_commands = ? WHERE id = 'vault_testopenai'",
            (b"not a sealed value",),
        )
        db.commit()
    result = fetch(vault_home, {"env": ENV})
    assert "OPENAI_API_KEY" not in result.secrets and result.secrets["ALSO"] == "tok-abc"
    assert any("command binding that cannot be read" in w for w in result.warnings)


def test_a_binding_moved_from_another_item_does_not_authenticate(vault_home, monkeypatch):
    import contextlib
    import sqlite3

    _as_started(monkeypatch, [HERMES, "chat"])
    _bind(vault_home, "vault_multi", [HERMES, "chat"])
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    with contextlib.closing(sqlite3.connect(vault_home / "agent-vault" / "vault.db")) as db:
        (donor,) = db.execute(
            "SELECT allowed_commands FROM vault_items WHERE id = 'vault_multi'"
        ).fetchone()
        db.execute(
            "UPDATE vault_items SET allowed_commands = ? WHERE id = 'vault_testopenai'", (donor,)
        )
        db.commit()
    # The sealed binding is tied to its item, so the copy fails authentication.
    result = fetch(vault_home, {"env": ENV})
    assert "OPENAI_API_KEY" not in result.secrets
    assert any("cannot be read" in w for w in result.warnings)


def test_an_older_floorvault_cannot_check_bindings_and_says_so(vault_home, monkeypatch):
    from floorvault.vaultkit.vault import VaultStore

    _as_started(monkeypatch, [HERMES, "chat"])
    monkeypatch.delattr(VaultStore, "get_allowed_commands")
    result = fetch(vault_home, {"env": ENV})
    assert result.secrets["OPENAI_API_KEY"] == "sk-test-123"
    assert any("older than 0.2.8: command bindings are not enforced" in w for w in result.warnings)
    required = fetch(vault_home, {"env": ENV, "require_binding": True})
    assert required.secrets == {}
    assert all("older than 0.2.8" in w for w in required.warnings if w.startswith("Skipped"))


def test_without_a_command_line_a_bound_item_is_refused(vault_home, monkeypatch):
    _as_started(monkeypatch, [], orig_argv=[], executable="")
    _bind(vault_home, "vault_testopenai", [HERMES, "chat"])
    result = fetch(vault_home, {"env": ENV})
    assert "OPENAI_API_KEY" not in result.secrets
    assert any("an unknown command line" in w for w in result.warnings)


def test_require_binding_must_be_a_boolean(vault_home):
    for value in ("yes", 1, None):
        result = fetch(vault_home, {"env": ENV, "require_binding": value})
        assert not result.ok and "require_binding must be a boolean" in result.error


def test_hvault_show_prints_the_bindings(plugin_cli, vault_home, monkeypatch, capsys):
    monkeypatch.setattr(plugin_cli, "get_hermes_home", lambda: vault_home)
    monkeypatch.setattr(plugin_cli, "_secrets_cfg", lambda: {"enabled": True})
    show = SimpleNamespace(hvault_command="show", ref="vault_testopenai", reveal=False)
    assert plugin_cli.hvault_command(show) == 0
    assert "bindings: none; resolved for any command" in capsys.readouterr().out
    _bind(vault_home, "vault_testopenai", [HERMES, "gateway", "run"])
    assert plugin_cli.hvault_command(show) == 0
    out = capsys.readouterr().out
    assert "bindings: 1 command line(s); resolved only when Hermes was started as:" in out
    assert f"  {shlex.join([HERMES, 'gateway', 'run'])}" in out
    assert "sk-test-123" not in out

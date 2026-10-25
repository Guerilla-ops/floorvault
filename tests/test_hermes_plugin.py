"""hermesvault plugin tests — real store, real SecretSource contract.

The plugin modules are imported from ``plugins/hermesvault`` and the Hermes
``agent.secret_sources`` contract from a Hermes checkout (HERMES_AGENT_SRC,
default ~/hermes-agent). ``floorvault`` itself is resolved through the
installed/editable package or this repo's ``src`` via pytest pythonpath.
"""

from __future__ import annotations

import os
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


def test_bootstrap_key_is_protected():
    source = HermesVaultSource()
    assert source.protected_env_vars({}) == frozenset({"HERMES_VAULT_KEY"})
    assert source.protected_env_vars({"token_env": "MY_KEY"}) == frozenset({"MY_KEY"})


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
    store = _open_store({}, tmp_path)
    store.add_item(kind="generic", label="k", secret={"value": "sk-hermes"}, item_id="vault_i")

    base = {k: v for k, v in os.environ.items() if k not in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY")}
    base["PYTHONPATH"] = str(ROOT / "src")
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

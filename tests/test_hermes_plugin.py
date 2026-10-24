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

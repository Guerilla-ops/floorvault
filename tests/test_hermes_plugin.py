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

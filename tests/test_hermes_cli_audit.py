"""Regression tests for the `hermes hvault` CLI audit (docs/HVAULT-CLI-AUDIT-2026-11-11.md).

Each test names the finding it pins (HV-n). Like tests/test_hermes_plugin.py
these need a Hermes checkout (HERMES_AGENT_SRC, default ~/hermes-agent) and
skip without one. Every store and key is a throwaway under tmp_path.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins" / "hermesvault"))
sys.path.insert(0, os.environ.get("HERMES_AGENT_SRC", str(Path.home() / "hermes-agent")))

pytest.importorskip("floorvault")
pytest.importorskip("agent.secret_sources.base")

from source import HermesVaultSource  # noqa: E402

import floorvault  # noqa: E402

KEY = "00" * 32
SECRET = "sk-fixture-SECRET"


@pytest.fixture()
def cli(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "plugins"))
    from hermesvault import cli as plugin_cli

    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setenv("FLOOR_VAULT_KEY", KEY)  # get_vault_store, as in test_hermes_plugin
    monkeypatch.setenv("FLOOR_VAULT_STATE_DIR", str(tmp_path / "state"))
    store = floorvault.get_vault_store(tmp_path / "agent-vault", auto_migrate=False)
    store.add_item(kind="generic", label="k", secret={"value": SECRET}, item_id="existing")
    monkeypatch.setattr(plugin_cli, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(plugin_cli, "_secrets_cfg", lambda: {"enabled": True})
    monkeypatch.setattr(plugin_cli, "_write_mapping", lambda _n, _r: True)
    plugin_cli._real_cmd_doctor = plugin_cli.__dict__.get(
        "_real_cmd_doctor", plugin_cli._cmd_doctor
    )
    monkeypatch.setattr(plugin_cli, "_cmd_doctor", lambda _a: 0)
    return plugin_cli


def _store(tmp_path):
    return floorvault.get_vault_store(tmp_path / "agent-vault", auto_migrate=False)


class _Pipe(io.StringIO):
    def isatty(self):
        return False


class _Terminal(io.StringIO):
    def isatty(self):
        return True


def _bind(cli, monkeypatch, name, data):
    monkeypatch.setattr(sys, "stdin", _Pipe(data))
    args = SimpleNamespace(
        hvault_command="bind",
        env_name=name,
        item_id=None,
        field="value",
        label=None,
        print_only=True,
        stdin=True,
        no_bind=True,
    )
    return cli.hvault_command(args)


def _put(cli, monkeypatch, value, field="value", item_id="existing"):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: value)
    return cli.hvault_command(SimpleNamespace(hvault_command="put", item_id=item_id, field=field))


def _add(cli, *, fields=(), stdin=False, item_id=None):
    return cli.hvault_command(
        SimpleNamespace(
            hvault_command="add", label="L", fields=list(fields), stdin=stdin, item_id=item_id
        )
    )


def test_hv_1_bind_stdin_drops_a_crlf_line_ending(cli, tmp_path, monkeypatch):
    assert _bind(cli, monkeypatch, "CRLF_KEY", "sk-crlf\r\n") == 0
    assert _store(tmp_path).resolve_secret("crlf_key") == {"value": "sk-crlf"}


@pytest.mark.parametrize("command", ["bind", "put", "add"])
def test_hv_2_a_nul_byte_is_refused_at_write_time(cli, tmp_path, monkeypatch, capsys, command):
    value = "sk-a\x00b"
    if command == "bind":
        code = _bind(cli, monkeypatch, "NUL_KEY", value + "\n")
    elif command == "put":
        code = _put(cli, monkeypatch, value)
    else:
        code = _add(cli, fields=[f"value={value}"], item_id="nul_key")
    assert code == 2
    err = capsys.readouterr().err
    assert "NUL byte" in err and "sk-a" not in err
    store = _store(tmp_path)
    assert store.get_meta("nul_key") is None
    assert store.resolve_secret("existing") == {"value": SECRET}


def test_hv_2_fetch_skips_a_stored_nul_value_instead_of_breaking_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    monkeypatch.setenv("FLOOR_VAULT_KEY", KEY)
    store = _store(tmp_path)
    store.add_item(kind="generic", label="n", secret={"value": "a\x00b"}, item_id="nul")
    store.add_item(kind="generic", label="ok", secret={"value": "fine"}, item_id="ok")
    cfg = {"enabled": True, "env": {"BAD": "hv:nul", "GOOD": "hv:ok"}}
    result = HermesVaultSource().fetch(cfg, tmp_path)
    assert result.ok and result.secrets == {"GOOD": "fine"}
    assert any("BAD" in w and "NUL byte" in w for w in result.warnings)
    # What Hermes does with every resolved value; the skipped one would raise here.
    staged = {}
    for name, value in result.secrets.items():
        os.environ[f"HV_AUDIT_{name}"] = value
        staged[name] = value
    assert staged == {"GOOD": "fine"}


def test_hv_3_add_refuses_a_blank_value(cli, tmp_path, capsys):
    assert _add(cli, fields=["value=   "], item_id="blank") == 2
    assert "argument 1: empty value" in capsys.readouterr().err
    assert _store(tmp_path).get_meta("blank") is None


def test_hv_4_add_with_an_existing_id_says_so(cli, tmp_path, capsys):
    assert _add(cli, fields=["value=other"], item_id="existing") == 1
    assert "item existing already exists" in capsys.readouterr().err
    assert _store(tmp_path).resolve_secret("existing") == {"value": SECRET}


@pytest.mark.parametrize("command", ["show", "put"])
def test_hv_5_an_unreadable_store_is_not_reported_as_a_missing_item(
    cli, monkeypatch, capsys, command
):
    monkeypatch.setenv("HERMES_VAULT_KEY", "11" * 32)  # not the store's key
    if command == "show":
        code = cli.hvault_command(
            SimpleNamespace(hvault_command="show", ref="existing", reveal=False)
        )
    else:
        code = _put(cli, monkeypatch, "new")
    assert code != 0
    err = capsys.readouterr().err
    assert "not found" not in err and "key custody" in err


def test_hv_5_a_missing_item_is_still_not_found(cli, monkeypatch, capsys):
    assert _put(cli, monkeypatch, "v", item_id="nope") == 1
    assert "item nope not found" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["a\x9b2Jb", "a b", "a b", "a\x85b"])
def test_hv_6_field_names_with_c1_controls_or_line_separators_are_refused(
    cli, monkeypatch, capsys, field
):
    assert _put(cli, monkeypatch, "v", field=field) == 2
    out = capsys.readouterr()
    assert field not in out.out + out.err


def test_hv_7_rm_warns_about_mappings_left_on_the_removed_item(cli, monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_secrets_cfg",
        lambda: {
            "enabled": True,
            "env": {"A": "hv:existing", "B": "hv:existing:value", "C": "hv:x"},
        },
    )
    assert cli.hvault_command(SimpleNamespace(hvault_command="rm", item_id="existing")) == 0
    err = capsys.readouterr().err
    assert "2 variable(s)" in err and "still map to existing" in err


def test_hv_7_rm_is_quiet_when_nothing_maps_to_the_item(cli, capsys):
    assert cli.hvault_command(SimpleNamespace(hvault_command="rm", item_id="existing")) == 0
    assert "still map" not in capsys.readouterr().err


def test_hv_8_add_stdin_refuses_a_terminal(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Terminal("value=typed\n"))
    assert _add(cli, stdin=True, item_id="tty") == 2
    assert "pipe or file" in capsys.readouterr().err
    assert _store(tmp_path).get_meta("tty") is None


def test_hv_9_add_stdin_keeps_values_as_written(cli, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Pipe("# comment\n\n  user = u1\r\npass=  two words  \n"))
    assert _add(cli, stdin=True, item_id="ws") == 0
    assert _store(tmp_path).resolve_secret("ws") == {"user": " u1", "pass": "  two words  "}


def test_hv_10_put_on_a_blank_value_says_so(cli, tmp_path, monkeypatch, capsys):
    assert _put(cli, monkeypatch, "   ") == 2
    err = capsys.readouterr().err
    assert "empty value" in err and "custody" not in err
    assert _store(tmp_path).resolve_secret("existing") == {"value": SECRET}


def _cfg(cli, monkeypatch, cfg):
    monkeypatch.setattr(cli, "_secrets_cfg", lambda: cfg)


def _allow(cli, command=(), **flags):
    return cli.hvault_command(
        SimpleNamespace(
            hvault_command="allow",
            item_id=flags.pop("item_id", "existing"),
            command_line=list(command),
            clear=False,
            remove=flags.pop("remove", False),
            accept=False,
        )
    )


def test_hv_12_bind_then_doctor_passes_for_a_gateway_bound_item(cli, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", _Pipe("sk-new\n"))
    args = SimpleNamespace(
        hvault_command="bind",
        env_name="OPENAI_API_KEY",
        item_id=None,
        field="value",
        label=None,
        print_only=False,
        stdin=True,
        no_bind=False,
    )
    _cfg(cli, monkeypatch, {"enabled": True, "env": {"OPENAI_API_KEY": "hv:openai_api_key"}})
    monkeypatch.setattr(cli, "_cmd_doctor", cli._real_cmd_doctor)
    assert cli.hvault_command(args) == 0
    out = capsys.readouterr()
    assert "resolved 1/1" in out.out
    assert "mapping #1: bound to 1 command line(s); Hermes resolves it only" in out.out
    assert "bound to other command lines" not in out.err
    assert "sk-new" not in out.out + out.err


def test_hv_12_doctor_still_refuses_a_binding_changed_behind_its_back(
    cli, tmp_path, monkeypatch, capsys
):
    assert _allow(cli, [sys.executable, "-m", "x"]) == 0
    _store(tmp_path).set_allowed_commands("existing", None)  # cleared in vault.db
    _cfg(cli, monkeypatch, {"enabled": True, "env": {"K": "hv:existing"}})
    capsys.readouterr()
    assert cli._real_cmd_doctor(None) == 1
    assert "changed since it was last recorded" in capsys.readouterr().err


def test_hv_13_a_non_string_env_key_is_skipped_not_a_crash(cli, tmp_path, monkeypatch, capsys):
    cfg = {"enabled": True, "env": {1: "hv:existing", "OK": "hv:existing"}}
    result = HermesVaultSource().fetch(cfg, tmp_path)
    assert result.ok and result.secrets == {"OK": SECRET}
    assert any("invalid env-var name 1" in w for w in result.warnings)
    _cfg(cli, monkeypatch, cfg)
    assert cli._real_cmd_doctor(None) == 1  # the skipped mapping is a warning
    assert "TypeError" not in capsys.readouterr().err


def test_hv_13_bare_hvault_errors_are_not_prefixed_none(cli, monkeypatch, capsys):
    def refuse():
        raise cli.CLIInputError("Hermes configuration must be a mapping")

    monkeypatch.setattr(cli, "_secrets_cfg", refuse)
    assert cli.hvault_command(SimpleNamespace(hvault_command=None)) == 2
    assert capsys.readouterr().err.startswith("hvault: ")


@pytest.mark.parametrize("name", ["FOO\n", "FOO\r", " FOO", "FO-O"])
def test_hv_14_env_names_are_checked_strictly(cli, tmp_path, monkeypatch, capsys, name):
    assert _bind(cli, monkeypatch, name, "v\n") == 2
    env_args = SimpleNamespace(hvault_command="env", item_id="existing", env_name=name, field=None)
    assert cli.hvault_command(env_args) == 2
    assert name not in capsys.readouterr().out
    result = HermesVaultSource().fetch({"enabled": True, "env": {name: "hv:existing"}}, tmp_path)
    assert result.secrets == {}


def test_hv_15_env_section_type_has_one_rule(cli, tmp_path, monkeypatch, capsys):
    from source import validate_config

    validate_config({"env": None})
    with pytest.raises(ValueError, match="env must be a map"):
        validate_config({"env": ["K"]})
    bad = HermesVaultSource().fetch({"enabled": True, "env": ["K"]}, tmp_path)
    assert not bad.ok
    _cfg(cli, monkeypatch, {"enabled": True, "env": None})
    assert cli._real_cmd_doctor(None) == 1
    assert "no mappings configured" in capsys.readouterr().err


def test_hv_16_an_empty_token_variable_is_not_reported_as_the_key(cli, monkeypatch):
    monkeypatch.setenv("HERMES_VAULT_KEY", "")
    assert cli._custody_line({}) == "key: custody os"


def test_hv_17_a_bad_key_is_a_runtime_failure_everywhere(cli, monkeypatch, capsys):
    monkeypatch.setenv("HERMES_VAULT_KEY", "zz" * 32)
    assert cli.hvault_command(SimpleNamespace(hvault_command="list")) == 1
    _cfg(cli, monkeypatch, {"enabled": True, "env": {"K": "hv:existing"}})
    assert cli.hvault_command(SimpleNamespace(hvault_command=None)) == 1
    assert "resolve failed" in capsys.readouterr().err


def test_hv_18_bound_lines_are_printed_escaped(cli, monkeypatch, capsys):
    line = f'["{sys.executable}", "\\u001b]0;PWNED\\u0007\\u001b[2J", "x"]'
    assert _allow(cli, [line]) == 0
    assert (
        cli.hvault_command(SimpleNamespace(hvault_command="show", ref="existing", reveal=False))
        == 0
    )
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\\x1b]0;PWNED" in out


def test_hv_19_remove_drops_the_line_of_a_program_that_is_gone(cli, tmp_path, monkeypatch):
    prog = tmp_path / "prog"
    prog.write_text("#!/bin/sh\n", encoding="utf-8")
    prog.chmod(0o755)
    assert _allow(cli, [str(prog), "serve"]) == 0
    assert _allow(cli, [sys.executable, "-m", "other"]) == 0
    prog.unlink()
    assert _allow(cli, [str(prog), "serve"], remove=True) == 0
    remaining = _store(tmp_path).get_allowed_commands("existing")
    assert remaining == [[os.path.abspath(sys.executable), "-m", "other"]]


@pytest.mark.skipif(shutil.which("[") is None, reason="no [ program on PATH")
def test_hv_20_the_test_program_can_be_bound(cli, tmp_path):
    # A lone "[" after -- was parsed as a JSON command line and refused.
    assert _allow(cli, ["["]) == 0
    bound = _store(tmp_path).get_allowed_commands("existing")
    assert bound == [[os.path.abspath(shutil.which("["))]]

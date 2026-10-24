"""floorvault.agentenv: reference grammar, env files, precedence, resolution."""

from __future__ import annotations

import pytest

from floorvault.agentenv import (
    AgentEnvError,
    SecretRef,
    collect,
    default_vault_dir,
    is_ref_like,
    parse_env_file,
    parse_ref,
    resolve,
    select_field,
)

SECRET = "sk-live-do-not-print-0123456789"


# ------------------------------------------------------------------ references


@pytest.mark.parametrize(
    "text, expected",
    [
        ("fv:openai", SecretRef("openai")),
        ("fv:vault_ab.c-1:token", SecretRef("vault_ab.c-1", "token")),
        ("hv:vault_abc", SecretRef("vault_abc")),
        ("hv:vault_abc:api key", SecretRef("vault_abc", "api key")),
        ("fv:a:b:c", SecretRef("a", "b:c")),
    ],
)
def test_valid_references_parse(text, expected):
    assert parse_ref(text) == expected


@pytest.mark.parametrize("text", ["plain", "op://vault/item", "x=fv:openai", " fv:openai", "", 42])
def test_non_references_are_plain_values(text):
    assert parse_ref(text) is None
    assert not is_ref_like(text)


@pytest.mark.parametrize(
    "text", ["fv:", "fv:bad id", "fv:" + "a" * 129, "fv:ok:", "fv:ok::x", "hv:a/b", "fv:a:b\nc"]
)
def test_malformed_references_are_errors_not_plaintext(text):
    with pytest.raises(AgentEnvError):
        parse_ref(text)


def test_reference_renders_canonically():
    assert str(SecretRef("a")) == "fv:a"
    assert str(SecretRef("a", "token")) == "fv:a:token"


# ----------------------------------------------------------------- field rules


def test_named_field_wins():
    assert select_field({"value": "v", "token": "t"}, "token") == "t"


def test_value_field_is_the_default():
    assert select_field({"value": "v", "other": "o"}, None) == "v"


def test_single_field_is_used_without_a_name():
    assert select_field({"token": "t"}, None) == "t"


@pytest.mark.parametrize(
    "secret, field",
    [
        ({"user": "u", "token": "t"}, None),  # ambiguous
        ({"value": "", "a": "1"}, None),  # empty value, still ambiguous
        ({}, None),
        ({"token": "t"}, "missing"),
        ({"token": ""}, "token"),
        ({"token": 7}, "token"),
        ({"token": "a\x00b"}, "token"),
    ],
)
def test_unusable_fields_fail(secret, field):
    with pytest.raises(AgentEnvError):
        select_field(secret, field)


# ------------------------------------------------------------------- env files


def test_env_file_grammar(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "# comment\n"
        "\n"
        "PLAIN=hello world\n"
        "export EXPORTED=fv:openai\n"
        "SINGLE='quoted # not a comment'\n"
        'DOUBLE="fv:multi:token"\n'
        "EMPTY=\n"
        "  SPACED  =  padded  \n",
        encoding="utf-8",
    )
    assert parse_env_file(path) == {
        "PLAIN": "hello world",
        "EXPORTED": "fv:openai",
        "SINGLE": "quoted # not a comment",
        "DOUBLE": "fv:multi:token",
        "EMPTY": "",
        "SPACED": "padded",
    }


@pytest.mark.parametrize(
    "line",
    [
        f"no equals {SECRET}",
        f"1BAD={SECRET}",
        f"BAD-NAME={SECRET}",
        f"OPEN='{SECRET}",
        f"MIXED='{SECRET}\"",
    ],
)
def test_malformed_env_file_line_names_the_line_not_the_value(tmp_path, line):
    path = tmp_path / ".env"
    path.write_text(f"OK=1\n{line}\n", encoding="utf-8")
    with pytest.raises(AgentEnvError) as info:
        parse_env_file(path)
    message = str(info.value)
    assert f"{path}:2" in message
    assert SECRET not in message


def test_duplicate_name_in_one_env_file_is_an_error(tmp_path):
    path = tmp_path / ".env"
    path.write_text(f"A=1\nA={SECRET}\n", encoding="utf-8")
    with pytest.raises(AgentEnvError) as info:
        parse_env_file(path)
    assert "A is set more than once" in str(info.value)
    assert SECRET not in str(info.value)


def test_unreadable_env_file_is_an_error(tmp_path):
    with pytest.raises(AgentEnvError):
        parse_env_file(tmp_path / "missing.env")
    (tmp_path / "binary.env").write_bytes(b"A=\xff\xfe\n")
    with pytest.raises(AgentEnvError):
        parse_env_file(tmp_path / "binary.env")


# ------------------------------------------------------------------ precedence


def test_precedence_inherited_then_files_then_explicit():
    inherited = {"A": "fv:inherited", "B": "fv:inherited", "C": "fv:inherited", "PATH": "/bin"}
    files = [{"B": "fv:file1", "C": "fv:file1"}, {"C": "fv:file2"}]
    env, refs = collect(inherited, files, ["A=fv:explicit"])
    assert refs == {
        "A": SecretRef("explicit"),
        "B": SecretRef("file1"),
        "C": SecretRef("file2"),
    }
    assert env == {"PATH": "/bin"}


def test_env_file_plain_value_overrides_an_inherited_reference():
    env, refs = collect({"A": "fv:x"}, [{"A": "literal"}])
    assert refs == {} and env == {"A": "literal"}


def test_no_inherit_refs_leaves_inherited_values_alone():
    env, refs = collect({"A": "fv:x"}, [{"B": "fv:y"}], inherit_refs=False)
    assert refs == {"B": SecretRef("y")}
    assert env == {"A": "fv:x"}


def test_explicit_pairs_must_be_references():
    with pytest.raises(AgentEnvError) as info:
        collect({}, [], [f"A={SECRET}", "=fv:x", "noequals"])
    assert len(info.value.problems) == 3
    assert SECRET not in str(info.value)


def test_malformed_inherited_reference_fails_closed():
    with pytest.raises(AgentEnvError) as info:
        collect({"TOKEN": "fv:bad id"})
    assert "TOKEN" in str(info.value)


@pytest.mark.parametrize("name", ["FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY", "MY_KEY"])
def test_references_may_not_target_custody_variables(name):
    with pytest.raises(AgentEnvError):
        collect({}, [], [f"{name}=fv:x"], key_env="MY_KEY")
    with pytest.raises(AgentEnvError):
        collect({}, [{name: "fv:x"}], key_env="MY_KEY")


def test_custody_variables_never_reach_the_child_environment():
    inherited = {"FLOOR_VAULT_KEY": "a" * 64, "VAULT_MASTER_KEY": "b" * 64, "MY_KEY": "c" * 64}
    env, _ = collect(inherited, [{"FLOOR_VAULT_KEY": "d" * 64, "OK": "1"}], key_env="MY_KEY")
    assert env == {"OK": "1"}


def test_shared_appstate_key_is_passed_through_for_other_tools():
    env, _ = collect({"APPSTATE_KEY": "other-tool"})
    assert env == {"APPSTATE_KEY": "other-tool"}


# ------------------------------------------------------------------ resolution


class _Store:
    def __init__(self, items):
        self.items = items
        self.calls = []

    def resolve_secret(self, item_id):
        self.calls.append(item_id)
        if item_id not in self.items:
            raise KeyError(f"no {item_id}")
        return self.items[item_id]


def test_resolve_fills_every_reference_and_decrypts_each_item_once():
    store = _Store({"multi": {"user": "u", "token": "t"}, "one": {"value": "v"}})
    refs = {
        "USER": SecretRef("multi", "user"),
        "TOKEN": SecretRef("multi", "token"),
        "ONE": SecretRef("one"),
    }
    assert resolve(store, refs) == {"USER": "u", "TOKEN": "t", "ONE": "v"}
    assert sorted(store.calls) == ["multi", "one"]


def test_resolve_reports_every_failure_and_no_value():
    store = _Store({"multi": {"user": SECRET, "token": SECRET}, "one": {"value": SECRET}})
    refs = {
        "A": SecretRef("missing"),
        "B": SecretRef("multi"),
        "C": SecretRef("one", "nope"),
        "D": SecretRef("one"),
    }
    with pytest.raises(AgentEnvError) as info:
        resolve(store, refs)
    problems = info.value.problems
    assert [p.split(":")[0] for p in problems] == ["A", "B", "C"]
    assert SECRET not in str(info.value)


# ----------------------------------------------------------------- store place


def test_default_vault_dir(monkeypatch, tmp_path):
    assert default_vault_dir({"FLOOR_VAULT_DIR": str(tmp_path)}) == tmp_path
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert default_vault_dir({}) == tmp_path / ".floorvault" / "agent-vault"


# ------------------------------------------------------------------- rewriting


def test_render_rewrites_only_the_named_lines_and_keeps_layout(tmp_path):
    from floorvault.agentenv import read_env_file, render_env_file

    raw = b"\xef\xbb\xbf# c\r\n  export A='x'\r\nB=y\nC=z"
    path = tmp_path / ".env"
    path.write_bytes(raw)
    env_file = read_env_file(path)
    assert env_file.bom
    assert [(line.name, line.value) for line in env_file.assignments()] == [
        ("A", "x"),
        ("B", "y"),
        ("C", "z"),
    ]
    assert render_env_file(env_file, {}) == raw
    by_name = {line.name: line.number for line in env_file.assignments()}
    out = render_env_file(env_file, {by_name["A"]: "fv:a", by_name["C"]: "fv:c"})
    assert out == b"\xef\xbb\xbf# c\r\n  export A=fv:a\r\nB=y\nC=fv:c"


def test_parse_env_file_still_returns_the_value_map(tmp_path):
    path = tmp_path / ".env"
    path.write_text("export A=1\n# x\nB='2'\n", encoding="utf-8")
    assert parse_env_file(path) == {"A": "1", "B": "2"}


def test_copies_of_a_key_value_are_removed_but_short_values_are_kept():
    key = "ab" * 32
    inherited = {"FLOOR_VAULT_KEY": key, "COPY": key, "SHORT_KEY": "1", "OTHER": "1"}
    env, _ = collect(inherited, [{"FILE_COPY": key, "HERMES_VAULT_KEY": "cd" * 32}])
    # The key variables and both copies go; SHORT_KEY is an ordinary name.
    assert env == {"SHORT_KEY": "1", "OTHER": "1"}
    short_env, _ = collect({"FLOOR_VAULT_KEY": "1", "OTHER": "1"})
    assert short_env == {"OTHER": "1"}


def test_hermes_vault_key_is_a_custody_name():
    env, _ = collect({"HERMES_VAULT_KEY": "x" * 64, "PATH": "/bin"})
    assert env == {"PATH": "/bin"}
    with pytest.raises(AgentEnvError):
        collect({}, [], ["HERMES_VAULT_KEY=fv:x"])


def test_only_fv_references_are_taken_from_the_environment():
    env, refs = collect({"A": "hv:x", "B": "fv:y", "C": "hv:not valid"})
    assert refs == {"B": SecretRef("y")}
    assert env == {"A": "hv:x", "C": "hv:not valid"}
    _, refs = collect({}, [{"D": "hv:z"}], ["E=hv:w"])
    assert refs == {"D": SecretRef("z"), "E": SecretRef("w")}


def test_key_file_variable_is_removed_refused_and_not_a_key_value():
    path = "/run/secrets/" + "x" * 40
    env, _ = collect({"FLOOR_VAULT_KEY_FILE": path, "SAME": path}, [{"FLOOR_VAULT_KEY_FILE": "/a"}])
    assert env == {"SAME": path}
    with pytest.raises(AgentEnvError):
        collect({}, [], ["FLOOR_VAULT_KEY_FILE=fv:x"])


def test_code_injection_variables():
    from floorvault.agentenv import code_injection_variables

    env = {
        "LD_PRELOAD": "x",
        "dyld_insert_libraries": "x",
        "npm_config_registry": "x",
        "npm_config_@scope:registry": "x",
        "Node_Options": "x",
        "npm_config_https_proxy": "x",
        "HTTPS_PROXY": "x",
        "PATH": "/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    assert code_injection_variables(env) == sorted(
        [
            "LD_PRELOAD",
            "dyld_insert_libraries",
            "npm_config_registry",
            "npm_config_@scope:registry",
            "Node_Options",
        ]
    )


def test_command_allowed_needs_the_exact_program_and_arguments():
    import os

    from floorvault.agentenv import command_allowed

    prog = os.path.abspath("/opt/bin/server")
    allowed = [[prog, "--stdio"], [os.path.abspath("/opt/bin/other")]]
    assert command_allowed([prog, "--stdio"], allowed)
    assert not command_allowed([prog], allowed)
    assert not command_allowed([prog, "--stdio", "x"], allowed)
    assert not command_allowed([os.path.abspath("/tmp/server"), "--stdio"], allowed)
    assert not command_allowed([], allowed)
    assert command_allowed([os.path.abspath("/opt/bin/other")], allowed)

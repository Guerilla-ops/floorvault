"""The examples are copied into real configs, so they must never hold a secret."""

from __future__ import annotations

import json
import re
from pathlib import Path

from floorvault.agentenv import is_ref_like, parse_env_file, parse_ref

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "agent-secrets"
# Names that hold secrets by convention ("PAT" only as a word: PATH is not one).
SECRET_NAME = re.compile(r"KEY|TOKEN|PASSWORD|SECRET|(?:^|_)PAT(?:_|$)", re.IGNORECASE)


def _assert_secrets_are_references(values: dict[str, str], where: str) -> None:
    for name, value in values.items():
        if SECRET_NAME.search(name):
            assert is_ref_like(value), f"{where}: {name} holds a value, not an fv: reference"
            assert parse_ref(value) is not None, f"{where}: {name} is not a valid reference"


def test_the_example_env_file_holds_only_references_for_secrets():
    values = parse_env_file(EXAMPLES / "app.env")
    assert values  # the strict parser accepted every line
    _assert_secrets_are_references(values, "app.env")


def test_the_example_mcp_config_starts_servers_through_run():
    config = json.loads((EXAMPLES / "mcp.json").read_text(encoding="utf-8"))
    for name, server in config["mcpServers"].items():
        assert server["args"][:2] == ["run", "--"], name
        _assert_secrets_are_references(server.get("env", {}), f"mcp.json {name}")

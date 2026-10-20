"""hermes-vault secret source: resolves hv: refs from a local SIV-encrypted store.

Mapped-shape source: ``secrets.hermesvault.env`` binds env-var names to
``hv:<item_id>`` or ``hv:<item_id>:<field>`` references. The store is the
agent-secret vault — a floorvault store at ``<home>/agent-vault`` (or
``secrets.hermesvault.dir``), kept deliberately separate from the browser-fill
login vault at ``<home>/vault`` so no legacy migration ever conflates the two.

The store's own key custody is floorvault's AdaptiveKeyProvider (OS keyring,
then the HERMES_VAULT_KEY-style env tier). The bootstrap key name is declared
via ``token_env`` so the orchestrator never lets a vault-resolved secret
overwrite the credential that unlocks the vault.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional, Tuple

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
    is_valid_env_name,
)


def _import_floorvault():
    """Import floorvault, falling back to the vendored ``vendor/`` sibling.

    ``vendor`` is a symlink to the package's own ``src/`` so the plugin always
    runs the checkout it ships with — no site-packages dependency is required."""
    try:
        return __import__("floorvault")
    except ImportError:
        vendor = Path(__file__).resolve().with_name("vendor")
        if vendor.is_dir() and str(vendor) not in sys.path:
            sys.path.insert(0, str(vendor))
        return __import__("floorvault")


DEFAULT_DIR_NAME = "agent-vault"
DEFAULT_TOKEN_ENV = "HERMES_VAULT_KEY"
_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")


def parse_ref(ref: str) -> Tuple[Optional[str], Optional[str]]:
    """``hv:<item_id>[:<field>]`` → (item_id, field-or-None); (None, None) when invalid."""
    if not isinstance(ref, str) or not ref.startswith("hv:"):
        return None, None
    body = ref[3:]
    item_id, _, field = body.partition(":")
    if not _ITEM_ID.fullmatch(item_id or ""):
        return None, None
    return item_id, (field if field else None)


def resolve_base_dir(cfg: dict, home_path: Path) -> Path:
    """Store directory: ``secrets.hermesvault.dir`` else ``<home>/agent-vault``.

    A relative ``dir`` is taken relative to the profile home; an absolute path
    is honoured as given (expanded)."""
    raw = cfg.get("dir") if isinstance(cfg, dict) else None
    if isinstance(raw, str) and raw.strip():
        candidate = Path(raw.strip()).expanduser()
        return candidate if candidate.is_absolute() else Path(home_path) / candidate
    return Path(home_path) / DEFAULT_DIR_NAME


def _open_store(cfg: dict, home_path: Path):
    """Open the agent-secret vault at its resolved directory.

    When the configured bootstrap key var is present in the fetch-scoped
    environment, it is used directly (keeping per-profile override semantics
    under multiplex); otherwise floorvault's AdaptiveKeyProvider resolves OS
    custody itself. ``auto_migrate=False`` is deliberate: this store never
    adopts the legacy browser vault files.
    """
    floorvault = _import_floorvault()

    base = resolve_base_dir(cfg, home_path)
    token_env = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV)
    key_hex = get_source_environment().get(token_env)
    if key_hex:
        from floorvault import FloorVault
        from floorvault.vaultkit import VaultStore

        crypto = FloorVault(bytes.fromhex(key_hex.strip()), app_instance_id="floor-agent")
        return VaultStore(base, crypto=crypto)
    return floorvault.get_vault_store(base, auto_migrate=False)


class HermesVaultSource(SecretSource):
    name = "hermesvault"
    label = "FloorVault"
    shape = "mapped"
    scheme = "hv"
    token_env_key = "token_env"
    default_token_env = DEFAULT_TOKEN_ENV
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "Set secrets.hermesvault.enabled: true and map vars under secrets.hermesvault.env.",
        ErrorKind.INTERNAL: "Is the hermes-vault package installed in this Python environment?",
        ErrorKind.AUTH_FAILED: "No usable key custody — set {token_env} or allow the OS keychain tier.",
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable the hermes-vault secret source", "default": False},
            "env": {"description": "Map of ENV_VAR to hv:<item_id>[:<field>] refs", "default": {}},
            "dir": {"description": "Vault directory (default <home>/agent-vault)", "default": ""},
            "token_env": {
                "description": "Env var holding the vault master key (64 hex)",
                "default": DEFAULT_TOKEN_ENV,
            },
            "override_existing": {
                "description": "May overwrite vars already set by .env/shell",
                "default": False,
            },
            "timeout_seconds": {"description": "Fetch wall-clock budget", "default": 120},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        if not isinstance(cfg, dict):
            return result
        env_map = cfg.get("env")
        if not isinstance(env_map, dict):
            if env_map is None:
                return result
            return result.fail(
                "secrets.hermesvault.env must be a map of ENV_VAR to hv: refs",
                ErrorKind.NOT_CONFIGURED,
            )
        if not env_map:
            return result
        try:
            store = _open_store(cfg, home_path)
        except ImportError:
            return result.fail(
                "floorvault package is not installed in this environment", ErrorKind.INTERNAL
            )
        except Exception as error:
            return result.fail(
                f"Could not open the hermes-vault store: {error}", ErrorKind.AUTH_FAILED
            )
        for name, ref in env_map.items():
            if not is_valid_env_name(name):
                result.warnings.append(f"Skipped invalid env-var name {name!r}")
                continue
            item_id, field = parse_ref(ref)
            if item_id is None:
                result.warnings.append(f"Skipped {name}: ref must be hv:<item_id>[:<field>]")
                continue
            try:
                secret = store.resolve_secret(item_id)
            except Exception:
                result.warnings.append(f"Skipped {name}: vault item {item_id} is unavailable")
                continue
            if field is not None:
                value = secret.get(field)
                if not isinstance(value, str) or not value:
                    result.warnings.append(f"Skipped {name}: item {item_id} has no field {field!r}")
                    continue
            elif isinstance(secret.get("value"), str) and secret["value"]:
                value = secret["value"]
            elif len(secret) == 1:
                value = next(iter(secret.values()))
                if not isinstance(value, str) or not value:
                    result.warnings.append(f"Skipped {name}: item {item_id} field is empty")
                    continue
            else:
                result.warnings.append(
                    f"Skipped {name}: item {item_id} holds {len(secret)} fields — "
                    "name one with hv:<item_id>:<field>"
                )
                continue
            result.secrets[name] = value
        return result

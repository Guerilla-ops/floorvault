"""hermes-vault secret source: resolves hv: refs from a local SIV-encrypted store.

Mapped-shape source: ``secrets.hermesvault.env`` binds env-var names to
``hv:<item_id>`` or ``hv:<item_id>:<field>`` references. The store is the
agent-secret vault — a floorvault store at ``<home>/agent-vault`` (or
``secrets.hermesvault.dir``), kept deliberately separate from the browser-fill
login vault at ``<home>/vault`` so no legacy migration ever conflates the two.

The store's key comes from the variable named by ``token_env``, read from the
fetch-scoped environment only, or else from the OS key store through
floorvault's AdaptiveKeyProvider with no environment tier: the process-wide
``FLOOR_VAULT_KEY`` / ``VAULT_MASTER_KEY`` are not accepted, so under the
multiplex gateway another profile's launch environment cannot unlock this
store. ``fetch`` never prompts and never creates anything (no Secret Service
unlock, no key, no store); ``hermes hvault setup`` does that once, interactively.
The bootstrap key name and floorvault's key variables are returned by
``protected_env_vars`` so a vault-resolved secret never overwrites them.
"""

from __future__ import annotations

import re
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
    """Import floorvault from the Hermes Python environment.

    ``plugin.yaml`` declares ``floorvault`` as a Python dependency, so
    ``hermes plugins install`` / ``enable`` prepares it through Hermes' package
    manager. The plugin directory carries no copy of the library."""
    import floorvault

    return floorvault


DEFAULT_DIR_NAME = "agent-vault"
DEFAULT_TOKEN_ENV = "HERMES_VAULT_KEY"
#: floorvault's own key variables. The plugin does not read them, but a mapped
#: output must not overwrite them for anything else in the process that does.
FLOORVAULT_KEY_ENV_NAMES = frozenset(
    {"FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"}
)
_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
#: Must equal VaultStore's default custody so stores made either way open alike.
_SERVICE_NAME = "floor-vault"
_APP_INSTANCE_ID = "floor-agent"


class StoreNotSetUp(Exception):
    """No store (or no key) yet; ``hermes hvault setup`` creates them."""


class CustodyUnavailable(Exception):
    """The store's key cannot be resolved here (locked key store, missing key,
    an older floorvault). Its message is written by floorvault or this plugin and
    names no key material, so it is safe to show, unlike arbitrary exceptions."""


def parse_ref(ref: str) -> Tuple[Optional[str], Optional[str]]:
    """``hv:<item_id>[:<field>]`` → (item_id, field-or-None); (None, None) when invalid."""
    if not isinstance(ref, str) or not ref.startswith("hv:"):
        return None, None
    body = ref[3:]
    item_id, _, field = body.partition(":")
    if not _ITEM_ID.fullmatch(item_id or ""):
        return None, None
    return item_id, (field if field else None)


def validate_config(cfg: dict) -> None:
    """Reject malformed settings rather than silently selecting default custody."""
    if not isinstance(cfg, dict):
        raise ValueError("secrets.hermesvault must be a mapping")
    if not isinstance(cfg.get("dir", ""), str):
        raise ValueError("secrets.hermesvault.dir must be a string")
    token = cfg.get("token_env", DEFAULT_TOKEN_ENV)
    if not isinstance(token, str) or not is_valid_env_name(token):
        raise ValueError("secrets.hermesvault.token_env must be an environment variable name")
    for name in ("enabled", "override_existing"):
        if name in cfg and not isinstance(cfg[name], bool):
            raise ValueError(f"secrets.hermesvault.{name} must be a boolean")


def resolve_base_dir(cfg: dict, home_path: Path) -> Path:
    """Store directory: ``secrets.hermesvault.dir`` else ``<home>/agent-vault``.

    A relative ``dir`` is taken relative to the profile home; an absolute path
    is honoured as given (expanded)."""
    raw = cfg.get("dir") if isinstance(cfg, dict) else None
    if isinstance(raw, str) and raw.strip():
        candidate = Path(raw.strip()).expanduser()
        return candidate if candidate.is_absolute() else Path(home_path) / candidate
    return Path(home_path) / DEFAULT_DIR_NAME


def _open_store(cfg: dict, home_path: Path, *, setup: bool = False):
    """Open the agent-secret vault at its resolved directory.

    The key is the ``token_env`` variable from the fetch-scoped environment
    (per-profile under multiplex), else the OS key store. Without ``setup``
    nothing is created and nothing prompts: a missing store, a missing key or a
    locked Secret Service collection raises instead. ``setup=True`` (only
    ``hermes hvault setup``) may unlock the collection and create the key and
    the store. Legacy browser-vault files are never adopted.
    """
    validate_config(cfg)
    _import_floorvault()
    from floorvault import FloorVault
    from floorvault.providers.adaptive import AdaptiveKeyProvider
    from floorvault.providers.base import KeyProviderError
    from floorvault.vaultkit import VaultStore

    base = resolve_base_dir(cfg, home_path)
    if not setup and not (base / "vault.db").is_file():
        raise StoreNotSetUp(f"no store at {base}; run `hermes hvault setup` once")
    token_env = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV)
    key_hex = get_source_environment().get(token_env)
    if key_hex:
        crypto = FloorVault(bytes.fromhex(key_hex.strip()), app_instance_id=_APP_INSTANCE_ID)
        return VaultStore(base, crypto=crypto)
    try:
        provider = AdaptiveKeyProvider(
            service_name=_SERVICE_NAME,
            fallback_dir=base,
            environ={},  # no environment tier: token_env above is the only key variable
            interactive=setup,
        )
    except TypeError:
        # An older floorvault would read the process environment and could prompt.
        raise CustodyUnavailable(
            "this hermesvault needs a newer floorvault (AdaptiveKeyProvider with "
            "environ= and interactive=); upgrade the floorvault package"
        ) from None
    try:
        key = provider.resolve_key(allow_create=setup)
    except KeyProviderError as exc:
        raise CustodyUnavailable(str(exc)) from None
    return VaultStore(base, crypto=FloorVault(key, app_instance_id=_APP_INSTANCE_ID))


class HermesVaultSource(SecretSource):
    name = "hermesvault"
    label = "FloorVault"
    shape = "mapped"
    scheme = "hv"
    token_env_key = "token_env"
    default_token_env = DEFAULT_TOKEN_ENV
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: "Set secrets.hermesvault.enabled: true and map vars under secrets.hermesvault.env.",
        ErrorKind.INTERNAL: (
            "Is floorvault installed in the Hermes environment? Re-run "
            "`hermes plugins enable hermesvault` so Hermes prepares its dependencies."
        ),
        ErrorKind.AUTH_FAILED: (
            "No usable key custody: set {token_env}, or run `hermes hvault setup` to "
            "unlock or create the OS key store entry."
        ),
    }

    def protected_env_vars(self, cfg: dict) -> frozenset[str]:
        return frozenset({self.token_env(cfg)}) | FLOORVAULT_KEY_ENV_NAMES

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
        try:
            validate_config(cfg)
        except ValueError as error:
            return result.fail(str(error), ErrorKind.NOT_CONFIGURED)
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
        except StoreNotSetUp as error:
            return result.fail(str(error), ErrorKind.NOT_CONFIGURED)
        except CustodyUnavailable as error:
            return result.fail(
                f"Could not open the hermes-vault store: {error}", ErrorKind.AUTH_FAILED
            )
        except ImportError:
            return result.fail(
                "floorvault package is not installed in this environment", ErrorKind.INTERNAL
            )
        except Exception as error:
            return result.fail(
                f"Could not open the hermes-vault store ({type(error).__name__}); "
                "check the profile directory and key custody",
                ErrorKind.AUTH_FAILED,
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

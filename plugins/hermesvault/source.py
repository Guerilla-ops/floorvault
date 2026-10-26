"""hermes-vault secret source: resolves hv: refs from a local SIV-encrypted store.

Mapped-shape source: ``secrets.hermesvault.env`` binds env-var names to
``hv:<item_id>`` or ``hv:<item_id>:<field>`` references. The store is the
agent-secret vault — a floorvault store at ``<home>/agent-vault`` (or
``secrets.hermesvault.dir``), kept deliberately separate from the browser-fill
login vault at ``<home>/vault`` so no legacy migration ever conflates the two.

The store's key comes from the variable named by ``token_env``, read from the
fetch-scoped environment only, or else from the custody the profile configures
with ``custody``:

* ``os`` (default): the OS key store through floorvault's AdaptiveKeyProvider
  with no environment tier.
* ``key_file``: the 64-hex key in the file named by ``key_file`` (an
  orchestrator secret mount on a headless host), checked as floorvault's CLI
  checks ``--key-file``.
* ``systemd-creds``: the key sealed by ``systemd-creds encrypt --user`` beside
  the store (``master.key.sdcred``), unsealed with ``systemd-creds decrypt``.
  This is the only custody that starts a subprocess.

The process-wide ``FLOOR_VAULT_KEY`` / ``VAULT_MASTER_KEY`` /
``FLOOR_VAULT_KEY_FILE`` are never read, so under the multiplex gateway another
profile's launch environment cannot unlock this store. A configured custody
that fails is reported; nothing falls back to another one. ``fetch`` never
prompts and never creates anything (no Secret Service unlock, no key, no
credential, no store); ``hermes hvault setup`` does that once. The bootstrap key
name and floorvault's key variables are returned by ``protected_env_vars`` so a
vault-resolved secret never overwrites them.
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
DEFAULT_CUSTODY = "os"
CUSTODIES = ("os", "key_file", "systemd-creds")
#: floorvault's own key variables. The plugin does not read them, but a mapped
#: output must not overwrite them for anything else in the process that does.
FLOORVAULT_KEY_ENV_NAMES = frozenset(
    {"FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "FLOOR_VAULT_KEY_FILE"}
)
_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
#: Must equal VaultStore's default custody so stores made either way open alike.
_SERVICE_NAME = "floor-vault"
#: floorvault.systemd_creds.CREDENTIAL_FILENAME, named here for floorvault 0.2.2.
_SYSTEMD_CREDENTIAL_FILENAME = "master.key.sdcred"
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
    custody = cfg.get("custody", DEFAULT_CUSTODY)
    if custody not in CUSTODIES:
        raise ValueError("secrets.hermesvault.custody must be one of: " + ", ".join(CUSTODIES))
    key_file = cfg.get("key_file")
    if custody == "key_file":
        if not isinstance(key_file, str) or not key_file.strip():
            raise ValueError("secrets.hermesvault.custody: key_file needs a key_file path")
    elif key_file is not None:
        # A key_file that is silently ignored would leave the store on another custody.
        raise ValueError("secrets.hermesvault.key_file is used only with custody: key_file")


def resolve_key_file(cfg: dict, home_path: Path) -> Path:
    """``secrets.hermesvault.key_file``; a relative path is taken from the profile home."""
    candidate = Path(str(cfg["key_file"]).strip()).expanduser()
    return candidate if candidate.is_absolute() else Path(home_path) / candidate


def resolve_base_dir(cfg: dict, home_path: Path) -> Path:
    """Store directory: ``secrets.hermesvault.dir`` else ``<home>/agent-vault``.

    A relative ``dir`` is taken relative to the profile home; an absolute path
    is honoured as given (expanded)."""
    raw = cfg.get("dir") if isinstance(cfg, dict) else None
    if isinstance(raw, str) and raw.strip():
        candidate = Path(raw.strip()).expanduser()
        return candidate if candidate.is_absolute() else Path(home_path) / candidate
    return Path(home_path) / DEFAULT_DIR_NAME


def _open_store(cfg: dict, home_path: Path, *, setup: bool = False, warnings=None):
    """Open the agent-secret vault at its resolved directory.

    The key is the ``token_env`` variable from the fetch-scoped environment
    (per-profile under multiplex), else the configured ``custody``. Without
    ``setup`` nothing is created and nothing prompts: a missing store, a missing
    key or credential, or a locked Secret Service collection raises instead.
    ``setup=True`` (only ``hermes hvault setup``) may unlock the collection and
    create the key (OS custody), the sealed credential (systemd-creds) and the
    store. Legacy browser-vault files are never adopted. Warnings that name no
    key material (a key file readable by others) are appended to ``warnings``.
    """
    validate_config(cfg)
    _import_floorvault()
    from floorvault import FloorVault
    from floorvault.vaultkit import VaultStore

    base = resolve_base_dir(cfg, home_path)
    store_exists = (base / "vault.db").is_file()
    if not setup and not store_exists:
        raise StoreNotSetUp(f"no store at {base}; run `hermes hvault setup` once")
    token_env = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV)
    key_hex = get_source_environment().get(token_env)
    if key_hex:
        key = bytes.fromhex(key_hex.strip())
    else:
        custody = cfg.get("custody", DEFAULT_CUSTODY)
        if custody == "key_file":
            key = _key_from_file(resolve_key_file(cfg, home_path), warnings)
        elif custody == "systemd-creds":
            key = _key_from_credential(base, setup=setup, store_exists=store_exists)
        else:
            key = _key_from_os(base, setup=setup)
    return VaultStore(base, crypto=FloorVault(key, app_instance_id=_APP_INSTANCE_ID))


def _newer_floorvault(custody: str) -> CustodyUnavailable:
    return CustodyUnavailable(
        f"custody: {custody} needs floorvault 0.2.8 or newer; upgrade the floorvault package"
    )


def _key_from_os(base: Path, *, setup: bool) -> bytes:
    from floorvault.providers.adaptive import AdaptiveKeyProvider
    from floorvault.providers.base import KeyProviderError

    try:
        (base / _SYSTEMD_CREDENTIAL_FILENAME).lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise CustodyUnavailable(f"cannot check {base} for a systemd-creds credential") from None
    else:
        raise CustodyUnavailable(
            f"{base} holds a systemd-creds credential; set "
            "secrets.hermesvault.custody: systemd-creds to open it"
        )
    try:
        provider = AdaptiveKeyProvider(
            service_name=_SERVICE_NAME,
            fallback_dir=base,
            environ={},  # no environment tier: token_env is the only key variable
            interactive=setup,
        )
    except TypeError:
        # An older floorvault would read the process environment and could prompt.
        raise CustodyUnavailable(
            "this hermesvault needs a newer floorvault (AdaptiveKeyProvider with "
            "environ= and interactive=); upgrade the floorvault package"
        ) from None
    try:
        return provider.resolve_key(allow_create=setup)
    except KeyProviderError as exc:
        raise CustodyUnavailable(str(exc)) from None


def _key_from_file(path: Path, warnings) -> bytes:
    try:
        from floorvault.key_file import KeyFileError, read_key_file
    except ImportError:
        raise _newer_floorvault("key_file") from None
    try:
        return read_key_file(path, warn=None if warnings is None else warnings.append)
    except KeyFileError as exc:
        raise CustodyUnavailable(str(exc)) from None


def _key_from_credential(base: Path, *, setup: bool, store_exists: bool) -> bytes:
    try:
        from floorvault import systemd_creds
    except ImportError:
        raise _newer_floorvault("systemd-creds") from None
    try:
        if setup and not systemd_creds.credential_present(base):
            if store_exists:
                # The store already has a key elsewhere; a new one would fork it.
                raise CustodyUnavailable(
                    f"{base} already holds a store without a systemd-creds credential; "
                    "setup seals the key of a new store only"
                )
            systemd_creds.create_credential(base)
        key = systemd_creds.read_key(base)
    except systemd_creds.SystemdCredsError as exc:
        raise CustodyUnavailable(str(exc)) from None
    if key is None:
        raise StoreNotSetUp(
            f"no systemd-creds credential at {systemd_creds.credential_path(base)}; "
            "run `hermes hvault setup` once"
        )
    return key


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
            "No usable key custody: set {token_env}, check secrets.hermesvault.custody, "
            "or run `hermes hvault setup` to unlock or create the key."
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
            "custody": {
                "description": "Where the key is kept when token_env is unset: "
                "os, key_file or systemd-creds",
                "default": DEFAULT_CUSTODY,
            },
            "key_file": {
                "description": "With custody: key_file, the file holding the key (64 hex)",
                "default": None,
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
            store = _open_store(cfg, home_path, warnings=result.warnings)
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

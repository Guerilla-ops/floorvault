"""Resolve ``fv:`` vault references into environment variables.

This is the library half of ``floorvault run``. A reference names an item in an
agent-secret store and, optionally, one of its fields::

    fv:<item_id>[:<field>]

``hv:`` is accepted as an alias so a Hermes ``secrets.hermesvault.env`` mapping
can be reused verbatim.

A value is a reference when it starts with ``fv:`` or ``hv:``. A value with
that prefix that does not match the grammar is an error, not plaintext: a
mistyped reference must never reach a child process as a literal string. A
prefix later in the value (``x=fv:y``) is not a reference.

Error messages name variables, files, line numbers and item ids. They never
contain a value, because a value may be a secret.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

__all__ = [
    "AgentEnvError",
    "CODE_INJECTION_ENV_NAMES",
    "CODE_INJECTION_ENV_PREFIXES",
    "CUSTODY_ENV_NAMES",
    "KEY_POINTER_ENV_NAMES",
    "EnvFile",
    "EnvFileLine",
    "SecretRef",
    "code_injection_variables",
    "collect",
    "command_allowed",
    "default_vault_dir",
    "is_ref_like",
    "is_valid_env_name",
    "parse_env_file",
    "parse_ref",
    "read_env_file",
    "render_env_file",
    "render_env_file_without",
    "resolve",
    "select_field",
]

REF_SCHEMES = ("fv", "hv")
# Master-key variables: the two AdaptiveKeyProvider reads by default, and the
# hermesvault plugin's default token_env. They are removed from the child's
# environment, and a reference may never be resolved onto them. Any other
# variable holding a copy of one of their values is removed too.
CUSTODY_ENV_NAMES = ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "HERMES_VAULT_KEY")
# APPSTATE_KEY is read only on explicit opt-in and is a name other tools share,
# so it is passed through untouched, but a reference may not target it either.
# Variables that point at a key rather than hold one (--key-file's default).
# They are removed from the child and may not be targeted, but their values
# are paths, not keys, so they are not used to find copies.
KEY_POINTER_ENV_NAMES = ("FLOOR_VAULT_KEY_FILE",)
_REFUSED_TARGETS = (*CUSTODY_ENV_NAMES, *KEY_POINTER_ENV_NAMES, "APPSTATE_KEY")
MAX_ENV_FILE_BYTES = 1 << 20

# Variables that let a configuration change what an allowed program loads or
# runs: dynamic-linker injection, interpreter start-up hooks and package-index
# redirection. While an item bound to commands is being resolved, `run`
# refuses to start if any of these is set. Best effort: no list can name every
# way an environment steers a program (HOME and PATH do too).
CODE_INJECTION_ENV_NAMES = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "NODE_OPTIONS",
        "NODE_PATH",
        "ELECTRON_RUN_AS_NODE",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PERL5OPT",
        "PERL5LIB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "BASH_ENV",
        "ENV",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        # Settings that pick the interpreter, a config file or a package source.
        "UV_PYTHON",
        "UV_PYTHON_INSTALL_MIRROR",
        "UV_CONFIG_FILE",
        "UV_FIND_LINKS",
        "PIP_CONFIG_FILE",
        "PIP_FIND_LINKS",
        # npm settings that pick where packages come from or what runs them.
        # Proxy settings are left alone: npm verifies TLS through a proxy.
        "NPM_CONFIG_REGISTRY",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_STRICT_SSL",
        "NPM_CONFIG_CA",
        "NPM_CONFIG_CAFILE",
        "NPM_CONFIG_NODE_OPTIONS",
        "NPM_CONFIG_SCRIPT_SHELL",
        "NPM_CONFIG_PREFIX",
    }
)
CODE_INJECTION_ENV_PREFIXES = ("DYLD_",)

_ITEM_ID = r"[A-Za-z0-9._-]{1,128}"
_REF = re.compile(
    rf"(?P<scheme>fv|hv):(?P<item>{_ITEM_ID})(?::(?P<field>[^\x00\r\n:][^\x00\r\n]*))?"
)
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# One env-file line and its terminator. Only CR, LF and CRLF end a line: the
# other characters str.splitlines() treats as breaks are refused instead (see
# _HIDDEN_BREAKS), so what an editor or grep shows as one line stays one line.
_LINE = re.compile(r"([^\r\n]*)(\r\n|\r|\n|\Z)")
_HIDDEN_BREAKS = frozenset("\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")


class AgentEnvError(ValueError):
    """One or more references or env-file lines could not be used.

    ``problems`` holds one line per problem, each safe to print.
    """

    def __init__(self, problems: Iterable[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class SecretRef:
    """A parsed ``fv:``/``hv:`` reference."""

    item_id: str
    field: Optional[str] = None

    def __str__(self) -> str:
        return f"fv:{self.item_id}" + (f":{self.field}" if self.field else "")


def is_ref_like(value: Any) -> bool:
    """Whether ``value`` claims to be a reference (it carries a ref prefix)."""
    return isinstance(value, str) and value.startswith(tuple(f"{s}:" for s in REF_SCHEMES))


def parse_ref(value: Any) -> Optional[SecretRef]:
    """Parse a reference.

    Returns ``None`` when ``value`` is not reference-shaped (plain value) and
    raises :class:`AgentEnvError` when it has a reference prefix but is
    malformed.
    """
    if not is_ref_like(value):
        return None
    match = _REF.fullmatch(value)
    if match is None:
        raise AgentEnvError(["malformed reference: expected fv:<item_id>[:<field>]"])
    return SecretRef(match.group("item"), match.group("field"))


def is_valid_env_name(name: Any) -> bool:
    return isinstance(name, str) and _ENV_NAME.fullmatch(name) is not None


def select_field(secret: Mapping[str, Any], field: Optional[str]) -> str:
    """Pick the value a reference points at, using the hermesvault rules.

    1. An explicit field is used as named.
    2. Otherwise a non-empty ``value`` field.
    3. Otherwise the item's only field.
    4. Otherwise the reference must name a field.
    """
    if field is not None:
        if field not in secret:
            raise AgentEnvError([f"has no field {field!r}"])
        value = secret[field]
    elif isinstance(secret.get("value"), str) and secret["value"]:
        value = secret["value"]
    elif len(secret) == 1:
        value = next(iter(secret.values()))
    elif not secret:
        raise AgentEnvError(["has no fields"])
    else:
        # No count: messages carry nothing derived from the decrypted item.
        raise AgentEnvError(["holds more than one field; name one with fv:<item_id>:<field>"])
    if not isinstance(value, str):
        raise AgentEnvError(["field is not a string"])
    if not value:
        raise AgentEnvError(["field is empty"])
    if "\x00" in value:
        raise AgentEnvError(["field contains a NUL byte and cannot be an environment value"])
    return value


def _unquote(raw: str) -> Optional[str]:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        inner = raw[1:-1]
        return None if raw[0] in inner else inner
    if raw[:1] in ("'", '"') or raw[-1:] in ("'", '"'):
        return None
    return raw


@dataclass(frozen=True)
class EnvFileLine:
    """One line of an env file, kept exactly enough to rewrite it in place.

    ``name``/``value`` are ``None`` for blank and comment lines. ``value`` is
    unquoted. ``ending`` is the original line terminator ("" on a final line
    without one).
    """

    number: int
    text: str
    ending: str
    name: Optional[str] = None
    value: Optional[str] = None
    exported: bool = False
    indent: str = ""

    def with_reference(self, ref: str) -> str:
        """This assignment rewritten to ``ref``, keeping indent, export and ending."""
        export = "export " if self.exported else ""
        return f"{self.indent}{export}{self.name}={ref}{self.ending}"


@dataclass(frozen=True)
class EnvFile:
    path: Path
    raw: bytes
    lines: tuple[EnvFileLine, ...]
    bom: bool = False

    def assignments(self) -> list[EnvFileLine]:
        return [line for line in self.lines if line.name is not None]


def read_env_file(path: Path | str) -> EnvFile:
    """Read and validate a strict dotenv-style file, keeping its layout.

    Accepted lines: blank, ``# comment``, and ``[export ]NAME=value``. A value
    may be wrapped in one pair of matching quotes, which are removed. There is
    no interpolation and no escape processing. A malformed line or a name set
    twice raises :class:`AgentEnvError` naming the file and line, never the
    value.
    """
    path = Path(path)
    label = str(path)
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_ENV_FILE_BYTES + 1)
    except OSError as exc:
        raise AgentEnvError([f"{label}: cannot read env file ({type(exc).__name__})"]) from None
    if len(data) > MAX_ENV_FILE_BYTES:
        raise AgentEnvError([f"{label}: env file is larger than {MAX_ENV_FILE_BYTES} bytes"])
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise AgentEnvError([f"{label}: env file is not valid UTF-8"]) from None

    lines: list[EnvFileLine] = []
    seen: set[str] = set()
    problems: list[str] = []
    for number, (line, ending) in enumerate(_split_lines(text), start=1):
        hidden = sorted({char for char in line if char in _HIDDEN_BREAKS})
        if hidden:
            codes = ", ".join(f"U+{ord(char):04X}" for char in hidden)
            problems.append(
                f"{label}:{number}: contains a line-break character ({codes}) that some "
                "tools show as part of one line; remove it"
            )
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(EnvFileLine(number, line, ending))
            continue
        indent = line[: len(line) - len(line.lstrip())]
        exported = stripped.startswith("export ") or stripped.startswith("export\t")
        if exported:
            stripped = stripped[len("export") :].lstrip()
        name, sep, raw = stripped.partition("=")
        name = name.strip()
        where = f"{label}:{number}"
        if not sep or not is_valid_env_name(name):
            problems.append(f"{where}: expected NAME=value")
            continue
        value = _unquote(raw.strip())
        if value is None:
            problems.append(f"{where}: {name}: unbalanced quotes")
            continue
        if "\x00" in value:
            problems.append(f"{where}: {name}: value contains a NUL byte")
            continue
        if name in seen:
            problems.append(f"{where}: {name} is set more than once")
            continue
        seen.add(name)
        lines.append(EnvFileLine(number, line, ending, name, value, exported, indent))
    if problems:
        raise AgentEnvError(problems)
    return EnvFile(path, data, tuple(lines), data.startswith(b"\xef\xbb\xbf"))


def _split_lines(text: str) -> list[tuple[str, str]]:
    """``(line, terminator)`` pairs, ending lines only at CR, LF or CRLF."""
    parts: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _LINE.match(text, pos)
        parts.append((match.group(1), match.group(2)))
        pos = match.end()
    return parts


def parse_env_file(path: Path | str) -> dict[str, str]:
    """``NAME -> value`` for a strict dotenv-style file (see :func:`read_env_file`)."""
    return {line.name: line.value for line in read_env_file(path).assignments()}


def render_env_file(env_file: EnvFile, replacements: Mapping[int, str]) -> bytes:
    """The file's bytes with line ``number -> reference`` rewritten, all else verbatim."""
    out = []
    for line in env_file.lines:
        ref = replacements.get(line.number)
        out.append(line.with_reference(ref) if ref is not None else line.text + line.ending)
    body = "".join(out).encode("utf-8")
    return (b"\xef\xbb\xbf" + body) if env_file.bom else body


def render_env_file_without(env_file: EnvFile, numbers: Iterable[int]) -> bytes:
    """The file's bytes with the lines numbered ``numbers`` deleted, all else verbatim.

    A deleted last line that had no terminator leaves the previous line's
    terminator in place, so the file ends with a newline.
    """
    drop = set(numbers)
    out = [line.text + line.ending for line in env_file.lines if line.number not in drop]
    body = "".join(out).encode("utf-8")
    return (b"\xef\xbb\xbf" + body) if env_file.bom else body


def _parse_explicit(pairs: Iterable[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    problems: list[str] = []
    for pair in pairs:
        name, sep, value = str(pair).partition("=")
        if not sep or not is_valid_env_name(name):
            problems.append("-e expects NAME=fv:<item_id>[:<field>]")
            continue
        if not is_ref_like(value):
            problems.append(f"-e {name}: value must be an fv: reference")
            continue
        values[name] = value
    if problems:
        raise AgentEnvError(problems)
    return values


def _custody_names(key_env: Optional[str], names: Iterable[str] = CUSTODY_ENV_NAMES) -> set[str]:
    result = {n.upper() for n in names}
    if key_env:
        result.add(key_env.upper())
    return result


def collect(
    inherited: Mapping[str, str],
    env_files: Iterable[Mapping[str, str]] = (),
    explicit: Iterable[str] = (),
    *,
    inherit_refs: bool = True,
    key_env: Optional[str] = None,
    fold_case: Optional[bool] = None,
) -> tuple[dict[str, str], dict[str, SecretRef]]:
    """Merge the three reference sources into a child environment plan.

    Precedence, lowest first: inherited environment, each env file in order,
    explicit ``-e`` pairs. Returns ``(environment, refs)``: ``environment`` is
    the child's environment with custody variables removed and references not
    yet filled in; ``refs`` maps each variable to resolve onto its reference.

    ``fold_case`` (default: on Windows) merges names case-insensitively, as
    Windows reads them: every name is upper-cased, so ``Path`` from an env file
    replaces the inherited ``PATH`` instead of reaching the child beside it.
    """
    if fold_case is None:
        fold_case = os.name == "nt"

    def fold(name: str) -> str:
        return name.upper() if fold_case else name

    custody = _custody_names(key_env)
    refused = _custody_names(key_env, _REFUSED_TARGETS)
    # Values of the key variables, so a copy under another name is caught too.
    # Compared case-insensitively: a hex key works in either case, so a copy
    # in the other case is still a copy.
    key_values = {
        value.strip().lower()
        for name, value in inherited.items()
        if name.upper() in custody and isinstance(value, str) and len(value.strip()) >= 32
    }
    pointers = {n.upper() for n in KEY_POINTER_ENV_NAMES}
    removed = custody | pointers
    env: dict[str, str] = {
        fold(name): value for name, value in inherited.items() if name.upper() not in removed
    }
    pending: dict[str, str] = {}
    if inherit_refs:
        # Only fv: is filled in from the environment: an hv: value there may
        # belong to another tool. -e and env files accept both schemes.
        pending.update({name: value for name, value in env.items() if value.startswith("fv:")})
    for file_values in env_files:
        for name, value in file_values.items():
            name = fold(name)
            if name.upper() in custody and not is_ref_like(value):
                # A vault key in an env file never reaches the child either.
                if len(value.strip()) >= 32:
                    key_values.add(value.strip().lower())
                continue
            if name.upper() in pointers and not is_ref_like(value):
                continue
            if is_ref_like(value):
                pending[name] = value
            else:
                pending.pop(name, None)
                env[name] = value
    pending.update({fold(name): value for name, value in _parse_explicit(explicit).items()})

    refs: dict[str, SecretRef] = {}
    problems: list[str] = []
    for name, value in pending.items():
        if name.upper() in refused:
            problems.append(f"{name}: references may not target a vault key variable")
            continue
        try:
            ref = parse_ref(value)
        except AgentEnvError:
            problems.append(f"{name}: malformed reference, expected fv:<item_id>[:<field>]")
            continue
        if ref is None:  # pending holds only ref-like values; kept defensive
            problems.append(f"{name}: not a reference")
            continue
        refs[name] = ref
        env.pop(name, None)
    if problems:
        raise AgentEnvError(problems)
    if key_values:
        env = {
            name: value for name, value in env.items() if value.strip().lower() not in key_values
        }
    return env, refs


def resolve(store: Any, refs: Mapping[str, SecretRef]) -> dict[str, str]:
    """Resolve every reference, or raise listing every one that failed.

    ``store`` is anything with ``resolve_secret(item_id) -> dict``. Each item
    is decrypted once however many variables point at it.
    """
    # Decrypted items and failures are kept apart so no error message is ever
    # built from data that came out of the vault.
    secrets: dict[str, Mapping[str, Any]] = {}
    failures: dict[str, str] = {}
    values: dict[str, str] = {}
    problems: list[str] = []
    for name, ref in refs.items():
        item_id = ref.item_id
        if item_id not in secrets and item_id not in failures:
            try:
                loaded = store.resolve_secret(item_id)
            except Exception as exc:  # noqa: BLE001 - report the type, never a value
                failures[item_id] = f"is unavailable ({type(exc).__name__})"
            else:
                if isinstance(loaded, Mapping):
                    secrets[item_id] = loaded
                else:
                    failures[item_id] = "is not a field map"
        if item_id in failures:
            problems.append(f"{name}: vault item {item_id} {failures[item_id]}")
            continue
        try:
            values[name] = select_field(secrets[item_id], ref.field)
        except AgentEnvError as exc:
            problems.extend(f"{name}: vault item {item_id} {p}" for p in exc.problems)
    if problems:
        raise AgentEnvError(problems)
    return values


def default_vault_dir(environ: Optional[Mapping[str, str]] = None) -> Path:
    """``$FLOOR_VAULT_DIR``, else ``~/.floorvault/agent-vault``."""
    environ = os.environ if environ is None else environ
    raw = (environ.get("FLOOR_VAULT_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".floorvault" / "agent-vault"


def code_injection_variables(env: Mapping[str, str]) -> list[str]:
    """Names in ``env`` that can change what a started program loads or runs.

    Compared case-insensitively (Windows names are, and npm reads both
    ``npm_config_*`` and ``NPM_CONFIG_*``).
    """
    found = []
    for name in env:
        upper = name.upper()
        if (
            upper in CODE_INJECTION_ENV_NAMES
            or upper.startswith(CODE_INJECTION_ENV_PREFIXES)
            # Scoped registries: npm_config_@scope:registry.
            or (upper.startswith("NPM_CONFIG_") and upper.endswith("REGISTRY"))
        ):
            found.append(name)
    return sorted(found)


def command_allowed(command: Sequence[str], allowed: Iterable[Sequence[str]]) -> bool:
    """True when ``command`` (absolute program path, then arguments) is listed.

    The program path is compared with ``os.path.normcase`` (case-insensitive
    on Windows); arguments must match exactly.
    """
    if not command:
        return False
    program = os.path.normcase(command[0])
    rest = list(command[1:])
    return any(
        entry and os.path.normcase(entry[0]) == program and list(entry[1:]) == rest
        for entry in allowed
    )

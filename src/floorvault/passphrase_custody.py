"""Passphrase-wrapped master key beside a store, for ``floorvault run`` and ``secrets`` (#84, step 3).

``floorvault secrets init --custody passphrase`` creates a random master key and
keeps it only as an ``FVPW1`` file (``master.key.fvpw``, scrypt + AES-SIV, see
:mod:`floorvault.providers.passphrase_store`) beside the store. A copy of the
disk or a backup then also needs the passphrase. The passphrase is asked for on
the terminal only: never from ``argv`` or the environment.

What this is not: protection against code running as the same user while the
key is unwrapped, against anyone who can observe the passphrase, or against
root. It is a key at rest that needs a person to unlock it, the same limits as
the other custody tiers.

Unattended callers (an MCP client's ``run``) cannot answer a prompt, so a store
with a wrapped key and no terminal is **locked**: it fails, naming the reason,
and never falls back to another custody. A key agent that holds the unwrapped
key for such callers is a later step of #84.
"""

from __future__ import annotations

import getpass
import os
import secrets
import sys
import warnings
from pathlib import Path
from typing import Optional

from .providers import passphrase_store
from .providers.adaptive import (
    OS_TIER_MARKER_FILENAME,
    SYSTEMD_CREDENTIAL_FILENAME,
    WRAPPED_KEY_FILENAME,
)
from .providers.platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    _mkdir_owner_only,
    read_protected,
    write_protected,
)

WRAPPED_FILENAME = WRAPPED_KEY_FILENAME
#: Files that mean another custody already holds (or held) this store's key.
OTHER_CUSTODY_FILES = ("master.key", SYSTEMD_CREDENTIAL_FILENAME, OS_TIER_MARKER_FILENAME)


class PassphraseCustodyError(Exception):
    """The wrapped key cannot be created, read or unlocked. The message is safe to print."""


class Locked(PassphraseCustodyError):
    """A wrapped key exists but there is no terminal to ask for the passphrase."""


def wrapped_path(vault_dir: Path) -> Path:
    return Path(vault_dir) / WRAPPED_FILENAME


def wrapped_present(vault_dir: Path) -> bool:
    """Whether a wrapped key sits beside ``vault_dir``.

    ``lstat``, and any failure other than "not found" counts as present: a
    lookup that cannot rule the file out must not let another key stand in.
    """
    try:
        os.lstat(wrapped_path(vault_dir))
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def other_custody_present(vault_dir: Path) -> Optional[str]:
    """The name of a file showing that another custody holds this store's key, or None."""
    for name in OTHER_CUSTODY_FILES:
        try:
            os.lstat(Path(vault_dir) / name)
        except FileNotFoundError:
            continue
        except OSError:
            return name
        return name
    return None


def prompt_passphrase(prompt: str = "Passphrase: ", *, confirm: bool = False) -> str:
    """Ask for the passphrase on the terminal without echo.

    ``getpass`` falls back to echoing stdin, with only a warning, when it cannot
    control a terminal; that is refused. Raises :class:`Locked` when there is no
    terminal at all, so an unattended caller fails instead of hanging.
    """
    if not sys.stdin.isatty() and not _has_controlling_terminal():
        raise Locked(
            "the store's key is passphrase-protected and there is no terminal to ask for "
            "the passphrase; run this command from an interactive terminal"
        )
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            first = getpass.getpass(prompt)
            if confirm and getpass.getpass("Repeat passphrase: ") != first:
                raise PassphraseCustodyError("the two passphrases differ; nothing was created")
    except getpass.GetPassWarning:
        raise PassphraseCustodyError(
            "cannot hide the passphrase here (no secure terminal); nothing was read"
        ) from None
    except (EOFError, KeyboardInterrupt):
        raise PassphraseCustodyError("no passphrase entered") from None
    if not first:
        raise PassphraseCustodyError("the passphrase must not be empty")
    return first


def _has_controlling_terminal() -> bool:
    try:
        fd = os.open(os.ctermid() if hasattr(os, "ctermid") else "CON", os.O_RDWR)
    except OSError:
        return False
    os.close(fd)
    return True


def create_wrapped_key(vault_dir: Path, passphrase: str) -> Path:
    """Create a random master key, wrap it beside ``vault_dir`` and return the file's path.

    Refuses when another custody already holds a key for the directory. The
    wrapped file is unwrapped again before this returns, so a file that cannot
    be opened is found here, not at the first ``run``. It is created exclusively
    with mode 0600 and never replaced. The key itself is not returned: it leaves
    this module only through :func:`read_key`, after an unlock.
    """
    other = other_custody_present(vault_dir)
    if other is not None:
        raise PassphraseCustodyError(
            f"{Path(vault_dir) / other} shows that another custody holds a key for this "
            "directory; a second key would fork the store"
        )
    key = secrets.token_bytes(32)
    path = wrapped_path(vault_dir)
    try:
        _mkdir_owner_only(Path(vault_dir))
        payload = passphrase_store.wrap(key, passphrase)
        write_protected(
            payload,
            path,
            header=passphrase_store.MAGIC,
            expected_length=passphrase_store.PAYLOAD_BYTES,
        )
    except ProtectedStoreError as exc:
        raise PassphraseCustodyError(f"cannot create {path}: {exc}") from None
    except (OSError, ValueError) as exc:
        raise PassphraseCustodyError(f"cannot create {path} ({type(exc).__name__})") from None
    check = read_key(vault_dir, passphrase)
    if check != key:
        raise PassphraseCustodyError(
            f"{path} did not unwrap to the same key; the key is not usable, nothing else changed"
        )
    return path


def read_key(vault_dir: Path, passphrase: str) -> Optional[bytes]:
    """The master key unwrapped from the file beside ``vault_dir``, or None if absent.

    None means only that no wrapped file exists. One that exists but cannot be
    opened (wrong passphrase, altered, unsafe permissions) raises: the store's
    key is there, so nothing else may stand in for it.
    """
    path = wrapped_path(vault_dir)
    try:
        payload = read_protected(
            path,
            header=passphrase_store.MAGIC,
            expected_length=passphrase_store.PAYLOAD_BYTES,
        )
    except ProtectedStoreMissing:
        return None
    except ProtectedStoreError as exc:
        raise PassphraseCustodyError(f"{path}: {exc}") from None
    try:
        return bytes(passphrase_store.unwrap(payload, passphrase))
    except passphrase_store.PassphraseStoreError as exc:
        raise PassphraseCustodyError(str(exc)) from None
    except ValueError as exc:
        raise PassphraseCustodyError(str(exc)) from None

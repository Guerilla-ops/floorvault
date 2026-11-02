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

import contextlib
import getpass
import os
import secrets
import sys
import warnings
from pathlib import Path
from typing import Optional

from ._filelock import exclusive_lock
from .providers import passphrase_store
from .providers.adaptive import (
    OS_TIER_MARKER_FILENAME,
    SYSTEMD_CREDENTIAL_FILENAME,
    TIER3_LOCK_FILENAME,
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


def _creation_lock(vault_dir: Path):
    """The Tier-3 creation lock (``master.key.lock``), shared with the library's resolvers.

    A raw-key resolver and this module publish different files (``master.key``,
    ``master.key.fvpw``), so no-clobber publication cannot stop both: only the
    shared lock, with the other-custody check repeated under it, can.
    """
    try:
        _mkdir_owner_only(Path(vault_dir))
    except FileExistsError:
        _mkdir_owner_only(Path(vault_dir))  # lost a creation race; the directory exists now
    return exclusive_lock(Path(vault_dir) / TIER3_LOCK_FILENAME)


def raw_key_present(vault_dir: Path) -> bool:
    """Whether a raw ``master.key`` sits beside ``vault_dir``.

    ``lstat``, and any failure other than "not found" counts as present, so an
    unsafe path or a lookup that cannot rule the file out is never taken for absent.
    """
    try:
        os.lstat(Path(vault_dir) / "master.key")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def refuse_raw_companion(vault_dir: Path) -> None:
    """Raise when a raw ``master.key`` sits beside a wrapped key.

    That is a usable plaintext copy of the key (for example after an interrupted
    ``protect``), which defeats the wrapping; the library's provider refuses it
    too (SPEC §10.8). The message says what to do.
    """
    if raw_key_present(vault_dir):
        raise PassphraseCustodyError(
            f"a raw {Path(vault_dir) / 'master.key'} sits beside the passphrase-wrapped key; "
            "it is a usable plaintext copy of the key and defeats the wrapping. If it is the "
            "same key (an interrupted `protect`), check that the store opens with the "
            "passphrase, then delete the raw file; nothing was opened"
        )


def read_raw_key(vault_dir: Path) -> bytes:
    """The key in the raw ``master.key`` beside ``vault_dir`` (64 hex or 32 bytes)."""
    path = Path(vault_dir) / "master.key"
    try:
        raw = read_protected(path, header=b"", expected_length=None)
    except ProtectedStoreMissing:
        raise PassphraseCustodyError(f"no raw key file at {path}") from None
    except ProtectedStoreError as exc:
        raise PassphraseCustodyError(f"{path}: {exc}") from None
    if len(raw) == 64:
        try:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            raise PassphraseCustodyError(f"{path} is not a valid hexadecimal key") from None
    if len(raw) != 32:
        raise PassphraseCustodyError(f"{path} does not hold a 32-byte key")
    return bytes(raw)


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

    Under the Tier-3 creation lock, and refusing when another custody already
    holds a key for the directory (checked again under the lock, so a raw-key
    resolver that published first is seen). The wrapped file is unwrapped again
    before this returns, so a file that cannot be opened is found here, not at
    the first ``run``. It is created exclusively with mode 0600 and never
    replaced. The key itself is not returned: it leaves this module only through
    :func:`read_key`, after an unlock.
    """
    path = wrapped_path(vault_dir)
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(_creation_lock(vault_dir))
        except (OSError, ValueError) as exc:
            raise PassphraseCustodyError(
                f"cannot take the creation lock for {vault_dir} ({type(exc).__name__})"
            ) from None
        other = other_custody_present(vault_dir)
        if other is not None:
            raise PassphraseCustodyError(
                f"{Path(vault_dir) / other} shows that another custody holds a key for this "
                "directory; a second key would fork the store"
            )
        key = secrets.token_bytes(32)
        try:
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
                f"{path} did not unwrap to the same key; the key is not usable, "
                "nothing else changed"
            )
    return path


def read_key(vault_dir: Path, passphrase: str) -> Optional[bytes]:
    """The master key unwrapped from the file beside ``vault_dir``, or None if absent.

    None means only that no wrapped file exists. One that exists but cannot be
    opened (wrong passphrase, altered, unsafe permissions) raises: the store's
    key is there, so nothing else may stand in for it.
    """
    path = wrapped_path(vault_dir)
    refuse_raw_companion(vault_dir)
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

"""Master-key custody through ``systemd-creds`` (systemd 256 or newer).

``floorvault secrets init --custody systemd-creds`` creates a random master key
and seals it with ``systemd-creds encrypt --user``. The credential is bound to
the calling user's UID, username and the machine-id. Which further secret it
is bound to (the host's credential key, a TPM2 chip, or both) is chosen by
systemd's automatic selection, not by floorvault: for an unprivileged caller
``systemd-creds encrypt`` hands the request to systemd without a key choice, so
floorvault offers no ``--with-key`` and does not report what systemd picked.
It is stored beside the vault as ``master.key.sdcred``; ``floorvault run`` and
``floorvault secrets`` find it there and unseal it with ``systemd-creds decrypt
--user`` without a prompt.

Rules this module keeps:

* It fails closed. Without a usable ``systemd-creds`` (Linux, systemd 256 or
  newer) it raises; nothing falls back to a weaker custody.
* The helper is looked up only in system directories, never on ``$PATH`` and
  never through an environment variable, so a configuration that sets
  variables for ``floorvault run`` cannot substitute a program that receives
  the new key or returns a chosen one.
* The key travels through pipes only: never argv, the environment or a
  temporary file. The helper runs with a minimal environment.
* Messages name paths and exit codes, never key material.

Decryption passes ``--refuse-null`` where the helper has it (systemd 259 and
newer), so a null-key credential, which carries no authentication, is refused.
On 256 to 258 the only defence against a planted credential is the file's
ownership and mode check.

Not verified here: unattended decryption on a real host (no login session, a
service, cron), which systemd versions and distributions ship ``--user``, and
whether cloud images expose a TPM2, and which key systemd's automatic selection
used for a given credential. See docs/USAGE.md.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
import subprocess  # nosec B404 - runs the system's own systemd-creds, as a list, no shell
import sys
from pathlib import Path
from typing import Optional

from .providers.adaptive import SYSTEMD_CREDENTIAL_FILENAME
from .providers.platform_custody import _mkdir_owner_only

__all__ = [
    "CREDENTIAL_FILENAME",
    "CREDENTIAL_NAME",
    "MIN_SYSTEMD_VERSION",
    "SystemdCredsError",
    "create_credential",
    "credential_path",
    "credential_present",
    "read_key",
]

CREDENTIAL_FILENAME = SYSTEMD_CREDENTIAL_FILENAME
#: Embedded in the credential and checked on decrypt, so it cannot be reused
#: for another purpose without notice.
CREDENTIAL_NAME = "floorvault.master-key"
MIN_SYSTEMD_VERSION = 256  # first release with `systemd-creds --user`
REFUSE_NULL_SINCE = 259  # first release with `decrypt --refuse-null`
#: Where the helper is looked for. Deliberately not ``$PATH``.
SEARCH_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/run/current-system/sw/bin")
TIMEOUT_SECONDS = 30
_MAX_CREDENTIAL_BYTES = 16 * 1024
_HEX_KEY = re.compile(r"[0-9A-Fa-f]{64}")
_HELPER_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


class SystemdCredsError(Exception):
    """``systemd-creds`` is unusable or refused. The message is safe to print."""


def credential_path(vault_dir: Path) -> Path:
    return Path(vault_dir) / CREDENTIAL_FILENAME


def credential_present(vault_dir: Path) -> bool:
    """Whether a credential sits beside ``vault_dir``.

    ``lstat``, and any failure other than "not found" counts as present: a
    lookup that cannot rule the credential out must not let another key stand in.
    """
    try:
        os.lstat(credential_path(vault_dir))
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _find_binary() -> str:
    if sys.platform != "linux":
        raise SystemdCredsError("systemd-creds custody is available on Linux only")
    for directory in SEARCH_DIRS:
        candidate = os.path.join(directory, "systemd-creds")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise SystemdCredsError(
        "systemd-creds not found in " + ", ".join(SEARCH_DIRS) + ". This custody needs "
        f"systemd {MIN_SYSTEMD_VERSION} or newer; it never falls back to a weaker one"
    )


def _run(argv: list[str], data: Optional[bytes] = None) -> "subprocess.CompletedProcess[bytes]":
    try:
        return subprocess.run(  # nosec B603 - fixed system binary, list argv, no shell
            argv,
            input=data,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            env=dict(_HELPER_ENV),
        )
    except subprocess.TimeoutExpired:
        raise SystemdCredsError(f"systemd-creds did not finish in {TIMEOUT_SECONDS}s") from None
    except OSError as exc:
        raise SystemdCredsError(f"cannot run systemd-creds ({type(exc).__name__})") from None


def _stderr_line(result: "subprocess.CompletedProcess[bytes]") -> str:
    """First line of the helper's stderr, trimmed. Never stdout, which can hold a key."""
    text = (result.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    return text[0][:200] if text else ""


def _failure(action: str, result: "subprocess.CompletedProcess[bytes]") -> SystemdCredsError:
    detail = _stderr_line(result)
    return SystemdCredsError(
        f"systemd-creds {action} failed (exit {result.returncode})"
        + (f": {detail}" if detail else "")
    )


def _require_binary(binary: Optional[str] = None) -> tuple[str, int]:
    """The helper's path and systemd version after checking it is new enough, or raise."""
    binary = binary or _find_binary()
    result = _run([binary, "--version"])
    first = (result.stdout or b"").decode("utf-8", "replace").splitlines()
    match = re.match(r"systemd (\d+)", first[0]) if result.returncode == 0 and first else None
    if match is None:
        raise SystemdCredsError(f"{binary} --version did not report a systemd version")
    version = int(match.group(1))
    if version < MIN_SYSTEMD_VERSION:
        raise SystemdCredsError(
            f"systemd {version} found, but `systemd-creds --user` needs "
            f"{MIN_SYSTEMD_VERSION} or newer. This custody never falls back to a weaker one"
        )
    return binary, version


def _encrypt(binary: str, plaintext: bytes) -> bytes:
    # No --with-key: an unprivileged `systemd-creds encrypt` ignores it (it sends the
    # request to systemd without a key choice, whatever the option says), and `tpm2`
    # alone is refused with --user. Offering it would claim a binding nothing enforces.
    argv = [binary, "encrypt", "--user", f"--name={CREDENTIAL_NAME}", "-", "-"]
    result = _run(argv, plaintext)
    if result.returncode != 0 or not result.stdout.strip():
        raise _failure("encrypt", result)
    return result.stdout


def _decrypt(binary: str, version: int, ciphertext: bytes) -> bytes:
    argv = [binary, "decrypt", "--user", f"--name={CREDENTIAL_NAME}"]
    if version >= REFUSE_NULL_SINCE:
        # A null-key credential carries no authentication, so anyone able to write
        # the file could forge one holding a key of their choosing.
        argv.append("--refuse-null")
    result = _run([*argv, "-", "-"], ciphertext)
    if result.returncode != 0:
        raise _failure("decrypt", result)
    return result.stdout


def _parse_key(plaintext: bytes) -> bytes:
    try:
        text = plaintext.decode("ascii").strip()
    except UnicodeDecodeError:
        raise SystemdCredsError("the unsealed credential is not a master key") from None
    if not _HEX_KEY.fullmatch(text):
        raise SystemdCredsError("the unsealed credential is not 64 hexadecimal characters")
    return bytes.fromhex(text)


def create_credential(vault_dir: Path, *, binary: Optional[str] = None) -> Path:
    """Create a random master key, seal it beside ``vault_dir`` and return the file's path.

    The credential is unsealed again before anything is written, so a host that
    can encrypt but not decrypt (or the reverse) fails here, not at the first
    ``run``. The file is created exclusively with mode 0600 and never replaced.
    """
    binary, version = _require_binary(binary)
    plaintext = (secrets.token_bytes(32).hex() + "\n").encode("ascii")
    ciphertext = _encrypt(binary, plaintext)
    if _decrypt(binary, version, ciphertext) != plaintext:
        raise SystemdCredsError(
            "the sealed credential did not unseal to the same key; nothing written"
        )
    path = credential_path(vault_dir)
    try:
        _mkdir_owner_only(Path(vault_dir))
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        raise SystemdCredsError(f"{path} already exists; it is never replaced") from None
    except (OSError, ValueError) as exc:
        raise SystemdCredsError(f"cannot create {path} ({type(exc).__name__})") from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(ciphertext)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass  # best effort: the write error below is the one to report
        raise
    return path


def read_key(vault_dir: Path, *, binary: Optional[str] = None) -> Optional[bytes]:
    """The master key unsealed from the credential beside ``vault_dir``, or None if absent.

    None means only that no credential exists. A credential that exists but
    cannot be unsealed raises: the store's key is there, so nothing else may
    stand in for it.
    """
    path = credential_path(vault_dir)
    try:
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemdCredsError(f"{path}: cannot open ({type(exc).__name__})") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise SystemdCredsError(f"{path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise SystemdCredsError(f"{path} is owned by another user")
        if st.st_mode & 0o022:
            raise SystemdCredsError(f"{path} is writable by group or others; run chmod go-w on it")
        if st.st_size > _MAX_CREDENTIAL_BYTES:
            raise SystemdCredsError(f"{path} is too large to be a credential")
        ciphertext = handle.read(_MAX_CREDENTIAL_BYTES + 1)
    binary, version = _require_binary(binary)
    return _parse_key(_decrypt(binary, version, ciphertext))

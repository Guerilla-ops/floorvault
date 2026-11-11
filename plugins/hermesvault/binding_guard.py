"""Command-binding checks for the hermesvault secret source.

``floorvault secrets allow`` binds an item to command lines. Inside Hermes the
command is Hermes itself, so the secret source compares the command line Hermes
was started with to the item's bindings. This module holds that logic apart from
the Hermes host contract (it imports nothing from ``agent``), so the repository's
own test run, which has no Hermes checkout, can test it.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Tuple


def hermes_command_lines() -> list[list[str]]:
    """The command lines this process was started with, as ``secrets allow`` records them.

    A binding is the program's absolute path, then its arguments. Hermes started
    through its script (``hermes gateway run``) is ``[<path of hermes>, gateway,
    run]``, which is ``sys.argv``. Started with the interpreter (``python -m
    hermes_cli gateway run``) it is ``[<python>, -m, hermes_cli, gateway, run]``,
    which is ``sys.orig_argv`` with the interpreter's own path. Both describe this
    process, and either may be what an operator bound.

    Only an absolute program path is used. A relative one (``./hermes``) would be
    resolved against the working directory *now*, which may no longer be the one
    Hermes started in, and could name a different program; it is left out, so a
    binding cannot match it.
    """
    lines: list[list[str]] = []
    argv = list(getattr(sys, "argv", None) or [])
    if argv and argv[0] and os.path.isabs(argv[0]):
        lines.append([os.path.abspath(argv[0]), *argv[1:]])
    original = list(getattr(sys, "orig_argv", None) or [])
    if len(original) > 1 and sys.executable and os.path.isabs(sys.executable):
        interpreted = [os.path.abspath(sys.executable), *original[1:]]
        if interpreted not in lines:
            lines.append(interpreted)
    return lines


def gateway_command_line(home) -> Optional[list[str]]:
    """The command line Hermes starts its local gateway with, for a client of ``home``.

    Chat and one-shot commands resolve secrets in a gateway that the client starts
    detached (``spawn_unmanaged_gateway``): this interpreter, ``-m hermes_cli.main``,
    ``--profile default`` unless the home is a ``profiles/<name>`` directory, then
    ``gateway run --quiet --idle-exit``. A binding must equal that argv exactly, so
    this returns the same list, built from the same two inputs Hermes uses. Hermes
    rewrites the line on Windows (a windowless interpreter), so there it is None; a
    gateway run by a service or by hand has its own line, which the skip warning
    prints and ``hermes hvault allow`` records.
    """
    if sys.platform == "win32" or not sys.executable or not os.path.isabs(sys.executable):
        return None
    resolved = Path(home).resolve()
    selector = [] if resolved.parent.name == "profiles" else ["--profile", "default"]
    return [
        os.path.abspath(sys.executable),
        "-m",
        "hermes_cli.main",
        *selector,
        "gateway",
        "run",
        "--quiet",
        "--idle-exit",
    ]


def started_as() -> str:
    """How this process was started, for a warning that tells the operator what to bind.

    Names the command line(s) ``secrets allow`` can record: ``allow`` refuses a program
    that is not executable on PATH (what `shutil.which` finds), so a script run as ``python script.py`` is bound as the
    interpreter line, and showing ``script.py ...`` alone would be advice that fails.
    """
    argv = list(getattr(sys, "argv", None) or [])
    if not argv:
        return "an unknown command line"
    lines = hermes_command_lines()
    bindable = [line for line in lines if shutil.which(line[0])] or lines
    text = " or ".join(shlex.join(line) for line in bindable) if bindable else shlex.join(argv)
    if argv[0] and not os.path.isabs(argv[0]):
        text += " (a relative program path cannot be matched; start Hermes with its absolute path)"
    return text


def _bind_command(store, item_id: str) -> str:
    """The command that binds ``item_id`` with the floorvault that is installed.

    ``hermes hvault allow`` keeps the sealed binding record of floorvault 0.3.0
    (``binding_fingerprint``). floorvault 0.2.x reads and enforces bindings but
    only ``floorvault secrets allow`` writes them, so a hint naming the first
    would send a 0.2.x user to a command that refuses.
    """
    if hasattr(store, "binding_fingerprint"):
        return f"hermes hvault allow {item_id} -- <command line>"
    return f"floorvault secrets allow {item_id} -- <command line>"


def binding_record_problems(
    store, base, item_ids: Iterable[str], environ: Optional[Mapping[str, str]] = None
) -> Tuple[dict, list]:
    """Check the items' stored bindings against the record `allow` keeps outside the store.

    A binding lives in vault.db, so whoever can write that file can clear one, or
    write back an older sealed binding of the same item, without the key (#97).
    Both still decrypt. ``hermes hvault allow``, ``hermes hvault bind`` and
    ``floorvault secrets allow`` keep each binding's fingerprint in the state
    directory, which a writer of the store need not reach; this compares against
    it and writes nothing.

    Returns ``(problems, notes)``. ``problems`` maps an item id to the reason it
    must not be resolved: its binding differs from the record, or a record exists
    and cannot be read (which never counts as "unchanged"). ``notes`` are warnings
    for the operator when no record can be consulted here; the items are then
    judged by the store alone, as they were before this check existed, and the
    note says so. An item the record does not hold is a first use and has no
    problem. A floorvault without ``BindingRecord.compare`` (0.4.0 and older)
    has no way to read the record without writing it, so nothing is checked; a
    note says so, because the check would otherwise be silently absent.
    """
    too_old = [
        "floorvault 0.4.0 or older cannot check the binding record, so a binding cleared or "
        "rolled back in vault.db is not noticed here; upgrade floorvault to a newer release"
    ]
    try:
        from floorvault.binding_record import (
            BindingRecord,
            BindingRecordError,
            BindingRecordLost,
            default_state_dir,
        )
    except ImportError:
        return {}, too_old
    fingerprint = getattr(store, "binding_fingerprint", None)
    if fingerprint is None or not hasattr(BindingRecord, "compare"):
        return {}, too_old
    current = {}
    for item_id in item_ids:
        try:
            current[item_id] = fingerprint(item_id)
        except Exception:  # nosec B112 - not swallowed: resolving the item reports it
            # A missing item, or a store that cannot be read: resolving it reports that.
            continue
    if not current:
        return {}, []
    try:
        state_dir = default_state_dir(os.environ if environ is None else environ)
    except RuntimeError:  # no home directory to put the default under
        return {}, [
            "the binding record cannot be located (no home directory and no "
            "$FLOOR_VAULT_STATE_DIR), so a binding cleared or replaced in vault.db is "
            "not noticed here"
        ]
    try:
        record = BindingRecord(base, state_dir)
    except BindingRecordError as exc:  # the state directory is inside the store
        return {}, [
            f"no binding record can be kept: {exc}; a binding cleared or replaced in "
            "vault.db is not noticed here"
        ]
    try:
        changed = record.compare(current)
    except BindingRecordLost as exc:
        return {}, [
            f"{exc}, though this store has had one (a state directory that was wiped, "
            "or a different $FLOOR_VAULT_STATE_DIR than `hermes hvault allow` ran with), "
            "so a binding cleared or replaced in vault.db is not noticed here"
        ]
    except BindingRecordError as exc:
        reason = f"cannot be checked against the binding record: {exc}"
        return {item_id: reason for item_id in current}, []
    return {
        item_id: (
            "has a command binding that changed since it was last recorded: cleared, "
            "or replaced outside `hermes hvault allow` (an older copy written back into "
            f"vault.db looks like this). Check it with `hermes hvault show hv:{item_id}`; "
            f"if the change was yours, accept it with `hermes hvault allow {item_id} --accept`"
        )
        for item_id in changed
    }, []


def binding_problem(
    store,
    item_id: str,
    command_lines: Optional[Sequence[Sequence[str]]],
    require_binding: bool,
) -> Optional[str]:
    """Why ``item_id`` may not be resolved for this process, or None when it may.

    Fails closed: a binding that cannot be read or compared is a reason to skip
    the item, never a reason to release it. A binding lives in vault.db, so
    whoever can write that file can clear one without the key (#97).
    ``require_binding``, which lives in Hermes' configuration, turns a cleared
    binding into a refusal; :func:`binding_record_problems` notices one that was
    recorded and then cleared or replaced. ``command_lines`` None skips only the
    comparison with this process's command line (see ``fetch_for``).
    """
    getter = getattr(store, "get_allowed_commands", None)
    if getter is None:
        # floorvault before 0.2.8 cannot hold or read bindings.
        if require_binding:
            return "cannot be checked for a command binding: floorvault is older than 0.2.8"
        return None
    try:
        allowed = getter(item_id)
    except Exception:
        return "has a command binding that cannot be read"
    if allowed is None:
        if require_binding:
            return (
                "has no command binding, and secrets.hermesvault.require_binding is set; "
                f"bind it with `{_bind_command(store, item_id)}`"
            )
        return None
    if command_lines is None:
        return None
    try:
        from floorvault.agentenv import command_allowed
    except ImportError:
        return "has a command binding that this floorvault cannot compare"
    if any(command_allowed(line, allowed) for line in command_lines):
        return None
    return (
        "is bound to other command lines than the one Hermes was started with "
        f"({started_as()}); bind that with `{_bind_command(store, item_id)}`"
    )

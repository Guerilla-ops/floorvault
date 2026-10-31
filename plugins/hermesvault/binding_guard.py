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
import sys
from typing import Optional, Sequence


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


def started_as() -> str:
    """How this process was started, for a warning that tells the operator what to bind."""
    argv = list(getattr(sys, "argv", None) or [])
    if not argv:
        return "an unknown command line"
    text = shlex.join(argv)
    if argv[0] and not os.path.isabs(argv[0]):
        text += " (a relative program path cannot be matched; start Hermes with its absolute path)"
    return text


def binding_problem(
    store, item_id: str, command_lines: Sequence[Sequence[str]], require_binding: bool
) -> Optional[str]:
    """Why ``item_id`` may not be resolved for this process, or None when it may.

    Fails closed: a binding that cannot be read or compared is a reason to skip
    the item, never a reason to release it. A binding lives in vault.db, so
    whoever can write that file can clear one without the key (#97); only
    ``require_binding``, which lives in Hermes' configuration, turns a cleared
    binding into a refusal.
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
                f"bind it with `floorvault secrets allow {item_id} -- <command line>`"
            )
        return None
    try:
        from floorvault.agentenv import command_allowed
    except ImportError:
        return "has a command binding that this floorvault cannot compare"
    if any(command_allowed(line, allowed) for line in command_lines):
        return None
    return (
        "is bound to other command lines than the one Hermes was started with "
        f"({started_as()}); bind that with `floorvault secrets allow {item_id} -- <command line>`"
    )

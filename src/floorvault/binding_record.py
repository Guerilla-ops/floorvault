"""A record of each item's command binding, kept outside the store (RUN-9, #97).

A binding is sealed under its item's id, so it cannot be forged or moved to
another item without the key. But it lives in ``vault.db``, and whoever can
write that file can clear the column or write back an older sealed binding of
the same item, and both still decrypt. Nothing inside ``vault.db`` can tell
that apart from a change made with the key.

This record can. For every item ``floorvault run`` resolves, it keeps a SHA-256
fingerprint of the sealed binding exactly as stored (or ``none`` when there is
no binding), in a file under the state directory rather than beside the store.
``run`` and ``secrets allow`` compare the stored binding against it and refuse
a mismatch: a cleared binding, an older one written back, or any change made
outside this CLI. ``secrets allow`` and ``secrets rm`` keep it current, and
``secrets allow ITEM --accept`` takes an intended change made by other code.

Limits, stated where they are documented (USAGE, SECURITY):

- **First use is trusted.** An item ``run`` has never seen is recorded as it is.
- **The record must be out of the attacker's reach.** It holds against someone
  who can write or restore the store but not the state directory (a synced or
  shared store, a store-only backup). Someone who can roll both back together,
  or who runs code as you, can defeat it; such code can read the key anyway.
- **The state directory must persist.** A marker file in the store directory
  says a record was kept for the store before. If the record is gone while the
  marker is not (a state directory wiped between runs: a container without a
  volume, a tmpfs, an ephemeral CI runner), :meth:`BindingRecord.lost` says so,
  and ``run`` warns, or with ``$FLOOR_VAULT_REQUIRE_RECORD`` refuses. The marker
  only exists to notice an accident: whoever can write the store directory can
  delete it, which is the same reach that defeats the record.
- The fingerprint is of ciphertext, so the record reveals nothing about the
  bound command lines, and needs no key.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import stat
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional, TypeVar

from .freshness import FileAnchorStore

#: Overrides where the record is kept.
STATE_DIR_ENV = "FLOOR_VAULT_STATE_DIR"

_FORMAT = "FVBR1"
_CAS_RETRIES = 20

#: Dropped in the store directory once a record exists for it (see ``lost``).
MARKER_NAME = ".floorvault-binding-record"
_MARKER_BODY = b"FVBM1\n"

T = TypeVar("T")


class BindingRecordError(Exception):
    """The record cannot be used. The message is safe to print."""


def default_state_dir(environ: Mapping[str, str], platform: str = sys.platform) -> Path:
    """``$FLOOR_VAULT_STATE_DIR``, else the platform's per-user, non-roaming state directory.

    Deliberately not ``~/.floorvault``, which holds the default store: a copy or
    rollback of that directory should not carry the record with it.
    """
    explicit = (environ.get(STATE_DIR_ENV) or "").strip()
    if explicit:
        return Path(explicit).expanduser()
    if platform == "win32":
        local = environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        return base / "floorvault"
    if platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "floorvault"
    xdg = environ.get("XDG_STATE_HOME") or ""
    # XDG paths are POSIX paths; judge them so whatever host this runs on.
    base = Path(xdg) if posixpath.isabs(xdg) else Path.home() / ".local" / "state"
    return base / "floorvault"


class BindingRecord:
    """The recorded binding fingerprints for one store directory."""

    def __init__(self, vault_dir: Path, state_dir: Path) -> None:
        vault = Path(os.path.realpath(vault_dir))
        state = Path(os.path.realpath(state_dir))
        if state == vault or vault in state.parents:
            raise BindingRecordError(
                f"the binding record directory {state} is inside the store at {vault}, so "
                f"restoring the store would restore the record with it; set ${STATE_DIR_ENV} "
                "to a directory outside the store"
            )
        self._vault = str(vault)
        self._name = hashlib.sha256(self._vault.encode("utf-8")).hexdigest()
        self._anchors = FileAnchorStore(state / "bindings")
        self.path = state / "bindings" / f"{self._name}.fvanchor"
        self.marker_path = vault / MARKER_NAME

    def _parse(self, raw: Optional[bytes]) -> dict[str, str]:
        if raw is None:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
            items = data["items"]
            valid = (
                data.get("format") == _FORMAT
                and data.get("vault") == self._vault
                and isinstance(items, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in items.items())
            )
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            valid = False
        if not valid:
            raise BindingRecordError(
                f"the binding record {self.path} is unreadable; move it aside to start a new "
                "record (every item is then trusted as it is on its next use)"
            )
        return dict(items)

    def _encode(self, items: Mapping[str, str]) -> bytes:
        payload = {"format": _FORMAT, "vault": self._vault, "items": dict(sorted(items.items()))}
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _update(self, change: Callable[[dict[str, str]], T]) -> T:
        """Apply ``change`` to the items with compare-and-swap; return its result."""
        try:
            for _ in range(_CAS_RETRIES):
                raw = self._anchors.load(self._name)
                items = self._parse(raw)
                before = dict(items)
                result = change(items)
                if items == before:
                    if raw is not None:
                        self._ensure_marker()
                    return result
                if self._anchors.compare_and_swap(self._name, raw, self._encode(items)):
                    self._ensure_marker()
                    return result
        except OSError as exc:
            raise BindingRecordError(
                f"cannot use the binding record in {self.path.parent} ({type(exc).__name__}); "
                f"set ${STATE_DIR_ENV} to a writable directory outside the store"
            ) from None
        raise BindingRecordError(f"the binding record {self.path} kept changing; try again")

    def _ensure_marker(self) -> None:
        """Leave the marker that says this store has had a record. Best effort."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            if os.path.lexists(self.marker_path):
                return
            fd = os.open(self.marker_path, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(_MARKER_BODY)
        except OSError:
            # A read-only store directory, or a racing writer: the record still
            # works; only the lost-record notice is unavailable.
            pass

    def lost(self) -> bool:
        """Whether a record was kept for this store before and is gone now.

        True when the marker is in the store directory but the record file is
        not in the state directory: the state directory was wiped, replaced or
        pointed elsewhere since the last run. Every item is then trusted as it
        is, as on a first use, and nothing else says so. Never raises.
        """
        try:
            if not stat.S_ISREG(os.lstat(self.marker_path).st_mode):
                return False
            return self._anchors.load(self._name) is None
        except OSError:
            return False

    def check(self, current: Mapping[str, str]) -> list[str]:
        """Return the items whose binding differs from the record, sorted.

        ``current`` maps item ids to their binding's fingerprint as stored
        now (:meth:`VaultStore.binding_fingerprint`). Items the record does not hold yet are added as they are.
        """

        def change(items: dict[str, str]) -> list[str]:
            changed = sorted(i for i, fp in current.items() if i in items and items[i] != fp)
            for item_id, fp in current.items():
                items.setdefault(item_id, fp)
            return changed

        return self._update(change)

    def record(self, item_id: str, fp: str) -> None:
        """Record ``item_id``'s binding as it is now (after this CLI changed it)."""

        def change(items: dict[str, str]) -> None:
            items[item_id] = fp

        self._update(change)

    def forget(self, item_id: str) -> None:
        """Drop ``item_id`` from the record (the item was deleted)."""

        def change(items: dict[str, str]) -> None:
            items.pop(item_id, None)

        self._update(change)

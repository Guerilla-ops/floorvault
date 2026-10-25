"""Linux Secret Service / keyring-backed master key provider.

Primary: the freedesktop Secret Service (GNOME Keyring / KWallet via the
`secretstorage` package) when it is reachable and a desktop session is present.
Fallback (headless / no D-Bus / library absent): a fail-closed protected file
exactly like the DPAPI provider, so the round-trip contract is testable on any
platform.

The fallback file is masked, NOT encrypted: the pad is a deterministic function
of the service name, a public constant, so a copy of the store is enough to
recover the key. Its protection is the 0600 owner-only file mode (and the ACL on
Windows), not the mask. See the "file-based key fallbacks are not a
confidentiality boundary" limit in SECURITY.md.

Fail-closed: if Secret Service is expected (interactive desktop) but cannot be
reached, and no key file exists yet, a MissingKeyError is raised rather than
silently writing an unprotected key.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable

from .._filelock import exclusive_lock
from ..memory import HardenedMemoryKey
from ..platform_support import is_linux
from .base import CustodyDowngradeError, KeyProvider, KeyProviderError, MissingKeyError
from .platform_custody import (
    LEGACY_STORE_NAME,
    ProtectedStoreError,
    ProtectedStoreMissing,
    _mkdir_owner_only,
    read_scheme_store,
    store_path_for,
    write_protected,
)

_HEADER = b"FLOORLV1"  # floorvault protected key store, linux/secret-service boundary

#: ``secretstorage`` module-level callables this client calls by name.
#:
#: Pinned here so the contract test can assert each one exists in the installed
#: package. The shipped defect was exactly this class of error: the client
#: imported ``SecretServiceNotAvailable`` (the real class is
#: ``SecretServiceNotAvailableException``) and called ``get_default_bus`` /
#: ``DBusAddressConnection``, none of which the library defines. The import
#: failed inside ``except ImportError: return None``, so the tier reported
#: "unavailable" forever and no test could see it.
_REQUIRED_SECRETSTORAGE_API = ("dbus_init", "get_default_collection", "get_collection_by_alias")

#: The exception raised by ``secretstorage`` when no session bus / service is
#: reachable. Named as a string so the contract test compares names rather than
#: importing a package that is absent on non-Linux hosts.
_SECRET_SERVICE_UNAVAILABLE_EXCEPTION = "SecretServiceNotAvailableException"  # nosec B105

#: ``secretstorage`` attribute key naming the application boundary.
_ATTRIBUTE_APPLICATION = "application"

#: Attribute key binding an entry to a floorvault account within the service.
_ATTRIBUTE_KEY = "floorvault"

#: Raised by ``get_collection_by_alias`` when no collection has the alias.
_ITEM_NOT_FOUND_EXCEPTION = "ItemNotFoundException"


def _random(n: int) -> bytes:
    return os.urandom(n)


def _looks_interactive_desktop() -> bool:
    return bool(
        os.environ.get("DISPLAY")
        or os.environ.get("WAYLAND_DISPLAY")
        or os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    )


def _secretstorage_api_gap(secretstorage, exceptions) -> str | None:
    """Names this client needs that the installed ``secretstorage`` lacks.

    Returns ``None`` when the API surface matches. Checked at call time rather
    than relying on an import to fail: an ``AttributeError`` deep inside the
    tier is indistinguishable from a broken service, whereas a pre-flight check
    produces an accurate message and a distinct failure.
    """
    missing = [name for name in _REQUIRED_SECRETSTORAGE_API if not hasattr(secretstorage, name)]
    if not hasattr(exceptions, _SECRET_SERVICE_UNAVAILABLE_EXCEPTION):
        missing.append(f"exceptions.{_SECRET_SERVICE_UNAVAILABLE_EXCEPTION}")
    return ", ".join(missing) if missing else None


class LinuxSecretServiceKeyProvider(KeyProvider):
    """Linux Secret Service master-key provider (with fail-closed fallback)."""

    #: Names this scheme's on-disk store: ``master.key.ss``. Distinct from the
    #: tier-3 raw key file (``master.key``) and the DPAPI store
    #: (``master.key.dpapi``) because the three formats are mutually unreadable
    #: and sharing one path locked whichever tier ran second out of the data.
    STORE_SCHEME = "ss"

    @classmethod
    def default_store_path(cls, base_dir: str | Path) -> Path:
        """Canonical store path for this scheme under ``base_dir``."""
        return store_path_for(base_dir, cls.STORE_SCHEME)

    def _legacy_store_path(self) -> Path:
        """Where this scheme's store lived before the schemes were separated."""
        return self._path.with_name(LEGACY_STORE_NAME)

    def __init__(
        self,
        *,
        store_path: str | Path,
        service: str = "floorvault",
        attribute: str = "master-key",
        random_bytes: Callable[[int], bytes] = _random,
        allow_file_fallback: bool = True,
        allow_legacy_adoption: bool = False,
        interactive: bool = True,
    ) -> None:
        if not service or not isinstance(service, str):
            raise ValueError("service must be a non-empty string")
        self._path = Path(store_path)
        self._allow_legacy_adoption = allow_legacy_adoption
        self._service = service
        self._attribute = attribute
        self._random_bytes = random_bytes
        # The masked-file tier is disk custody, so it obeys the caller's disk
        # policy too: AdaptiveKeyProvider passes allow_disk_fallback here, and
        # strict mode must not have an existing master.key.ss silently read for
        # it. Standalone callers keep the documented fallback by default.
        self._allow_file_fallback = allow_file_fallback
        # False: never prompt. The default collection is looked up without
        # being created, a locked collection is reported instead of unlocked,
        # and no key is created through the service.
        self._interactive = interactive

    # ---- Secret Service primary (Linux, interactive) ----------------------

    def _secret_service_available(self) -> bool:
        if not is_linux() or not _looks_interactive_desktop():
            return False
        try:
            import secretstorage  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    def _resolve_via_secret_service(self, *, allow_create: bool) -> HardenedMemoryKey | None:
        """Resolve the key through the freedesktop Secret Service.

        Written against the real ``secretstorage`` API:
        ``dbus_init()`` -> ``get_default_collection(connection)`` ->
        ``Collection.search_items`` -> ``Item.get_attributes()``. Each name is
        verified by :func:`_secretstorage_api_gap` before use, so a library this
        build cannot talk to is reported as such instead of looking absent.

        Returns ``None`` only when the service is genuinely unavailable on this
        session (no session bus), which is not a custody downgrade. Every other
        failure raises rather than falling through to a weaker tier.
        """
        try:
            import secretstorage
            import secretstorage.exceptions as secretstorage_exceptions
        except ImportError:
            return None

        gap = _secretstorage_api_gap(secretstorage, secretstorage_exceptions)
        if gap is not None:
            raise CustodyDowngradeError(
                "the Secret Service library is present but unusable by this build "
                f"(secretstorage does not provide {gap}); refusing to fall back to a "
                "weaker custody tier"
            )
        unavailable = getattr(secretstorage_exceptions, _SECRET_SERVICE_UNAVAILABLE_EXCEPTION)

        item_not_found = getattr(secretstorage_exceptions, _ITEM_NOT_FOUND_EXCEPTION, None)

        connection = None
        try:
            connection = secretstorage.dbus_init()
            if self._interactive:
                # Creates the default collection when there is none (a prompt).
                collection = secretstorage.get_default_collection(connection)
            else:
                try:
                    collection = secretstorage.get_collection_by_alias(connection, "default")
                except Exception as exc:
                    if item_not_found is None or not isinstance(exc, item_not_found):
                        raise
                    raise MissingKeyError(
                        "the Secret Service has no default collection, and it is not "
                        "created without a prompt; set the key up interactively first"
                    ) from None
            if collection.is_locked():
                if not self._interactive:
                    raise KeyProviderError(
                        "the Secret Service collection is locked and is not unlocked "
                        "without a prompt; unlock it (for example by logging in to the "
                        "desktop session) and retry"
                    )
                # ``unlock()`` returns True when the prompt was DISMISSED, i.e.
                # when the unlock did NOT happen - the opposite of the intuitive
                # reading. Re-check the lock state instead of trusting it.
                collection.unlock()
                if collection.is_locked():
                    raise CustodyDowngradeError(
                        "the Secret Service collection is locked and could not be "
                        "unlocked; refusing to fall back to a weaker custody tier"
                    )
            query = {
                _ATTRIBUTE_APPLICATION: self._service,
                _ATTRIBUTE_KEY: self._attribute,
            }
            items = self._matching_items(collection, query)
            if items:
                return self._single_key(items)
            if not allow_create:
                raise MissingKeyError("Secret Service master key not found; recovery is required")
            if not self._interactive:
                raise MissingKeyError(
                    "Secret Service master key not found, and it is not created without "
                    "a prompt; set the key up interactively first"
                )
            # Every store resolved through this service/attribute shares one entry,
            # but callers lock per store directory. Serialize creation on the
            # identity itself, re-check under the lock, and check afterwards that
            # exactly one entry exists, so two first-time resolvers cannot each
            # create a different key under the same attributes.
            with exclusive_lock(self._identity_lock_path()):
                items = self._matching_items(collection, query)
                if items:
                    return self._single_key(items)
                key = self._random_bytes(32)
                collection.create_item(
                    f"{self._service}:{self._attribute}",
                    dict(query),
                    key,
                    replace=False,
                )
                items = self._matching_items(collection, query)
                if len(items) != 1:
                    raise KeyProviderError(
                        f"{len(items)} Secret Service entries now exist for "
                        f"{self._service}/{self._attribute} after creating one; another "
                        "process created a key at the same time. Refusing to choose; "
                        "no entry was changed or removed"
                    )
                return self._single_key(items)
        except unavailable:
            # The tier is genuinely not present on this session: falling through
            # is correct and is not a downgrade.
            return None
        except (KeyProviderError, ProtectedStoreError):
            # Deliberate failures (invalid key length, missing key, locked
            # collection, unusable client) must surface rather than become a
            # silent fall-through. This clause is why they are no longer dead
            # code.
            raise
        except Exception as exc:
            raise CustodyDowngradeError(
                "Secret Service is present but unusable "
                f"({type(exc).__name__}: {exc}); refusing to fall back to a "
                "weaker custody tier"
            ) from exc
        finally:
            # The D-Bus socket is not closed automatically; leaving it open
            # leaks a connection per resolve.
            close = getattr(connection, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 - cleanup must not mask the result  # nosec B110
                    pass

    @staticmethod
    def _matching_items(collection, query: dict[str, str]) -> list:
        return [
            candidate
            for candidate in collection.search_items(query)
            # Exact re-check: a backend that ignores query filters would
            # otherwise hand back another application's entry.
            if all(candidate.get_attributes().get(key) == value for key, value in query.items())
        ]

    def _single_key(self, items: list) -> HardenedMemoryKey:
        """The key the matching entries hold; refuses entries that disagree.

        Duplicates holding the same key are harmless. Duplicates holding
        different keys mean two keys were created for one identity: data may be
        under either, so neither is chosen and nothing is overwritten.
        """
        secrets = []
        for item in items:
            secret = item.get_secret()
            if secret is None or len(secret) != 32:
                # KeyProviderError, not ProtectedStoreError: the latter is a
                # file-store implementation detail. A caller of any tier
                # should see one provider-level error type for "the store
                # holds something that is not a master key".
                raise KeyProviderError("Secret Service entry has an invalid key length")
            secrets.append(bytes(secret))
        if any(secret != secrets[0] for secret in secrets[1:]):
            raise KeyProviderError(
                f"{len(items)} Secret Service entries for {self._service}/{self._attribute} "
                "hold different keys; refusing to choose one. Data may be encrypted under "
                "either: recover it with each key before removing an entry"
            )
        return HardenedMemoryKey(secrets[0])

    def _identity_lock_path(self) -> Path:
        """A per-user lock file for this service/attribute pair.

        ``$XDG_RUNTIME_DIR`` (per-user, on tmpfs) when it is set, else
        ``~/.cache/floorvault``; the directory is created owner-only.
        """
        runtime = os.environ.get("XDG_RUNTIME_DIR", "")
        base = (
            Path(runtime) / "floorvault"
            if runtime and os.path.isabs(runtime)
            else Path.home() / ".cache" / "floorvault"
        )
        try:
            _mkdir_owner_only(base)
        except FileExistsError:
            # Two first-time resolvers both saw the directory missing; it exists
            # now, so validate it again rather than fail (as the Tier-3 lock does).
            _mkdir_owner_only(base)
        digest = hashlib.sha256(f"{self._service}\0{self._attribute}".encode()).hexdigest()
        return base / f"secret-service-{digest[:32]}.lock"

    # ---- fallback custody (masked protected file) -------------------------

    def _mask(self, plaintext: bytes) -> bytes:
        """Mask with a deterministic pad derived from the service name.

        A public constant: this is obfuscation, not encryption. It keeps the
        stored blob from being raw key material (and gives the store a header
        that says which scheme wrote it), and nothing more - the confidentiality
        of this tier is the file mode. See SECURITY.md.
        """
        pad = hashlib.sha256(self._service.encode()).digest()
        return bytes(a ^ b for a, b in zip(plaintext, pad))

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        # Try the primary boundary first.
        if self._secret_service_available():
            via_ss = self._resolve_via_secret_service(allow_create=allow_create)
            if via_ss is not None:
                return via_ss
        # Fallback: masked protected file. The mask is a deterministic public
        # pad, so this tier is disk custody - a caller whose policy forbids disk
        # custody must not have an existing store silently read for it either.
        if not self._allow_file_fallback:
            raise MissingKeyError(
                "Secret Service did not resolve a key and file-based key custody "
                "is not permitted by policy; refusing to read or create the "
                "masked key store"
            )
        try:
            blob = read_scheme_store(
                self._path,
                header=_HEADER,
                legacy_path=self._legacy_store_path(),
                allow_legacy_adoption=self._allow_legacy_adoption,
            )
        except ProtectedStoreMissing:
            # Absent: creating below is correct. Other read failures propagate,
            # so an unreadable store is never replaced by a fresh key.
            blob = None
        if blob is not None:
            key = self._mask(blob)
            if len(key) != 32:
                raise ProtectedStoreError("protected store key has unexpected length")
            return HardenedMemoryKey(key)
        if not allow_create:
            raise MissingKeyError("Linux Secret Service store is missing; recovery is required")
        # On an interactive desktop where Secret Service is expected but absent,
        # fail closed rather than silently writing a key file.
        if _looks_interactive_desktop() and is_linux():
            raise MissingKeyError(
                "Secret Service is not available in this session (no reachable "
                "session bus) but a desktop session is present; refusing to fall "
                "back to a key file. Set a key explicitly."
            )
        key = self._random_bytes(32)
        if len(key) != 32:
            raise ProtectedStoreError("random source must return 32 bytes")
        write_protected(self._mask(key), self._path, header=_HEADER)
        return HardenedMemoryKey(key)

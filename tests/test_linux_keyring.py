"""Linux Secret Service provider: API contract and custody behaviour.

Two distinct classes of coverage live here, and both are needed:

* **A contract test against the real package.** The client talks to
  ``secretstorage`` by name, and a name that does not exist raises
  ``AttributeError`` - which the provider's fail-closed handler turns into a
  custody error, or (worse, at import time inside a broad ``except ImportError``)
  into a silent "tier unavailable". Nothing in the suite could see that, because
  the only Linux test faked the *provider*, not the library. The contract test
  asserts every name the client relies on actually exists in the installed
  package.

* **Behavioural tests against a faithful fake.** The fake deliberately mirrors
  the real API surface (``dbus_init``, ``get_default_collection``,
  ``Item.get_attributes``, ``SecretServiceNotAvailableException``) and defines
  *only* those names. A client written against a name that does not exist in the
  real library therefore fails here too - which is the regression this file
  exists to prevent.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

from floorvault.providers import linux_keyring as lk_module
from floorvault.providers.base import CustodyDowngradeError, KeyProviderError, MissingKeyError
from floorvault.providers.linux_keyring import LinuxSecretServiceKeyProvider

# --------------------------------------------------------------------------
# Faithful fake secretstorage
# --------------------------------------------------------------------------


class _FakeItem:
    def __init__(self, attributes: dict[str, str], secret: bytes) -> None:
        self._attributes = dict(attributes)
        self._secret = secret
        self.secret_reads = 0

    def get_attributes(self) -> dict[str, str]:
        return dict(self._attributes)

    def get_secret(self) -> bytes:
        self.secret_reads += 1
        return self._secret


class _FakeLockedException(Exception):
    """Mirrors ``secretstorage.exceptions.LockedException``."""


class _FakeCollection:
    def __init__(
        self,
        *,
        items: tuple[_FakeItem, ...] = (),
        locked: bool = False,
        unlock_dismissed: bool = False,
        create_error: Exception | None = None,
        ignore_query_filters: bool = False,
    ) -> None:
        self.items = list(items)
        self._locked = locked
        self.unlock_dismissed = unlock_dismissed
        self.ignore_query_filters = ignore_query_filters
        self.unlock_calls = 0
        self.ensure_not_locked_calls = 0
        self.created: list[dict[str, object]] = []
        self.create_error = create_error

    def is_locked(self) -> bool:
        return self._locked

    def unlock(self) -> bool:
        """Real semantics: returns True when the prompt was DISMISSED.

        That is the opposite of the intuitive reading, and a client that treats
        the return as "did it work?" inverts the security decision - hence the
        provider checks ``is_locked()`` again rather than trusting this value.
        """
        self.unlock_calls += 1
        if not self.unlock_dismissed:
            self._locked = False
        return self.unlock_dismissed

    def ensure_not_locked(self) -> None:
        self.ensure_not_locked_calls += 1
        if self._locked:
            raise _FakeLockedException("Collection is locked!")

    def search_items(self, attributes: dict[str, str]):
        if self.ignore_query_filters:
            # A backend that returns everything regardless of the query. The
            # client must not trust the backend's filtering.
            return iter(self.items)
        return iter(
            item
            for item in self.items
            if all(item.get_attributes().get(key) == value for key, value in attributes.items())
        )

    def create_item(
        self,
        label: str,
        attributes: dict[str, str],
        secret: bytes,
        replace: bool = False,
        content_type: str = "text/plain",
    ) -> _FakeItem:
        if self.create_error is not None:
            raise self.create_error
        self.created.append(
            {
                "label": label,
                "attributes": dict(attributes),
                "secret": secret,
                "replace": replace,
            }
        )
        item = _FakeItem(attributes, secret)
        self.items.append(item)
        return item


def _install_fake_secretstorage(
    monkeypatch,
    *,
    collection: _FakeCollection | None = None,
    dbus_init_raises: Exception | None = None,
    dbus_init_unavailable: bool = False,
    omit_module_attrs: tuple[str, ...] = (),
    no_default_collection: bool = False,
):
    """Install a fake ``secretstorage`` defining only the REAL API surface."""
    module = types.ModuleType("secretstorage")
    exceptions = types.ModuleType("secretstorage.exceptions")

    class SecretStorageException(Exception):
        pass

    class SecretServiceNotAvailableException(SecretStorageException):
        pass

    class ItemNotFoundException(SecretStorageException):
        pass

    for name, value in (
        ("SecretStorageException", SecretStorageException),
        ("SecretServiceNotAvailableException", SecretServiceNotAvailableException),
        ("ItemNotFoundException", ItemNotFoundException),
        ("LockedException", _FakeLockedException),
    ):
        setattr(exceptions, name, value)
        setattr(module, name, value)
    module.exceptions = exceptions

    class _FakeConnection:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    connection = _FakeConnection()

    def dbus_init():
        if dbus_init_unavailable:
            # The real ``dbus_init`` raises this exact class when the session
            # bus is unset - the documented headless condition.
            raise SecretServiceNotAvailableException("DBUS_SESSION_BUS_ADDRESS is unset")
        if dbus_init_raises is not None:
            raise dbus_init_raises
        return connection

    calls: list[str] = []

    def get_default_collection(connection, session=None):
        # The real function creates the default collection when there is none,
        # which shows a prompt; the record lets tests prove it was not called.
        calls.append("get_default_collection")
        assert collection is not None, "client called get_default_collection without a fake"
        return collection

    def get_collection_by_alias(connection, alias):
        calls.append(f"get_collection_by_alias:{alias}")
        if no_default_collection:
            raise ItemNotFoundException("No collection with such alias.")
        assert collection is not None, "client called get_collection_by_alias without a fake"
        return collection

    if "dbus_init" not in omit_module_attrs:
        module.dbus_init = dbus_init  # type: ignore[attr-defined]
    if "get_default_collection" not in omit_module_attrs:
        module.get_default_collection = get_default_collection  # type: ignore[attr-defined]
    if "get_collection_by_alias" not in omit_module_attrs:
        module.get_collection_by_alias = get_collection_by_alias  # type: ignore[attr-defined]
    module.calls = calls  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "secretstorage", module)
    monkeypatch.setitem(sys.modules, "secretstorage.exceptions", exceptions)
    return module, SecretServiceNotAvailableException


def _secret_service_provider(
    monkeypatch, tmp_path, *, allow_disk_fallback: bool = False, interactive: bool = True
):
    """A provider that believes it is on an interactive Linux desktop."""
    monkeypatch.setattr(lk_module, "is_linux", lambda: True)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    return LinuxSecretServiceKeyProvider(
        store_path=tmp_path / "master.key",
        service="floorvault",
        attribute="master-key",
        interactive=interactive,
    )


# --------------------------------------------------------------------------
# Contract test: the client's names must exist in the real package
# --------------------------------------------------------------------------


def _secretstorage_names_used_in_source() -> tuple[set[str], set[str]]:
    """Module attributes and exception names the client actually calls.

    Derived by walking the source's AST, deliberately *not* read from a
    hand-maintained constant. A constant can only ever confirm itself: the first
    version of this test asserted ``_REQUIRED_SECRETSTORAGE_API`` existed in the
    real package, which passed unchanged against the shipped defect because the
    names it listed were already correct while the names the code *called* were
    not.
    """
    import ast

    with open(lk_module.__file__, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())

    module_attrs: set[str] = set()
    exception_names: set[str] = set()
    module_aliases: set[str] = set()
    exception_module_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "secretstorage":
                    module_aliases.add(alias.asname or "secretstorage")
                elif alias.name == "secretstorage.exceptions":
                    exception_module_aliases.add(alias.asname or "secretstorage.exceptions")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("secretstorage"):
                for alias in node.names:
                    exception_names.add(alias.name)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in exception_module_aliases:
                exception_names.add(node.attr)
            elif node.value.id in module_aliases:
                module_attrs.add(node.attr)

    module_attrs.discard("exceptions")  # the submodule itself, checked separately
    return module_attrs, exception_names


def test_every_secretstorage_name_the_client_calls_exists_in_the_real_package():
    """The client's actual API surface must match the installed ``secretstorage``.

    This is the test that would have caught the shipped defect: the client
    imported ``SecretServiceNotAvailable`` (the real class is
    ``SecretServiceNotAvailableException``) and called ``get_default_bus``,
    ``DBusAddressConnection`` and ``Item.get_attribute``. The import failure was
    swallowed by ``except ImportError: return None``, so the tier reported
    "unavailable" forever and nothing in the suite could see it.
    """
    secretstorage = pytest.importorskip("secretstorage")
    import secretstorage.collection as collection_module
    import secretstorage.exceptions as exceptions_module
    from secretstorage.collection import Collection
    from secretstorage.item import Item

    module_attrs, exception_names = _secretstorage_names_used_in_source()
    assert module_attrs, "no secretstorage module attributes detected; the walk is broken"

    missing_module_attrs = sorted(name for name in module_attrs if not hasattr(secretstorage, name))
    assert not missing_module_attrs, (
        f"the client calls secretstorage.{missing_module_attrs} but the installed "
        "package does not define them"
    )

    missing_exceptions = sorted(
        name for name in exception_names if not hasattr(exceptions_module, name)
    )
    assert not missing_exceptions, (
        f"the client references secretstorage.exceptions.{missing_exceptions} but the "
        "installed package does not define them"
    )

    # The runtime pre-flight constant must agree with what the source calls, so
    # it cannot drift into listing names the code no longer uses.
    asserted = set(lk_module._REQUIRED_SECRETSTORAGE_API)
    assert asserted <= module_attrs, (
        f"_REQUIRED_SECRETSTORAGE_API lists {sorted(asserted - module_attrs)}, which the "
        "client never calls"
    )
    assert lk_module._SECRET_SERVICE_UNAVAILABLE_EXCEPTION in exception_names or hasattr(
        exceptions_module, lk_module._SECRET_SERVICE_UNAVAILABLE_EXCEPTION
    ), "the declared unavailable-exception name does not exist in the real package"

    for name in ("search_items", "create_item", "ensure_not_locked", "is_locked", "unlock"):
        assert hasattr(Collection, name), f"Collection has no {name!r}"
    assert hasattr(collection_module, "get_default_collection"), (
        "secretstorage.collection has no get_default_collection"
    )

    # ``get_attributes`` is the real accessor; the singular form never existed.
    assert hasattr(Item, "get_attributes"), "Item has no get_attributes()"
    assert not hasattr(Item, "get_attribute"), (
        "Item.get_attribute exists after all - the client's singular call would "
        "have been valid; revisit this test"
    )


def test_client_does_not_reference_nonexistent_secretstorage_names():
    """Guard against reintroducing a name that is not in the real package.

    Cheap static check so the defect cannot return on a host where the package
    is not installed (where the contract test above is skipped). Tokens are
    examined rather than raw text, so a comment or docstring that *names* the
    removed API while explaining it is not a false positive.
    """
    import tokenize

    forbidden = {
        "SecretServiceNotAvailable",
        "get_default_bus",
        "DBusAddressConnection",
        "get_attribute",
    }
    with open(lk_module.__file__, encoding="utf-8") as handle:
        names = {
            token.string
            for token in tokenize.generate_tokens(handle.readline)
            if token.type == tokenize.NAME
        }
    offenders = forbidden & names
    assert not offenders, (
        f"linux_keyring.py uses {sorted(offenders)} as code, but secretstorage does not define it"
    )


# --------------------------------------------------------------------------
# Behaviour: available and found / created
# --------------------------------------------------------------------------


def test_secret_service_returns_the_stored_key(monkeypatch, tmp_path):
    """An item already in the collection is returned without contacting a file."""
    stored = b"\xa5" * 32
    item = _FakeItem({"application": "floorvault", "floorvault": "master-key"}, stored)
    collection = _FakeCollection(items=(item,))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    key = provider.resolve_key()

    assert key.get_bytes() == stored
    assert item.secret_reads == 1
    assert collection.created == []
    assert not (tmp_path / "master.key").exists()
    key.wipe()


def test_secret_service_creates_a_key_when_absent(monkeypatch, tmp_path):
    """No matching item and creation allowed: store a fresh key in the service."""
    collection = _FakeCollection()
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    key = provider.resolve_key(allow_create=True)

    assert len(key.get_bytes()) == 32
    assert len(collection.created) == 1
    created = collection.created[0]
    assert created["secret"] == key.get_bytes()
    assert created["attributes"] == {"application": "floorvault", "floorvault": "master-key"}
    assert created["replace"] is False
    assert not (tmp_path / "master.key").exists(), "fell back to file custody"
    key.wipe()


def test_secret_service_unlocks_a_locked_collection(monkeypatch, tmp_path):
    """A locked collection must be unlocked before searching, not skipped."""
    stored = b"\x5a" * 32
    item = _FakeItem({"application": "floorvault", "floorvault": "master-key"}, stored)
    collection = _FakeCollection(items=(item,), locked=True)
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    key = provider.resolve_key()

    assert key.get_bytes() == stored
    assert collection.ensure_not_locked_calls + collection.unlock_calls >= 1, (
        "a locked collection was never unlocked"
    )
    assert collection.is_locked() is False
    key.wipe()


def test_secret_service_ignores_items_for_other_services(monkeypatch, tmp_path):
    """Attribute matching is exact: another application's entry is not the key."""
    other = _FakeItem({"application": "someone-else", "floorvault": "master-key"}, b"\x01" * 32)
    collection = _FakeCollection(items=(other,))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    key = provider.resolve_key(allow_create=True)

    assert key.get_bytes() != b"\x01" * 32
    assert len(collection.created) == 1
    key.wipe()


def test_secret_service_does_not_trust_backend_query_filtering(monkeypatch, tmp_path):
    """A backend returning every entry must not be believed.

    ``search_items`` is a request, not a guarantee. A client that returns the
    first result without re-checking the attributes hands one application the
    key of another - so the match is verified on the item's own attributes
    rather than on the backend having honoured the query.
    """
    foreign = _FakeItem({"application": "someone-else", "floorvault": "master-key"}, b"\x01" * 32)
    collection = _FakeCollection(items=(foreign,), ignore_query_filters=True)
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    key = provider.resolve_key(allow_create=True)

    assert key.get_bytes() != b"\x01" * 32, "took another application's entry"
    assert len(collection.created) == 1, "should have created its own entry instead"
    key.wipe()


def test_secret_service_rejects_an_entry_with_the_wrong_key_length(monkeypatch, tmp_path):
    """A short/oversized entry is a hard failure, never silently accepted."""
    item = _FakeItem({"application": "floorvault", "floorvault": "master-key"}, b"\x07" * 16)
    collection = _FakeCollection(items=(item,))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    with pytest.raises(KeyProviderError, match="invalid key length"):
        provider.resolve_key()


def test_secret_service_missing_key_without_create_is_recovery_required(monkeypatch, tmp_path):
    """``allow_create=False`` on an empty service must not mint a new key."""
    collection = _FakeCollection()
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    with pytest.raises(MissingKeyError, match="recovery is required"):
        provider.resolve_key(allow_create=False)

    assert collection.created == []


# --------------------------------------------------------------------------
# Behaviour: genuinely unavailable vs present-but-unusable-by-this-build
# --------------------------------------------------------------------------


def test_genuinely_unavailable_service_falls_through_not_downgrades(monkeypatch, tmp_path):
    """The service is absent from this session: that is not a custody downgrade.

    ``dbus_init`` raises ``SecretServiceNotAvailableException`` when the session
    bus is unset - the documented, expected condition on a headless host.
    """
    _install_fake_secretstorage(
        monkeypatch,
        collection=_FakeCollection(),
        dbus_init_unavailable=True,
    )
    provider = _secret_service_provider(monkeypatch, tmp_path)

    # Falls through to file custody, which then fails closed because the file
    # tier is not explicitly allowed - and the message must say the service was
    # not available, not that the client is broken.
    with pytest.raises(MissingKeyError, match="not available in this session"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_locked_collection_that_stays_locked_fails_closed(monkeypatch, tmp_path):
    """A dismissed unlock prompt must not fall through to file custody.

    ``unlock()`` returns True when the prompt was DISMISSED, so the provider
    re-checks ``is_locked()`` rather than trusting the return value.
    """
    collection = _FakeCollection(locked=True, unlock_dismissed=True)
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    with pytest.raises(CustodyDowngradeError, match="locked"):
        provider.resolve_key()

    assert collection.unlock_calls == 1
    assert not (tmp_path / "master.key").exists(), "downgraded to file custody"


def test_broken_client_reports_present_but_unusable(monkeypatch, tmp_path):
    """A client that cannot use the installed library must fail closed, distinctly.

    With the wrong API names this is exactly what happened, except the failure
    was swallowed at import time and misreported as "unavailable". The message
    must distinguish the two conditions: the library IS present, this build
    cannot talk to it.
    """
    _install_fake_secretstorage(
        monkeypatch,
        collection=_FakeCollection(),
        omit_module_attrs=("dbus_init",),
    )
    provider = _secret_service_provider(monkeypatch, tmp_path)

    with pytest.raises(CustodyDowngradeError, match="present but unusable"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists(), "downgraded to file custody"


def test_unexpected_service_failure_fails_closed(monkeypatch, tmp_path):
    """Any other runtime failure in the service path must not downgrade custody."""
    collection = _FakeCollection(create_error=RuntimeError("dbus exploded"))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)

    with pytest.raises(CustodyDowngradeError, match="present but unusable"):
        provider.resolve_key()

    assert not (tmp_path / "master.key").exists()


def test_missing_library_is_not_a_custody_failure(monkeypatch, tmp_path):
    """An uninstalled library is a genuinely absent tier, not a broken one."""
    monkeypatch.setitem(sys.modules, "secretstorage", None)  # import -> ImportError
    provider = _secret_service_provider(monkeypatch, tmp_path)

    assert provider._secret_service_available() is False

    with pytest.raises(MissingKeyError, match="not available in this session"):
        provider.resolve_key()


# --------------------------------------------------------------------------
# The masked-file tier obeys the caller's disk-custody policy
# --------------------------------------------------------------------------


def _seed_ss_store(tmp_path, key: bytes) -> "LinuxSecretServiceKeyProvider":
    """Write a valid master.key.ss via the provider's own headless fallback."""
    seed = LinuxSecretServiceKeyProvider(
        store_path=tmp_path / "master.key.ss",
        service="floorvault",
        attribute="master-key",
        random_bytes=lambda n: key[:n],
    )
    created = seed.resolve_key()
    created.wipe()
    return seed


def test_existing_ss_store_is_not_read_when_file_fallback_is_forbidden(monkeypatch, tmp_path):
    """allow_file_fallback=False must gate READS, not only creation.

    Regression: AdaptiveKeyProvider passed no policy, so strict=True still
    resolved a key from an existing masked store when Secret Service was
    unreachable - a deterministic public pad is disk custody, not a boundary.
    """
    stored_key = b"\x5c" * 32
    # Seed the store headless (no desktop), fallback allowed by default.
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(lk_module, "is_linux", lambda: False)
    _seed_ss_store(tmp_path, stored_key)
    assert (tmp_path / "master.key.ss").exists()

    # Now the session looks like an interactive desktop with the service down.
    monkeypatch.setattr(lk_module, "is_linux", lambda: True)
    monkeypatch.setenv("DISPLAY", ":0")
    _install_fake_secretstorage(
        monkeypatch, collection=_FakeCollection(), dbus_init_unavailable=True
    )

    provider = LinuxSecretServiceKeyProvider(
        store_path=tmp_path / "master.key.ss",
        service="floorvault",
        attribute="master-key",
        allow_file_fallback=False,
    )
    with pytest.raises(MissingKeyError, match="file-based key custody"):
        provider.resolve_key()


def test_existing_ss_store_is_read_when_file_fallback_is_allowed(monkeypatch, tmp_path):
    """Guard against over-blocking: the documented opt-in still works."""
    stored_key = b"\x6d" * 32
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(lk_module, "is_linux", lambda: False)
    _seed_ss_store(tmp_path, stored_key)

    monkeypatch.setattr(lk_module, "is_linux", lambda: True)
    monkeypatch.setenv("DISPLAY", ":0")
    _install_fake_secretstorage(
        monkeypatch, collection=_FakeCollection(), dbus_init_unavailable=True
    )

    provider = LinuxSecretServiceKeyProvider(
        store_path=tmp_path / "master.key.ss",
        service="floorvault",
        attribute="master-key",
        allow_file_fallback=True,
    )
    key = provider.resolve_key()
    assert key.get_bytes() == stored_key
    key.wipe()


# --------------------------------------------------------------------------
# Non-interactive resolution (a secret source's fetch must not prompt)
# --------------------------------------------------------------------------

_QUERY = {"application": "floorvault", "floorvault": "master-key"}


def test_non_interactive_reads_the_key_without_the_creating_lookup(monkeypatch, tmp_path):
    stored = b"\x21" * 32
    collection = _FakeCollection(items=(_FakeItem(_QUERY, stored),))
    module, _ = _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path, interactive=False)
    key = provider.resolve_key(allow_create=False)
    assert key.get_bytes() == stored
    # get_default_collection creates a missing collection (a prompt); the
    # non-interactive path looks the alias up instead.
    assert module.calls == ["get_collection_by_alias:default"]
    key.wipe()


def test_non_interactive_without_a_default_collection_creates_nothing(monkeypatch, tmp_path):
    module, _ = _install_fake_secretstorage(monkeypatch, no_default_collection=True)
    provider = _secret_service_provider(monkeypatch, tmp_path, interactive=False)
    with pytest.raises(MissingKeyError, match="not created without a prompt"):
        provider.resolve_key(allow_create=True)
    assert "get_default_collection" not in module.calls
    assert not (tmp_path / "master.key").exists()


def test_non_interactive_reports_a_locked_collection_instead_of_unlocking(monkeypatch, tmp_path):
    collection = _FakeCollection(items=(_FakeItem(_QUERY, b"\x22" * 32),), locked=True)
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path, interactive=False)
    with pytest.raises(KeyProviderError, match="not unlocked without a prompt"):
        provider.resolve_key(allow_create=False)
    assert collection.unlock_calls == 0


def test_non_interactive_never_creates_a_key(monkeypatch, tmp_path):
    collection = _FakeCollection()
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path, interactive=False)
    with pytest.raises(MissingKeyError, match="not created without a prompt"):
        provider.resolve_key(allow_create=True)
    assert collection.created == []


# --------------------------------------------------------------------------
# One key per service/attribute identity
# --------------------------------------------------------------------------


def test_duplicate_entries_with_different_keys_are_refused_and_kept(monkeypatch, tmp_path):
    first, second = _FakeItem(_QUERY, b"\x01" * 32), _FakeItem(_QUERY, b"\x02" * 32)
    collection = _FakeCollection(items=(first, second))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)
    for allow_create in (True, False):
        with pytest.raises(KeyProviderError, match="hold different keys"):
            provider.resolve_key(allow_create=allow_create)
    assert collection.items == [first, second] and collection.created == []


def test_duplicate_entries_with_the_same_key_resolve(monkeypatch, tmp_path):
    stored = b"\x03" * 32
    collection = _FakeCollection(items=(_FakeItem(_QUERY, stored), _FakeItem(_QUERY, stored)))
    _install_fake_secretstorage(monkeypatch, collection=collection)
    key = _secret_service_provider(monkeypatch, tmp_path).resolve_key()
    assert key.get_bytes() == stored
    key.wipe()


def test_creation_rechecks_under_the_identity_lock(monkeypatch, tmp_path):
    """A key another resolver created while this one waited is used, not doubled."""
    import contextlib

    winner = b"\x04" * 32
    collection = _FakeCollection()
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)
    taken = []

    @contextlib.contextmanager
    def lock(path, **_kw):
        taken.append(path)
        collection.items.append(_FakeItem(_QUERY, winner))  # the other resolver finished first
        yield

    monkeypatch.setattr(lk_module, "exclusive_lock", lock)
    key = provider.resolve_key()
    assert key.get_bytes() == winner and collection.created == []
    assert taken and taken[0].parent == tmp_path / "runtime" / "floorvault"
    key.wipe()


def test_an_entry_created_alongside_ours_is_reported_not_overwritten(monkeypatch, tmp_path):
    collection = _FakeCollection()
    real_create = collection.create_item

    def create_item(label, attributes, secret, replace=False, content_type="text/plain"):
        item = real_create(label, attributes, secret, replace=replace)
        # A resolver that does not take the lock (another tool, an older build).
        collection.items.append(_FakeItem(_QUERY, b"\x05" * 32))
        return item

    collection.create_item = create_item
    _install_fake_secretstorage(monkeypatch, collection=collection)
    provider = _secret_service_provider(monkeypatch, tmp_path)
    with pytest.raises(KeyProviderError, match="2 Secret Service entries now exist"):
        provider.resolve_key()
    assert len(collection.items) == 2 and all(c["replace"] is False for c in collection.created)


def test_concurrent_first_resolutions_create_one_key(monkeypatch, tmp_path):
    """Two stores sharing the identity, resolving for the first time at once."""
    import threading
    import time

    class SlowSearch(_FakeCollection):
        def search_items(self, attributes):
            found = list(super().search_items(attributes))
            time.sleep(0.05)  # widen the window between "none found" and creating
            return iter(found)

    collection = SlowSearch()
    _install_fake_secretstorage(monkeypatch, collection=collection)
    # One user, so one runtime directory; two store directories.
    _secret_service_provider(monkeypatch, tmp_path)
    providers = [
        LinuxSecretServiceKeyProvider(
            store_path=tmp_path / name / "master.key", service="floorvault", attribute="master-key"
        )
        for name in ("store-a", "store-b")
    ]
    keys: list[bytes] = []
    errors: list[BaseException] = []

    def resolve(provider):
        try:
            keys.append(provider.resolve_key().get_bytes())
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=resolve, args=(p,)) for p in providers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not errors, errors
    assert len(collection.created) == 1
    assert len(keys) == 2 and keys[0] == keys[1]


def test_identity_lock_lives_in_an_owner_only_runtime_directory(monkeypatch, tmp_path):
    import stat

    provider = _secret_service_provider(monkeypatch, tmp_path)
    path = provider._identity_lock_path()
    assert path.parent == tmp_path / "runtime" / "floorvault"
    if os.name != "nt":  # Windows reports no POSIX mode; the tier is Linux only
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    other = LinuxSecretServiceKeyProvider(
        store_path=tmp_path / "x", service="floorvault", attribute="other-account"
    )
    assert other._identity_lock_path() != path
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))  # Path.home() on Windows
    assert provider._identity_lock_path().parent == tmp_path / "home" / ".cache" / "floorvault"

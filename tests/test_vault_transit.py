"""Vault Transit provider tests against a fake Vault (roadmap 1f).

The fake implements the narrow transport interface (``post(path, body,
token)``) with real semantics: blobs carry their context, decrypt/rewrap
reject a mismatched context, and faults are injected per call. No sockets.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error

import pytest

from floorvault.providers.base import CustodyDowngradeError, MissingKeyError
from floorvault.providers.generation_store import (
    GenerationMismatchError,
    GenerationStore,
)
from floorvault.providers.vault_transit import (
    UrllibTransport,
    VaultTransitProvider,
)

TOKEN = "test-only-vault-token"
ADDR = "https://vault.example.test:8200"


class FakeVault:
    """In-memory Transit engine: datakey/decrypt/rewrap, context-checked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail_next: Exception | None = None
        self.version = 0
        self.on_call = None

    def post(self, path: str, body: dict, token: str) -> dict:
        self.calls.append((path, dict(body)))
        if self.on_call is not None:
            self.on_call(path, body)
        if self.fail_next is not None:
            exc, self.fail_next = self.fail_next, None
            raise exc
        # Real Vault encodes the datakey type in the path
        # (/v1/<mount>/datakey/plaintext/<key>); the provider must too.
        op = path.split("/")[3]
        context = body.get("context")
        if op == "datakey":
            assert path.split("/")[4] == "plaintext", path
            self.version = 1
            plaintext = bytes(32)
            blob = "vault:v1:" + base64.b64encode(context.encode() + b"|" + plaintext).decode()
            return {"data": {"ciphertext": blob, "plaintext": base64.b64encode(plaintext).decode()}}
        if op in ("decrypt", "rewrap"):
            blob = body["ciphertext"]
            encoded = blob.split(":", 2)[2]
            ctx_b, plaintext = base64.b64decode(encoded).split(b"|", 1)
            if ctx_b.decode() != context:
                raise CustodyDowngradeError("context mismatch")
            if op == "decrypt":
                return {"data": {"plaintext": base64.b64encode(plaintext).decode()}}
            self.version += 1
            blob = (
                f"vault:v{self.version}:"
                + base64.b64encode(context.encode() + b"|" + plaintext).decode()
            )
            return {"data": {"ciphertext": blob}}
        raise AssertionError(f"unexpected path {path}")


def make_provider(tmp_path, **kw) -> tuple[VaultTransitProvider, FakeVault]:
    fake = FakeVault()
    provider = VaultTransitProvider(
        vault_addr=ADDR,
        key_name="floorvault",
        store_dir=tmp_path / "vt",
        token=TOKEN,
        transport=fake,
        **kw,
    )
    return provider, fake


def test_requires_https(tmp_path):
    with pytest.raises(ValueError):
        VaultTransitProvider(
            vault_addr="http://vault:8200",
            key_name="k",
            store_dir=tmp_path,
            token=TOKEN,
            transport=FakeVault(),
        )


def test_requires_a_token(tmp_path):
    with pytest.raises(MissingKeyError):
        VaultTransitProvider(
            vault_addr=ADDR,
            key_name="k",
            store_dir=tmp_path,
            token=None,
            transport=FakeVault(),
        )


def test_provision_mints_and_wraps(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    provider, fake = make_provider(tmp_path)
    key = provider.resolve_key()
    assert key.get_bytes() == bytes(32)
    assert fake.calls[0][0] == "/v1/transit/datakey/plaintext/floorvault"
    # The store holds only the wrapped blob, never the plaintext.
    generation, blob = GenerationStore(tmp_path / "vt").read_active()
    assert generation == 1
    assert bytes(32) not in blob


def test_resolve_decrypts_existing_blob(tmp_path):
    provider, fake = make_provider(tmp_path, cache_ttl=0)
    provider.resolve_key()
    provider2 = VaultTransitProvider(
        vault_addr=ADDR,
        key_name="floorvault",
        store_dir=tmp_path / "vt",
        token=TOKEN,
        transport=fake,
    )
    key = provider2.resolve_key()
    assert key.get_bytes() == bytes(32)
    assert fake.calls[-1][0].endswith("/decrypt/floorvault")


def test_allow_create_false_on_empty_store_is_missing(tmp_path):
    provider, _ = make_provider(tmp_path)
    with pytest.raises(MissingKeyError):
        provider.resolve_key(allow_create=False)


def test_context_is_versioned_and_constant_across_ops(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()
    provider.rewrap()
    provider.wipe()
    provider2 = VaultTransitProvider(
        vault_addr=ADDR,
        key_name="floorvault",
        store_dir=tmp_path / "vt",
        token=TOKEN,
        transport=fake,
    )
    provider2.resolve_key()
    contexts = [json.loads(base64.b64decode(body["context"])) for _, body in fake.calls]
    assert len(contexts) == 3
    assert len({json.dumps(c, sort_keys=True) for c in contexts}) == 1
    ctx = contexts[0]
    assert ctx["purpose"] == "floorvault-master-wrap"
    assert ctx["custody"] == "vault-transit"
    assert ctx["v"] == 1
    assert set(ctx) == {"v", "app", "store", "purpose", "custody"}


def test_unreachable_vault_fails_closed(tmp_path):
    provider, fake = make_provider(tmp_path)
    fake.fail_next = urllib.error.URLError("connection refused")
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_vault_403_fails_closed(tmp_path):
    provider, fake = make_provider(tmp_path)
    fake.fail_next = urllib.error.HTTPError(ADDR, 403, "Forbidden", {}, None)
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_malformed_decrypt_response_fails_closed(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()
    provider.wipe()
    fake.fail_next = None

    class BrokenVault(FakeVault):
        def post(self, path, body, token):
            if "decrypt" in path:
                return {"data": {"plaintext": "not-valid-b64!"}}
            return super().post(path, body, token)

    provider._transport = BrokenVault()
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_wrong_length_plaintext_fails_closed(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()
    provider.wipe()

    class ShortVault(FakeVault):
        def post(self, path, body, token):
            if "decrypt" in path:
                return {"data": {"plaintext": base64.b64encode(b"short").decode()}}
            return super().post(path, body, token)

    provider._transport = ShortVault()
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_token_never_appears_in_errors(tmp_path):
    provider, fake = make_provider(tmp_path)
    fake.fail_next = urllib.error.HTTPError(ADDR, 403, f"Forbidden for {TOKEN}", {}, None)
    with pytest.raises(CustodyDowngradeError) as excinfo:
        provider.resolve_key()
    assert not _chain_contains_token(excinfo.value)


def test_rewrap_publishes_next_generation(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()
    first_blob = GenerationStore(tmp_path / "vt").read_active()[1]
    assert provider.rewrap() == 2
    generation, blob = GenerationStore(tmp_path / "vt").read_active()
    assert generation == 2
    assert blob != first_blob
    assert blob.startswith(b"vault:v2:")
    # Key material is unchanged by a KEK rewrap.
    provider.wipe()
    assert provider.resolve_key().get_bytes() == bytes(32)


def test_concurrent_rewrap_loses_to_cas(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()
    store = GenerationStore(tmp_path / "vt")

    def interloper(path, body):
        if "rewrap" in path:
            store.update(b"vault:v9:other", expected_generation=1)

    fake.on_call = interloper
    with pytest.raises(GenerationMismatchError):
        provider.rewrap()
    assert store.read_active() == (2, b"vault:v9:other")


def test_cache_ttl_bounds_vault_calls(tmp_path):
    provider, fake = make_provider(tmp_path, cache_ttl=300)
    provider.resolve_key()
    provider.resolve_key()
    provider.resolve_key()
    assert len(fake.calls) == 1  # datakey only; decrypts served from cache

    provider2 = VaultTransitProvider(
        vault_addr=ADDR,
        key_name="floorvault",
        store_dir=tmp_path / "vt",
        token=TOKEN,
        transport=fake,
        cache_ttl=0,
    )
    provider2.resolve_key()
    provider2.resolve_key()
    assert fake.calls[-1][0].endswith("/decrypt/floorvault")
    assert sum(1 for p, _ in fake.calls if "decrypt" in p) == 2


def test_wipe_drops_cache(tmp_path):
    provider, fake = make_provider(tmp_path, cache_ttl=300)
    provider.resolve_key()
    provider.wipe()
    assert provider._cached is None


def test_corrupt_store_fails_closed_not_missing(tmp_path):
    provider, _ = make_provider(tmp_path)
    provider.resolve_key()
    (tmp_path / "vt" / "active").write_bytes(b"corrupt")
    provider.wipe()
    with pytest.raises(CustodyDowngradeError) as excinfo:
        provider.resolve_key()
    assert not isinstance(excinfo.value, MissingKeyError)


def test_missing_store_id_is_corruption_on_decrypt_path(tmp_path):
    provider, _ = make_provider(tmp_path)
    provider.resolve_key()
    (tmp_path / "vt" / "store.id").unlink()
    provider.wipe()
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_provision_race_resolves_the_winners_blob(tmp_path):
    provider, fake = make_provider(tmp_path)
    store = GenerationStore(tmp_path / "vt")
    rival_blob = "vault:v1:" + base64.b64encode(b"ctx-not-checked-here|otherkey").decode()

    def rival(path, body):
        if "datakey" in path:
            store.provision(rival_blob.encode())

    fake.on_call = rival

    class RivalAwareVault(FakeVault):
        def post(self, path, body, token):
            if "decrypt" in path:
                return {"data": {"plaintext": base64.b64encode(b"R" * 32).decode()}}
            return super().post(path, body, token)

    provider._transport = RivalAwareVault()
    provider._transport.on_call = rival
    key = provider.resolve_key()
    assert key.get_bytes() == b"R" * 32
    assert store.read_active()[1] == rival_blob.encode()


class _StubResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, _n: int) -> bytes:
        # Like a real response: the body once, then end of stream.
        payload, self._payload = self._payload, b""
        return payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _StubOpener:
    """First call raises a 307 to ``location``; second returns the payload."""

    def __init__(self, location: str) -> None:
        self.location = location
        self.urls: list[str] = []
        self._answered = False

    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        if not self._answered:
            self._answered = True
            raise urllib.error.HTTPError(
                request.full_url, 307, "Temporary Redirect", {"Location": self.location}, None
            )
        return _StubResponse(json.dumps({"data": {"ok": True}}).encode())


def test_redirect_to_trusted_standby_is_followed_once():
    transport = UrllibTransport(ADDR, allowed_redirect_hosts=("standby.example",))
    transport._opener = _StubOpener("https://standby.example/v1/x")
    assert transport.post("/v1/x", {}, TOKEN) == {"data": {"ok": True}}
    assert transport._opener.urls == [
        "https://vault.example.test:8200/v1/x",
        "https://standby.example/v1/x",
    ]


def test_redirect_to_untrusted_or_plaintext_host_is_refused():
    transport = UrllibTransport(ADDR, allowed_redirect_hosts=("standby.example",))
    transport._opener = _StubOpener("https://evil.example/v1/x")
    with pytest.raises(CustodyDowngradeError):
        transport.post("/v1/x", {}, TOKEN)

    transport2 = UrllibTransport(ADDR, allowed_redirect_hosts=("standby.example",))
    transport2._opener = _StubOpener("http://standby.example/v1/x")
    with pytest.raises(CustodyDowngradeError):
        transport2.post("/v1/x", {}, TOKEN)


def test_redirect_is_refused_by_default():
    transport = UrllibTransport(ADDR)
    transport._opener = _StubOpener("https://standby.example/v1/x")
    with pytest.raises(CustodyDowngradeError):
        transport.post("/v1/x", {}, TOKEN)


def test_transport_refuses_4xx_and_unreachable():
    class RefusingOpener:
        def __init__(self) -> None:
            self.calls = 0

        def open(self, request, timeout=None):
            self.calls += 1
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

    refusing = RefusingOpener()
    transport = UrllibTransport(ADDR)
    transport._opener = refusing
    with pytest.raises(CustodyDowngradeError):
        transport.post("/v1/x", {}, TOKEN)
    # A 4xx is a policy answer, not a transient fault: it must not be retried.
    assert refusing.calls == 1

    class DeadOpener:
        def open(self, request, timeout=None):
            raise urllib.error.URLError("connection refused")

    transport._opener = DeadOpener()
    with pytest.raises(CustodyDowngradeError):
        transport.post("/v1/x", {}, TOKEN)


def test_cache_expiry_forces_a_fresh_decrypt(tmp_path):
    provider, fake = make_provider(tmp_path, cache_ttl=0.05)
    provider.resolve_key()
    time.sleep(0.1)
    provider.resolve_key()
    assert sum(1 for p, _ in fake.calls if "decrypt" in p) == 1


def test_rewrap_rejects_a_non_vault_blob(tmp_path):
    provider, fake = make_provider(tmp_path)
    provider.resolve_key()

    class BadRewrapVault(FakeVault):
        def post(self, path, body, token):
            if "rewrap" in path:
                return {"data": {"ciphertext": "not-a-vault-blob"}}
            return super().post(path, body, token)

    provider._transport = BadRewrapVault()
    with pytest.raises(CustodyDowngradeError):
        provider.rewrap()


def test_datakey_wrong_length_plaintext_fails_closed(tmp_path):
    provider, _ = make_provider(tmp_path)

    class ShortDatakeyVault(FakeVault):
        def post(self, path, body, token):
            if "datakey" in path:
                return {
                    "data": {
                        "ciphertext": "vault:v1:eA",
                        "plaintext": base64.b64encode(b"short").decode(),
                    }
                }
            return super().post(path, body, token)

    provider._transport = ShortDatakeyVault()
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()


def test_transport_bounds():
    with pytest.raises(ValueError):
        UrllibTransport("http://vault:8200")
    with pytest.raises(ValueError):
        UrllibTransport(ADDR, timeout=0)
    with pytest.raises(ValueError):
        UrllibTransport(ADDR, timeout=120)


def test_provision_validates_the_wrapped_blob(tmp_path):
    """A malformed datakey ciphertext must not become generation 1 - the
    plaintext we hold would be unrecoverable on the next resolve."""
    provider, fake = make_provider(tmp_path)

    class GarbageBlobVault(FakeVault):
        def post(self, path, body, token):
            if "datakey" in path:
                return {
                    "data": {
                        "ciphertext": "not-a-vault-blob",
                        "plaintext": base64.b64encode(bytes(32)).decode(),
                    }
                }
            return super().post(path, body, token)

    provider._transport = GarbageBlobVault()
    provider._transport.calls = fake.calls
    with pytest.raises(CustodyDowngradeError):
        provider.resolve_key()
    assert GenerationStore(tmp_path / "vt").active_generation() is None


def test_wrapped_blob_must_match_the_full_vault_shape(tmp_path):
    """vault:v is a prefix, not a shape: version digits and valid base64 are
    mandatory, and anything else fails closed on every op that returns one."""
    provider, _ = make_provider(tmp_path)
    provider.resolve_key()

    malformed = [
        "vault:vgarbage",  # no version digits
        "vault:v1:!!!not-base64!!!",  # invalid alphabet
        "vault:v1:",  # empty payload
        "vaultv1:eA",  # missing colon
        "vault:v-1:eA",  # signed version
        "vault:v1:café",  # non-ASCII
        "vault:v1:eA tail",  # trailing junk
    ]
    for bad in malformed:

        class MalformedVault(FakeVault):
            def post(self, path, body, token, _bad=bad):
                if "rewrap" in path:
                    return {"data": {"ciphertext": _bad}}
                return super().post(path, body, token)

        provider._transport = MalformedVault()
        provider.wipe()
        with pytest.raises(CustodyDowngradeError, match="wrapped blob|no wrapped"):
            provider.rewrap()
        # The store stays at generation 1: nothing malformed was published.
        assert GenerationStore(tmp_path / "vt").active_generation() == 1


def _chain_contains_token(exc: BaseException) -> bool:
    """Walk cause and context: does ANY retained exception hold the token?

    ``.object``/``.doc`` on decode errors and ``.headers`` on HTTPErrors keep
    the server-controlled bytes that ``str()`` hides - printing is only half
    the surface, structured error reporters serialize the attributes.
    """
    seen: set[int] = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        if TOKEN in str(cur) or TOKEN in repr(cur):
            return True
        for attr in ("object", "doc", "headers", "msg"):
            payload = getattr(cur, attr, None)
            if payload is not None and TOKEN in str(payload):
                return True
        stack.extend((cur.__cause__, cur.__context__))
    return False


def test_invalid_json_does_not_chain_server_bytes(tmp_path):
    """A non-JSON response body is server-controlled: it can echo the token
    back, so no part of the exception chain may retain it."""
    transport = UrllibTransport(ADDR)
    token_echo = TOKEN.encode() + b"-echoed"

    class GarbageOpener:
        def open(self, request, timeout=None):
            return _StubResponse(b"\xff\xfe not json " + token_echo)

    transport._opener = GarbageOpener()
    with pytest.raises(CustodyDowngradeError) as excinfo:
        transport.post("/v1/x", {}, TOKEN)
    assert not _chain_contains_token(excinfo.value)
    # The decode error object itself must be detached, not merely unprinted.
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_non_ascii_response_fields_are_detached_from_the_cause(tmp_path):
    """``encode('ascii')`` retains the server-supplied string; a field that
    echoes the token must not reach the printed exception chain."""
    provider, _ = make_provider(tmp_path)

    class NonAsciiVault(FakeVault):
        def post(self, path, body, token):
            if "datakey" in path:
                return {
                    "data": {
                        "ciphertext": "vault:v1:eA",
                        "plaintext": TOKEN + "-café",
                    }
                }
            if "rewrap" in path:
                return {"data": {"ciphertext": TOKEN + "-café"}}
            return super().post(path, body, token)

    provider._transport = NonAsciiVault()
    with pytest.raises(CustodyDowngradeError) as excinfo:
        provider.resolve_key()
    # The chain may legitimately retain OUR exceptions (ProtectedStoreMissing
    # from the provision attempt); it must not retain anything holding the
    # server-supplied string.
    assert not _chain_contains_token(excinfo.value)

    # The same sanitizer guards the wrapped-blob path (rewrap returns a
    # non-ASCII blob containing the token).
    provider2, _ = make_provider(tmp_path / "vt2")
    provider2.resolve_key()
    provider2._transport = NonAsciiVault()
    with pytest.raises(CustodyDowngradeError) as excinfo2:
        provider2.rewrap()
    assert not _chain_contains_token(excinfo2.value)


def test_context_is_canonical_utf8_for_non_ascii_app_ids(tmp_path):
    """ensure_ascii escaping would diverge from spec-following implementers."""
    provider, fake = make_provider(tmp_path, app_instance_id="héllo-世界")
    provider.resolve_key()
    context_b64 = fake.calls[0][1]["context"]
    raw = base64.b64decode(context_b64)
    assert b"\\u" not in raw  # no ASCII-escape smuggling
    decoded = json.loads(raw)
    assert decoded["app"] == "héllo-世界"
    assert decoded["v"] == 1
    assert decoded["purpose"] == "floorvault-master-wrap"


@pytest.mark.parametrize("suffix", ["\n", "\r\n", " ", "\x00", "é"])
def test_a_token_that_cannot_be_a_header_value_is_refused_without_being_quoted(suffix):
    """http.client rejects a line break by quoting the whole value in its ValueError.

    A token read from a file with its trailing newline is the usual way to get
    there, and the transport promises the token never appears in raised errors.
    """
    transport = UrllibTransport(ADDR)
    transport._opener = _StubOpener("https://standby.example/v1/x")
    with pytest.raises(ValueError) as caught:
        transport.post("/v1/x", {}, TOKEN + suffix)
    assert TOKEN not in str(caught.value) and TOKEN not in repr(caught.value)
    assert transport._opener.urls == [], "nothing may be sent"


# ---------------------------------------------------------------------------
# A crash between the generation file and the pointer
#
# The store adopts an orphaned generation only when a retry presents the same
# bytes. The provider never can: Vault mints a fresh datakey and a fresh
# rewrap nonce on every call. (The plain FakeVault above returns the same blob
# each time, which is why this went unseen.) One crash at that point refused
# every later provision or rewrap until a file was deleted by hand.
# ---------------------------------------------------------------------------


class FreshVault(FakeVault):
    """Like real Transit: no two datakeys and no two rewraps are the same."""

    def post(self, path, body, token):
        op = path.split("/")[3]
        context = body.get("context")
        if op == "datakey":
            self.calls.append((path, dict(body)))
            plaintext = os.urandom(32)
            blob = "vault:v1:" + base64.b64encode(context.encode() + b"|" + plaintext).decode()
            return {"data": {"ciphertext": blob, "plaintext": base64.b64encode(plaintext).decode()}}
        return super().post(path, body, token)  # a rewrap already differs: the version moves


def _fresh_provider(tmp_path, fake=None):
    fake = fake or FreshVault()
    provider = VaultTransitProvider(
        vault_addr=ADDR,
        key_name="floorvault",
        store_dir=tmp_path / "vt",
        token=TOKEN,
        transport=fake,
        cache_ttl=0,
    )
    return provider, fake


def _crash_before_the_pointer(monkeypatch):
    def crash(self, generation, payload):
        raise KeyboardInterrupt("simulated crash before the pointer is published")

    monkeypatch.setattr(GenerationStore, "_publish_pointer", crash)


def test_a_provision_that_crashed_before_its_pointer_is_finished_by_the_next(tmp_path, monkeypatch):
    provider, fake = _fresh_provider(tmp_path)
    with monkeypatch.context() as patch:
        _crash_before_the_pointer(patch)
        with pytest.raises(KeyboardInterrupt):
            provider.resolve_key()
    store = GenerationStore(tmp_path / "vt")
    orphan = store.unpublished_generation(1)
    assert orphan is not None
    datakeys = sum(1 for path, _ in fake.calls if "/datakey/" in path)

    again, _ = _fresh_provider(tmp_path, fake)
    key = again.resolve_key().get_bytes()
    assert store.read_active() == (1, orphan)
    assert sum(1 for path, _ in fake.calls if "/datakey/" in path) == datakeys, (
        "a second key was minted over the unpublished one"
    )
    # It is the key the orphan wraps, and it is stable from then on.
    assert _fresh_provider(tmp_path, fake)[0].resolve_key().get_bytes() == key


def test_an_unpublished_generation_vault_does_not_unwrap_is_never_adopted(tmp_path, monkeypatch):
    provider, fake = _fresh_provider(tmp_path)
    with monkeypatch.context() as patch:
        _crash_before_the_pointer(patch)
        with pytest.raises(KeyboardInterrupt):
            provider.resolve_key()
    # Wrapped under another store's context: not this store's key.
    foreign = b"vault:v1:" + base64.b64encode(b"some-other-context|" + bytes(32))
    store = GenerationStore(tmp_path / "vt")
    store._generation_path(1).unlink()
    store._write_generation(1, foreign)
    with pytest.raises(CustodyDowngradeError, match="unpublished generation 1 .* not adopted"):
        _fresh_provider(tmp_path, fake)[0].resolve_key()
    with pytest.raises(Exception, match="."):
        store.read_active()  # still unprovisioned: nothing was published


def test_a_rewrap_that_crashed_before_its_pointer_is_finished_by_the_next(tmp_path, monkeypatch):
    provider, fake = _fresh_provider(tmp_path)
    key = provider.resolve_key().get_bytes()
    with monkeypatch.context() as patch:
        _crash_before_the_pointer(patch)
        with pytest.raises(KeyboardInterrupt):
            provider.rewrap()
    store = GenerationStore(tmp_path / "vt")
    orphan = store.unpublished_generation(2)
    assert orphan is not None and store.read_active()[0] == 1
    assert provider.rewrap() == 2
    assert store.read_active() == (2, orphan)
    assert _fresh_provider(tmp_path, fake)[0].resolve_key().get_bytes() == key
    assert provider.rewrap() == 3  # and rotation carries on


def test_a_rewrap_does_not_adopt_a_generation_that_wraps_another_key(tmp_path):
    provider, fake = _fresh_provider(tmp_path)
    provider.resolve_key()
    store = GenerationStore(tmp_path / "vt")
    context = fake.calls[0][1]["context"]
    other_key = b"vault:v2:" + base64.b64encode(context.encode() + b"|" + b"\x99" * 32)
    store._write_generation(2, other_key)
    with pytest.raises(CustodyDowngradeError, match="unpublished generation 2 .* not adopted"):
        provider.rewrap()
    assert store.read_active()[0] == 1


class _TrickleResponse(_StubResponse):
    """A body that arrives a byte at a time, each inside the socket timeout."""

    def __init__(self, clock):
        self._clock = clock
        self.reads = 0

    def read1(self, _n: int) -> bytes:
        self.reads += 1
        self._clock.now += 0.4
        return b" "

    read = read1


def test_a_response_that_trickles_is_cut_off_at_the_timeout(monkeypatch):
    """The socket timeout bounds each receive, so a slow drip never tripped it."""
    from floorvault.providers import vault_transit

    class Clock:
        now = 1000.0

    clock = Clock()
    monkeypatch.setattr(vault_transit.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(vault_transit.time, "sleep", lambda _s: None)
    transport = UrllibTransport(ADDR, timeout=2.0, retries=0)
    response = _TrickleResponse(clock)
    transport._opener = type("Opener", (), {"open": lambda self, request, timeout: response})()
    with pytest.raises(CustodyDowngradeError, match="unreachable .TimeoutError."):
        transport.post("/v1/x", {}, TOKEN)
    assert response.reads <= 7, "the read went on past the deadline"


def test_a_body_in_several_pieces_is_put_together_and_still_bounded():
    from floorvault.providers import vault_transit

    class Pieces(_StubResponse):
        def __init__(self, pieces):
            self._pieces = list(pieces)

        def read1(self, n: int) -> bytes:
            return self._pieces.pop(0)[:n] if self._pieces else b""

    transport = UrllibTransport(ADDR, retries=0)
    body = Pieces([b'{"data": ', b'{"ok": ', b"true}}"])
    transport._opener = type("Opener", (), {"open": lambda self, request, timeout: body})()
    assert transport.post("/v1/x", {}, TOKEN) == {"data": {"ok": True}}
    huge = Pieces([b"x" * 16384] * 10)
    transport._opener = type("Opener", (), {"open": lambda self, request, timeout: huge})()
    with pytest.raises(CustodyDowngradeError, match="exceeds the bounded size"):
        transport.post("/v1/x", {}, TOKEN)
    assert vault_transit._MAX_RESPONSE_BYTES < 16384 * 10

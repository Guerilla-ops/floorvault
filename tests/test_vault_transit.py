"""Vault Transit provider tests against a fake Vault (roadmap 1f).

The fake implements the narrow transport interface (``post(path, body,
token)``) with real semantics: blobs carry their context, decrypt/rewrap
reject a mismatched context, and faults are injected per call. No sockets.
"""

from __future__ import annotations

import base64
import json
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
        op = path.split("/")[3]
        context = body.get("context")
        if op == "datakey":
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
    assert fake.calls[0][0] == "/v1/transit/datakey/floorvault"
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
    assert TOKEN not in str(excinfo.value)
    assert TOKEN not in repr(excinfo.value.__cause__)


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
        return self._payload

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

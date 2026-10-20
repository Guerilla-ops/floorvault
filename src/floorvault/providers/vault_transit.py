"""HashiCorp Vault Transit provider: a Vault-wrapped master key.

The master key is generated and unwrapped by Vault's Transit engine; only the
ciphertext blob is stored locally, in a :class:`GenerationStore` whose
governed update protocol handles KEK rewraps. This module owns the online
contract (R2/R4/R5):

  * **Verified HTTPS only.** Plain HTTP and unverified TLS are refused at
    construction. Timeouts, response size and retries are bounded; Vault HA
    307 redirects are refused unless the caller names trusted standby hosts.
  * **Versioned context.** Every ``datakey``/``decrypt``/``rewrap`` call
    carries the same context: app instance + store ID + the fixed purpose
    ``floorvault-master-wrap`` + custody scheme. Context is cryptographic
    separation, not tenant authorization - provisioning the transit key
    (``derived=true``, ``aes256-gcm96``, ``exportable=false``,
    ``allow_plaintext_backup=false``) and splitting provisioning from runtime
    permissions are operator duties documented in ``docs/VAULT-TRANSIT.md``.
  * **Fail closed.** Unreachable Vault, 403, malformed or failing decrypt all
    raise ``CustodyDowngradeError``; nothing falls through to weaker custody.
    Tokens never appear in error messages or logs.
  * **Narrow revocation scope.** The decrypted master key is cached for
    ``cache_ttl`` seconds; token revocation does not retroactively expire an
    already-derived key. The TTL bounds staleness, not revocation.

The transport is stdlib ``urllib``/``ssl`` behind a narrow ``post(path, body)``
interface, so tests exercise the full provider against a fake Vault without
sockets (``hvac`` remains a possible optional extra, not a dependency).
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..memory import HardenedMemoryKey
from .base import CustodyDowngradeError, KeyProvider, MissingKeyError
from .generation_store import MAX_PAYLOAD_BYTES, GenerationStore
from .platform_custody import (
    ProtectedStoreError,
    ProtectedStoreMissing,
    read_protected,
    write_protected,
)

#: Fixed cryptographic purpose for every Transit call - the context names
#: *what this ciphertext is*, so a Vault-wrapped blob can never be replayed
#: into a different purpose by a confused operator.
PURPOSE = "floorvault-master-wrap"
CUSTODY_SCHEME = "vault-transit"
_CONTEXT_VERSION = 1

#: Store-identity file: a random, immutable 16-byte ID minted at provision and
#: bound into every Transit context. No filesystem paths and no KEK version go
#: into the context - both are mutable facts, not identity.
_STORE_ID_NAME = "store.id"
_STORE_ID_HEADER = b"FVSTORID1"

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_RETRIES = 2
_DEFAULT_CACHE_TTL = 300.0
_MAX_RESPONSE_BYTES = 65536
#: A wrapped blob lands in a generation file, so its size ceiling is the
#: store's payload capacity - a blob that fits the response cap but not the
#: store would publish state that can never be read back.
_MAX_BLOB_BYTES = MAX_PAYLOAD_BYTES
#: ``vault:v<digits>:<standard base64>`` - the complete shape, not a prefix.
#: `startswith("vault:v")` admits `vault:vgarbage`; Vault would never emit it,
#: so a blob that fails this is malformed, not merely old.
_BLOB_PATTERN = re.compile(rb"vault:v\d+:[A-Za-z0-9+/=]+")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect; Vault HA 307s need an explicit trust contract.

    With this handler installed the opener raises ``HTTPError`` for any
    redirect response, and the transport vets the ``Location`` itself -
    urllib's redirect machinery is not built to apply a per-host trust
    policy, so the policy lives in the bounded loop, not the handler.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibTransport:
    """Narrow HTTPS transport: ``post(path, body) -> decoded JSON``.

    Verified TLS, bounded timeout and response size, bounded retries on
    connection failures and 5xx, redirects refused unless the caller named
    trusted standby hosts. The Vault token is attached per request and never
    appears in raised errors.
    """

    def __init__(
        self,
        vault_addr: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        allowed_redirect_hosts: frozenset[str] = frozenset(),
        cafile: str | os.PathLike | None = None,
    ) -> None:
        parts = urllib.parse.urlparse(vault_addr)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(
                "vault_addr must be an https:// URL; plain HTTP cannot carry "
                "a token that unwraps the master key"
            )
        if not 0 < timeout <= 60:
            raise ValueError("timeout must be in (0, 60] seconds")
        self._base = vault_addr.rstrip("/")
        self._timeout = timeout
        self._retries = max(0, retries)
        self._allowed_redirect_hosts = frozenset(allowed_redirect_hosts)
        # The verified-TLS context is bound into the HTTPS handler itself:
        # OpenerDirector.open() takes no per-call context argument. The
        # redirect handler refuses everything; redirects are reissued
        # manually below so the trusted-standby list is enforced per hop.
        # ``cafile`` pins an internal-CA bundle for Vaults that are not on a
        # public CA (private PKI is the norm, not an exception); verification
        # stays on in every case.
        context = ssl.create_default_context(cafile=None if cafile is None else str(cafile))
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def _build_request(self, url: str, body: dict, token: str) -> urllib.request.Request:
        return urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "X-Vault-Token": token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

    def post(self, path: str, body: dict, token: str) -> dict:
        url = f"{self._base}{path}"
        request = self._build_request(url, body, token)
        redirected = False
        attempt = 0
        while True:
            attempt += 1
            # HTTPError retains server-controlled response headers and the
            # redirect Location - a Vault endpoint can echo request material
            # back. The terminal raises happen AFTER the except so neither
            # __cause__ nor __context__ can reach the exception object; only
            # extracted scalars (code, vetted location) survive.
            http_failure: str | None = None
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    raw = response.read(_MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as exc:
                code = exc.code
                if code in (307, 308):
                    location = exc.headers.get("Location", "")
                    target = urllib.parse.urlparse(location)
                    if (
                        not redirected
                        and target.scheme == "https"
                        and target.hostname in self._allowed_redirect_hosts
                    ):
                        redirected = True
                        request = self._build_request(location, body, token)
                        continue
                    http_failure = (
                        f"Vault answered with redirect {code}; redirects are "
                        "refused unless the standby host is trusted via "
                        "allowed_redirect_hosts"
                    )
                elif 400 <= code < 500:
                    http_failure = (
                        f"Vault refused the request (HTTP {code}); check the "
                        "runtime token's transit decrypt/datakey permissions"
                    )
                elif attempt > self._retries:
                    http_failure = f"Vault returned HTTP {code} after {attempt} attempt(s)"
                else:
                    time.sleep(0.1 * attempt)
                    continue
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                # URLError is raised client-side (DNS/connect/TLS failure) and
                # carries no server response body; keeping the cause preserves
                # diagnostics without a server-controlled chain object.
                if attempt > self._retries:
                    raise CustodyDowngradeError(
                        f"Vault is unreachable ({type(exc).__name__}); refusing "
                        "to fall back to weaker custody"
                    ) from exc
                time.sleep(0.1 * attempt)
                continue
            if http_failure is not None:
                raise CustodyDowngradeError(http_failure)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise CustodyDowngradeError("Vault response exceeds the bounded size")
            # Decode errors retain the server-controlled body (UnicodeDecode
            # Error.object / JSONDecodeError.doc hold the raw bytes - a Vault
            # response can echo the token we sent). Capture only the error
            # class name and raise OUTSIDE the except block: 'from None'
            # suppresses the printed chain but __context__ still retains the
            # object, which structured error reporters can serialize.
            decode_error: str | None = None
            try:
                decoded = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                decode_error = type(exc).__name__
            if decode_error is not None:
                raise CustodyDowngradeError(f"Vault response is not valid JSON ({decode_error})")
            if not isinstance(decoded, dict):
                raise CustodyDowngradeError("Vault response is not a JSON object")
            return decoded


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    # encode() failure retains the server-supplied string in
    # UnicodeEncodeError.object; raise outside the except so no exception
    # attribute (__cause__ or __context__) can reach it.
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError:
        encoded = None
    if encoded is None:
        raise ValueError("field is not ASCII")
    return base64.b64decode(encoded, validate=True)


def _require_wrapped_blob(value: object) -> bytes:
    """Return a ``vault:vN:<base64>`` blob as bytes, or refuse, sanitized.

    Shared by provisioning and rewrap: a malformed or oversized blob must
    never become the authoritative generation - the plaintext master key
    it claims to wrap would be unrecoverable on the next resolve.
    """
    if not isinstance(value, str):
        raise CustodyDowngradeError("Vault response carries no wrapped blob")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raw = None
    if raw is None:
        # The encode error retains the server-supplied string; raising after
        # the except keeps it out of __cause__ and __context__ alike.
        raise CustodyDowngradeError("Vault wrapped blob is not ASCII")
    if len(raw) > _MAX_BLOB_BYTES:
        raise CustodyDowngradeError("wrapped blob exceeds the bounded size")
    if not _BLOB_PATTERN.fullmatch(raw):
        raise CustodyDowngradeError("Vault wrapped blob is not vault:vN:<base64>")
    return raw


class VaultTransitProvider(KeyProvider):
    """Resolve the master key from a Vault-Transit-wrapped generation store.

    ``resolve_key`` mints a datakey on first use (``allow_create``) or
    decrypts the stored wrapped blob. ``rewrap`` asks Vault to re-encrypt the
    blob under the current KEK version and CAS-publishes it as the next
    generation. Neither path ever writes or logs the plaintext master key.
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        key_name: str,
        store_dir: str | Path,
        token: str | None = None,
        app_instance_id: str = "default",
        transit_mount: str = "transit",
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        cache_ttl: float = _DEFAULT_CACHE_TTL,
        allowed_redirect_hosts: frozenset[str] | tuple[str, ...] = (),
        cafile: str | os.PathLike | None = None,
        transport: Any | None = None,
    ) -> None:
        if not key_name or not key_name.strip():
            raise ValueError("key_name must name an operator-provisioned transit key")
        # The HTTPS contract lives at the provider too: an injected transport
        # must not be able to weaken the advertised endpoint guarantee.
        parsed_addr = urllib.parse.urlparse(vault_addr)
        if parsed_addr.scheme != "https" or not parsed_addr.hostname:
            raise ValueError("vault_addr must be an https:// URL")
        self._key_name = key_name
        self._app_instance_id = app_instance_id
        self._mount = transit_mount.strip("/")
        self._cache_ttl = cache_ttl
        self._token = token if token is not None else os.environ.get("VAULT_TOKEN")
        if not self._token:
            raise MissingKeyError(
                "no Vault token configured (token= or VAULT_TOKEN); the runtime "
                "token needs only transit datakey/decrypt/rewrap on this key"
            )
        self._store = GenerationStore(store_dir)
        self._store_id_path = self._store.directory / _STORE_ID_NAME
        self._transport = transport or UrllibTransport(
            vault_addr,
            timeout=timeout,
            retries=retries,
            allowed_redirect_hosts=frozenset(allowed_redirect_hosts),
            cafile=cafile,
        )
        self._cached: bytearray | None = None
        self._cached_at = 0.0

    # ------------------------------------------------------------------
    # KeyProvider
    # ------------------------------------------------------------------

    def resolve_key(self, *, allow_create: bool = True) -> HardenedMemoryKey:
        cached = self._read_cache()
        if cached is not None:
            return cached
        try:
            generation, blob = self._store.read_active()
        except ProtectedStoreMissing:
            if not allow_create:
                raise MissingKeyError(
                    "no wrapped master key is stored and creation is disallowed"
                ) from None
            return self._provision()
        except ProtectedStoreError as exc:
            raise CustodyDowngradeError(f"wrapped-master store is unusable: {exc}") from exc
        # The store is provisioned, so its identity must exist: the context is
        # rebuilt only on this path, where a missing store.id is corruption.
        plaintext = self._transit_decrypt(blob, self._context())
        return self._cache(plaintext)

    def rewrap(self) -> int:
        """Rewrap under the current KEK version; return the new generation.

        Vault returns the same plaintext under a fresh ``vault:vN`` blob; the
        pointer CAS prevents a concurrent rewrap from resurrecting the old
        generation. Documented alongside DEK rotation in docs/VAULT-TRANSIT.md.
        """
        context = self._context()
        try:
            generation, blob = self._store.read_active()
        except (ProtectedStoreMissing, ProtectedStoreError) as exc:
            raise CustodyDowngradeError(
                f"cannot rewrap: wrapped-master store is unusable ({exc})"
            ) from exc
        response = self._call("rewrap", {"ciphertext": blob.decode("ascii"), "context": context})
        new_blob = self._unwrap_response(response)
        return self._store.update(new_blob, expected_generation=generation)

    # ------------------------------------------------------------------
    # Transit calls
    # ------------------------------------------------------------------

    def _provision(self) -> HardenedMemoryKey:
        # The store ID must exist before the context is computed, and a failed
        # first attempt must not leave an orphan ID that poisons every retry:
        # ensure-or-read rather than create-or-fail.
        store_id = self._ensure_store_id()
        context = self._context_for(store_id)
        # The plaintext/ciphertext selector is a path segment in the Vault
        # API, not a request field.
        response = self._call("datakey/plaintext", {"context": context})
        data = self._data_field(response)
        plaintext_b64 = data.get("plaintext")
        if not isinstance(plaintext_b64, str):
            raise CustodyDowngradeError("Vault datakey response lacks plaintext/ciphertext")
        try:
            plaintext = _b64d(plaintext_b64)
        except ValueError as exc:
            raise CustodyDowngradeError("Vault datakey plaintext is not valid base64") from exc
        if len(plaintext) != 32:
            raise CustodyDowngradeError(
                f"Vault datakey returned {len(plaintext)} bytes, not a 32-byte master key"
            )
        # Validate the wrapped blob BEFORE it becomes authoritative: a blob
        # that is not vault:vN:<base64> would publish state whose plaintext we
        # hold now but no future resolve can ever decrypt.
        blob = _require_wrapped_blob(data.get("ciphertext"))
        try:
            self._store.provision(blob)
        except ProtectedStoreError:
            # Another writer won the provision race. The datakey we hold is not
            # the store's blob - resolve the winner's instead of returning a
            # key the store does not authenticate.
            winner = self._await_active()
            plaintext = self._transit_decrypt(winner[1], self._context())
        return self._cache(plaintext)

    def _await_active(self, attempts: int = 10) -> tuple[int, bytes]:
        """Read the authoritative generation after losing a provision race.

        The winner may still be between writing its generation file and
        repointing ``active``, so a brief bounded wait replaces a spurious
        failure - bounded, because waiting forever is its own failure.
        """
        for attempt in range(attempts):
            try:
                return self._store.read_active()
            except ProtectedStoreMissing:
                time.sleep(0.05)
            except ProtectedStoreError as exc:
                raise CustodyDowngradeError(
                    f"wrapped-master store is unusable after a provision race: {exc}"
                ) from exc
        raise CustodyDowngradeError(
            "a competing provision won but never published a readable generation"
        )

    def _transit_decrypt(self, blob: bytes, context: str) -> bytes:
        response = self._call("decrypt", {"ciphertext": blob.decode("ascii"), "context": context})
        data = self._data_field(response)
        plaintext_b64 = data.get("plaintext")
        if not isinstance(plaintext_b64, str):
            raise CustodyDowngradeError("Vault decrypt response lacks plaintext")
        try:
            plaintext = _b64d(plaintext_b64)
        except ValueError as exc:
            raise CustodyDowngradeError("Vault decrypt plaintext is not valid base64") from exc
        if len(plaintext) != 32:
            raise CustodyDowngradeError(
                f"Vault decrypt returned {len(plaintext)} bytes, not a 32-byte master key"
            )
        return plaintext

    def _call(self, operation: str, body: dict) -> dict:
        path = f"/v1/{self._mount}/{operation}/{self._key_name}"
        # Transport exceptions may embed server-controlled text that echoes
        # request headers or the token. Capture only the exception's class
        # name and raise OUTSIDE the except: 'from None' would still leave
        # the object reachable through __context__.
        failure: str | None = None
        try:
            return self._transport.post(path, body, self._token)
        except CustodyDowngradeError:
            raise
        except Exception as exc:
            failure = type(exc).__name__
        raise CustodyDowngradeError(f"Vault {operation} failed ({failure})")

    def _data_field(self, response: dict) -> dict:
        data = response.get("data")
        if not isinstance(data, dict):
            raise CustodyDowngradeError("Vault response has no data object")
        return data

    def _unwrap_response(self, response: dict) -> bytes:
        data = self._data_field(response)
        return _require_wrapped_blob(data.get("ciphertext"))

    # ------------------------------------------------------------------
    # Context and store identity
    # ------------------------------------------------------------------

    def _context(self) -> str:
        store_id = self._read_store_id()
        return self._context_for(store_id)

    def _context_for(self, store_id: bytes) -> str:
        return _b64e(
            json.dumps(
                {
                    "v": _CONTEXT_VERSION,
                    "app": self._app_instance_id,
                    "store": store_id.hex(),
                    "purpose": PURPOSE,
                    "custody": CUSTODY_SCHEME,
                },
                separators=(",", ":"),
                sort_keys=True,
                # Canonical JSON is UTF-8-as-written: ensure_ascii escaping
                # would make a non-ASCII app id produce different context
                # bytes than an implementation following the spec produces.
                ensure_ascii=False,
            ).encode("utf-8")
        )

    def _read_store_id(self) -> bytes:
        try:
            return read_protected(self._store_id_path, header=_STORE_ID_HEADER, expected_length=16)
        except (ProtectedStoreMissing, ProtectedStoreError) as exc:
            raise CustodyDowngradeError(
                f"store identity is missing or unreadable ({exc}); the Transit "
                "context cannot be rebuilt, so the wrapped blob cannot be decrypted"
            ) from exc

    def _ensure_store_id(self) -> bytes:
        """Return the store's identity, minting it only when it is absent.

        Absent is the only mintable state: a corrupt identity must surface
        the corruption, not be silently replaced - a new ID changes the
        context and strands every blob the old ID ever wrapped.
        """
        try:
            return read_protected(self._store_id_path, header=_STORE_ID_HEADER, expected_length=16)
        except ProtectedStoreMissing:
            pass
        except ProtectedStoreError as exc:
            raise CustodyDowngradeError(f"store identity is corrupt: {exc}") from exc
        store_id = secrets.token_bytes(16)
        try:
            write_protected(
                store_id, self._store_id_path, header=_STORE_ID_HEADER, expected_length=16
            )
        except ProtectedStoreError:
            # Lost a mint race: adopt the winner's identity so both writers
            # compute the same Transit context.
            return self._read_store_id()
        return store_id

    # ------------------------------------------------------------------
    # Cache - bounded staleness, never a revocation claim
    # ------------------------------------------------------------------

    def _read_cache(self) -> HardenedMemoryKey | None:
        if self._cached is None or self._cache_ttl <= 0:
            return None
        if time.monotonic() - self._cached_at > self._cache_ttl:
            self._drop_cache()
            return None
        return HardenedMemoryKey(bytes(self._cached))

    def _cache(self, plaintext: bytes) -> HardenedMemoryKey:
        if self._cache_ttl > 0:
            self._drop_cache()
            self._cached = bytearray(plaintext)
            self._cached_at = time.monotonic()
        return HardenedMemoryKey(plaintext)

    def _drop_cache(self) -> None:
        if self._cached is not None:
            for i in range(len(self._cached)):
                self._cached[i] = 0
            self._cached = None

    def wipe(self) -> None:
        """Drop the cached master key; the wrapped blob stays durable on disk."""
        self._drop_cache()

    def __enter__(self) -> VaultTransitProvider:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()


__all__ = ["PURPOSE", "CUSTODY_SCHEME", "UrllibTransport", "VaultTransitProvider"]

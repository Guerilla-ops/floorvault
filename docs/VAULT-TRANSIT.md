# Vault Transit custody — operator guide

`VaultTransitProvider` stores the FloorVault master key as a blob *wrapped* by
HashiCorp Vault's Transit engine. Vault holds the key-encryption key (KEK);
the repository's on-disk state holds only ciphertext. Normative formats are in
[SPEC.md §10.6–10.7](SPEC.md); this document is the operator's view.

## What lives where

```
<store_dir>/                 (owner-only directory, 0700)
  store.id                   FVSTORID1 + 16 random bytes — the store's identity
  g-00000001.gen             FVGW1 + the Vault "vault:v1:<...>" wrapped blob
  active                     FVGW0 + generation + SHA-256(payload)
```

- `store.id` is minted once. It is part of the Transit **encryption context**,
  so a blob wrapped for one store directory can never be decrypted for another.
- `g-*.gen` files are immutable; `active` is the only replaced object.
- Nothing in `store_dir` is secret in itself — it is ciphertext and identity —
  but the directory is still hardened to the protected-store contract so that
  an attacker who can only *replace* files cannot point the provider at a
  foreign generation.

## Vault-side setup (operator duty)

```hcl
# runtime policy — the ONLY permissions the resolving token needs
path "transit/datakey/plaintext/floorvault-master"  { capabilities = ["update"] }
path "transit/decrypt/floorvault-master"  { capabilities = ["update"] }
path "transit/rewrap/floorvault-master"   { capabilities = ["update"] }
```

```bash
# derived=true makes the context binding enforceable; exportable=false and
# allow_plaintext_backup=false keep key material inside Vault.
vault write transit/keys/floorvault-master \
    type=aes256-gcm96 \
    derived=true \
    exportable=false \
    allow_plaintext_backup=false
vault policy write floorvault-runtime runtime-policy.hcl
vault token create -policy=floorvault-runtime -period=24h
```

Notes:

- The Transit key is **operator-provisioned** with exactly these settings;
  the provider never creates or configures keys, and needs no `read`/`list`
  on `keys/*`. `derived=true` is what turns the `context` parameter into an
  enforced cryptographic binding — without it Vault ignores the context and
  any store's blob would decrypt under any context. `exportable=false` and
  `allow_plaintext_backup=false` keep the KEK non-extractable.
- The context mechanism (`datakey`/`decrypt`/`rewrap` all carry it) means a
  ciphertext provisioned under a different app/store will fail to decrypt even
  with a perfectly valid token — that is the intended binding.
- Keep the token out of logs. The provider never places it in exception
  messages or causes, but the token is the only credential standing between
  a stolen `store_dir` and the plaintext master key.

## Using it

```python
from floorvault.providers.vault_transit import VaultTransitProvider

provider = VaultTransitProvider(
    vault_addr="https://vault.internal:8200",
    key_name="floorvault-master",
    store_dir="/var/lib/myapp/floorvault",
    app_instance_id="my-app",
    # token=... or VAULT_TOKEN env var
    # cafile="/etc/myapp/vault-ca.pem",  # internal-CA bundle if Vault is on
    #                                    # private PKI; TLS stays verified
)
master = provider.resolve_key()  # provisions on first use
```

`cafile` pins a CA bundle for Vaults on internal PKI (the common case). TLS
verification is never disabled — `cafile` changes *which* CAs are trusted, not
*whether* the chain is checked.

`resolve_key()` mints a `datakey` on first use (subject to `allow_create`),
decrypts the stored blob afterwards, and caches the plaintext in-process for
`cache_ttl` seconds (default 300). `provider.wipe()` drops the cache; the
wrapped store is unaffected.

## KEK rotation (rewrap)

```bash
vault write -f transit/keys/floorvault-master/rotate   # Vault-side KEK -> v2
```

```python
provider.rewrap()  # rewrap blob under KEK v2, publish generation 2
```

`rewrap` returns the new plaintext-independent blob and CAS-publishes it:
a concurrent or stale `rewrap` fails with `GenerationMismatchError` rather
than resurrecting the superseded generation. Older `g-*.gen` files stay
immutable on disk; remove them only after verifying `active` points to the
newest generation.

**Data-key rotation is different** — rewrapping changes which KEK protects
the master key, not the key itself. Rotating the actual master key means
`rotate_vault_store` (data re-encryption), which is orthogonal.

## Failure semantics — all fail closed

| Condition | Result |
|---|---|
| `store_dir` uninitialized | `resolve_key` provisions (if `allow_create`) |
| Vault unreachable / timeout / 5xx (after retries) | `CustodyDowngradeError` |
| Any 4xx (bad token, missing permission) | `CustodyDowngradeError`, no retry |
| Malformed response, wrong-length plaintext, non-`vault:v*` blob | `CustodyDowngradeError` |
| Redirect to a non-allowlisted or non-HTTPS host | `CustodyDowngradeError` |
| `store.id` corrupt or pointer/generation tampered | `CustodyDowngradeError` |
| Writer lock held | `StoreLockError` |

**There is no fallback to weaker custody.** If the provider is configured and
Vault is down, resolution fails — it does not write a `master.key` and it does
not decrypt against a file. This is deliberate: silent downgrade converts an
availability event into a custody downgrade.

## Cache caveat

`cache_ttl` bounds how long a resolved plaintext master stays in memory and
how stale a Vault-side policy revocation can be. It is a *latency bound*, not
a revocation guarantee: a revoked token stops future `decrypt` calls, but the
in-process cache keeps serving until it expires. Set `cache_ttl=0` to require
a Transit round-trip per resolution.

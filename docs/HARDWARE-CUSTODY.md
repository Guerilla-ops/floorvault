# Hardware custody: PKCS#11 tokens (Swissbit iShield HSM / Key Pro)

Design for keeping a FloorVault master key behind a hardware token. Status:
**planned** — tracked in
[issue #35](https://github.com/Guerilla-ops/floorvault/issues/35). Nothing on
this page is implemented yet; the document exists so the mechanism choices are
pinned down before code.

## Scope

A hardware token does **not** encrypt records. Per-record AES-256-SIV stays in
software, with the same contextual AAD the rest of the library uses. What the
hardware protects is **custody of the 32-byte master key**: the only durable
form is a ciphertext wrapped under a non-exportable key-encryption key (KEK)
that never leaves the secure element.

This is the same shape as the Vault Transit provider
(`docs/VAULT-TRANSIT.md`): a remote KEK over HTTPS is replaced by a local KEK
over PKCS#11, and every other property carries over — a wrapped-blob
`GenerationStore`, fixed-purpose context binding, bounded plaintext cache, and
fail-closed error semantics.

## Device model

The target hardware is a Swissbit unit combining:

- **HSM/PIV side** — a CCID smartcard (OpenSC `opensc-pkcs11.so`, IsoApplet on
  a CC EAL6+ secure element) holding non-exportable keys.
- **FIDO2 side** — a WebAuthn authenticator for human-approval ceremonies in
  consuming applications. It signs challenges; it does not wrap keys. The two
  functions stay cryptographically and administratively separate.

The device never sees record plaintexts and never should.

## Architecture

```
PKCS#11 token (OpenSC)
  KEK: non-exportable RSA or EC key
    |
    | unwrap / wrap
    v
GenerationStore                 HardenedMemoryKey (bounded TTL)
  g-00000001.gen  ─────────────>  32-byte master key
  active (CAS pointer +           -> HKDF -> AES-SIV subkeys
          SHA-256 bound)
```

1. `GenerationStore.read_active()` returns `(generation, wrapped_blob)`.
   `ProtectedStoreMissing` is the only state that may provision.
2. A single PKCS#11 session locates the KEK by label and expected mechanism.
3. The blob is unwrapped on-device; the provider validates exactly 32 bytes
   and caches the `HardenedMemoryKey` for a bounded TTL (default 300 s,
   matching the Transit provider).
4. Every failure — device absent, PIN refused, mechanism missing, blob
   malformed — is a `CustodyDowngradeError`. Nothing falls through to a
   weaker custody tier, ever.

## Provisioning ceremony

1. Probe the token (`pkcs11-tool --module opensc-pkcs11.so -M -O`) and record
   the mechanism matrix; this decides the wrap scheme below.
2. Generate the KEK on-device: RSA-3072/4096 with OAEP-SHA-256 preferred;
   EC P-256 ECDH-derive or AES key-wrap are the documented fallbacks. Template
   must set `SENSITIVE`, `NEVER_EXTRACTABLE`, `ALWAYS_SENSITIVE`, PIN required.
3. Generate the 32-byte master key in-process and wrap it under the KEK —
   the operation depends on the probed mechanism: RSA-OAEP encrypts to the
   KEK public key; AES key-wrap or ECDH-derive wrap under a token-resident
   key directly (no public-key step exists for those paths).
   Publish via `GenerationStore.provision`.
4. Mint the `store.id` identity (`FVSTORID1`) and bind the wrapped blob to
   this deployment: RSA-OAEP carries the store id in the mechanism's
   source-data (label) field where the token exposes it. Mechanisms without
   a context field produce a blob that authenticates only to the KEK — for
   those, cross-store substitution is outside what the wrap can express and
   store binding lives solely in the GenerationStore pointer binding.
5. Independent recovery: `floorvault.key_recovery.wrap_master_key` produces a
   `FVRB1` bundle under a separately protected recovery key — this is what
   survives a lost or factory-reset token.

Migrating an existing deployment changes custody only: the master key value is
unchanged, so all existing ciphertext stays valid. Read the current provider's
key once, rewrap to the device, publish, verify reads, and only then retire
the old custody item.

## Failure-mode contract

- Device removed or locked → `CustodyDowngradeError`; the TTL cache serves
  until expiry, then reads fail closed.
- PIN lockout (PIV devices lock after a fixed retry count and may require a
  factory reset) → backoff with hard retry ceiling; never loop on the PIN.
- Pointer tampering → the CAS pointer's SHA-256 binding refuses an
  inconsistent generation. A superseded-but-valid generation is NOT refused:
  replaying an earlier `active` pointer is a rollback, and freshness needs a
  trusted monotonic anchor outside the attacker's rewrite domain (the same
  caveat class as whole-directory rollback below).
- Whole-directory rollback is out of scope (same caveat as Vault Transit).
- In-process key disclosure is bounded by TTL, not eliminated — the same
  honest limit every provider has.

## Verification plan

- Contract tests run against a fake PKCS#11 seam (the provider takes a narrow
  `decrypt(blob) -> bytes` transport, mirroring `UrllibTransport`), so the
  suite never touches hardware.
- An opt-in hardware leg (env-gated, like the live Vault tests) exercises
  provision → resolve → rewrap → recover on the real token.
- Mutation coverage for the new guards: mechanism pinning, 32-byte
  enforcement, store-id binding, unwrap-failure classification.

## Open items before implementation

1. Vendor/firmware documentation for the specific unit: mechanism table,
   PIV applet version, whether subsystems share PIN session state, and the
   certification scope of the FIPS 140-3 claim.
2. UX decision: PIN per unwrap, or a short-lived logged-in session bounded by
   TTL and device-removal events.
3. Packaging: `floorvault[pkcs11]` extra carrying `python-pkcs11`, with
   `opensc-pkcs11.so` as the system dependency.

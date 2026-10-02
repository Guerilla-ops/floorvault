# FloorVault wire format — cross-language contract

**Status:** current as of 2026-10-02 · applies to `feat/v3-token-ttl`
**Audience:** port implementers, auditors, anyone re-deriving these bytes
outside this repository.

This document is the complete byte-level contract. A conforming port must
produce and accept exactly the envelopes described here.
`tests/vectors/floorvault_wire_vectors.json` pins the contract — envelopes
built independently of the implementation; if a port reproduces those bytes
from the documented inputs, it is wire-correct both directions.

Supersedes `docs/RECORD-FORMAT-2026-09-15.md` (which documents v1/v2 and the
store format; the v1/v2 sections there remain accurate and are restated here
for a single-source reference).

---

## 1. Key derivation

```
siv_key = HKDF-SHA256(
    ikm  = master_key,          # exactly 32 bytes
    salt = None,                # absent — not the empty string
    info = "floorvault-v1-aes-siv",   # ASCII, no trailing NUL
    L    = 64,
)
```

The 64-byte output is the AES-256-SIV key material directly (RFC 5297 takes
a double-length key: first 32 bytes = S2V/CMAC key, second 32 = CTR key —
the AESSIV implementation splits internally; a port hands it all 64 bytes).

`master_key` shorter or longer than 32 bytes is refused.

## 2. Canonical AAD JSON

The AAD payload is a JSON object serialized with **Python-canonical**
semantics:

- keys sorted lexicographically (`sort_keys=True`)
- compact separators `,` and `:` — no whitespace anywhere
- UTF-8 output with **no** `\uXXXX` escaping of non-ASCII
  (`ensure_ascii=False`)
- standard JSON escaping only where required: `"` `\` and C0 controls
  (`\b` `\f` `\n` `\r` `\t`, other C0 as `\u00XX`)
- integers render bare (no quotes, no leading zeros)

Field set, in the emitted (sorted) order — this exact key set:

| key | type | notes |
|---|---|---|
| `app_instance_id` | string | from the instance |
| `column` | string | field coordinate |
| `record_id` | string | field coordinate |
| `revision` | integer | **only present when non-null** |
| `schema_id` | string | e.g. `floor.vault.v1` |
| `schema_version` | integer | bool/non-int refused at the API |
| `table` | string | field coordinate |

Example (from the corpus):

```
{"app_instance_id":"default","column":"email","record_id":"u-1001","schema_id":"floor.vault.v1","schema_version":1,"table":"users"}
```

**This is not RFC 8785 (JCS).** JCS prescribes different number and string
normalization; do not substitute a JCS serializer. Byte-exactness on
adversarial strings (embedded quotes, backslashes, NUL, non-BMP) is pinned
by the `v2-unicode-escape` vector.

## 3. Envelopes

All integers are unsigned, big-endian, fixed width. `nonce` is 16 bytes from
a CSPRNG, fresh per record.

### v2 — field ciphertexts (current field writer)

```
FLV2 ‖ crypto_version(1) ‖ key_id(1) ‖ nonce_len(1) ‖ nonce(16) ‖ ct
```

`crypto_version` = `2` for this construction. `key_id` selects the key
(0–255). `nonce_len` must be `16`.

### v1 — legacy field ciphertexts (read-only)

```
FLRV ‖ nonce_len(1) ‖ nonce(16) ‖ ct
```

No header. Carried for back-compat; nothing writes it now.

### v3 — token envelopes (one-shot API)

```
FLV3 ‖ crypto_version(1) ‖ key_id(1) ‖ exp(8) ‖ nbf(8) ‖ iat(8)
     ‖ ctx_len(2) ‖ ctx(ctx_len) ‖ nonce_len(1) ‖ nonce(16) ‖ ct
```

`exp`, `nbf`, `iat` are unix seconds; `0` means absent (`exp`/`nbf`) or is
always present (`iat`). `ctx` is a canonical-JSON object with **exactly**:

```json
{"app_instance_id": "<writer instance id>", "purpose": "<token purpose>"}
```

Unknown or mis-typed ctx keys are rejected — an ignored claim is a
downgrade vector.

**Cleartext metadata note:** the ctx claim is authenticated but not secret —
anyone holding the token reads `purpose` and `app_instance_id` (the same
exposure class as Fernet's cleartext timestamp, just richer). If a purpose
label would itself be sensitive, mint it opaquely (`"t7"`, `"flow:b"`); the
assertion contract is unaffected.

**Overhead:** the v3 header is fixed at `33 + ctx_len` bytes — ~115 B total
envelope overhead for typical purposes vs Fernet's ~57 B raw (+padding)
× 4/3 base64. v3 is larger below ~48 B payloads and increasingly smaller
past that.

v3 coordinates are fixed: `table="_fv.token"`, `column="payload"`,
`schema_id="floor.vault.token.v1"`, `schema_version=1`, `revision` absent;
`record_id` = the ctx `purpose`. The `app_instance_id` in the AAD is the
*reader's* instance id — a token only authenticates under the same
instance id and key it was sealed for.

## 4. SIV associated-data vector

`AESSIV.encrypt(plaintext, ad)` where `ad` is an ordered list:

| index | element | v1 | v2 | v3 |
|---|---|:---:|:---:|:---:|
| 0 | canonical AAD JSON (§2) | ✅ | ✅ | ✅ |
| 1 | envelope header bytes — everything before `nonce` | — | 7 B | `33 + ctx_len` B |
| 2 | nonce (as the final AD component — RFC 5297 nonce position) | ✅ | ✅ | ✅ |

Element boundaries are part of the contract: the cleartext header is a
*separate* AD element, so rewritten `key_id`, `exp`, or `ctx` fail the tag.

`ct` = `SIV_tag(16) ‖ CTR_ciphertext` — the AESSIV output verbatim.

## 5. Rejection rules (a port must fail identically)

- Wrong magic, truncated header, `nonce_len != 16`, empty `ct` → reject.
- `crypto_version != 2` → reject.
- v3: `ctx_len` beyond envelope bounds, malformed/non-canonical-shape ctx →
  reject.
- `decrypt(key_id=k)` with envelope `key_id != k` → reject. Requested
  `key_id` on a v1 record → reject (nothing to verify against).
- v3 on the field path (`decrypt`/`decrypt_bytes`) → reject, always.
- Tag failure → reject; **policy checks (exp/nbf/max_age/purpose) run only
  after the tag verifies**.

## 6. Token time semantics

- `exp` (writer-fixed): reject when `now - leeway > exp`.
- `nbf` (writer-fixed): reject when `now + leeway < nbf`.
- `max_age` (reader-side over `iat`): reject when `now - leeway > iat +
  max_age`. Reader policies can only tighten the writer's window.
- `leeway` ≥ 0 seconds, default 0.

## 7. Known-good implementations for ports

| Language | AES-256-SIV (RFC 5297) | Notes |
|---|---|---|
| Python | `cryptography` AESSIV | reference implementation |
| Rust | RustCrypto `aes-siv` | `Aes256SivAead` |
| Go | `jacobsa/crypto/siv` | |
| JS/TS | `@noble/ciphers` `aessiv` | audited; "nonce as final AAD component" = this construction |
| Java/Kotlin | BouncyCastle `SIVBlockCipher` | |
| C#/.NET | BouncyCastle.NET | |
| Ruby/PHP | OpenSSL 3.2+ EVP `aes-256-siv` | works but binding layers are awkward — weakest legs |
| Swift | none in CryptoKit | needs OpenSSL/BoringSSL path — weakest leg |

**Interop trap to pin in every port:** RFC 5297 allows at most 126 AD
components and the nonce must occupy the *last* slot (that's how noble and
OpenSSL both express it — matching this spec's vector order).

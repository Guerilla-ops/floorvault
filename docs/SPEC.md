# FloorVault on-disk format specification

**Status:** Phase-0 format freeze · normative
**Applies to:** FloorVault 0.1.x (original freeze: `main` @ `49c00a0`;
updated for explicit legacy-metadata migration and target-bound rotation)
**Audience:** independent implementors, auditors, migration tooling
**Supersedes:** `docs/RECORD-FORMAT-2026-09-15.md` (which remains as the
informal design note; where the two disagree, the code — and therefore this
document — is authoritative)

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are to be interpreted as in RFC 2119 / RFC 8174.

---

## 1. Scope, conformance, and versioning

This document specifies the byte-level formats FloorVault writes to and reads
from persistent storage and wires: the record envelope (§4), its associated-data
encoding (§5–§7), search beacons (§9), protected key-store files (§10), the
recovery bundle (§11), the vault SQLite schema (§12), and the session-message
framing (§13). It exists so that a second implementation can produce byte-
compatible records and read records written by this build.

### Freeze semantics

This specification describes the format **as implemented**, including behavior
that would not be designed this way again. Where this document, older
documentation, and the source disagree, **the source for the associated revision is
correct** and this document records the disagreement (§17). Ambiguities are
resolved in favor of observed behavior, not intended behavior. Callers MUST NOT
rely on any behavior not documented here.

### Versioning policy

Any byte-level change to a format in this document — a field added, removed,
resized, re-ordered, re-encoded, or re-interpreted — is a **new format
version** and MUST be given a distinguishing marker (envelope magic,
`crypto_version`, store header, or bundle magic). Readers MUST continue to
accept every version documented in the spec in force at their build.
Writers SHOULD emit the newest version they implement. A change that keeps
the byte layout but alters authenticated content semantics (for example the
associated-data encoding) is still a format change.

Concretely, a conforming reader:

- MUST read v1 (`FLRV`) and v2 (`FLV2`) envelopes (§4);
- MUST apply the associated-data vector matching the envelope version (§6);
- MUST NOT silently reinterpret a record under a different version's rules;
- MUST fail closed on anything not matching a documented version (§16).

An implementation is conforming if the bytes it accepts and produces match
this document. APIs and error types are normative only for the reference
implementation; a foreign implementation MAY map the rejection table (§16)
onto its own error hierarchy provided the accept/refuse decisions match.

---

## 2. Cryptographic primitives

| Primitive | Parameterization |
|---|---|
| AEAD | AES-256-SIV per RFC 5297, keyed with 64 bytes (two 256-bit subkeys) |
| KDF | HKDF-SHA256 per RFC 5869, salt absent (RFC 5869 default: `HashLen` zero octets) |
| MAC | HMAC-SHA256 |
| Hash | SHA-256 |
| Randomness | OS CSPRNG (`os.urandom` / `getrandom` / `CryptGenRandom` class) |

AES-256-SIV is used in its deterministic misuse-resistant mode: the S2V
output (the "tag") is a 16-byte value **prepended** to the CTR-mode
ciphertext, so `len(ciphertext) == 16 + len(plaintext)`. Implementations
MUST reproduce the tag-first byte order of RFC 5297 §5.2 / PyCA `AESSIV`
output.

The plaintext inside an envelope is opaque to this format: writers UTF-8
encode `str` input and take byte buffers verbatim; readers MUST NOT assume
the plaintext is UTF-8 (§4.4).

---

## 3. Key derivation

All keys derive from a 32-byte **master key**. A master key MUST be exactly
32 bytes; other lengths MUST be rejected before derivation.

Two HKDF-SHA256 subkeys are defined, domain-separated by their `info`
strings. The `info` strings are normative bytes (ASCII, no NUL terminator):

| Subkey | `info` | `length` |
|---|---|---|
| AEAD (SIV) key | `floorvault-v1-aes-siv` | 64 |
| Beacon index key | `floorvault-v1-beacon-index` | 32 |

`salt` is absent in both derivations (RFC 5869 default of `HashLen` zero
octets). Both derive directly from the 32-byte master key — the beacon key is
not derived from the SIV key or vice versa.

Implementations deriving additional subkeys MUST NOT reuse either `info`
string for a different purpose (collision between purposes is the defect the
separation exists to prevent).

---

## 4. Record envelope

### 4.1 v2 envelope (current writer)

```
offset  size  field
0       4     magic          = "FLV2" (0x46 0x4C 0x56 0x32)
4       1     crypto_version = 0x02
5       1     key_id         (0x00-0xFF; see §4.5)
6       1     nonce_len      = 0x10
7       16    nonce          (CSPRNG)
23      n     ciphertext     = SIV_tag(16) || CTR_ciphertext
```

Fixed overhead is 23 bytes before the ciphertext; an empty plaintext yields a
39-byte record (tag only). The bytes at offsets 0–6 are collectively the
**header**, which is bound into the AEAD associated-data vector (§6) and is
therefore authenticated despite being cleartext.

### 4.2 v1 envelope (read-only)

```
offset  size  field
0       4     magic          = "FLRV" (0x46 0x4C 0x52 0x56)
4       1     nonce_len      = 0x10
5       16    nonce
21      n     ciphertext     = SIV_tag(16) || CTR_ciphertext
```

v1 carries no `crypto_version` or `key_id` and uses the v1 associated-data
vector (§6). This build never writes v1 records; readers MUST keep accepting
them and MUST NOT rewrite them in place.

### 4.3 Parsing rules and rejection order

A reader processing an envelope MUST apply the following checks **in order**
(the ordering is observable and frozen):

1. The input MUST be `bytes` or `bytearray`; every other object type —
   including `memoryview` and `str` — is a type error. (`bytearray` input
   is snapshotted once to `bytes` before parsing; caller-side mutation
   cannot reach the verified bytes.)
2. `len < 21` → *Malformed ciphertext envelope: too short*. (This check
   precedes the magic check: a short buffer with a bad magic reports "too
   short".)
3. `magic` not in {`FLRV`, `FLV2`} → *Invalid ciphertext magic header*.
4. v2 only: `crypto_version != 2` → *Unsupported envelope crypto version*.
   Readers of other builds accept their own documented set.
5. `nonce_len != 16`, or the buffer does not contain `nonce_len` bytes past
   the header → *Invalid nonce length in ciphertext envelope*.
6. Zero bytes remaining after the nonce → *Malformed ciphertext envelope: no
   ciphertext*.

A header-introspection path (`envelope_header`) exists with a weaker minimum
(5 bytes for v1, 7 for v2) and no ciphertext requirement; it reports `magic`,
`header_len`, `nonce_len`, and for v2 `crypto_version` and `key_id`. It is
for key selection only — it authenticates nothing by itself.

### 4.4 Decryption

1. Parse per §4.3.
2. If the caller requires a `key_id`: a v1 record (which carries none) MUST
   be refused; a v2 record whose authenticated `key_id` differs MUST be
   refused.
3. Reconstruct the AAD from the claimed coordinates (§5) and build the AD
   vector matching the envelope version (§6).
4. AEAD-open `ciphertext`. Any verification failure is a single error class
   (`DecryptionVerificationError`); implementations MUST NOT distinguish
   "tag failed" from "AAD mismatched" to callers.
5. Text-mode readers decode the plaintext as UTF-8; a decode failure is a
   verification failure, not a partial success. Binary-mode readers return
   the bytes uninterpreted.

### 4.5 `key_id`

`key_id` records which key generation sealed the record, so a reader holding
several generations can select without trial decryption. It is authenticated
(it sits inside the bound header). The reference build's writer defaults to
`0` but accepts and writes any caller-supplied value in `[0, 255]` — earlier
documentation's claim that it "writes 0" describes the default only.
Multi-generation readers MUST dispatch on the header value and MUST NOT
try keys in turn: a record naming an unheld `key_id` is an error
(`UnknownKeyIdError`), as is a v1 record presented to a ring with no declared
`default_key_id`.

---

## 5. Associated Data (canonical coordinate encoding)

Every record is bound to database coordinates serialized as a canonical JSON
object and passed to AES-SIV as associated data. The AAD is **not** stored in
the envelope; the reader reconstructs it from claimed coordinates, so a
ciphertext moved between coordinates fails authentication.

### 5.1 Schema

```
{"app_instance_id":"...","column":"...","record_id":"...",
 "revision":N?,                       -- present only when supplied
 "schema_id":"...","schema_version":N,"table":"..."}
```

Keys appear in sorted order: `app_instance_id`, `column`, `record_id`,
`revision` (only when supplied), `schema_id`, `schema_version`, `table`.

Reference defaults: `schema_id = "floor.vault.v1"`, `schema_version = 1`,
`app_instance_id = "default"`. Deployments MAY use other values; records are
only readable by parties knowing the exact values used.

### 5.2 Serialization rules (all normative)

- Keys sorted; separators are `,` and `:` with **no whitespace** anywhere.
- The object is the UTF-8 encoding of the JSON text as written —
  `json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(",",":"))`.
- Inside strings, only `"` (U+0022), `\` (U+005C), and the C0 controls
  (U+0000–U+001F) are escaped, using JSON's short escapes where they exist
  (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`) and `\u00XX` otherwise. Every
  other code point — including DEL, C1 controls, and non-ASCII text — is
  emitted **verbatim** as UTF-8. There is NO `\uXXXX` escaping of non-ASCII.
- **No Unicode normalization is applied.** NFC and NFD spellings of the same
  logical string produce different AAD bytes and therefore different
  ciphertexts. This is frozen behavior: writers MUST NOT normalize, and
  readers MUST use the exact byte sequence the writer used.
- Integers serialize via C `int.__repr__` semantics: decimal, arbitrary
  precision, leading `-` permitted. Values larger than 64 bits and negative
  `schema_version` are currently accepted and produce valid AAD (frozen
  quirk). `revision` MUST be a non-negative integer when present.
- Validation (applied to every coordinate): string coordinates MUST be
  `str` and MUST be non-empty *after* `str.strip()` — whitespace-only is
  rejected, and a non-string coordinate raises the same "non-empty string"
  error rather than a type error. `schema_version` and `revision` MUST be
  `int` — `bool` is rejected (`TypeError`), and `revision < 0` is rejected
  (`ValueError`). Rejection details are in §16.
- The encoding is injective over the accepted domain: no two distinct
  coordinate sets produce the same bytes.

### 5.3 Tenant-bound record coordinate

Adapters that serve several tenants compose the `record_id` coordinate via
`records.bound_record_id(record_id, tenant)`:

```
bound = record_id                                # tenant is None
bound = "<len(tenant)>:<tenant><record_id>"      # tenant set (length-prefixed)
```

Plain concatenation would be ambiguous (`("ab","c")` vs `("a","bc")` produce
the same string), so the tenant's length is committed first; the composite
is then bound into the AAD like any other coordinate. The composition is
deterministic and unambiguous for all string inputs; a ciphertext written
under one tenant cannot be verified under another.

---

## 6. S2V associated-data vector

RFC 5297 AEAD takes a *vector* of associated-data elements. FloorVault passes
the coordinate JSON, the cleartext header (v2 only), and the nonce as
**separate** elements — the nonce doubles as the nonce input per RFC 5297 §4
and is also authenticated:

| Envelope | AD vector |
|---|---|
| v1 (`FLRV`) | `[aad, nonce]` |
| v2 (`FLV2`) | `[aad, header, nonce]` where `header` is the full 7-byte prefix `FLV2‖ver‖key_id‖nonce_len` |

The vectors are **not interchangeable**: a v1 record verified against
`[aad, header, nonce]` MUST fail (the version marker is what the differing
vector authenticates), and vice versa. Readers MUST select the vector from
the parsed magic, never from caller preference.

Because `header` is its own element, a rewritten `crypto_version` or `key_id`
fails authentication rather than being ignored — these bytes are cleartext
but not malleable.

---

## 7. Nonce

- Length: exactly 16 bytes; other lengths are refused on parse (§4.3).
- Source: OS CSPRNG, fresh per encryption (per field, in batch APIs).
- The reference implementation keeps a process-lifetime dedup window
  (deque + set, default capacity 10,000, oldest-evicted FIFO): a nonce
  already in the window raises `NonceReuseError` before encryption; an
  evicted nonce may be re-tracked. **The window is an implementation detail,
  not part of the format.** It provides within-process belt-and-suspenders
  dedup only; it does not survive restart and is not a freshness mechanism.
- Cross-session freshness — defense against same-coordinate replay — is the
  caller's responsibility via `revision` bound into the AAD (§5), and only
  when the revision comes from state the attacker cannot roll back together
  with the ciphertext. AES-SIV provides authenticity, not freshness.

---

## 8. Batch APIs

`encrypt_fields` / `decrypt_fields` process several columns of one record in
a single call. Normative equivalence:

- Each field's envelope MUST be constructed exactly as `encrypt` would
  construct it for that column — same per-field AAD, same v2 header, an
  independent CSPRNG nonce, the same AD vector. There is no batch framing,
  count prefix, or shared nonce.
- Consequently a batch-produced envelope for column C is interchangeable
  with a single-`encrypt` envelope for C at the same coordinates; either may
  be decrypted by the other path. (Byte-identity to a hypothetical single
  call holds modulo the independently drawn nonce.)
- The record-constant AAD section and coordinate validation are computed
  once; a shared `key_id` applies to all fields.
- Failure of any field aborts the call; no partial result is returned. On
  decrypt, fields are processed in mapping order and the first failure
  raises.

---

## 9. Search beacons (opt-in)

Beacons are deterministic keyed indexes stored *beside* ciphertexts by the
caller; the envelope format does not embed them. They are a deliberate,
documented confidentiality trade (see `SECURITY.md` §5); nothing here is
active unless the caller opts in.

### 9.1 Key

```
beacon_key = HKDF-SHA256(master_key, salt=absent,
                         info="floorvault-v1-beacon-index", L=32)
```

The key argument to `compute_beacon` MUST be at least 32 bytes; longer keys
are accepted and passed to HMAC as-is.

### 9.2 Payload and truncation

```
payload = u32be(len(scope_utf8)) || scope_utf8 || value_utf8
beacon  = HMAC-SHA256(beacon_key, payload)[:ceil(bits/8)]
```

- `value` MUST be `str` (a `TypeError` otherwise); it is UTF-8 encoded, no
  normalization. `scope` MUST be a non-empty `str` (post-`strip()`); it is
  the domain separator, conventionally `"<table>.<column>"`.
- The scope is length-prefixed so the `(scope, value)` encoding is
  injective; `value` is not length-prefixed (it is last).
- `bits` MUST be an integer in `[4, 64]`; `bool` is rejected. Storage is
  byte-aligned: `ceil(bits/8)` bytes are emitted, so 4–8 bits are the same
  stored index and 9–16 are the same index. Implementations reporting a
  width to users MUST report the stored byte width, not the requested bits.
- `beacon_matches` is bucket agreement under `hmac.compare_digest`; a match
  is NOT an equality proof — confirm by decrypting the candidate.
- The `BeaconIndexer` convenience wrapper additionally refuses a `bits`
  value not divisible by 8.

---

## 10. Protected key-store files

Master-key custody providers persist a small store file. All store files
share one envelope:

```
store = scheme_header || payload      (max read: 4096 bytes)
```

### 10.1 Schemes

| Scheme | File name | Header | Payload | Notes |
|---|---|---|---|---|
| tier-3 raw | `master.key` | *(empty)* | 32 raw key bytes | also accepts a 64-byte ASCII-hex encoding on read (decoded to 32 bytes) |
| Secret Service | `master.key.ss` | `FLOORLV1` (8 B) | masked key, exactly 32 B | mask is deterministic — see §10.2 |
| DPAPI | `master.key.dpapi` | `FLOORWV1` (8 B) | OS DPAPI blob, variable length | non-Windows fallback: XOR mask — see §10.3 |

Scheme paths are disjoint by construction (`master.key.<scheme>`); a file is
only *this* scheme's store if it parses under this scheme's header. A reader
whose scheme path is absent MAY adopt the legacy `master.key` path, but only
when that file parses under the scheme's header (adoption emits a warning).

### 10.2 `ss` mask (normative, byte-for-byte)

The mask is a deterministic, keyless transform — obfuscation for
boundary-tagging, NOT encryption:

```
pad          = SHA256(service_name_utf8)          # 32 bytes, public constant
masked[i]    = key[i] XOR pad[i]                  # i = 0 .. len(key)-1
```

`zip` semantics: the output length equals `min(len(input), 32)` — a shorter
input produces a proportionally shorter output. The store contract requires
exactly 32 masked bytes, so on the wire the payload is 32 bytes and the
unmask is the identical function. The `service_name` default is
`"floorvault"`. A copy of this file plus knowledge of the service name
recovers the key; the confidentiality of this tier is the file mode, nothing
else.

### 10.3 `dpapi` payload

- Windows: `CryptProtectData(key, entropy)` — variable-length OS blob;
  `entropy` is caller-supplied or the public constant `b"floorvault-dpapi"`
  (a label, not a secret).
- Non-Windows (contract testing): `mask = SHA256(entropy)`, `out[i] = in[i]
  XOR mask[i]` with the same `zip` truncation semantics as §10.2.
- Payload length is validated only after unprotection (must be 32).

### 10.4 Store file safety contract (normative)

- **Size:** the read buffer is 4096 bytes; a file larger than the buffer is
  refused rather than truncated-accepted.
- **Validation order on read:** regular-file and ownership checks (POSIX:
  current uid) → size → header prefix → payload length → permission check.
- **POSIX permission:** `mode & 0o077` MUST be 0 (0600/0400/0700 qualify);
  extended ACLs are not queried. **Windows:** the effective DACL is read via
  `GetNamedSecurityInfoW`; access beyond {owner, SYSTEM, Administrators,
  CREATOR OWNER, OWNER RIGHTS} is refused, and an unverifiable ACL is
  refused ("cannot tell" is never "fine").
- **Create-never-replace:** writes go to a sibling temp file
  `.{name}.{12-hex}.tmp` (mode 0600, `O_EXCL|O_NOFOLLOW`), are fsynced, and
  are published with `os.link` — which fails `FileExistsError` if the
  destination exists. There is no check-then-replace fallback; a filesystem
  without hard links fails closed.
- **Directory:** the vault directory is created/hardened to 0700,
  current-uid owned, with symlinks refused in the directory and its
  ancestors (root-owned system links such as macOS `/tmp` excepted).
- **Absent vs. unreadable:** a missing store (`ProtectedStoreMissing`) is the
  only state that permits creating one; every other failure means "exists
  but invalid" and MUST NOT be treated as absent.
- Tier-3 (raw `master.key`) is only ever used when the caller has explicitly
  opted into disk custody (`allow_disk_fallback`, and never under
  `strict`); it is the weakest tier and is documented as no confidentiality
  boundary.

### 10.5 Adaptive provider resolution order

1. Environment, in this order: `APPSTATE_KEY`, `FLOOR_VAULT_KEY`,
   `VAULT_MASTER_KEY` — first non-empty wins; value MUST be exactly 64
   hexadecimal characters (32 bytes); `APPSTATE_KEY` emits a deprecation
   warning.
2. OS-native custody: Windows DPAPI store; Linux Secret Service (when a
   session bus and the `secretstorage` package are reachable, else absent);
   macOS Keychain. A present-but-unusable native tier raises rather than
   silently downgrading.
3. Tier-3 raw file (gated as in §10.4).

### 10.6 Governed generation store (`FVGW*`)

`GenerationStore` holds a *wrapped* master key that must be updatable (KEK
rotation re-wraps the master without re-encrypting records), while the
§10.4 contract forbids replacement in place. It resolves that tension with
immutable payload files behind an atomic pointer, in a directory hardened
to §10.4's owner-only contract:

```
g-%08x.gen     = "FVGW1" (5 B) || opaque wrapped-key payload   - immutable
active         = "FVGW0" (5 B) || u64be generation || SHA-256(payload)  - 45 B
.active.lock   = "pid=<pid>\n"  - present only while a writer holds the lock
```

Normative rules:

- **Generation files** are published create-never-replace (0600 temp,
  fsync, `os.link` no-clobber, directory fsync). Once published their bytes
  never change; the filename encodes the generation as 8 lowercase hex digits.
- **The pointer** is the only replaced object: 0600 temp, fsync, atomic
  `os.replace`, directory fsync. Readers take a whole old or whole new
  pointer on every platform with atomic rename; reads never take the lock.
- **Pointer integrity:** the reader resolves the pointer's generation file
  and verifies its payload SHA-256 equals the pointer's digest. A missing
  file or a mismatch is `ProtectedStoreError`, *not* `ProtectedStoreMissing`
  — "absent" may only mean the pointer itself does not exist.
- **Writer lock:** `.active.lock` is created `O_CREAT | O_EXCL`; a held
  lock raises `StoreLockError`. A stale lockfile is never broken
  automatically — the operator confirms no writer is alive and deletes it.
- **CAS:** `update(payload, expected_generation=N)` refuses with
  `GenerationMismatchError` unless the current pointer's generation equals
  `N`; the write target is always `N+1`.
- **Crash adoption:** an unpublished `g-<n>.gen` (pointer never repointed)
  is adopted by a retrying writer *iff* its bytes equal the caller's
  payload; any other content raises `ProtectedStoreError` for manual
  resolution — a crashed provision or update is resumed, never guessed.
- **Empty payloads** are refused (`ProtectedStoreInvalidLength`).

### 10.7 Vault Transit custody (`FVSTORID1` + Transit blob)

`VaultTransitProvider` keeps the master key wrapped by HashiCorp Vault's
Transit engine; the generation store (§10.6) holds the wrapped blob.

```
store.id       = "FVSTORID1" (9 B) || 16 random bytes   - minted once, immutable
g-<n>.gen      = "FVGW1" || ASCII "vault:v<kek_version>:<base64>" blob
```

- **Store identity** is a random 16-byte value minted at first provision.
  A missing identity can be minted; a corrupt one raises
  `CustodyDowngradeError` — reminting would change the Transit context and
  strand every blob wrapped under the old ID.
- **Transit context** (normative): standard Base64 of the canonical JSON
  `{"app","custody","purpose","store","v"}` — sorted keys, separators
  `,`/`:` — where `v` is the context version, `store` is the lowercase hex
  of `store.id`, `purpose` is `"floorvault-master-wrap"`, and `custody` is
  the custody-scheme label. The context is sent to Transit on datakey and
  decrypt calls; Transit refuses a blob whose stored context differs.
- **Operations:** `transit/datakey` (provision: returns a `vault:v1:` blob
  plus the plaintext key), `transit/decrypt` (resolve), `transit/rewrap`
  (KEK rotation: same plaintext, new `vault:v<k+1>:` blob — the store then
  CAS-publishes a new generation).
- **Transport contract:** HTTPS only, verified TLS, timeout ≤ 60 s, bounded
  retries (default 2) on connect failures and 5xx — never on 4xx — response
  ≤ 64 KiB, blob ≤ 4 KiB. Redirects are refused by default; a 307/308 is
  followed at most once and only to an explicitly allowlisted `https` host.
- **Failure contract:** every Vault failure — unreachable, HTTP error,
  malformed/short response, missing fields, corrupt store identity —
  raises `CustodyDowngradeError`. The configured provider never falls
  through to a weaker custody tier, and the Vault token cannot appear in
  exception causes or messages.
- **Cache:** the resolved plaintext master may be cached in-process for a
  bounded TTL (default 300 s) in a wipeable buffer, dropped on expiry or
  `wipe()`. The cache bounds Transit latency; it is NOT a revocation
  mechanism — Vault-side revocation takes effect no later than the TTL.

---

## 11. Recovery bundle (`FVRB1`)

```
offset  size  field
0       5     magic     = "FVRB1" (0x46 0x56 0x52 0x42 0x31)
5       16    bundle_id (CSPRNG)
21      n     v2 envelope — plaintext is the raw 32-byte master key,
              sealed under the recovery key with coordinates:
                app_instance_id = "floorvault-recovery"
                table           = "recovery"
                record_id       = hex(bundle_id)   (32 lowercase hex chars)
                column          = "master_key"
                schema_id       = "floor.vault.v1"
                schema_version  = 1
```

- Writer inputs: `master_key` and `recovery_key`, each exactly 32 bytes.
  The two keys MUST differ; the writer refuses self-wrapped recovery bundles.
- Reader: `len < 22` or wrong magic → `ValueError`; the embedded envelope is
  decrypted with `record_id = hex(bundle_id)` taken from the bundle itself
  (binding the id to the payload); the recovered key MUST be 32 bytes.
- The recovery key is an ordinary FloorVault master key (same derivation);
  bundle security is exactly the envelope's security under that key.
- The Python recovery API returns a hardened handle, but its decryption API
  first produces immutable plaintext bytes. Wiping the handle zeroes its owned
  buffer only, not every Python/OpenSSL copy; it does not promise heap erasure.

---

## 12. Vault SQLite store (`vault.db`)

The application-level vault is a SQLite database (file `<base>/vault.db`,
directory hardened per §10.4) holding encrypted records as BLOBs. Pragmas
set on every connection: `secure_delete=ON`, `journal_mode=DELETE`,
`synchronous=FULL`. `PRAGMA user_version = 3` marks the current schema.

### 12.1 Schema (verbatim)

```sql
CREATE TABLE IF NOT EXISTS vault_items (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    origin TEXT,
    identifier_type TEXT,
    identifier TEXT,
    has_otp INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    payload_cipher BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_legacy_retirements (
    legacy_id TEXT PRIMARY KEY,
    tombstone_cipher BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_rotation_journal (
    record_kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    column_name TEXT NOT NULL DEFAULT '',
    target_key_id INTEGER NOT NULL,
    state TEXT NOT NULL,
    PRIMARY KEY (record_kind, record_id, column_name)
);
CREATE TABLE IF NOT EXISTS vault_rotation_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    target_key_id INTEGER NOT NULL,
    target_commitment BLOB
);
-- seeded with: INSERT ... VALUES (1, 0, 0) ON CONFLICT DO NOTHING
```

### 12.2 Cleartext vs. sealed columns

| Column | Content |
|---|---|
| `id` | cleartext item id (`vault_<12 lowercase hex>` when auto-generated) |
| `kind` | cleartext: `login` / `payment` / `address` / `generic` |
| `has_otp` | cleartext 0/1 |
| `label`, `origin`, `identifier_type`, `identifier`, `created_at` | **sealed** — v2 envelopes stored in the TEXT-declared columns (SQLite affinity permits BLOBs there) |
| `payload_cipher` | **sealed** — envelope whose plaintext is `json.dumps(secret_dict, ensure_ascii=False)` with DEFAULT separators (i.e. `", "` / `": "` — spaces present) |
| `tombstone_cipher` | **sealed** — see §12.3 |

This is the documented leakage contract: an observer learns item count, ids,
kinds, and OTP flags; nothing that identifies or reconstructs a secret.

### 12.3 Sealing coordinates (exact)

All vault records use `schema_id="floor.vault.v1"`, `schema_version=1`, no
`revision`, and — for the default constructor — `app_instance_id="floor-agent"`.

| Content | `table` | `record_id` | `column` |
|---|---|---|---|
| item payload | `vault_items` | `<item id>` | `payload` |
| item metadata field `<f>` in {label, origin, identifier_type, identifier, created_at} | `vault_items` | `<item id>` | `meta:<f>` |
| retirement tombstone | `vault_legacy_retirements` | `<legacy_id>` | `tombstone` |

The tombstone plaintext is `json.dumps({"legacy_id": ..., "modern_id": ...},
ensure_ascii=False)` — again DEFAULT separators (spaces), with `legacy_id`
before `modern_id` in the object. A reader MUST additionally require
`payload["legacy_id"] == legacy_id`; a tombstone failing authentication or
mismatching is an error, never "not retired".

### 12.4 Rotation tables

- `vault_rotation_journal` rows record re-seal progress: unit keys are
  `("item", <item_id>, "payload")`, `("item", <item_id>, "meta:<f>")` for the
  five sealed metadata columns, and `("tombstone", <legacy_id>,
  "tombstone")`; `state` is `'done'`; each unit is journaled in the same
  transaction as its write.
- `vault_rotation_state` is a single-flight barrier: `singleton=1`, `active`
  in {0,1}, `target_key_id` = the generation being rotated to. Writes through
  `VaultStore` are refused while `active=1`.
- `target_commitment` is a v2 envelope sealed under the target vault with
  plaintext `b"floorvault-rotation-target-v1"`, `key_id=target_key_id`,
  `table="vault_rotation_state"`, `record_id="target"`, and
  `column="commitment"`. Resume MUST authenticate this envelope and require
  the expected plaintext before any resumed record write; a matching key id
  alone is insufficient. The application instance is the target vault's.
  Completion clears the commitment. Existing stores gain the nullable column
  on open; active legacy state with no commitment is refused, never adopted.
  Schema version 3 identifies this extension. New readers refuse unsupported
  future versions before schema updates; the version marker is not an
  authorization mechanism for plaintext data. Already-released older writers
  cannot be made to enforce this guard retroactively: do not downgrade a
  schema-3 store to them. Complete an in-flight legacy rotation with its
  original target generation before upgrading. If already interrupted,
  preserve both original key generations and obtain verified recovery before
  clearing any journal or barrier; never guess a missing target commitment.
- `rotate_vault_store` reads through a `KeyRing` holding all generations,
  re-seals under the new key with `key_id = new_key_id`, re-seals tombstones,
  verifies every item and tombstone through `KeyRing({new_key_id:
  new_vault})`, then clears the journal and barrier atomically.

### 12.5 Schema migration behavior

- Ordinary opens reject string-typed metadata regardless of `user_version`.
  A verified legacy upgrade requires explicit `migrate_legacy_metadata=True`
  at construction; rows mixing plaintext and encrypted metadata are refused
  even with that flag. The attacker-editable version marker never authorizes
  plaintext resealing.
- A legacy `origin_idx` column triggers a table rebuild without it (drop
  `idx_vault_origin`, copy rows, rename).

---

## 13. SessionCrypto framing

Per-message records bound to a two-part identifier:

```
record_id = session_id || 0x00 || message_id
table     = "messages"
column    = "content"
```

- `0x00` is the separator, so a NUL inside either component is refused on
  **both** read and write — `("a", "b\x00c")` and `("a\x00b", "c")` would
  otherwise bind to the same record_id.
- Empty components are refused on **write only** (`session_id` and
  `message_id` must be non-empty `str`); the read path still accepts empty
  components so pre-refusal records remain readable. With NUL banned, the
  composition is injective even over empty parts.
- The `fts_text` return is `""` unless the caller opted into plaintext FTS;
  it is not part of the stored record.

---

## 14. SQLite adapter and column migration

`EncryptedSQLiteTable` stores §4 envelopes verbatim in caller-declared BLOB
columns — no additional framing exists at the SQL layer. Column/table
identifiers are allow-listed (`^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$`,
max 128 chars) and bracket-quoted at the SQL boundary. `migrate_plaintext_column`
seals each non-NULL source value under `table=<table>`,
`record_id=str(<id-column value>)`, `column=<destination_column>` and refuses
to overwrite a destination that already holds data; `verify_encrypted_column`
decrypts every destination and compares to the source, failing on any NULL id,
missing ciphertext, or mismatch.

`drop_plaintext_column` carries a residue contract worth one paragraph: it
arms `PRAGMA secure_delete=ON` (and leaves it on), drops the column inside a
transaction (SQLite 3.35 or later), checkpoints-truncates the WAL when in WAL
mode (reporting what the checkpoint actually did), and optionally `VACUUM`s.
This scrubs the database file's live and freed pages; it cannot erase
filesystem-level residue — deallocated disk blocks and deleted rollback
journals can retain plaintext — so its return value permanently reports
`filesystem_residue: True`, and the only complete guarantee is destroying
the file. A bare `DROP COLUMN` without these steps leaves the plaintext
readable in freelist and WAL pages.

### 14.1 SQLAlchemy ORM adapter (behavioral contract)

`SqlAlchemyEncryption.protect()` binds a mapped class to FloorVault without
adding a wire format: ciphertext stored on disk is the same §4 envelope.
The contract is about which write paths are *legal*:

- Plaintext-facing attributes are non-mapped `EncryptedField` descriptors.
  Assignment encrypts immediately against the record's coordinates and
  stores the envelope on the mapped ciphertext column; identity attributes
  (`id_attr`, and `tenant_attr` when declared) must already be set —
  otherwise the assignment fails closed (`EncryptedWriteError`).
- A `set`-time attribute validator on every registered ciphertext column
  accepts only `None` or a structurally valid §4 envelope; anything else
  raises `EncryptedWriteError`. A `before_insert`/`before_update` barrier
  re-checks the staged values for writes that bypassed attribute events.
- ORM-level `insert()`/`update()` statements — including executemany
  parameter sets and `Query.update` — that name a registered ciphertext
  column are refused (`UnsupportedWriteError`) inside `do_orm_execute`:
  bulk rows cannot carry per-record coordinates.
- `tenant_attr` composes the record coordinate via §5.3; `revision_attr`
  supplies the §5 `revision` coordinate per record. Revision detects
  same-coordinate replay of an older ciphertext — it is not, and is not
  documented as, whole-database rollback protection.

Not in the guard's scope: `Connection.execute`/driver-SQL writes on a
connection the ORM session does not govern. Those bypass ORM events by
construction; applications mixing raw SQL with these tables must produce
ciphertext through the same binding.

---

## 15. Explicit non-goals

The following are **not part of this format** and are deliberately excluded:

- **`FLV3` token envelope** — exists only on the unmerged branch
  `feat/v3-token-ttl`; nothing on this branch reads or writes it.
- **Cloud KMS tiers** — no AWS/GCP/Azure KMS custody exists in this build;
  HashiCorp Vault Transit (§10.7) is the only remote-custody backend.
- **SQLCipher / page-level encryption** — FloorVault encrypts values, not
  pages.
- **The legacy Fernet store** (`vault.json.enc` + `vault.key`) — a foreign
  format the migration facade reads but never writes; specified by the
  `cryptography` Fernet spec, not here.
- **Nonce-window mechanics, lock discipline, memory hygiene** — process
  behavior, not format (§7).

---

## 16. Rejection rules appendix

Reference-implementation error taxonomy. `DVE` = `DecryptionVerificationError`
(subclass of `FloorVaultError`). A foreign implementation MUST make the same
accept/refuse decisions; error names are its own.

| Condition | Raised |
|---|---|
| Envelope input not bytes/bytearray | `TypeError` |
| Envelope < 21 bytes (`_split_envelope`) | `DVE` "too short" |
| Header introspection on < 5 B (v1) / < 7 B (v2) | `DVE` "too short" |
| Magic not `FLRV`/`FLV2` | `DVE` "invalid magic" |
| v2 `crypto_version` != 2 | `DVE` "unsupported version" |
| `nonce_len` != 16, or truncated nonce | `DVE` "invalid nonce length" |
| Empty ciphertext remainder | `DVE` "no ciphertext" |
| AEAD tag / AAD verification failure | `DVE` "verification failed" |
| Plaintext not UTF-8 (text path) | `DVE` |
| `key_id` requested on a v1 record | `DVE` "no key id" |
| `key_id` mismatch on a v2 record | `DVE` "written under key id N" |
| Record names a generation the ring lacks | `UnknownKeyIdError` |
| v1 record to a ring with no `default_key_id` | `UnknownKeyIdError` |
| Coordinate empty / whitespace-only / non-str | `ValueError` |
| `schema_version` non-int or bool | `TypeError` |
| `revision` bool/non-int (`TypeError`), < 0 (`ValueError`) | as noted |
| `key_id` write param bool/non-int (`TypeError`), outside [0,255] (`ValueError`) | as noted |
| Plaintext not str/bytes-like | `TypeError` |
| Nonce in dedup window | `NonceReuseError` |
| Operation on wiped engine | `RuntimeError` |
| Master key not bytes-like (`TypeError`), not 32 B (`ValueError`) | as noted |
| Beacon `bits` bool/non-int (`TypeError`), outside [4,64] (`ValueError`) | as noted |
| Beacon value non-str (`TypeError`), scope empty (`ValueError`) | as noted |
| Beacon key < 32 B | `ValueError` |
| Recovery bundle < 22 B or bad magic / recovered key != 32 B | `ValueError` |
| Store missing | `ProtectedStoreMissing` |
| Store non-regular/wrong owner/oversized/unverifiable ACL/exists-on-write | `ProtectedStoreError` |
| Store bad header (`ProtectedStoreHeaderError`), bad length (`ProtectedStoreInvalidLength`) | subclasses of `ProtectedStoreError` |
| Env key non-64-hex / key file malformed | `KeyProviderError` |
| OS-native tier present but unusable | `CustodyDowngradeError` |
| Tombstone auth/match failure, plaintext metadata post-migration, write during rotation | `VaultError` |
| Retired legacy id whose modern record is missing | `LegacyRetiredError` |
| `session_id`/`message_id` non-empty-on-write violation or containing NUL | `VaultError` |
| SQL identifier rejected | `ValueError` |
| Generation file/pointer bad header, bad length, dangling pointer, payload-hash mismatch, or differing orphan content | `ProtectedStoreError` |
| `expected_generation` != current generation | `GenerationMismatchError` (subclass of `ProtectedStoreError`) |
| Writer lock held | `StoreLockError` (subclass of `ProtectedStoreError`) |
| Vault unreachable / HTTP error / redirect without trust / malformed, oversized, or short response / corrupt store identity | `CustodyDowngradeError` |
| Non-envelope staged onto an ORM ciphertext column; identity/tenant attribute missing | `EncryptedWriteError` |
| Bulk or `Query`-level write naming an ORM ciphertext column | `UnsupportedWriteError` (subclass of `EncryptedWriteError`) |

Check *order* inside envelope parsing is normative (§4.3): length → magic →
crypto_version → nonce_len → non-empty ciphertext. The wiped-engine check
precedes all envelope errors.

---

## 17. Known discrepancies with earlier documentation

Frozen for transparency; the code is authoritative.

1. `docs/RECORD-FORMAT-2026-09-15.md` and `SECURITY.md` describe `key_id` as
   "0" for this build. Accurate: the writer *defaults* to 0 but accepts any
   value in [0,255] (§4.5).
2. The `VaultStore` docstring lists `decommissioned_at` as a cleartext
   column; no such column exists in the schema (§12.2).
3. `adaptive.py`'s module docstring describes tier 2 as "macOS Keychain";
   the implementation dispatches Windows DPAPI and Linux Secret Service at
   the same tier (§10.5).
4. `maximum_tracked_nonces` accepts `bool` (`True` behaves as 1) because the
   range check does not exclude it — quirk, not contract.
5. `vault.py` contains a self-referential `VaultStore = VaultStore` alias —
   harmless no-op.

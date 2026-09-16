# Record and store format contract

**Status:** current as of 2026-09-15 · applies to `main`
**Audience:** anyone implementing against FloorVault's storage, or auditing it

FloorVault's on-disk layout is a **contract**, not an implementation detail. Two
consequences follow: the sizes below are part of the public surface, and any change
to them is a format change (a new version, with the old one still readable).

---

## 1. Record envelope

### v2 (current writer)

| Field | Size | Authenticated | Notes |
|---|---:|:---:|---|
| `magic` | 4 B | ✅ | `FLV2` |
| `crypto_version` | 1 B | ✅ | `2` for this build |
| `key_id` | 1 B | ✅ | Which key the record was written under; `0` here |
| `nonce_len` | 1 B | ✅ | Always `16`; other values are refused |
| `nonce` | 16 B | ✅ | Cleartext, fresh per encryption |
| `ciphertext` | n B | — | AES-256-SIV output (includes the tag) |

**Fixed overhead: 23 bytes** of envelope before the ciphertext, plus AES-SIV's
16-byte tag inside it — so a 20-byte plaintext costs 20 + 16 + 23 = **59 bytes** on
disk.

### v1 (read-only, still supported)

| Field | Size | Notes |
|---|---:|---|
| `magic` | 4 B | `FLRV` |
| `nonce_len` | 1 B | Always `16` |
| `nonce` | 16 B | |
| `ciphertext` | n B | |

v1 records carry no version or key id, and are read with the v1 associated-data
vector (§2). They are not rewritten on read.

### Inspecting a header

```python
from floorvault import envelope_header, RECORD_MAGIC_V2

header = envelope_header(blob)
# v2: {"magic": b"FLV2", "header_len": 7, "nonce_len": 16,
#      "crypto_version": 2, "key_id": 0}
# v1: {"magic": b"FLRV", "header_len": 5, "nonce_len": 16}
```

`header_len` is the offset of the nonce, so tooling can split an envelope without
knowing which version it is looking at — which is what a rotation script needs.

---

## 2. Associated data

AES-256-SIV takes a *vector* of associated-data elements. FloorVault passes:

| # | Element | v1 | v2 |
|---|---|:---:|:---:|
| 1 | canonical coordinate JSON (§3) | ✅ | ✅ |
| 2 | the cleartext header (7 bytes) | — | ✅ |
| 3 | the nonce | ✅ | ✅ |

Element boundaries are part of the design. Passing the coordinates as *one*
structured element means field values can never be concatenated into a different
valid tuple, and binding the header as its own element means a rewritten
`crypto_version` or `key_id` fails authentication rather than being ignored.

**The v1 and v2 vectors are not interchangeable.** A v1 record verified against the
v2 vector must fail (pinned by `tests/test_rfc5297_independent.py`), or the version
field would carry no meaning.

---

## 3. Coordinate encoding (canonical)

```json
{"app_instance_id":"default","column":"email","record_id":"12","schema_id":"floor.vault.v1","schema_version":1,"table":"users"}
```

- UTF-8 JSON, keys sorted, separators `,` and `:` with no whitespace.
- Every coordinate must be a non-empty string; `revision`, when supplied, must be a
  non-negative integer (booleans are refused).
- The encoding is injective for this schema: no two distinct coordinate sets produce
  the same bytes, and empty coordinates are rejected rather than encoded.

- Any change to this encoding is a format change.

## 4. SQLite store version and schema migration

The SQLite store sets `PRAGMA user_version = 2` after metadata migration. Opening
an older store re-seals legacy metadata and removes the retired application-level
origin search column while preserving encrypted records. The migration is
idempotent and existing records remain readable.

## 5. Retirement tombstones (migration)

| Column | Type | Notes |
|---|---|---|
| `legacy_id` | TEXT PRIMARY KEY | The pre-migration item id |
| `tombstone_cipher` | BLOB | `{"legacy_id": ..., "modern_id": ...}` sealed with AES-256-SIV |

Associated data: `table="vault_legacy_retirements"`, `record_id="<legacy_id>"`,
`column="tombstone"` — so a tombstone cannot be moved to another id and a flipped
byte fails authentication instead of reading as "not retired".

**What it guarantees.** Once an id is retired, the pre-migration source is never
consulted for it again, even if the modern record is later deleted or rolled back;
the read fails instead.

**What it does not.** The tombstone lives in the same database as the data. An
attacker who rolls the whole database back rolls the tombstones back with it, so this
makes a downgrade *detectable*, not *impossible*. Freshness still requires state the
attacker cannot roll back (see `SECURITY.md` §5).

---

## 6. Changing the format

1. Bump `crypto_version` and give the new layout its own magic.
2. Keep the previous reader path, and add a test that the previous format is still
   verified by the independent implementation.
3. Bind every new cleartext field into the associated data.
4. Update this document and the `SECURITY.md` design summary in the same change.

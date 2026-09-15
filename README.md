# floorvault

[![PyPI version](https://img.shields.io/pypi/v/floorvault.svg)](https://pypi.org/project/floorvault/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/floorvault/)

> **Contextual, misuse-resistant, searchable database encryption for SQLite and beyond — zero C compilation.**

`floorvault` provides field- and record-level Authenticated Encryption with Associated Data (AEAD) and **searchable beacons** over standard, unmodified SQLite. It is designed for autonomous AI agents, local desktop software (Tauri, Electron, PyQt), and edge services that need tamper-proof local storage without the compilation and portability friction of SQLCipher.

---

## Why FloorVault?

| Capability | SQLCipher | Fernet / Ad-Hoc AES | FloorVault |
| :--- | :---: | :---: | :---: |
| **Installation** | Custom C build | Stock Python | **Stock Python (`pip install`)** |
| **Tamper Resistance** | None (page HMAC only) | None | **Contextual AAD binding** |
| **Cut-and-Paste Splicing** | Vulnerable | Vulnerable | **Cryptographically immune** |
| **Cipher suite** | AES-GCM / CBC | AES-128-CBC | **AES-256-SIV (RFC 5297)** |
| **Nonce misuse resistance** | Fragile (GCM leaks keys) | None | **Immune (deterministic SIV)** |
| **Search privacy** | Decrypt-all in RAM | Full table scan | **Truncated HMAC beacon** |
| **Exact-match search** | Yes | No | **Beacon bucket + verify** |
| **Key lifetime** | Permanent in RAM | Permanent in RAM | **Subkeys pinned; master wiped in <5 ms** |
| **Swap / dump protection** | None | None | **`mlock` / `VirtualLock` (best-effort)** |

---

## Features

* **Contextual AAD binding** — every encrypted value is cryptographically bound to its `table`, `record_id`, `column`, `schema`, and `app_instance_id`. Splicing ciphertext between rows, columns, or tables fails authentication instantly.
* **Deterministic misuse resistance (RFC 5297)** — AES-256-SIV synthesizes the IV from plaintext + AAD, so even a repeated nonce never leaks the key or enables forgery (unlike AES-GCM).
* **Ephemeral master key handling** — derives functional subkeys via HKDF-SHA256 (domain-separated encryption / SIV / index keys) and overwrites the mutable master-key buffer after derivation.
* **Best-effort memory hardening (`HardenedMemoryKey`)** — pins derived keys on a page-aligned mapping via POSIX `mlock()` or Win32 `VirtualLock()`; Linux additionally applies `MADV_DONTDUMP`/`MADV_DONTFORK`, macOS relies on `RLIMIT_CORE=0` plus page pinning. `strict` mode fails closed when the platform cannot honour its guarantees.
* **Searchable beacons** — store only a truncated, bounded HMAC bucket (default 4 bits = 256 buckets, configurable to 64 bits) so encrypted fields remain indexable in native SQLite B-Trees **without revealing exact equality or value frequency** to database readers. Confirm candidates with `beacon_matches`.
* **Zero C-compilation overhead** — runs on Python's built-in `sqlite3` and PyCA `cryptography`. Universal binary wheels install anywhere.

---

## Installation

```bash
pip install floorvault
# or with uv:
uv add floorvault
```

---

## Quickstart

### 1. Contextual field encryption

```python
from floorvault import FloorVault, HardenedMemoryKey

# The raw master key is wiped from memory within ~5 ms after HKDF derivation.
master_key = HardenedMemoryKey.from_hex(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
crypto = FloorVault(master_key, app_instance_id="agent-001")

# Encrypt with contextual binding to table, row, and column.
ciphertext = crypto.encrypt(
    plaintext="sk-ant-...", table="credentials", record_id="user-123", column="api_key"
)

# Decrypt verifies the exact coordinates.
token = crypto.decrypt(
    ciphertext=ciphertext, table="credentials", record_id="user-123", column="api_key"
)

# TAMPERING: decrypting under a different row/table/column aborts.
# Raises DecryptionVerificationError.
crypto.decrypt(ciphertext, table="credentials", record_id="user-attacker", column="api_key")
```

### 2. Searchable encryption with beacons

Use a **truncated HMAC beacon** to index an encrypted field. The stored index
is a coarse bucket, so an attacker holding the database cannot recover the
exact value or its frequency — unlike a full-width hash.

```python
import sqlite3
from floorvault import AdaptiveKeyProvider, FloorVault

# Key resolution that works on desktop, CI, and headless/Docker.
crypto = FloorVault(AdaptiveKeyProvider(service_name="my-app").resolve_key())

conn = sqlite3.connect("local_vault.db")
conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email_cipher BLOB NOT NULL,
        email_bucket BLOB NOT NULL
    )
""")

email = "scott@example.com"
cipher = crypto.encrypt(email, table="users", record_id="usr-1", column="email")
bucket = crypto.beacon(email, scope="users.email", bits=16)  # bounded bucket
conn.execute("INSERT INTO users VALUES (?, ?, ?)", ("usr-1", cipher, bucket))

# Exact-match search: find candidate rows via the bucket, then confirm.
probe = crypto.beacon("scott@example.com", scope="users.email", bits=16)
for row in conn.execute("SELECT id, email_cipher FROM users WHERE email_bucket = ?", (probe,)):
    user_id, email_cipher = row
    print(crypto.decrypt(email_cipher, table="users", record_id=user_id, column="email"))
```

**Choosing a beacon width:** smaller widths (`bits=4…8`) maximize privacy (the
bucket reveals less) at the cost of more candidate rows to decrypt-confirm;
larger widths (`bits=32…64`) minimise collisions but reveal more. For low-volume
uniqueness you may use `bits=64`; treat 4–16 as the privacy-first default.

### 4. Lazy non-destructive migration from a legacy Fernet vault

Upgrade an existing legacy Fernet vault (`vault.json.enc` + `vault.key`)
to AES-256-SIV **without a risky one-time conversion**: records are read from
the modern store first, and any legacy-only item is transparently read and
upgraded on first touch, with the legacy source left byte-for-byte intact until
an explicit `verify()` proves the migration is sound.

```python
from floorvault import FloorVault, HardenedMemoryKey, MigratingVaultStore
from floorvault.vaultkit.vault import VaultStore

crypto = FloorVault(HardenedMemoryKey.from_hex("01" * 32))
modern = VaultStore("~/.floor/vault/modern", crypto=crypto)
store = MigratingVaultStore(modern_store=modern, legacy_base_dir="~/.floor/vault")

# Reads are transparently served from modern, else legacy (and lazily migrated).
secret = store.resolve_secret("some-legacy-item-id")

# Batch-migrate everything, keeping a pre-migration backup and verifying.
result = store.migrate_all()  # {"migrated": N, "verified": True, ...}
assert store.verify() is True  # only safe to delete legacy after this passes
```

`migrate_all()` writes a `vault.json.enc.pre-migration.bak` first and never
removes the legacy source — you finalise deletion yourself only after `verify()`
passes. Legacy items that conform to no declared required shape are stored under
a schema-free `generic` kind so nothing is silently dropped.

### 5. CLI inspector (debugging)

The bundled `floorvault` CLI decrypts an encrypted record on demand and, for the
`index` subcommand, prints a blind index / beacon:

```bash
floorvault inspect local_vault.db users usr-1 email
floorvault index 'scott@example.com' --scope users.email
```

Identifiers are validated against a strict allowlist before any SQL is built, so
hostile table / column names are refused rather than interpolated.

---

## Security notes

* **Search beacons leak a bounded bucket, not the value.** Even so, treat
  beacons as *coarse* — re-keying changes all buckets. Do not index values that
  cannot tolerate any equality leakage unless you raise `bits` consciously.
* **Platform-native key custody.** `WindowsDPAPIKeyProvider` binds the master
  key to the Windows user via `CryptProtectData` with secondary entropy (so an
  infostealer cannot decrypt it by calling `CryptUnprotectData` alone);
  `LinuxSecretServiceKeyProvider` stores it in the freedesktop Secret Service
  (GNOME Keyring / KWallet), failing closed if a desktop session is present but
  the service is unreachable. Where the OS backend is absent both fall back to
  an entropy-masked, 0600, no-symlink protected store.
* **Same-UID process threat.** Like all pure user-space crypto, floorvault
  protects *at rest* and against memory scraping, but a process executing as the
  same operating-system user can read the key from an OS keychain / key file.
  For malware-resistance at the approval boundary, pair this library with a
  hardware-anchored signer (e.g. the macOS Secure-Enclave pipeline described in
  the Floor design docs).
* **Memory hardening is best-effort.** Python, ctypes, and OpenSSL may still
  create transient heap copies. `strict` mode fails closed rather than running
  with an unpinned key.

## Performance & functionality cost of the hardening

A frequently asked question: *"Did the beacon upgrade slow AI or drop features?"*
Short answer: **no** — measured encrypt/decrypt are unchanged (~5–10 µs for a 1-KB
message) and index ops went from ~1.29 µs to ~1.37 µs (sub-microsecond). Measured
against Fernet, floorvault is **~21% faster to encrypt and ~30% faster to
decrypt** at identical payloads (same AES hardware, no two-pass token framing),
and its search beacon is sub-1.4 µs.

See [`docs/PERFORMANCE-HARDENING-COST-REVIEW-2026-09-15.md`](docs/PERFORMANCE-HARDENING-COST-REVIEW-2026-09-15.md)
for the honest trade-off discussion and
[`docs/COMPARATIVE-BENCHMARK-2026-09-15.md`](docs/COMPARATIVE-BENCHMARK-2026-09-15.md)
for the measured comparison vs. Fernet and plain SQLite (reproduce with
`uv run python scripts/benchmark_compare.py`).

---

## Roadmap

- [x] Contextual AES-256-SIV AEAD + HKDF key separation
- [x] Searchable HMAC blind index / beacon (`beacon`, `beacon_matches`)
- [x] Hardened memory custody (`mlock`/`VirtualLock`/anti-dump)
- [x] Adaptive key provider (Keychain / env / machine key file)
- [x] **Lazy non-destructive migration** from legacy Fernet / plaintext stores
      (`MigratingVaultStore`: modern-first dual-read, on-touch upgrade, `.bak`
      backup + verify; adds a schema-free `generic` vault kind so nothing is
      silently dropped)
- [x] **Windows DPAPI** (`CryptProtectData` + secondary entropy) and **Linux
      Secret Service** (GNOME Keyring / KWallet) key providers, fail-closed
- [x] **Comparative benchmark** harness + measured results vs. Fernet / plain
      SQLite (`scripts/benchmark_compare.py`, `docs/COMPARATIVE-BENCHMARK…`)
- [x] **Deterministic fuzz harness** (seeded, dependency-free: round-trip,
      splice-immunity, malformed-envelope, nonce-reuse, beacon exactness —
      `tests/test_fuzz.py`)
- [ ] CI matrix (macOS / Linux / Windows runners)

---

## License

Dual-licensed under either of:
- **MIT License** ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
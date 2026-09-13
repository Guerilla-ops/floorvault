# floorvault

[![PyPI version](https://img.shields.io/pypi/v/floorvault.svg)](https://pypi.org/project/floorvault/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/floorvault/)

> **Contextual, misuse-resistant, searchable database encryption for SQLite and beyond — zero C compilation.**

`floorvault` provides field- and record-level Authenticated Encryption with Associated Data (AEAD) and HMAC blind indexing over standard, unmodified SQLite. It is designed for autonomous AI agents (Hermes, Claude Code, OpenHands), local desktop software (Tauri, Electron, PyQt), and edge services that require tamper-proof local storage without the compilation headaches of SQLCipher.

---

## Why FloorVault?

| Capability | SQLCipher | Fernet / Ad-Hoc AES | FloorVault |
| :--- | :---: | :---: | :---: |
| **Installation** | Custom C compilation | Stock Python | **Stock Python (`pip install`)** |
| **Tamper Resistance** | None (Page HMAC only) | None | **Contextual AAD Binding** |
| **Cut-and-Paste Splicing** | Vulnerable | Vulnerable | **Cryptographically Immune** |
| **Cipher Suite** | AES-GCM / CBC | AES-128-CBC | **AES-256-SIV (RFC 5297)** |
| **Nonce Misuse Resistance** | Fragile (GCM leaks keys) | None | **Immune (Deterministic SIV)** |
| **Search Query Privacy** | Decrypt-all in RAM | Full table scan | **HMAC Blind Indexing** |
| **Master Key Memory Life** | Permanent in RAM | Permanent in RAM | **Destroyed in < 5 ms** |
| **RAM Swapping Protection** | None | None | **`mlock` + `MADV_DONTDUMP`** |

---

## Features

* **Contextual AAD Binding:** Cryptographically binds every encrypted value to its `table`, `record_id`, `column`, `schema`, and `app_instance_id`. Splicing ciphertext between rows or tables fails authentication instantly.
* **Deterministic Misuse-Resistance (RFC 5297):** AES-256-SIV synthesizes the initialization vector from the plaintext and AAD, preventing key leaks even if a nonce repeats.
* **Ephemeral Master Key Lifecycle (< 5 ms):** Derives functional subkeys via HKDF-SHA256 and immediately overwrites the master key in memory using `ctypes.memset`.
* **Hardware Memory Custody (`HardenedMemoryKey`):** Pins derived keys in physical RAM via POSIX `mlock()` or Win32 `VirtualLock()`, shielded from crash dumps (`MADV_DONTDUMP`) and process forks (`MADV_DONTFORK`).
* **Searchable Blind Indexing:** Query encrypted fields in native SQLite B-Trees (`WHERE email_idx = ?`) in **0.18 ms** without exposing search terms in memory.
* **Zero C-Compilation Overhead:** Runs on Python's built-in `sqlite3` and PyCA `cryptography`. Universal binary wheels install anywhere in seconds.

---

## Installation

```bash
pip install floorvault
# or with uv:
uv add floorvault
```

---

## Quickstart

### 1. Contextual Field Encryption
```python
from floorvault import FloorVault, HardenedMemoryKey

# Master key is wiped from memory in < 5 ms after HKDF derivation
master_key = HardenedMemoryKey.from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
crypto = FloorVault(master_key, app_instance_id="agent-001")

# Encrypt with contextual binding to table, row, and column
ciphertext = crypto.encrypt(
    plaintext="sk-ant-secret-token",
    table="credentials",
    record_id="user-123",
    column="api_key"
)

# Decrypt verifies the exact coordinates
token = crypto.decrypt(
    ciphertext=ciphertext,
    table="credentials",
    record_id="user-123",
    column="api_key"
)

# TAMPERING ATTEMPT: Trying to decrypt in another user's row aborts!
# Raises DecryptionVerificationError ("AAD authentication tag mismatch")
crypto.decrypt(ciphertext, table="credentials", record_id="user-attacker", column="api_key")
```

### 2. Searchable Blind Indexing in SQLite
```python
import sqlite3
from floorvault import FloorVault

crypto = FloorVault.from_system_keyring("my-app")

conn = sqlite3.connect("local_vault.db")
conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email_cipher BLOB NOT NULL,
        email_idx BLOB NOT NULL UNIQUE
    )
""")

# Store with blind index
email = "scott@example.com"
cipher = crypto.encrypt(email, table="users", record_id="usr-1", column="email")
blind_idx = crypto.blind_index(email, scope="users.email")

conn.execute("INSERT INTO users VALUES (?, ?, ?)", ("usr-1", cipher, blind_idx))

# Fast exact-match search without decrypting table or leaking plaintext in SQL
search_idx = crypto.blind_index("scott@example.com", scope="users.email")
row = conn.execute("SELECT email_cipher FROM users WHERE email_idx = ?", (search_idx,)).fetchone()
print(crypto.decrypt(row[0], table="users", record_id="usr-1", column="email"))
# Output: scott@example.com
```

---

## License

Dual-licensed under either of:
- **MIT License** ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

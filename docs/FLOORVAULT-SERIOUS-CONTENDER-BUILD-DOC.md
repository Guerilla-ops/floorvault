# FloorVault: Universal Serious Contender Build Specification
**Cross-Platform Secure Storage Engine with Optional the agent Integration**

- **Document Version:** 2.0.0 (Production Architecture & Engineering Blueprint)
- **Status:** Approved target specification; implementation is incomplete
- **Date:** 2026-09-14
- **Classification:** Technical Architecture Directive / Security Engineering Specification
- **Author:** Scott Lee (floorbond@pm.me)
- **Approved by:** Scott (Estate Operator & Final Authority)
- **Scope:** Universal FloorVault core, cross-platform storage services, language bindings, application adapters, and optional the agent integration

---

## 1. Executive Summary & Strategic Positioning

### 1.1 The "Serious Contender" Mandate
FloorVault is currently a hardened application-layer cryptographic component providing contextual AES-256-SIV encryption and blind indexing for SQLite rows. To compete with mature solutions, it must advance from an envelope-encryption utility to a **universal production-grade secure-storage platform**. the agent is one optional consumer, not the product boundary. The capabilities in this document are targets, not current implementation claims.

A serious contender cannot rely on marketing claims, partial memory zeroing, or hand-waving around SQLite metadata leakage. It must provide:
1. **Verifiable cryptographic integrity and confidentiality** across the entire storage lifecycle (data at rest, data in flight, WAL frames, spillover caches, and crash states).
2. **First-class developer ergonomics and AI agent capability**, preserving full-text search, multi-session concurrency, and sub-millisecond query execution without breaking foundation-model prompt caching.
3. **Rigorous security engineering maturity**, backed by reproducible builds, continuous fuzzing, multi-platform CI, formal threat modeling, and fail-closed regression gates.

### 1.2 The "Best of 5" Architectural Synthesis
Rather than reinventing isolated cryptographic mechanisms, FloorVault deliberately synthesizes the architectural strengths of the industry's five leading paradigms:

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     THE BEST-OF-5 ARCHITECTURAL SYNTHESIS                      │
├───────────────────────┬─────────────────────────────────────────────────────────┤
│ Industry Paradigm     │ Core Architectural Strength Adopted by FloorVault        │
├───────────────────────┼─────────────────────────────────────────────────────────┤
│ 1. SQLCipher          │ Whole-database & WAL frame confidentiality; page-level  │
│                       │ encryption; zero metadata leakage in temp files & index │
├───────────────────────┼─────────────────────────────────────────────────────────┤
│ 2. age / SOPS         │ Explicit key hierarchy; multi-recipient envelope        │
│                       │ encryption (X25519/ChaCha20-Poly1305); offline recovery │
├───────────────────────┼─────────────────────────────────────────────────────────┤
│ 3. Bitwarden          │ Explicit vault lifecycle (Locked, Unlocked, Timeout,    │
│                       │ Revoked); planned password KDF; recovery kits           │
├───────────────────────┼─────────────────────────────────────────────────────────┤
│ 4. OS Keyring         │ Hardware-anchored platform integration (macOS Keychain, │
│                       │ Windows DPAPI-NG, Linux Secret Service); fail-closed    │
├───────────────────────┼─────────────────────────────────────────────────────────┤
│ 5. FloorVault (Native)│ RFC 5297 AES-256-SIV coordinate binding; anti-splicing; │
│                       │ blind indexing with Bloom filter beaconing              │
└───────────────────────┴─────────────────────────────────────────────────────────┘
```

---

## 2. Target Architecture

```text
                         Any Host Application or Service
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼                                           ▼
          Application Adapter A                       Application Adapter B
          (the agent is one adapter)                    (custom app / CLI / service)
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                         FLOORVAULT UNIVERSAL ENGINE API
         ┌───────────────────────────────────┬───────────────────────────────────┐
         │ • Session Custody & Auto-Lock     │ • Record Encryption & Anti-Splice │
         │ • Key Providers & Recipients      │ • Blind Index Search Projection   │
         │ • Monotonic Migration State       │ • Tamper-Evident Audit Ledger     │
         └───────────────────────────────────┴───────────────────────────────────┘
                                             │
                         ┌───────────────────┴───────────────────┐
                         ▼                                       ▼
            Pillar 2 & 4: Key Custody               Pillar 1: Encrypted Storage
         ┌───────────────────────────────┐       ┌───────────────────────────────┐
         │ Master Key (planned KDF)      │       │ Encrypted SQLite Backend / VFS│
         │ OS Keychain / DPAPI / Secrets │       │ AES-256 Page & Frame Crypto   │
         │ age X25519 Recipient Bundles  │       │ Hardened WAL & Checkpoint Sync│
         │ Memory Custody (mlock/zeroize)│       │ PRAGMA temp_store = MEMORY    │
         └───────────────────────────────┘       └───────────────────────────────┘
```

The target architecture defines two explicit, documented modes:
1. **Managed Vault API (Object Store)**: Owns the record schema, cryptographic metadata envelopes, blind search indices, recipient headers, and migration state machines.
2. **Encrypted SQLite Database Backend**: Transparently encrypts SQLite database pages, indices, rollback journals, write-ahead log (WAL) frames, and temporary spill files.

The modes may be composed only after an explicit design and migration. Double encryption does not automatically eliminate metadata leakage and must specify key rotation, search-index placement and backup behavior.

## Universal platform boundary

FloorVault’s cryptographic and storage core must remain independent of the agent. Application-specific concepts belong in adapters that declare their schema, fields, migration version and threat boundary.

```text
Universal Core
  ├── canonical authenticated envelopes
  ├── key hierarchy and provider interface
  ├── encrypted storage and transaction engine
  ├── migration, snapshot and rollback policy
  ├── search projection interface
  └── audit and lifecycle state machine

Bindings and transports
  ├── C ABI / native library
  ├── Swift package for macOS and future Windows/Linux clients
  ├── Python package
  ├── Rust, Go and TypeScript bindings
  └── local service, Unix-socket and named-pipe transports

Application adapters
  ├── the agent
  ├── credential vaults
  ├── desktop applications
  ├── agent state stores
  ├── document and configuration stores
  └── custom third-party integrations
```

The core must not import the agent modules, assume `~/.floor`, or encode the agent session concepts as universal fields. Bindings must preserve typed errors, binary-safe values, lifecycle semantics and version negotiation.

---

## 3. Formal Threat Model & Security Invariants

### 3.1 Trust Boundaries & System Decomposition
```text
[ Untrusted External Environment: Cold Disks, Cloud Sync, Backups, Forensic Extractors ]
───────────────────────────────────────▲────────────────────────────────────────
                                       │ (Ciphertext + AAD Only)
┌──────────────────────────────────────┴───────────────────────────────────────┐
│ OS Platform Boundary (User Space)                                            │
│   • Host Filesystem: ~/.floor/state.db, ~/.floor/vault/, WAL, temp files   │
│   • Key Storage Subsystem: Apple Keychain, Windows DPAPI, Linux Secret Svc   │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────────┐ │
│   │ FloorVault Execution Boundary (Python Process / Ephemeral Memory)      │ │
│   │   • Raw Master Key (lifetime and memory controls to be measured)       │ │
│   │   • Derived Subkeys (AES-256-SIV enc, HMAC-SHA256 blind index)         │ │
│   │   • Plaintext buffers (Scrubbed and garbage-collected deterministically)│ │
│   └────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Adversary Profiles & Capabilities
The target design addresses four formal attacker models while explicitly documenting the fifth as a non-goal. These are required defenses, not claims about the current package:

- **Attacker A1 (Cold-Disk Forensic Extractor):**
  - *Capability:* Obtains physical access to a powered-off storage medium or disk image.
  - *Target Defense:* Database pages, WAL frames, record payloads, and search indices are encrypted at rest with an implemented and tested backend. No plaintext key is intentionally stored on disk. Key-provider behavior remains deployment-dependent until implemented.
- **Attacker A2 (Offline Backup & Snapshot Thief):**
  - *Capability:* Steals Time Machine backups, snapshot files, or cloud-synced SQLite database copies.
  - *FloorVault Defense:* Data remains indecipherable without the platform hardware key or recovery passphrase. Snapshot restoration requires explicit operator authorization.
- **Attacker A3 (Malicious Restore & Rollback Attacker):**
  - *Capability:* Restores an older, legitimate version of the encrypted database to resurrect revoked credentials, roll back message history, or replay obsolete states.
  - *Target Defense:* An external monotonic epoch, with specified crash, restore and multi-device semantics, rejects rollback. This is not yet implemented in the current package.
- **Attacker A4 (Adjacent Unprivileged Process & Swap/Core Inspector):**
  - *Capability:* Unprivileged local malware or multi-tenant processes inspecting disk swap files, crash dumps, or core dumps.
  - *Target Defense:* Platform-specific memory controls reduce exposure where supported. They do not guarantee protection of backend copies or a fixed zeroization time.
- **Attacker A5 (Full OS / Kernel / Root Memory Compromise) — EXPLICIT NON-GOAL:**
  - *Capability:* An adversary with active root/kernel access, ptrace injection, or hypervisor control over the running Python interpreter process.
  - *Boundary:* **FloorVault does not and cannot protect against an adversary with active root code execution or memory-inspection access to the running process.** Any claim of zero-trust security against an active in-memory root attacker in user-space Python is snake oil.

### 3.3 Core Cryptographic Invariants
1. **Anti-Splicing Invariant:** Ciphertext cannot be moved between rows, columns, tables, namespaces, or sessions. Every ciphertext is cryptographically bound to its unique canonical coordinates via RFC 5297 AES-256-SIV Associated Authenticated Data (AAD).
2. **Anti-Replay Requirement:** Once a trusted freshness mechanism exists, old ciphertexts must not replay into newer epochs. Current nonce tracking detects only in-process nonce reuse.
3. **Deterministic Key Destruction Invariant:** Master keys must never persist in heap memory longer than the immediate derivation window ($< 5\text{ ms}$). All intermediate buffers are zeroized byte-by-byte in `finally:` blocks.
4. **No Plaintext Fallback Invariant:** Once encryption is enabled, a direct plaintext write/read attempt must abort the current transaction and return a typed security error. It must not require an uncatchable exception or process termination.
5. **Bounded Search Leakage Invariant:** Blind indices must strictly follow documented leakage models (equality and frequency pattern only; no order-revealing encryption; zero plaintext in FTS tokens).

---

## 4. The 5-Pillar Architectural Deep-Dive

### Pillar 1: SQLCipher-Grade Full-Database Confidentiality
Application-layer encryption alone leaves database metadata vulnerable: table schemas, row counts, index distributions, B-Tree layouts, and unencrypted WAL frame headers are visible to any binary parser. FloorVault integrates a page-level cryptographic abstraction:
- **Page-Level Encryption:** Every database page is encrypted using one specified authenticated-encryption construction (prefer AES-256-GCM or another approved AEAD). Do not leave CBC as an equivalent implementation choice.
- **WAL & Journal Hardening:** SQLite Write-Ahead Log (WAL) frames and rollback journals are encrypted using the same page cipher before flushing to disk. Checkpoints enforce deterministic `TRUNCATE` operations on shutdown to wipe transient logs.
- **Spillover Prevention:** Temporary sorting files and B-Tree spillover are locked to memory via `PRAGMA temp_store = MEMORY;` and `PRAGMA cache_size = -64000;`.
- **Cryptographic Page Authentication:** Every page incorporates an HMAC-SHA256 or GCM authentication tag covering the page header, page data, and page sequence counter to defeat bit-flipping attacks.

### Pillar 2: age / SOPS-Grade Explicit Key & Recipient Management
Rather than relying on a single hardcoded password, the target FloorVault design uses modern envelope encryption inspired by Filippo Valsorda's `age` tool and Mozilla's `SOPS`:
- **DEK / KEK Hierarchy:**
  - **Data Encryption Key (DEK):** A unique, random 256-bit symmetric key generated per database/vault.
  - **Key Encryption Keys (KEK):** Asymmetric public keys belonging to authorized recipients (user, recovery keys, audit agents).
- **Multi-Recipient Envelope:** The vault header stores a list of encrypted DEK instances, each wrapped to a distinct recipient using X25519 Diffie-Hellman and ChaCha20-Poly1305.
- **Instantaneous Key Rotation:** Adding a recipient, removing a compromised key, or rotating recovery credentials requires re-encrypting only the 32-byte DEK in the header block. It does not require re-encrypting terabytes of stored records.
- **Offline Recovery Bundles:** Supports exporting human-readable, printable `age`-compatible Bech32 emergency recovery keys (`AGE-SECRET-KEY-1...`) with quorum capabilities ($k$-of-$n$ Shamir secret sharing or multi-recipient bundles).

### Pillar 3: Bitwarden-Grade Vault Lifecycle & Recovery
The target FloorVault design requires an explicit, stateful lifecycle machine modeled on enterprise password managers:

```text
                     ┌────────────────────────┐
                     │     UNINITIALIZED      │
                     └───────────┬────────────┘
                                 │ vault.create()
                                 ▼
                     ┌────────────────────────┐
        ┌───────────►│         LOCKED         │◄───────────┐
        │            └───────────┬────────────┘            │
        │                        │ vault.unlock()          │
        │                        ▼                         │
        │            ┌────────────────────────┐            │
        │ vault.lock│        UNLOCKED        │            │ Idle Timeout
        │            └───────────┬────────────┘            │ / Revoke
        │                        │                         │
        └────────────────────────┴─────────────────────────┘
```

- **Vault States:**
  - `UNINITIALIZED`: No master key, salt, or schema registered.
  - `LOCKED`: Cryptographic state is purged; master keys and subkeys are zeroed. No reads, writes, searches, or exports permitted.
  - `UNLOCKED`: Active in-memory session. Keys are pinned in memory with lease-based lifetimes.
  - `TIMEOUT_LOCKED`: Automatically transitions to `LOCKED` following an idle inactivity window (default: 15 minutes).
  - `REVOKED`: Session invalidated remotely or by security violation; immediate cryptographic wipe.
- **Memory-Hard Passphrase KDF:** The selected password KDF must be versioned, salted, memory-hard and benchmark-calibrated per supported platform. Argon2id is the proposed choice; parameters are not final until denial-of-service and compatibility testing is complete.
- **Emergency Access Bundles:** Encrypted backup packages that can be decrypted independently of the active runtime using standard CLI tooling.

### Pillar 4: Keyring-Grade Native Platform Integration
Keys must be stored where the operating system can defend them with hardware-level security:
- **macOS:** Apple Keychain Services via Security.framework. Accessibility attributes can reduce backup exposure; Secure Enclave binding must not be claimed unless the selected key type and API actually provide hardware-backed protection.
- **Windows:** Windows Data Protection API (DPAPI) via `CryptProtectData` and DPAPI-NG, anchoring encryption keys to the user's active Windows login session and TPM.
- **Linux:** FreeDesktop Secret Service API over DBus (gnome-keyring / KWallet). For headless servers, FloorVault supports strict Unix domain socket key brokers, systemd credential storage, or explicit environment variable keys.
- **Fail-Closed Fallback Policy:** If a requested platform provider is unavailable, FloorVault refuses to operate. It never silently downgrades to world-readable disk files. Disk-based fallback requires explicit operator override (`ALLOW_INSECURE_DISK_KEY=1`) and enforces strict `0600` file permissions.

### Pillar 5: FloorVault Contextual Coordinate Binding (Native)
Application records are protected against logical database manipulation via RFC 5297 AES-256-SIV:
- **Length-Delimited Canonical AAD:**
  ```text
  AAD = Len(vault_id) || vault_id ||
        Len(namespace) || namespace ||
        Len(record_id) || record_id ||
        Len(field)      || field ||
        Len(schema_ver) || schema_ver ||
        Len(epoch)      || epoch
  ```
- **Splicing Immunity:** Moving a ciphertext from `messages.content` to `tool_calls.arguments` fails tag authentication. Moving a record between sessions, users, or instances fails tag authentication.
- **Sliding-Window Nonce Tracking:** FloorVault tracks synthetic IVs within a bounded memory window to detect accidental ciphertext reuse.

---

## 5. Comprehensive Functional API Specification

### 5.1 Vault Lifecycle API
```python
class VaultStatus(enum.Enum):
    UNINITIALIZED = "uninitialized"
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    REVOKED = "revoked"


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    unlocked_at: datetime
    expires_at: datetime
    idle_timeout_seconds: int
    provider_name: str


class Vault:
    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        key_provider: Optional[KeyProvider] = None,
        storage_mode: str = "encrypted_sqlite",
        app_instance_id: str = "default",
    ) -> Vault:
        """Open a vault database. Does not load cryptographic keys into RAM."""
        ...

    def unlock(
        self,
        credentials: Optional[VaultCredentials] = None,
        *,
        timeout_seconds: int = 900,
    ) -> SessionInfo:
        """Authenticate and transition vault from LOCKED to UNLOCKED.
        Derives subkeys, pins memory via mlock(), and starts session lease timer.
        Raises VaultAuthenticationError on bad credentials.
        Raises VaultRateLimitError on brute-force attempts (>5 failures).
        """
        ...

    def lock(self) -> None:
        """Immediately purge functional keys, zeroize memory buffers, and transition to LOCKED."""
        ...

    def close(self) -> None:
        """Idempotent shutdown. Locks vault, checkpoints WAL to disk, and closes handles."""
        ...

    def status(self) -> VaultStatus:
        """Return the current lifecycle state of the vault."""
        ...

    def revoke_session(self, session_id: str) -> None:
        """Explicitly invalidate an active session and purge state."""
        ...
```

### 5.2 Records & Transactional CRUD API
```python
class VaultTransaction:
    def put(
        self,
        namespace: str,
        record_id: str,
        value: bytes | str | dict,
        *,
        metadata: Optional[dict] = None,
    ) -> None: ...
    def get(self, namespace: str, record_id: str) -> Optional[Record]: ...
    def delete(self, namespace: str, record_id: str) -> bool: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...


class Vault:
    def put(
        self,
        namespace: str,
        record_id: str,
        value: bytes | str | dict,
        *,
        metadata: Optional[dict] = None,
    ) -> None:
        """Encrypt and atomically store a record bound to its namespace and record_id coordinates."""
        ...

    def get(self, namespace: str, record_id: str) -> Optional[Record]:
        """Retrieve, authenticate, and decrypt a record. Raises TagVerificationError on tamper."""
        ...

    def delete(self, namespace: str, record_id: str) -> bool:
        """Cryptographically overwrite and remove record and associated blind indices."""
        ...

    def list(self, namespace: str, *, prefix: Optional[str] = None) -> list[str]:
        """List record IDs within a namespace."""
        ...

    def exists(self, namespace: str, record_id: str) -> bool:
        """Return True if record exists without decrypting payload."""
        ...

    def transaction(self) -> ContextManager[VaultTransaction]:
        """Context manager providing atomic ACID transactions across encrypted records."""
        ...

    def verify(self) -> IntegrityReport:
        """Traverse all records and verify coordinate AAD authentication tags."""
        ...

    def snapshot(self, destination: str | Path, *, passphrase: Optional[str] = None) -> Path:
        """Generate a consistent, encrypted point-in-time snapshot of the vault."""
        ...

    def restore(self, snapshot_path: str | Path, *, policy: str = "new-vault") -> Vault:
        """Restore vault from snapshot under strict freshness and safety policies."""
        ...
```

### 5.3 Key Management & Recipient Wrapping API
```python
@dataclass
class Recipient:
    recipient_id: str
        public_key: str  # proposed age-recipient identifier; interoperability is required before this is called age-compatible
    label: str
    created_at: datetime

class VaultKeyManager:
    def rotate_master_key(self, new_credentials: VaultCredentials) -> None:
        """Re-key vault under a new master passphrase or platform key."""
        ...

    def add_recipient(self, recipient: Recipient) -> None:
        """Wrap active DEK with recipient's public key and append to vault header."""
        ...

    def remove_recipient(self, recipient_id: str) -> None:
        """Remove recipient envelope and rotate DEK to invalidate removed party."""
        ...

    def export_recovery_bundle(self, destination: str | Path, *, recipients: list[Recipient]) -> Path:
        """Export an encrypted recovery bundle; actual age interoperability is a release gate."""
        ...

    def import_recovery_bundle(self, source: str | Path, recovery_key: str) -> Vault:
        """Recover vault access using an emergency recovery key."""
        ...
```

### 5.4 Search & Blind Indexing API
```python
@dataclass
class SearchResult:
    namespace: str
    record_id: str
    score: float
    matched_tokens: list[str]
    snippet: Optional[str] = None  # Reconstructed in-memory after post-decryption


class VaultSearch:
    def search(
        self,
        query: str,
        *,
        namespace: Optional[str] = None,
        fields: Optional[list[str]] = None,
        limit: int = 50,
    ) -> list[SearchResult]:
        """Perform zero-knowledge search over encrypted data using HMAC-SHA256 blind indices.
        Candidate rows are fetched via index, decrypted in-memory, verified, and filtered.
        Plaintext search queries never leave the memory boundary.
        """
        ...

    def rebuild_search_index(self, *, namespace: Optional[str] = None) -> None:
        """Re-tokenize and rebuild blind search indices."""
        ...

    def rotate_search_index(self) -> None:
        """Rotate the blind index HMAC pepper key and re-index all records."""
        ...
```

### 5.5 Audit Trail & Tamper-Evident Ledger API
```python
@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: datetime
    event_type: str  # UNLOCK, FAILED_UNLOCK, LOCK, ROTATE, PUT, DELETE, EXPORT, RECOVER
    principal: str
    epoch: int
    prev_event_hash: str
    payload_hash: str
    signature: str


class VaultAuditLedger:
    def record(self, event_type: str, details: dict) -> None:
        """Append an event to the cryptographically linked tamper-evident audit ledger."""
        ...

    def verify_integrity(self) -> bool:
        """Verify the SHA-256 hash chain and digital signatures across all audit entries."""
        ...

    def export_audit(self, destination: str | Path) -> Path:
        """Export signed audit ledger for external compliance verification."""
        ...
```

---

## 6. Optional Application Adapter Contract

### 6.1 the agent adapter example
For a target the agent deployment, FloorVault may become the persistence backbone. This is not true of the current package until the integration gates below pass. the agent is an adapter example; the same contract applies to credential, document, desktop, CLI, service and other application adapters.

```text
                               the reference agent Core
                                      │
           ┌──────────────────────────┴──────────────────────────┐
           ▼                                                     ▼
the agent Session Database (~/.floor/state.db)       the agent Credential Vault (~/.floor/vault/)
  • Conversations & Turns                            • Browser Passwords & Logins
  • Tool Calls & Results                             • Payment Cards & Billing Info
  • Internal Thinking / Reasoning                    • Identity & Addresses
  • File & Multimodal Attachments                    • One-Time Passwords (TOTP/HOTP)
  • Context & Prefix Caches                          • Model-Blind Vault Handles
           │                                                     │
           └──────────────────────────┬──────────────────────────┘
                                      │
                                      ▼
                      FloorVault Unified the agent Adapter
           ┌─────────────────────────────────────────────────────┐
           │ • Transparent write/read interception               │
           │ • Coordinate binding: (session_id, turn, field)     │
           │ • Memory-hard zeroization of session tokens         │
           │ • Startup cryptographic attestation handshake       │
           └─────────────────────────────────────────────────────┘
```

### 6.2 Full Surface Coverage Requirements
Every persistence path in the agent must route through FloorVault. The implementation contract requires explicit coverage for:

1. **User & Assistant Messages:** Role, content, metadata, timestamps, token counts.
2. **Tool Invocations:** Tool names, input arguments, execution contexts, and authorization tickets.
3. **Tool Execution Results:** Raw standard output, standard error, exit codes, binary payloads, and structured return dictionaries.
4. **Agent Reasoning Traces:** Internal chain-of-thought, scratchpads, and model-specific thinking tokens (e.g., Claude 3.7 thinking blocks).
5. **Multimodal Attachments:** Binary image buffers, audio recordings (voice memos), PDF documents, and cached downloads.
6. **Exports & Transcripts:** Session dumps, JSONL exports, and markdown summaries.
7. **Caches & Temporary Files:** KV prompt-cache prefix caches, hamelnb scratchpads, and intermediate tool artifacts.

### 6.3 Strict "No Plaintext Fallback" Guarantee
- Once encryption is enabled in the agent configuration (`storage.encryption = "floorvault"`), the runtime enters a **fail-closed cryptographic lockdown**.
- Any attempt by an agent tool, background thread, or third-party extension to write unencrypted data directly to SQLite files, disk logs, or temporary directories will raise a fatal `VaultSecurityViolation` error and immediately abort execution.
- Silent fallback to unencrypted storage is categorically prohibited.

### 6.4 Mandatory Startup Self-Test & Cryptographic Attestation
During agent boot, the agent executes a mandatory pre-flight cryptographic self-test before reading instructions or receiving user tokens:
```python
class the agentVaultStartupSelfTest:
    @staticmethod
    def verify_runtime_binding(vault: Vault) -> None:
        """Pre-flight cryptographic attestation executed during the agent startup.
        1. Generates ephemeral canary record.
        2. Encrypts canary through FloorVault adapter.
        3. Inspects raw SQLite pages to assert ciphertext entropy (Shannon entropy > 7.9).
        4. Verifies AAD coordinate tamper rejection.
        5. Proves that direct plaintext SQLite INSERT is rejected.
        6. Destroys canary record and flushes WAL.
        Raises CryptographicAttestationError if any assertion fails.
        """
        ...
```
If the self-test fails, the agent must fail closed for the affected storage operation, emit an auditable alert, and refuse to bind protected surfaces. Process termination is optional and must not be the only recovery behavior.

### 6.5 Disposable Profile Integration Test Harness
CI and release gating must validate FloorVault against a real, running the agent instance in an isolated environment:
- Provision a temporary, disposable the agent profile (`FLOOR_HOME=$(mktemp -d)`).
- Execute full conversational turn cycles: prompt ingestion, LLM streaming, tool call execution, reasoning capture, attachment storage, and search retrieval.
- Terminate process, inspect database file on disk, verify zero plaintext strings matching canary tokens.
- Unlock profile and verify 100% functional data recovery and snippet search.

### 6.6 Fail-Closed Behavior on Adapter Bypass
If an attacker or errant code attempts to bypass the `the agentVaultAdapter` by calling native `sqlite3.connect("~/.floor/state.db")`:
- The database file is unreadable (SQLCipher page encryption).
- If operating under application-layer projection, raw tables contain only encrypted blobs and HMAC tokens.
- Attempting to bypass coordinate verification throws `InvalidTag` at the engine boundary.

### 6.7 Version Compatibility Matrix
The build must guarantee forward and backward compatibility across the agent and FloorVault versions:

```text
┌────────────────────┬────────────────────┬─────────────────┬──────────────────────┐
│ the reference agent Ver.  │ FloorVault Engine  │ Schema Version  │ Python Runtimes      │
├────────────────────┼────────────────────┼─────────────────┼──────────────────────┤
│ the agent 0.8.x       │ FloorVault 1.0.x   │ floor.vault.v1  │ Python 3.11 – 3.12   │
│ the agent 0.9.x       │ FloorVault 1.1.x   │ floor.vault.v2  │ Python 3.11 – 3.13   │
│ the agent 1.0.x (Prod)│ FloorVault 2.0.0   │ floor.vault.v2  │ Python 3.11 – 3.14   │
└────────────────────┴────────────────────┴─────────────────┴──────────────────────┘
```

---

## 7. Storage, Migration & Rollback Protection

### 7.1 Encrypted Storage Engine Selection
To satisfy the Pillar 1 mandate, FloorVault must implement full-database confidentiality through a specified strategy:
1. **Primary Target (Native Page Cipher):** Select one maintained backend using authenticated encryption (for example SQLCipher or an approved AEAD-backed VFS). Do not treat unauthenticated AES-OFB as equivalent. The chosen backend must demonstrate page, header and WAL-frame coverage.
2. **Universal Fallback Target (Pure Python / Stock SQLite VFS Shim):** For environments where C compilation and pre-built binaries are strictly forbidden, FloorVault provides a pure-Python SQLite Virtual File System (VFS) shim (`FloorVaultVFS`). The VFS shim intercepts 4096-byte page reads and writes, performing hardware-accelerated AES-GCM encryption before committing bytes to the OS kernel.

### 7.2 Authenticated Migration State Machine
Migration from legacy plaintext databases or earlier schema formats is governed by a strict, authenticated state machine:

```text
┌───────────────────────┐
│   LEGACY_UNVERIFIED   │
└───────────┬───────────┘
            │ Operator Authentication (CLI flag + recovery key)
            ▼
┌───────────────────────┐
│ MIGRATION_AUTHORIZED  │
└───────────┬───────────┘
            │ vault.migrate_start()
            ▼
┌───────────────────────┐
│       MIGRATING       │ ◄── Resumable atomic chunk batches
└───────────┬───────────┘
            │ All records encrypted & verified
            ▼
┌───────────────────────┐
│        MIGRATED       │ ── Plaintext access permanently disabled
└───────────────────────┘
```

- **Resumability:** Migrations operate in chunked transactions (500 records per batch). Interrupted migrations resume cleanly without data loss.
- **Operator Authorization:** Transition from `LEGACY_UNVERIFIED` requires explicit operator confirmation. A mutable flag in the SQLite database is strictly insufficient; authorization requires a signed migration token or active master key entry.

### 7.3 Anti-Rollback Freshness Architecture
SQLite databases are vulnerable to snapshot rollback: an attacker can replace `state.db` with an older valid database file. FloorVault prevents rollback using external state anchoring:
- **Monotonic Epoch Counter:** FloorVault binds every database write to a monotonically increasing integer epoch.
- **External Epoch Storage:** The current valid epoch is stored in the OS Keychain / DPAPI hardware store, outside the rollbackable SQLite file.
- **Rollback Detection:** On database open, FloorVault reads the internal header epoch and compares it against the OS Keychain epoch. If `Header_Epoch < Keychain_Epoch`, FloorVault declares a **Rollback Attack**, refuses to decrypt, and alerts the operator.

---

## 8. Security Engineering Maturity & Assurance Program

To compete credibly with established open-source cryptographic software, FloorVault enforces strict security engineering disciplines:

### 8.1 Formal Threat Model
- Maintain and publish a formal threat model based on STRIDE-LM (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege, and Lateral Movement).
- Include comprehensive Data Flow Diagrams (DFDs) highlighting cryptographic boundaries, memory lifetimes, and trust transitions.

### 8.2 Published SECURITY.md & Vulnerability Disclosure Protocol
- Publish `SECURITY.md` in repository root detailing supported versions, reporting procedures, and response SLAs.
- Provide a dedicated security contact email and team PGP public key for encrypted vulnerability reports.
- Commit to a 90-day coordinated disclosure timeline with a mandatory 48-hour initial response SLA.

### 8.3 Reproducible Builds
- Guarantee bit-for-bit deterministic wheel generation using pinned build environments and `SOURCE_DATE_EPOCH`.
- Publish Software Bill of Materials (SBOM) in CycloneDX and SPDX formats with every release.

### 8.4 Dependency Pinning & Automated CVE Scans
- All direct and transitive dependencies must be strictly pinned with cryptographic SHA-256 hashes in `requirements.lock`.
- Automated CI pipeline runs `pip-audit`, `osv-scanner`, and GitHub Dependabot on every pull request and nightly schedule.
- Zero known CVEs allowed in production release builds.

### 8.5 Continuous Fuzzing Pipeline
- Implement continuous coverage-guided fuzzing using **Google Atheris** and **Hypothesis** property-based testing.
- Target surfaces:
  - Ciphertext envelope deserializers and canonical JSON parsers.
  - Page-level VFS headers and corrupt database frames.
  - Blind index tokenizers with malformed Unicode, null bytes, and oversized inputs.
  - Migration state machine transition sequences under simulated crash interrupts.

### 8.6 Multi-Platform CI Matrix
Automated test suite executes on every commit across a cross-platform matrix:
- **macOS:** Apple Silicon (M1/M2/M3) and Intel (x86_64); testing Apple Keychain integration and `mlock` behavior.
- **Linux:** Ubuntu LTS (x86_64, aarch64); testing GNOME Secret Service, headless socket brokers, and `MADV_DONTDUMP`.
- **Windows:** Windows 11 (x86_64); testing DPAPI, `VirtualLock`, and named pipe access controls.
- **Python Matrix:** Python 3.11, 3.12, 3.13, and 3.14.

### 8.7 Static Analysis & Sanitizer Builds
- Static analysis: Run `ruff`, `mypy --strict`, `bandit -c bandit.yaml`, and `semgrep --config p/security-audit` on every PR.
- Sanitizer builds: Test native C bindings (e.g., OpenSSL, SQLCipher, VFS shims) under Clang AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) to catch memory leaks, buffer overflows, and use-after-free vulnerabilities.

### 8.8 Independent External Cryptographic Audit
- Prior to declaring Version 2.0.0 production-ready, contract an independent external security firm (e.g., Trail of Bits, Cure53, NCC Group, or Quarkslab) to conduct an exhaustive source-code review and cryptographic audit.
- Resolve all High and Critical findings; publish the full, unredacted audit report in the `docs/audits/` directory.

### 8.9 Cryptographically Signed Releases & Provenance Attestations
- Release artifacts (wheels, source tarballs, Git tags) must be signed using Sigstore / Cosign and release team GPG keys.
- Generate SLSA Level 3 provenance attestations for all distributed binaries.

### 8.10 Zero-Skip Security Regression Suite
- The security test runner enforces a strict **Zero-Skip Policy**:
  ```python
  # Security testing invariant
  def test_security_gate_runner():
      missing_tools = check_required_security_tools(["bandit", "pip-audit", "semgrep", "gitleaks"])
      if missing_tools:
          raise SecurityGateFailure(
              f"Security tools missing: {missing_tools}. Skipping is forbidden!"
          )
  ```
- If a security tool, linter, or platform provider is absent in the test environment, the test run must report **`FAIL`**, never `SKIP` or `PASS`.

---

## 9. Phased Delivery Roadmap & Exit Gates

```text
  Phase 1           Phase 2           Phase 3           Phase 4           Phase 5           Phase 6
 Integrity      Storage Boundary    Lifecycle &       the agent Prod.       Search &         Independent
 Baseline      (Full-DB Encryption)   Recovery        Integration        Platform          Assurance
┌─────────┐       ┌─────────┐       ┌─────────┐       ┌─────────┐       ┌─────────┐       ┌─────────┐
│ Q3 2026 │──────►│ Q3 2026 │──────►│ Q4 2026 │──────►│ Q4 2026 │──────►│ Q1 2027 │──────►│ Q2 2027 │
└─────────┘       └─────────┘       └─────────┘       └─────────┘       └─────────┘       └─────────┘
```

### Phase 1: Cryptographic Integrity Baseline (Current Milestone)
- Enforce length-delimited canonical AAD encoding.
- Implement monotonic database epochs and anti-rollback headers.
- Eliminate weak key derivation; enforce Argon2id with strict memory-hardness.
- Harden memory custody (`mlock`, `MADV_DONTDUMP`, sub-5ms key zeroization).
- **Exit Gate:** 100% pass on RFC 5297/5869 test vectors; zero metadata re-signing; zero cross-session replay; zero unpersisted key paths.

### Phase 2: Full-Database Storage Boundary
- Integrate page-level encryption backend (SQLCipher / pure-Python VFS shim).
- Enforce encrypted WAL frames and deterministic `TRUNCATE` checkpoints.
- Implement `PRAGMA temp_store = MEMORY` and crash-recovery verification.
- Add atomic encrypted snapshot and restore routines.
- **Exit Gate:** Disposable database test proves zero plaintext bytes across database, WAL, journal, and temporary files during normal and crash states.

### Phase 3: Vault Lifecycle & Multi-Recipient Recovery
- Implement full `Vault` lifecycle state machine (`LOCKED`, `UNLOCKED`, `TIMEOUT_LOCKED`, `REVOKED`).
- Implement age-compatible X25519 multi-recipient wrapping and DEK/KEK envelope encryption.
- Deliver printable emergency recovery bundles with Bech32 rescue keys.
- Build tamper-evident cryptographic audit ledger.
- **Exit Gate:** Key rotation and recipient revocation execute instantly without database re-encryption; audit ledger verifies hash chain integrity.

### Phase 4: the agent Production Integration
- Deploy `the agentVaultAdapter` covering 100% of the agent persistence paths (messages, tools, reasoning, attachments, caches).
- Enforce strict fail-closed boundary: reject all direct plaintext SQLite writes.
- Embed mandatory pre-flight cryptographic self-test in the agent startup sequence.
- Build automated disposable-profile integration test harness.
- **Exit Gate:** End-to-end the agent test demonstrates full agent execution loop with zero plaintext storage leakage and verified runtime binding.

### Phase 5: Search Optimization & Platform Expansion
- Finalize HMAC blind indexing with Bloom filter beaconing to prevent frequency analysis.
- Build in-memory sub-millisecond search snippet highlighter.
- Deliver native key providers for Windows DPAPI and Linux Secret Service.
- Multi-platform CI pipeline operational across macOS, Linux, and Windows.
- **Exit Gate:** Blind search benchmarks achieve $< 5\text{ ms}$ query latency across 100,000 records; zero plaintext in FTS indices; 100% CI pass on all target OSs.

### Phase 6: Independent Assurance & Production Release
- Deploy continuous coverage-guided fuzzing (Atheris / Hypothesis).
- Commission external cryptographic audit and remediate findings.
- Publish formal threat model, `SECURITY.md`, and SLSA Level 3 signed release builds.
- **Exit Gate:** Clean external audit sign-off; published security documentation; production v2.0.0 release.

---

## 10. Definition of Done (DoD)

FloorVault is declared production-ready and a serious industry contender **only** when all of the following criteria are satisfied and cryptographically verified:

1. **Storage Confidentiality:** The complete storage boundary (database pages, schema, indices, WAL frames, journals, and temp spillover) is encrypted at rest.
2. **Coordinate Binding target:** 100% of protected application records must be bound to canonical length-delimited AAD via RFC 5297 AES-256-SIV; splicing should fail authentication.
3. **Key Management target:** DEK/KEK envelope encryption, verified recipient wrapping and emergency recovery kits must be implemented and tested before being claimed.
4. **Lifecycle & Custody:** The vault enforces explicit state transitions, idle timeouts, session revocation, and sub-5ms memory zeroization.
5. **the agent Integration:** the reference agent persists all messages, tool calls, reasoning traces, attachments, and caches exclusively through FloorVault; startup self-test passes; fail-closed enforcement verified.
6. **Freshness & Anti-Rollback:** Database epochs are anchored to external platform stores; rollback attacks fail closed.
7. **Security Tooling:** Automated dependency audits, CVE scans, AST taint analysis, and zero-skip regression suites are active in CI.
8. **Independent Assurance:** External cryptographic audit is completed, all high-severity findings are resolved, and signed SLSA Level 3 artifacts are generated.

---

## 11. Immediate Implementation Order

```text
┌───┐   1. Finalize Canonical Length-Delimited AAD & Monotonic Epochs
│ 1 │   Refactor core.py to use canonical length prefixes for all coordinate components;
└───┘   bind database headers to external epoch counters.
  │
  ▼
┌───┐   2. Complete Full the agent Surface Adapter & Fail-Closed Guard
│ 2 │   Extend vaultkit/vault.py and vaultkit/session_crypto.py to cover reasoning traces,
└───┘   tool call arguments, attachments, and temp caches; enforce hard plaintext reject.
  │
  ▼
┌───┐   3. Implement Mandatory Startup Self-Test & Disposable Profile Harness
│ 3 │   Build the runtime pre-flight attestation suite and automated disposable
└───┘   the agent profile verification script.
  │
  ▼
┌───┐   4. Implement Page-Level Encrypted Storage Backend
│ 4 │   Integrate SQLCipher / FloorVaultVFS page encryption; configure PRAGMA temp_store,
└───┘   WAL frame ciphers, and deterministic TRUNCATE checkpoints.
  │
  ▼
┌───┐   5. Build Bitwarden-Style Lifecycle State Machine & Argon2id KDF
│ 5 │   Implement Vault.unlock(), Vault.lock(), idle timeout leases, and Argon2id KDF.
└───┘
  │
  ▼
┌───┐   6. Deliver age-Compatible Recipient Wrapping & Recovery Bundles
│ 6 │   Implement X25519/ChaCha20 DEK wrapping, Bech32 emergency rescue keys, and
└───┘   instant key rotation.
  │
  ▼
┌───┐   7. Activate Security Engineering Pipeline & Zero-Skip CI Gates
│ 7 │   Publish SECURITY.md, enable pip-audit / Atheris fuzzing / bandit, and configure
└───┘   cross-platform GitHub Actions matrix.
```

---
*FloorVault Engineering Specification — the agent Security & Architecture Fleet Directive.*

# FloorVault Performance Note

**Date:** 2026-09-15
**Status:** Historical engineering measurement; the current implementation is authoritative.
**Scope:** `vaultfloor/floorvault`

This note records measurements from an earlier design iteration. The application-level search
and indexing APIs described by the earlier version were removed from the current implementation.
The current performance-sensitive path is contextual AES-256-SIV encryption and decryption.

## Current implementation

FloorVault provides:

- contextual AES-256-SIV encryption;
- canonical associated-data binding to table, record, column, schema and application instance;
- HKDF-SHA256 derivation of the AEAD key;
- hardened key buffers where platform capabilities permit;
- cross-platform key custody and non-destructive migration.

No application-level search index is part of the current public API. Applications that need
lookup should use an outer query or index layer and decrypt only the selected records.

## Historical measurements

The earlier benchmark measured approximately:

| Operation | Historical result |
|---|---:|
| Encrypt 1-KB message | `~0.0053 ms` |
| Decrypt 1-KB message | `~0.0104 ms` |

These figures are reference measurements, not production guarantees. Results depend on hardware,
Python version, operating system, cryptography backend, payload size and workload. Re-run the
current benchmark harness before making a performance claim about a release.

## Security interpretation

The current design prioritises authenticated context binding and explicit custody boundaries over
an application-level searchable projection. Metadata and payload values remain protected according
to the limits stated in [`SECURITY.md`](../SECURITY.md). This document is not a cryptographic
audit or security sign-off.

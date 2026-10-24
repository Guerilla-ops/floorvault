# Security Policy

FloorVault is a Python library for contextual field encryption and local credential
stores. This policy covers the core, database adapters, key providers, migration,
rotation, recovery, optional integrations, and build and release machinery.

- **Project / package:** FloorVault / `floorvault`
- **Repository:** [Guerilla-ops/floorvault](https://github.com/Guerilla-ops/floorvault)
- **Maintainer:** Scott Lee, **floorbond@pm.me**
- **Status:** Beta. No completed independent code audit, formal verification,
  FIPS validation or Common Criteria certification is claimed.

## Supported versions

Security fixes cover `main` and the latest release; earlier releases are
unsupported. Current package metadata is `0.2.1` (Beta). Reports against development
commits are welcome; provide the exact revision. Branch names do not define release
versions. Python 3.10 and newer is the declared interpreter range.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Guerilla-ops/floorvault/security/advisories/new)
or email **floorbond@pm.me** with a subject beginning `SECURITY:`. Do not disclose
security reports in public issues, pull requests or discussions.

Include the affected version or commit, component, attacker capabilities, expected
and observed behavior, and reproduction steps or a reasoned explanation. A working
exploit is not required. Remove live secrets and other people's data. State any
disclosure deadline and how you wish to be credited.

Response targets:

| Stage | Target |
| --- | --- |
| Acknowledgment | Within 48 hours |
| Initial triage | Within 5 business days |
| Updates while open | At least every 7 days |
| Critical / high fixes | As soon as practicable; typically within 30 days |
| Coordinated disclosure | By agreement; default 90 days from acknowledgment |

We will explain our assessment, coordinate disclosure and credit with the reporter,
keep them informed, and aim to publish affected and fixed versions for confirmed
issues. If we remain unresponsive beyond these targets, we do
not object to responsible disclosure after a reasonable opportunity to fix the
issue. There is no paid bug bounty.

## System and scope

The core encrypts selected application values using AES-256-SIV. Credential stores
persist secret payloads and protected metadata in SQLite. Database adapters apply
field encryption to caller-managed tables. Optional facilities include equality
beacons, external freshness anchors, passphrase-wrapped file custody, Vault Transit
wrapping, recovery bundles and local libSQL page encryption.

The optional Hermes Agent plugin resolves local item references into plaintext
values for host-managed environment injection. It is an integration with FloorVault.
Its default agent-secret directory is separate from the browser-fill vault, and
its read path disables legacy browser-vault migration. Distinct directories are
not proof of independent keys or authorisation.

Review source, plugin code, dependencies, configuration, imports, packaging,
tests, fuzz targets and release workflows where they affect these properties.
Historical review documents apply to their stated revisions. No path is excluded
from security assessment merely because it contains tests or tooling.

## Threat model and trust boundaries

Important assets are master and derived keys, recovery material, credential values,
protected metadata, expected record coordinates and trusted freshness state.

The primary storage attacker can copy or modify databases, ciphertext, metadata
and backups without possessing the key. Tampering must not release unauthenticated
plaintext or move ciphertext into another expected context. An attacker who also
obtains an unwrapped key file can recover its key; owner-only permissions do not
turn that file into an independent confidentiality boundary.

The application must supply trustworthy expected coordinates, authorise reads and
writes, protect key sources and the running process, and manage backup and recovery.
Plugin configuration and host APIs select references, directories, bootstrap
credentials and environment injection. These are integration boundaries that need
verification; configuration names alone do not establish isolation.

An authorised or prompt-injected agent can request authentic plaintext if the host
allows it. The library cannot distinguish coerced use from intended use. Scope
access in the application or a separate broker. This design limit does not excuse
plugin defects that disclose additional secrets, cross configured boundaries or
mishandle bootstrap credentials.

## Security invariants

1. **Authenticate before releasing plaintext.** Reject tampered, malformed,
   truncated and wrong-context envelopes. Bind the application, table, record,
   column, schema and optional revision through unambiguous context encoding.
2. **Preserve the versioned protocol.** `FLV2` writes authenticate `[context,
   header, nonce]`; legacy `FLRV` records use their original vector. New writes
   use fresh 16-byte random nonces. Header parsing alone never establishes trust.
3. **Preserve domain separation and compatibility.** Keep the existing
   `floorvault-v1-aes-siv`, `floorvault-v1-beacon-index`,
   `floorvault-v1-libsql-file` and `floorvault-v1-freshness` purpose labels.
   Header bytes, context defaults, DPAPI entropy, Transit context and rotation
   commitments are protocol values, not branding strings. Change them only through
   an explicit versioned migration with verified recovery.
4. **Preserve custody identity.** Unusable or refused backends must not silently
   downgrade or mint an unrelated replacement key. Respect existing file custody,
   OS-tier markers, protected-file checks and read-only resolution requests.
   Keep existing service/account identities and paths stable for existing users.
5. **Keep strict custody strict.** `AdaptiveKeyProvider(strict=True)` refuses
   environment custody and file fallback. Legacy environment names and key-store
   adoption require explicit opt-ins. Integration helpers must not quietly broaden
   those defaults. `VaultStore` does not enable legacy `APPSTATE_KEY` adoption.
6. **Keep SQL values and identifiers safe.** Validate and quote identifiers,
   parameterise values, require exact single-row field updates and preserve caller
   transaction ownership where the adapter does not manage transactions.
7. **Make migration and rotation recoverable.** Preserve the source until
   verification, never resurrect retired legacy records, verify rotation targets,
   and retain necessary key generations through staged operations and recovery.
8. **Respect configured integration boundaries.** Resolve configured references,
   avoid mixing agent-secret and browser-vault migration paths, and verify host
   bootstrap overwrite protection, profile scoping and environment injection.
9. **Keep diagnostics and artifacts honest.** Do not unexpectedly expose secret
   values or keys in errors and logs. Make explicit plaintext CLI output clear.
   Publish artifacts consistent with their declared package and provenance.

## Reportable findings and severity context

Report realistic paths to unauthenticated decryption, cross-context acceptance,
key disclosure, custody downgrade or key fork, SQL injection, unintended secret
output, migration/rotation corruption, boundary-crossing integration behavior,
or compromised build and release integrity. Unsafe public defaults or documentation
that materially misstate guarantees also warrant investigation.

Explain reachability and the additional capability a defect gives the attacker.
Assess severity using exposure, preconditions and impact. Possession of a key or
account may explain an expected ability to decrypt; it must not dismiss a separate,
lower-privilege path to compromise. Scanner warnings are leads to investigate,
not proof by themselves. A passing test or absent dependency alert is not disproof.

AES-SIV avoids catastrophic nonce-reuse failures associated with some AEAD modes,
but repeating the same key, nonce, context and plaintext reveals equality. Evaluate
nonce issues against those actual guarantees rather than treating repetition as
proof of a plaintext-recovery attack.

## Design limits and known limitations

- **Freshness is opt-in.** Ordinary decryption accepts same-context replay.
  Revisions require trusted expected state. `FreshnessAnchor` covers configured
  SQLite/libSQL tables through externally stored keyed state and its verified
  transaction path. Protect that state from joint rollback. Interrupted commits
  need deliberate recovery. Credential stores and the plugin do not automatically
  enable anchoring.
- **Metadata remains visible.** Field encryption does not hide unencrypted columns,
  schema, counts, IDs, lengths or access patterns. `kind` and `has_otp` are unsealed
  by default. Listing sealing protects those values and their integrity, but does
  not hide cardinality or erase historical plaintext residue.
- **Beacons leak structure.** Optional truncated keyed indexes expose buckets,
  frequencies and query patterns. Decrypt candidates to confirm equality.
  Low-cardinality values may remain identifiable despite truncation.
- **File custody needs a boundary.** Copying an unwrapped Tier-3 file can yield
  its key. Passphrase wrapping adds scrypt + AES-SIV; it does not provide hardware
  custody. Weak or stolen passphrases defeat it. Wrapping a formerly exposed key
  does not revoke prior copies.
- **OS custody is account-based.** Keychain, DPAPI and Secret Service do not promise
  a secure enclave or protection from the account or an administrator. Default
  DPAPI entropy is public, unless the caller supplies a secret. Windows checks
  effective DACLs; POSIX mode checks do not inspect extended ACLs.
- **Custody tiers do not share a store.** Sessions in one home can see
  different tiers: a desktop login can reach the Keychain or Secret Service, while
  SSH, cron or a container cannot. Without a guard, the second session would mint
  a second master key, and data written under one key cannot be read with the
  other. `AdaptiveKeyProvider` blocks this in both directions (SPEC §10.5):
  - While `master.key` or `master.key.fvpw` exists, the OS tier is only read. If
    it is usable but empty, resolution refuses instead of creating an OS key.
  - When the OS tier holds the key, it records `master.key.ostier` in the
    fallback directory. The marker is owner-only and holds the tier, service and
    account names, with no key material. While it exists, raw and passphrase
    file-key creation both refuse. A marker that cannot be read counts as
    present.
  - If the OS key named by the marker goes missing (deleted, or the store reset),
    resolution refuses rather than minting a replacement.

  Limits: the marker is written on the first successful OS-tier resolve that is
  allowed to create a key (read-only resolution writes nothing), so an existing
  OS-key install has no marker until that happens. If the fallback directory is
  unwritable, the OS key is still used and a warning says the guard is absent. A key fork from before the guard is not repaired: an
  existing file key is still read. Whoever can delete files in the fallback
  directory can remove the marker.
- **Memory hardening is limited.** Wiping reaches managed buffers, not every
  Python, provider or AEAD-engine copy. Locking and anti-dump advice depend on
  the platform. Key construction attempts to disable core dumps process-wide
  without restoring the setting. Required memory mode enforces its implemented
  checks, not an enclave guarantee.
- **Plaintext has a lifecycle.** Migration, deletion and SQLite cleanup do not
  guarantee erasure from pages, WAL, backups, snapshots or storage media.
  Plugin results and revealed CLI output become plaintext in the consuming
  process. CLI secret arguments may appear in process listings; prefer stdin.
  `put` (in `floorvault secrets` and the optional plugin) replaces one field in
  a single SQLite transaction through `VaultStore.update_generic_field()`.
  `floorvault secrets import --write` replaces the `.env` file atomically and
  makes no backup, but it cannot erase earlier copies of that file.
- **`floorvault run` hands plaintext to the child.** Resolved values become
  ordinary environment variables of the started process and of anything it
  starts. Code running as the same user can usually read a process's
  environment. `run` keeps secrets out of files and configs; it is not an
  access-control boundary. It removes vault key variables (`FLOOR_VAULT_KEY`,
  `VAULT_MASTER_KEY`, `HERMES_VAULT_KEY`, the `--key-env` name), the
  `FLOOR_VAULT_KEY_FILE` pointer, and any copy of a key they or `--key-file`
  supply from the child environment, refuses references onto them, and only
  reads existing keys. A `--key-file` key is plaintext at rest, guarded only by
  file permissions: `run` refuses a file that another user owns or that group or
  others can write, but the child runs as the same user and can read the file. On macOS and Linux the default custody uses one
  key-store entry per user, so every default store shares one master key.
  The configuration `run` reads chooses which items are resolved: a `.env` or
  MCP entry from an untrusted source can name any item by its id. Review such
  configuration first, or use `--no-inherit-refs` with explicit `-e`
  references. `floorvault secrets` commands print no values, but `run` can
  start a command that does.
- **Migration can write during listing.** The migration-aware `list_items()` path
  upgrades legacy items through metadata lookup. It can write modern records and
  retirement tombstones without a separate bulk-migration request. Back up legacy
  files before enabling migration; listing is not a read-only assurance.
- **Page encryption is separate.** Native local libSQL encryption does not
  authenticate the whole database or convert an existing plaintext file in place.
  Field authenticity still comes from the FloorVault envelopes.

Attacks whose only premise is full host, process or account compromise, physical
attacks, unspecified timing differences, unclaimed features and denial of service
remain outside this policy's protected threat model. Reports should explain any
incremental capability beyond those premises. These limits do not exclude defects
that give a less-privileged caller new access or contradict a documented control.

## Assurance and supply chain

The repository includes RFC and Wycheproof vectors, an independent SIV reference,
wire fixtures, deterministic and coverage-guided fuzz targets, regression and
mutation tests, dependency auditing, static analysis, linting and secret scanning.
They provide evidence for exercised paths, not an independent security audit.

Inspect actual CI results and skips. Hermes plugin tests require a compatible
host checkout and may skip entirely. macOS Keychain and Linux Secret Service
models do not constitute live backend verification. Windows has an unmocked DPAPI
test; a configured matrix alone does not prove every native backend ran.

`pyproject.toml` declares consumer dependency ranges; `uv.lock` records a development
resolution. Validate alerts against the affected installed version and reachable
API. Do not treat one scanner or GitHub's dependency graph as complete coverage.
The optional plugin is outside the standalone gate's current lint/static-analysis
paths, and host integration tests can skip. Do not present the library checks as
complete verification of plugin installation or host behavior.

PR CI runs four test cells: Ubuntu Python 3.10/3.14 and macOS/Windows Python 3.13.
Weekly, version-tag and expanded manual runs cover the broader nine-cell matrix.
Shared lint/build/static/history scans run once. Full curated mutations run on
Linux; macOS/Windows repeat platform controls, including the equivalent canary and
platform-specific expectations. All-extras dependency audits run on each OS.
The standalone local gate remains a complete check independent of CI job splitting.

The release workflow builds twice on one runner, checks universal wheel tags,
creates an SBOM and configures provenance and publishing. Tags or digests alone
do not prove source equivalence, independent review or cross-platform byte identity.
Verify the exact release artifact using [RELEASING.md](docs/RELEASING.md).
Hardware custody remains a proposal; it is not supplied by default.

## Compatibility and recovery

The FloorVault package, record formats, HKDF labels, recovery bundle identity,
DPAPI entropy, Linux key attributes, Transit context purpose, default directories
and service names retain their existing identities. Compatibility tests use
fixtures generated by the earlier `main` revision, including an on-disk sealed
store and recovery bundle; new round trips alone are not compatibility evidence.

Records or stores created by the experimental rename in earlier PR #53 commits
are not automatically migrated. Keep the exact writer revision, keys and context
for recovery. Retired legacy records fail with `LegacyRetiredError`; ciphertext
verification failures use `DecryptionVerificationError`. Handle these failures
explicitly rather than substituting a different key or legacy record.

## Safe harbour and advisories

We will not pursue or support legal action against researchers who make a
good-faith effort to follow this policy, report privately and allow a reasonable
opportunity to fix issues, avoid privacy violations, destruction or interruption
of service, and do not exfiltrate, retain or share data that is not their own.

Published advisories are listed in [GitHub Security Advisories](https://github.com/Guerilla-ops/floorvault/security/advisories).
Review material changes to this policy and record them in release notes.

# Security Policy

FloorVault is a cryptographic library. We take its security seriously and we
welcome reports from security researchers, cryptographers, and users.

This document explains what we consider a security issue, how to report one,
what to expect after you do, and the guarantees — and the non-guarantees — of
the design.

- **Project:** FloorVault (`floorvault` on PyPI)
- **Repository:** https://github.com/vaultfloor/floorvault
- **Maintainer:** Scott Lee `<floorbond@pm.me>`

---

## 1. Supported versions

Security fixes are provided for the following:

| Version | Supported |
| --- | --- |
| `main` branch | :white_check_mark: |
| Latest release (0.1.x, Beta) | :white_check_mark: |
| Any earlier release | :x: |

FloorVault is currently **Beta (0.1.x)**. Until 1.0, the supported surface is the
`main` branch plus the most recent release. If you depend on a specific release,
pin it and upgrade promptly when a security release is published.

**Supported Python:** 3.10 and later.

---

## 2. Reporting a vulnerability

**Please do not report security issues in public GitHub issues, pull requests,
or discussions.**

Use one of the private channels below:

1. **GitHub private vulnerability reporting (preferred).**
   Open a draft advisory at:
   https://github.com/vaultfloor/floorvault/security/advisories/new
   This keeps the report private, gives us a shared workspace to collaborate in,
   and lets us request a CVE through GitHub when one is warranted.

2. **Email:** `floorbond@pm.me`
   Please use a subject line beginning with `SECURITY:`.

   If you would like to encrypt your report, request our PGP public key in a
   first, content-free email and we will send it; verify the fingerprint out of
   band before trusting it. *(Maintainer: publish the key and fingerprint here
   once generated — see the note at the end of this document.)*

### What to include

Help us reproduce and assess the issue quickly. Where applicable, please include:

- A description of the issue and the impact you believe it has.
- The affected version(s) or commit hash.
- A minimal, self-contained reproduction — code, a test case, or exact steps.
- The threat model you have in mind: who the attacker is, what they control,
  and what they gain.
- Any suggested fix or mitigation.
- Whether you intend to publish, and on what timeline.
- How you would like to be credited (name, handle, or organisation), or if you
  prefer to remain anonymous.

You do **not** need a working exploit, and you do **not** need a proof of
concept. A clear, reasoning-based argument under a plausible threat model is
enough for us to investigate. If you are unsure whether something is a security
issue, please tell us anyway — it is far better for us to triage it than for you
to sit on it.

---

## 3. What happens next

| Stage | Target |
| --- | --- |
| Acknowledgment of your report | Within **48 hours** |
| Initial triage and severity assessment | Within **5 business days** |
| Status update to you | At least every **7 days** while open |
| Fix for Critical / High severity | As soon as practicable; typically within **30 days** |
| Coordinated public disclosure | By agreement; default **90 days** from acknowledgment |

- We will confirm the issue, assess its severity, and tell you our assessment.
- We will keep you informed of progress and will not disclose the issue publicly
  before the agreed date.
- We will credit you in the advisory and release notes unless you ask us not to.
- If we conclude something is not a vulnerability, we will explain why — and we
  will not treat your report as noise for having asked.
- We aim to publish a security release for any confirmed security issue, with an
  advisory that states the affected and fixed versions.

If we are unresponsive beyond these targets, we will not object to responsible
disclosure by the reporter, provided we were given a reasonable opportunity to
fix the issue first.

### Credit

With your permission we will name you in the advisory. We do not currently
operate a paid bug bounty.

---

## 4. What we consider a security issue

Our scope is deliberately **broad**, in line with the approach taken by mature
cryptographic libraries: if a reasonable developer can use FloorVault's *public
API* in a way that does not provide the guarantees our documentation describes,
we want to know.

**In scope — examples:**

- A path through the public API that allows **nonce or IV reuse** under a given
  key, or that otherwise breaks the confidentiality guarantees of AES-256-SIV.
- A way to make a ciphertext **decrypt under the wrong context** — i.e. to defeat
  the contextual associated data (AAD) binding and splice a record from one
  table/record/column into another.
- **Failure to fail closed**: any case where tampered, truncated, or malformed
  input is accepted, returns wrong plaintext, or raises a raw/internal error
  instead of a clean verification failure.
- A derivation that is not domain-separated or otherwise reuses key material across
  cryptographic purposes.
- A **non-fork-safe** or otherwise unsafe source of randomness.
- Mishandling of an error condition in the underlying `cryptography`/OpenSSL
  primitives that leads to unsafe behaviour.
- Unsafe handling of **key material in memory** that contradicts the documented
  guarantees (e.g. keys written to disk or logs contrary to the documentation).
- Weaknesses in the **packaging** that mislead users about what they are
  installing — e.g. a shipped wheel that does not match the source, or a build
  that silently pulls in unexpected native code.

**Out of scope — examples:**

- Attacks that require the attacker to already control the host, the process, or
  the user account running FloorVault (see the threat model in §5).
- Generic timing differences for which no concrete information-disclosure attack
  can be articulated.
- The absence of a feature that was never claimed (e.g. protection against a
  compromised dependency, or against an attacker who can read process memory).
- Documentation typos, or a design trade-off that is explicitly documented.
- Reports produced solely by a pattern-matching scanner with no analysis of
  reachability (we are happy to receive these, but please note the tool and why
  you believe the finding is reachable).

If you are unsure which side of the line your finding falls on, report it
privately and let us make the call.

---

## 5. Threat model — what FloorVault protects against, and what it does not

FloorVault protects **data at rest** in a SQLite database or application-state
store against an attacker who obtains a copy of the stored data but not the key
material.

**In scope (protected):**

- Theft or exfiltration of the database file(s) or a backup of them.
- An attacker who can read the raw stored rows/pages but does not hold the key.
- Silent modification of stored ciphertext — including **splicing** a ciphertext
  into a different row, column, or table, which the contextual AAD binding is
  designed to detect.
- Offline analysis of the stored data: no plaintext is exposed by the encrypted
  fields or metadata values.

**Explicitly out of scope (not protected):**

- An attacker who controls the host, the operating system, or the user account
  running FloorVault while it is running (root/admin, kernel-level malware,
  debuggers, memory dumps of the live process).
- Attacks requiring the ability to read process memory, or to observe the key
  after it has been unlocked.
- Physical attacks: cold-boot, DMA, bus probing, fault injection, power/EM
  side channels.
- Compromise of the caller's application — including logging plaintext or the
  key, mishandling the key, or passing attacker-controlled data where keys are
  expected.
- Weakness or compromise of the underlying platform: Python, the `cryptography`
  package, OpenSSL, PyPI, or the user's own dependency resolution.
- Denial of service of any kind.
- Loss of data because the key was not backed up.

**Two general limits worth stating explicitly:**

- **Same-coordinate replay is not detected by default.** The contextual binding
  detects a ciphertext *moved* to different coordinates, but a previously valid
  ciphertext written back into its *original* coordinates authenticates
  successfully — AES-SIV provides authenticity, not freshness. FloorVault
  detects rollback when the caller binds a monotonic `revision` sourced from
  trusted state (`encrypt(..., revision=)` / `decrypt(..., revision=)`); where
  no such trusted source exists, rollback protection is out of scope. If the
  revision is stored beside the ciphertext, an attacker who can rewrite one can
  roll back both.
- **The file-based key fallbacks are not a confidentiality boundary.** Where no
  OS-native key store is available or enabled, the fallback store keeps the key
  recoverable from the file itself (raw, or masked with a deterministic pad
  seeded by public constants): a copy of the store is enough to recover the
  key. The OS-native tiers (macOS Keychain, Windows DPAPI, Linux Secret
  Service) bind the key to the OS user instead.
- **Schema metadata leakage is an accepted design residual.** To preserve fast
  listing and filtering without decrypting every item, stored metadata such as
  item cardinality, item kind, and whether an item contains an OTP is visible
  to an attacker who can read the database. These fields do not reveal secret
  values, but their presence, absence, and distribution are intentionally not
  hidden by the design.
- **Searchable beacons are opt-in and are the one feature that deliberately
  re-introduces query leakage.** The default library stores no derived search
  index, so nothing below applies unless an application calls
  `floorvault.beacons` itself. When it does, the stored beacon is a
  deterministic keyed function of the plaintext, which discloses: coarse
  equality (unequal beacons prove unequal values); bucket frequency, since
  occupancy remains a function of the plaintext distribution even though
  truncation makes the index non-injective; and query access patterns. The
  anonymity a beacon provides is roughly the bucket occupancy `rows / 256**k`
  for a stored width of `k` bytes, so **a small table with a one-byte beacon is
  close to exact equality** — size the width to the data with
  `suggest_beacon_bits()` rather than choosing a constant. Do not beacon a
  low-cardinality column (a status flag, a country, a boolean): with few
  distinct values the beacon histogram mirrors the plaintext histogram
  regardless of width. A beacon hit is not proof of equality — collisions are
  by design — so the confirmation step is to decrypt the candidate row and
  compare the plaintext. Applications whose threat model cannot accept any
  structural or statistical exposure should not enable beacons and should
  filter client-side after decrypting.
- **Tier-3 local file custody is not a hardware or OS confidentiality boundary.**
  When `~/.floorvault/master.key` is used, the key remains recoverable from the
  local file by an attacker who can copy that file or its containing store. The
  owner-only filesystem permissions reduce accidental exposure but do not
  provide Keychain, DPAPI, Secure Enclave, or hardware-backed confidentiality.
  Use an OS-native provider or external secret source when that boundary is
  required.
- **`wipe()` zeroes only the buffers FloorVault manages.** `FloorVault.wipe()`
  and `HardenedMemoryKey.wipe()` deterministically zero the locked/mapped key
  buffers under the library's control. They cannot reach key copies made
  inside the `cryptography` library's AEAD engine (released unzeroed on
  garbage collection), `bytes` intermediates held by the caller or produced
  during derivation, or copies made by providers before custody transfers.
  Treat `wipe()` as relinquishing FloorVault's own custody, not as proof that
  no key material remains anywhere in the process.
- **Removing a migrated plaintext column requires residue-aware cleanup.**
  `migrate_plaintext_column` never deletes the plaintext source, and a plain
  `DROP COLUMN` afterwards leaves the plaintext readable in freed pages and
  the WAL. `drop_plaintext_column` arms `secure_delete`, truncates the WAL,
  and optionally `VACUUM`s — which scrubs the database file's pages but still
  cannot erase filesystem-level block slack; only destroying the file
  guarantees complete removal.

**A third limit, specific to migration:**

- **A retired legacy id is refused, not protected against a full rollback.**
  Once an id has been migrated its pre-migration value is retired permanently:
  if the modern record is later deleted or rolled back, the read fails
  (`LegacyRetiredError`) instead of silently serving the value from before the
  credential was rotated. The retirement record is authenticated under the
  master key and bound to the id, so it cannot be rewritten or moved. It does
  live in the same database as the data, though, so an attacker who can roll the
  *whole* database back rolls the retirement back with it. This closes silent
  resurrection and makes a downgrade detectable; genuine freshness still needs
  state the attacker cannot roll back, as above.

### Attacker capabilities, and what to expect from each

Stated by capability rather than by feature, so a threat that is out of scope
cannot be mistaken for one that is covered.

| Attacker | Can read store | Can modify store | Can read the process | Controls the account | Expected protection |
|---|:---:|:---:|:---:|:---:|---|
| A1 — stolen database file | ✅ | ❌ | ❌ | ❌ | **Strong**: no plaintext in protected fields |
| A2 — stolen disk / backup files | ✅ | ❌ | ❌ | ❌ | **Strong**, minus what the key store itself gives up (see the fallback limit above) |
| A3 — malicious store writer | ✅ | ✅ | ❌ | ❌ | **Partial**: values cannot be forged or spliced; rows can be deleted, duplicated or replayed (see freshness above) |
| A4 — malicious same-UID process | ✅ | ✅ | Possibly | ✅ | **Weak**: it can use the same custody the application uses |
| A5 — compromised application | ✅ | ✅ | ✅ | ✅ | **Not protected** — see the next section |
| A6 — administrator / root | ✅ | ✅ | ✅ | ✅ | **Not protected** |
| A7 — snapshot / backup attacker | ✅ | Possibly rollback | ❌ | ❌ | **Partial**, as A3 |

### When the caller is an autonomous agent (authorised-use attacks)

This is a scope statement, not a mitigation.

FloorVault cannot tell an authorised request from a coerced one. If an agent is
prompt-injected, or otherwise steered, into making a request the application
would normally make, then `decrypt()` returns the plaintext and every
cryptographic check legitimately passes — the value is authentic, the
coordinates are right, and the caller holds exactly the authority it was given.
The library has no way to see the difference, and it does not try to.

Consequences an integrator should plan for:

- An agent that holds the master key **is** the decryption authority. Compromise
  of the agent is compromise of everything it can decrypt.
- Narrowing what an agent may decrypt is an *application* concern: pass it
  scoped credentials, not one master key, and keep the ability to request a
  secret out of the model's control where you can.
- Where the authority must not travel with the caller, put policy **outside**
  the process that holds the key — a broker or service that authenticates the
  request and returns an outcome rather than the secret. That is a deployment
  architecture; FloorVault does not implement it.
- Memory hardening, mlock and anti-dump measures raise the cost of some
  opportunistic inspection. They do not turn a Python process into an enclave
  and are not a defence against a compromised application (A5).

These exclusions mirror the practice of well-established cryptographic
libraries, including OpenSSL. Issues in these classes are not treated as
FloorVault vulnerabilities and will not receive a CVE — though we may still act
on them where practical, and we will always tell you our reasoning.

---

## 6. Cryptographic design summary

For a full description see the README and the design notes in `docs/`.

- **Confidentiality + integrity:** AES-256-SIV (RFC 5297), a misuse-resistant
  authenticated encryption mode. Because SIV is nonce-misuse-resistant, a
  repeated nonce does not by itself leak plaintext relationships — a deliberate
  choice over a stream/counter mode.
- **Context binding:** every record is encrypted with associated data derived
  from its coordinates (table, record id, column, schema id and version, and the
  application instance id). Moving or splicing ciphertext between coordinates
  causes a verification failure rather than a silent wrong-plaintext result. An
  optional caller-supplied `revision` can additionally be bound for
  same-coordinate rollback detection (see §5).
  **The coordinate encoding is canonical and unambiguous.** The fields are
  serialised as UTF-8 JSON with sorted keys and no insignificant whitespace, and
  the resulting block is passed to AES-SIV as *one* associated-data element with
  the nonce and (for v2 records) the header as *separate* elements. Field
  boundaries therefore cannot be blurred by concatenation: no two distinct
  coordinate sets produce the same associated data, and empty coordinates are
  rejected outright. This is a guarantee, not an implementation detail — a
  change to it is a format change.
- **Record format (v2):** `FLV2` (4 bytes) ‖ `crypto_version` (1) ‖ `key_id` (1)
  ‖ `nonce_len` (1) ‖ `nonce` (16) ‖ ciphertext. The cleartext header is bound
  into the associated data as its own element, so a rewritten version or key id
  fails authentication rather than being ignored. `envelope_header()` reports
  these fields without decrypting. v1 records (`FLRV` ‖ `nonce_len` ‖ `nonce` ‖
  ciphertext) remain readable and keep their original associated-data vector.
- **Key identifiers:** `key_id` records which key a record was written under, so
  a reader can select the right one and a rotation can be staged per record.
  `decrypt(..., key_id=)` can require a specific key. This build derives one
  subkey per instance and writes `0`.
- **Zeroization scope:** `wipe()` zeroes the primary mlock'd key buffer, but
  zeroization cannot reach every copy: immutable Python `bytes` objects derived
  from the key, and the internal memory of the OpenSSL (Rust/C) AEAD
  implementation, are outside the library's control. Integrators should treat
  zeroization as best-effort and avoid holding key material in long-lived
  immutable objects where possible.
- **Key derivation:** the master key is expanded once with HKDF-SHA256 into the
  64-byte AES-256-SIV key, using the domain-separating info value
  `floorvault-v1-aes-siv`. **The default library derives no secondary index
  key** — decryption and context binding use the AEAD key alone. The opt-in
  `floorvault.beacons` module additionally derives a separate 32-byte beacon
  subkey under the distinct info value `floorvault-v1-beacon-index` (see
  `derive_beacon_key()`), so the search index never shares key material with
  the AEAD; that key is derived only when a caller asks for it, never by
  constructing a `FloorVault` or `VaultStore`. The leakage this opt-in enables
  is stated in §5.
- **Key-store protection:** the store is refused unless it is owner-only. On
  POSIX that is the standard file mode (extended ACLs such as macOS
  `chmod +a` or Linux `setfacl` are not queried); on Windows, where there
  are no POSIX permission
  bits and `os.stat()` reports a synthesised mode, the store's **effective NT
  DACL** is read (`GetNamedSecurityInfoW`) and a store granting access to any
  principal other than its owner, SYSTEM and Administrators is refused. If the
  protection cannot be established on either platform, the store is refused
  rather than trusted.
- **Key custody tiers:** the environment, the OS store (macOS Keychain, Windows
  DPAPI, Linux Secret Service), then — only if the caller
  explicitly enables it — a local file. A present-but-unusable OS store raises
  instead of quietly dropping to a weaker tier. The DPAPI tier accepts optional
  caller-supplied secondary entropy (`dpapi_entropy=` on `AdaptiveKeyProvider`,
  `entropy=` on `WindowsDPAPIKeyProvider`); without it the blob uses a public
  constant, so it is bound to the Windows user account but carries no extra
  secret a same-user process could not reproduce.

  Each tier keeps its own store file (`master.key` for the local-file tier,
  `master.key.dpapi` for DPAPI, `master.key.ss` for Secret Service). The three
  formats are mutually unreadable, so sharing one path would let whichever tier
  ran first lock the others out of the user's own data.

  **Verification status by tier.** Windows DPAPI is exercised unmocked on the
  `windows-latest` CI legs. macOS Keychain and Linux Secret Service are not:
  the Keychain live test is opt-in and no workflow sets its flag, and no CI leg
  runs a `dbus-run-session` + Secret Service environment. Both are therefore
  **implemented and unit-tested against a faithful model of the library API,
  but not live-verified**. The Linux client is checked against the real
  `secretstorage` package by a contract test that derives the names it calls
  from its own source and asserts each exists; that is an API-surface check,
  not a live round trip.
- **Zero C compilation:** FloorVault ships as a universal pure-Python wheel
  (`py3-none-any`) and does not compile native code at install time. Its
  cryptographic primitives come from the `cryptography` project (PyCA).
- **Memory hardening is best-effort, and one part of it is process-wide.**
  `mlock`/`VirtualLock` page-pinning and the Linux `MADV_DONTDUMP`/
  `MADV_DONTFORK` advice depend on the platform and are reported through the key
  handle rather than guaranteed; macOS implements neither `madvise` advice.
  Separately, constructing a key handle sets `RLIMIT_CORE` to 0 for the **whole
  process** and never restores it, so the host application's own crash dumps are
  disabled from that point on. That is deliberate — a core dump of a process
  holding a master key writes the key to disk — but it is a library side effect,
  so an application that needs its own dumps must know about it.

---

## 7. Dependencies and supply chain

- FloorVault's cryptographic operations are implemented on top of
  [`cryptography`](https://github.com/pyca/cryptography), which in turn links
  OpenSSL. A vulnerability in those projects is a vulnerability we inherit.
- We track upstream advisories for `cryptography` and OpenSSL and will publish a
  release when a security fix affects a supported version. As with PyCA itself,
  we would rather ship an update promptly than leave users exposed.
- The supported Python floor is raised when upstream fixes require it — including
  when a patched dependency is unavailable on an older interpreter.
- Dependency versions are pinned in `uv.lock`, and the pre-push checks audit
  dependencies with `pip-audit` on every run.

### Where a dependency alert comes from, and which source we trust

`pip-audit` over the locked environment in `scripts/security-check.sh` (gate
step 2, fatal on a finding by default) is the authoritative dependency check: it
resolves exactly the versions this project ships.

GitHub's dependency graph and its Dependabot alerts are advisory, and for
`uv.lock` they can be **stale**. As of 2026-09-15 the graph for this repository
simultaneously listed two versions of most packages — `cryptography` 47.0.0 *and*
50.0.1, `pytest` 8.4.2 *and* 9.1.1, `cffi` 2.0.0 *and* 2.1.1 — omitted `pip-audit`
entirely despite it being in `uv.lock`, and raised five alerts against versions
that appear in no manifest in this repository. There is no supported way to force
a rescan of the graph (see [dependabot-core#15010](https://github.com/dependabot/dependabot-core/issues/15010)).

How we handle that:

- A dependency alert is verified against `uv.lock` and `pip-audit` before it is
  acted on. If the flagged version is not in the tree, the alert is **dismissed
  as `inaccurate`** with the evidence in the dismissal comment — never as
  "tolerable risk" or "not used", which would imply we had accepted something.
- Dismissal is not a substitute for a fix: if `pip-audit` reports a real
  vulnerability, it fails the gate and the fix is a normal dependency update.
- **Residual risk:** while the graph is stale, a *genuine* alert could be
  missed. That is precisely why the gate runs its own SCA rather than relying on
  the platform, and why the gate fails closed when `pip-audit` is missing.

---

## 8. Assurance practices — what we do today, and what we do not

We prefer measured claims over marketing claims. Currently in place:

- A test suite covering the crypto core, and **published RFC test vectors**,
  including an **independent, from-spec RFC 5297 (AES-SIV) implementation** used
  to verify that FloorVault's records are conformant SIV rather than merely
  self-consistent; it is additionally cross-checked against a second,
  independent AES-SIV implementation.
- A **deterministic, seeded fuzz harness** asserting the core invariants —
  round-trip, splice-immunity, and fail-closed behaviour on malformed input.
- Static analysis, secret scanning, and dependency auditing in the automated
  checks run on every push (`scripts/security-check.sh`): `gitleaks` (secrets),
  `ruff` (lint/format), `pip-audit` (dependency CVEs), the RFC vector suites,
  the memory-custody/zeroization tests, the core crypto and splice-immunity
  tests, the fuzz harness, and a universal-wheel build.
- **Mutation testing of the security gate itself**: curated behavioural mutants
  of the custody, migration and envelope code must all be killed before
  the gate passes, with a canary mutant that must survive to prove the harness
  can still detect a live mutant. A green suite proves nothing if the tests
  cannot fail.
- The **deep-dive security regression scan** (`tests/test_security_scan.py`) runs in
  the gate and deterministically covers five reviewed vulnerability classes:
  rotation/write handoff, exact schema-version typing in authenticated context,
  migration collision equivalence, memory-mode validation, and existing vault
  directory custody. Its five curated mutants (`DS-1` through `DS-5`) are required
  to be killed; the scan is regression coverage, not a claim of complete static
  analysis or security certification.
- A **universal wheel** build verified on every push, so the published artifact
  matches the audited source and carries no unexpected native code.
- **Artifact identity — and what is explicitly NOT claimed.** The gate prints the
  SHA-256 of the wheel and sdist it built on every runner, and CI publishes the
  artifacts from one leg, so a download can be identified against a build from
  source. **Reproducibility is per platform, not across platforms, and two
  attempts to attribute it precisely have each been falsified by the next run -
  treat the per-platform digests as facts and the causes below as partial.**

  Measured for a single commit, before line endings were pinned:

  | Runner | wheel | sdist |
  |---|---|---|
  | ubuntu py3.10, py3.13 / macos py3.13 / maintainer host | `0c0e2ae7…` | `882a8a26…` |
  | windows py3.10, py3.13 | `d17b4902…` | `1ec7155e…` |

  After pinning line endings (`* text=auto eol=lf`), the Windows artifacts
  *changed* — `26d36487…` and `9fdc6857…` — but still do not match the POSIX
  values. So:

  - *Line endings were a real cause and are fixed.* A CRLF-forced checkout of the
    pinned tree now builds the POSIX digest, and every Windows artifact moved when
    this landed.
  - *The zip creating-system byte — confirmed by reading, not inferred.* The gate
    prints it per runner: ubuntu and macOS build `create_system=[3]` (Unix),
    Windows builds `create_system=[0]`, with byte-identical content and identical
    file modes (`0o644`/`0o100644`). CPython derives that byte from the platform,
    so it differs for every entry in every wheel built on Windows.
  - *The sdist's executable bit — confirmed the same way.* ubuntu and macOS report
    `tar_modes=['0o644', '0o755']` (the gate script is tracked executable), Windows
    reports `['0o644']`: it cannot represent the bit. The gzip OS byte is `255` on
    every runner, so it is **not** a cause.

  **Byte-identity across operating systems is therefore not achievable from
  repository settings**, because both remaining causes live in metadata that
  CPython derives from the platform. Reaching it would mean normalising the
  archives after the build (rewriting the creating-system byte and the tar modes)
  or — the usual answer — building the published artifact in one designated
  environment. That is the position taken here: the ubuntu-built wheel is the
  release identity, and verifying a download means comparing it against *that*
  artifact rather than against a build from an arbitrary machine. A digest
  identifies an artifact for its platform — it is **not** a cross-platform
  identity, and no such identity is claimed.

**Not** (yet) in place, and not claimed:

- No third-party security **audit** or cryptographic review of the code has been
  performed. An independent architecture and threat-model review of the README
  was received and triaged; it found no weakness in the cryptographic design, and
  its findings were verified against source before any were acted on (one did
  become a real fix). A README review is not a code audit and is not presented as
  one.
- No formal verification, and no FIPS/Common Criteria validation.
- No paid bug bounty.

We would rather you know this precisely than assume otherwise.

---

## 9. Safe harbour

We will not pursue or support legal action against researchers who:

- make a good-faith effort to comply with this policy;
- report issues privately through the channels above and give us a reasonable
  opportunity to fix them before publication;
- avoid privacy violations, data destruction, and interruption of service; and
- do not exfiltrate, retain, or share data that is not their own.

If in doubt, ask first. We would much rather answer a question than litigate one.

---

## 10. Known vulnerabilities and advisories

Published advisories for FloorVault:

- GitHub Security Advisories: https://github.com/vaultfloor/floorvault/security/advisories
- Dependabot alerts (dependency issues): https://github.com/vaultfloor/floorvault/security/dependabot

Dependency vulnerabilities can be tracked through the ecosystem databases
(for example [osv.dev](https://osv.dev)) and audited locally with `pip-audit`.

---

## 11. Changes to this policy

This policy may be updated as the project matures — in particular when a PGP key
is published, when GitHub private vulnerability reporting and secret scanning are
enabled, and if a security audit is ever commissioned. Material changes will be
noted in the changelog.

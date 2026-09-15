# Security Policy

FloorVault is a cryptographic library. We take its security seriously and we
welcome reports from security researchers, cryptographers, and users.

This document explains what we consider a security issue, how to report one,
what to expect after you do, and the guarantees — and the non-guarantees — of
the design.

- **Project:** FloorVault (`floorvault` on PyPI)
- **Repository:** https://github.com/Guerilla-ops/floorvault
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
   https://github.com/Guerilla-ops/floorvault/security/advisories/new
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
- **Key-separation failures** — e.g. the same key material used for both the SIV
  subkey and the blind-index/beacon subkey, or a derivation that is not
  domain-separated.
- Weakness in the **blind index / beacon** that leaks more than the documented
  bound (equality within a bucket, frequency, or ordering information beyond
  what the configured bucket width permits).
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
- Documentation typos, or a design trade-off that is explicitly documented (for
  example, the intentional bucket-collision behaviour of the search beacons).
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
- Offline analysis of the stored data: no plaintext, and only bounded equality /
  frequency information via the search beacons.

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
  causes a verification failure rather than a silent wrong-plaintext result.
- **Key separation:** a single master key is expanded with HKDF-SHA256 into
  domain-separated subkeys — one for the AEAD and one for the blind-index/beacon
  MAC — which are never reused across purposes.
- **Searchable encryption:** deterministic search uses truncated HMAC-SHA256
  *beacons* over a bounded bucket. Exact matches are confirmed by decrypting the
  candidate. Beacons deliberately trade exact-match precision for a bounded
  leakage profile; collisions within a bucket are by design, not a defect.
- **Zero C compilation:** FloorVault ships as a universal pure-Python wheel
  (`py3-none-any`) and does not compile native code at install time. Its
  cryptographic primitives come from the `cryptography` project (PyCA).

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
- A **universal wheel** build verified on every push, so the published artifact
  matches the audited source and carries no unexpected native code.

**Not** (yet) in place, and not claimed:

- No third-party security audit or cryptographic review has been performed.
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

- GitHub Security Advisories: https://github.com/Guerilla-ops/floorvault/security/advisories
- Dependabot alerts (dependency issues): https://github.com/Guerilla-ops/floorvault/security/dependabot

Dependency vulnerabilities can be tracked through the ecosystem databases
(for example [osv.dev](https://osv.dev)) and audited locally with `pip-audit`.

---

## 11. Changes to this policy

This policy may be updated as the project matures — in particular when a PGP key
is published, when GitHub private vulnerability reporting and secret scanning are
enabled, and if a security audit is ever commissioned. Material changes will be
noted in the changelog.

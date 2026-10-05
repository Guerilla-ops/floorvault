# Copilot review instructions — FloorVault

FloorVault is contextual, misuse-resistant database encryption (AES-256-SIV
with coordinate-bound AAD). Reviews here are security reviews first, style
reviews second.

## Hard rules — flag any violation

- **Never weaken authentication.** The AEAD associated-data vector is
  `[aad, header, nonce]` for v2 envelopes and `[aad, nonce]` for v1. Every
  cleartext envelope field must stay inside that vector. Removing an element,
  reordering, or mutating cleartext fields is a critical finding.
- **Never remove or weaken validation.** Rejection rules in `docs/SPEC.md`
  §4.3/§16 are normative, including their ORDER. Do not suggest relaxing a
  check for convenience.
- **Nonce discipline.** Nonces are 16 bytes from `os.urandom`, fresh per
  field. Counter-derived, reused, or truncated nonces are critical findings.
  The dedup window is defence-in-depth, not a freshness mechanism.
- **No key/custody downgrades.** A broken or refused custody tier must raise,
  never silently fall through to a weaker one. No-clobber store publication
  (hard link) is deliberate; do not suggest `os.replace`.
- **SQL identifiers** must pass `_safe_identifier` and be interpolated via
  `_quoted_identifier` (bracket-quoted). Any other interpolation of a name
  into SQL is a finding.
- **On-disk formats are a contract** (`docs/SPEC.md`). Byte-level changes
  require a version bump AND a reader for every documented version. Flag any
  wire-format change without a spec + vector update.
- **Tombstones/retirement** are fail-closed: a migrated id is never served
  from the legacy source again, even if the modern record is gone.

## Conventions

- Errors are honest: no swallowed exceptions, no "cannot tell is fine", no
  masking one check behind another (the mutation suite hunts these).
- New security guards get a curated mutant in `scripts/mutation_check.py`;
  platform-equivalent survivors are declared, not silently skipped.
- Comments and docstrings explain *why*, and state limits plainly. Correct an
  outdated claim rather than leave it — this codebase treats wrong docs as
  bugs (see `docs/SPEC.md` §17).
- `json.dumps` for authenticated data uses `ensure_ascii=False`,
  `sort_keys=True`, `separators=(",", ":")`; payload JSON uses default
  separators. They are NOT interchangeable.
- Style: ruff clean, compact, no unnecessary try/except — error boundaries
  follow the existing pattern.

## Frozen quirks — flag these too, and weigh them in every review

These behaviors are deliberate *today* (documented and frozen in
`docs/SPEC.md`), but they are not above scrutiny. Flag them when they appear
in a diff or are relevant to a change, note that the design intent is known,
and assess whether the change under review makes the quirk riskier — e.g.
new code that relies on one of these edge cases is worth a comment even
though the behavior itself is intentional:

- `memoryview` plaintext input is refused; `bytearray` envelope input is
  snapshotted once before parsing (§4.3). Intentional — snapshot safety.
- Negative or >64-bit `schema_version`/`revision` integers serialize into
  the AAD (§5.2). Frozen quirk — any tightening must be write-side only so
  existing records stay readable.
- `record_id=" r "` (whitespace-padded) is accepted verbatim; only
  whitespace-only strings are refused (frozen).
- Integer subclasses in coordinate ints are serialized via `int.__repr__`,
  not `str()` — the fast path exists specifically so a subclass cannot
  inject bytes into the AAD. Any new serialization path must keep that.
- Nonce dedup is in-process only (deque+set window): it does not survive
  restart and is not a freshness mechanism — `revision` bound into the AAD
  is. Flag anything that treats the window as stronger.

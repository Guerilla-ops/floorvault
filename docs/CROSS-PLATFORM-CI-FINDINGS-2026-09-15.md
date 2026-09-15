# Cross-platform CI findings (2026-09-15)

The first fully green run of the CI matrix — `macos-latest`, five Linux
interpreters, and `windows-latest` — completed at commit `815a4a0`.

Getting there took three iterations, and **every single failure was
Windows-only and invisible from macOS or Linux**. This document records what the
matrix found, because each defect passed a complete local suite and each would
have shipped.

## Result

```
run 34938062024 @ 815a4a0 — success
  ubuntu-latest / py3.10  py3.11  py3.12  py3.13  py3.14
  macos-latest  / py3.13
  windows-latest / py3.13    150 passed, 4 skipped
  secret scan (history)
```

On the Windows runner the security gate completed end to end: full suite, the
universal-wheel check, and the curated mutation set (20/20 mutants killed).

## Defect 1 — `os.open` without `O_BINARY` opens in TEXT mode

**Symptom.** Eight test failures on Windows, all length errors:

```
ProtectedStoreInvalidLength: protected store key has an unexpected length   (read)
ProtectedStoreInvalidLength: master key must be exactly 32 bytes            (write)
```

**Cause.** On Windows, `os.open` passes its flags to the C runtime, and a
descriptor opened without `O_BINARY` is in **text mode**. The runtime then
expands `\n` to `\r\n` on write and treats `0x1A` (Ctrl-Z) as end-of-file on
read. Key material is uniformly random bytes, so a 40-byte key store contains
one of those bytes often enough that the store is routinely mangled or
truncated. The custody layer fails closed, so this surfaced as a length error
rather than as silent corruption — which is the only reason it was diagnosable.

**Fix** (`5214a7f`). `platform_support.binary_mode_flag()` returns `O_BINARY`
where it exists and `0` on POSIX, and is applied at every raw-descriptor site:
the custody write, the custody read, and the adaptive machine-bound key file.
Other key-material access already used `pathlib.read_bytes`, which is binary.

## Defect 2 — a hard-coded payload size refused the OS-produced DPAPI blob

**Symptom.** Every DPAPI test failed with
`ProtectedStoreInvalidLength: master key must be exactly 32 bytes` — after
defect 1 was fixed, so this had been hidden behind it.

**Cause.** `WindowsDPAPIKeyProvider` stores `_protect(key)`. On **real Windows**
that is a `CryptProtectData` blob whose length is chosen by the **operating
system** (~100+ bytes). The protected store hard-coded a 32-byte payload. On
macOS the provider's cross-platform fallback masks the key to exactly 32 bytes,
so every local run agreed with the wrong assumption.

The Windows provider could not persist a master key at all: it refused its own
freshly produced blob.

**Fix** (`81cf0db`). `read_protected`/`write_protected` take `expected_length`,
defaulting to 32 so key-material stores keep the hard invariant. `None` permits
an opaque variable-length payload, used only by the Windows provider, which
still verifies that the **recovered** key is 32 bytes — the location where that
invariant actually belongs. A store larger than the read buffer is now refused
outright, which closes a silent-truncation hole that the opaque mode would
otherwise have opened.

## Defect 3 — a test skipped on Windows left a security check uncovered

**Symptom.** The suite passed on Windows while the gate failed at its mutation
step: `AD-1 survived — adaptive provider stops refusing group/other-accessible
files`. The mutant disables the check; nothing on that runner killed it.

**Cause.**

```python
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits are not implemented on Windows; ...",
)
```

The reason is true about the *platform* and wrong for the *test*. Skipping on
Windows meant no test on that runner exercised the permission gate at all, so
the suite was green while a security control had zero coverage there.

**Fix** (`815a4a0`). Patch the platform predicate
(`monkeypatch.setattr(platform_support, "IS_WINDOWS", False)`) so the real code
path runs on every runner, instead of skipping the test. On Windows the
synthesised `0o666` mode still carries group/other bits, so the gate fires
exactly as the test expects.

## What this changes about how we work

1. **A green local suite is not evidence about Windows.** All three defects
   passed complete macOS and Linux runs. Treat a green matrix as the only
   evidence, and say "unconfirmed" about that leg until a run says otherwise.
2. **Do not simulate a platform from memory.** A local simulation models what we
   *remember* about Windows, not what it does. Two consecutive predictions made
   that way were both wrong; the CI runs were right both times.
3. **Prefer patching predicates to `skipif(sys.platform == ...)`.** A skipped
   test is zero coverage on that runner, and regressions there go unnoticed. The
   mutation step — not the test suite — is what caught defect 3.
4. **Never hard-code the size of a value the OS produces.** Pin invariants you
   control; validate the rest after the fact.
5. **Fail closed earns its keep.** Defect 1 corrupted a key store, and because
   the custody layer refuses rather than guesses, it became a loud length error
   instead of a silent loss of the user's data.

## Reference

| defect | commit | guard now in place |
|---|---|---|
| text-mode descriptors | `5214a7f` | `binary_mode_flag()` + tests; curated mutant `PC-16` |
| DPAPI blob payload | `81cf0db` | `expected_length=None` for the Windows provider + tests; curated mutant `WD-2` |
| skipped permission-gate test | `815a4a0` | predicate patched, test runs everywhere; mutant `AD-1` |

Each defect is also pinned as a curated mutant, so `scripts/mutation_check.py
--mode curated` (gate step 11) fails if either of the first two regresses.

## After the first green run: the floor is now tested on every OS

The run above had macOS and Windows on 3.13 only — the newest interpreter — while
`pyproject.toml` declares support from **3.10**. Since every defect found so far
was platform-specific, testing only the newest version on those two operating
systems left the floor itself unexercised there.

The matrix now runs both ends of the range on every OS:

```
ubuntu-latest   3.10  3.11  3.12  3.13  3.14
macos-latest    3.10                3.13
windows-latest  3.10                3.13
```

`tests/test_ci_workflow.py` pins the invariant by reading the declared floor out
of `pyproject.toml` and requiring every operating system in the matrix to test
it, so a future edit cannot quietly drop the floor from a platform. Removing
those two cells fails that test with:

```
AssertionError: macos-latest does not test the declared floor 3.10: it tests ['3.13']
```

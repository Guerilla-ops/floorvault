#!/usr/bin/env python3
"""Mutation testing for FloorVault: curated safety mutants plus a full AST sweep.

Two modes:

  --mode curated   A small hand-picked set targeting the permission/custody
                   contract (fast; suitable for a pre-push gate).
  --mode auto      Systematically generates mutants across the whole package by
                   walking the AST with standard mutation operators, then runs
                   the test suite once per mutant. This is a real mutation
                   score rather than a spot check.

Design choices:
  * Deterministic and dependency-free - no mutation framework, so it runs in CI
    and in a project that advertises zero toolchain requirements.
  * Every mutant is applied to a throwaway copy of the repository, never the
    working tree, so an interrupted run cannot leave mutated source behind.
  * Mutants that do not compile are reported as INVALID and excluded from the
    score rather than counted as "killed".
  * Curated mode includes a deliberately equivalent docstring mutant that must
    SURVIVE; if everything were reported killed the harness would be measuring
    nothing.

Usage:
    python scripts/mutation_check.py                       # curated
    python scripts/mutation_check.py --shard 3/10          # one tenth of curated (CI)
    python scripts/mutation_check.py --mode auto --list     # count mutants
    python scripts/mutation_check.py --mode auto --jobs 8
    python scripts/mutation_check.py --mode auto --limit 200
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import os
import shutil
import subprocess  # runs pytest on mutated checkouts  # nosec B404
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATHS = ("src/floorvault",)

#: Platform flag for platform-conditional mutant expectations (see ``Mutation``).
IS_WINDOWS = os.name == "nt"


def _curated_tests() -> list[str]:
    """Discover all test modules so new security suites cannot be omitted."""
    tests_dir = REPO / "tests"
    return sorted(
        str(path.relative_to(REPO)) for path in tests_dir.glob("test_*.py") if path.is_file()
    )


# --------------------------------------------------------------------------
# Curated mutants (fast, contract-focused)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    find: str
    replace: str
    why: str
    expect: str = "killed"
    #: What this mutant must produce on Windows, when that differs.
    #:
    #: A mutant that targets a POSIX-only check is an *equivalent mutant* on
    #: Windows - the guard it removes is already dead there - so no test can
    #: kill it and demanding a kill makes the Windows legs fail for a reason
    #: unrelated to the code under test. Declaring the platform-specific
    #: expectation keeps the POSIX kill (which is the point of the mutant)
    #: instead of deleting the mutant to make Windows green.
    #:
    #: The reverse also exists: a guard that runs only on Windows is dead code
    #: elsewhere, so its mutant declares ``expect="survived"`` with
    #: ``expect_on_windows="killed"``.
    expect_on_windows: str | None = None


def expected_result(mutation: Mutation, *, on_windows: bool | None = None) -> str:
    """The result ``mutation`` must produce on the platform being tested."""
    if on_windows is None:
        on_windows = IS_WINDOWS
    if on_windows and mutation.expect_on_windows is not None:
        return mutation.expect_on_windows
    return mutation.expect


def anchor_status(matches: int) -> str | None:
    """Label for a mutant anchor's match count, or ``None`` when exactly one line matched.

    A curated anchor must identify exactly ONE line. ``str.replace(..., 1)`` mutates
    the first match, so an anchor that also matches elsewhere silently becomes a
    mutant of a different check than the one it describes - PC-17's did (the reader's
    ``except OSError`` branch carried the same two lines as its main path), and the
    only symptom was a Windows CI leg reporting a kill the declaration said could not
    happen. Neither case is a pass: 0 means the anchor moved, >1 means it is ambiguous.
    """
    if matches == 1:
        return None
    return "PATTERN?" if matches == 0 else "AMBIGUOUS"


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "PC-1",
        "src/floorvault/platform_support.py",
        "    if is_windows():\n        return False",
        "    if False:  # MUTANT\n        return False",
        "Windows exemption disabled: a synthesised 0o666 treated as insecure",
    ),
    Mutation(
        "PC-2",
        "src/floorvault/platform_support.py",
        "    return bool(mode & 0o077)",
        "    return False  # MUTANT",
        "POSIX group/other gate disabled entirely",
    ),
    Mutation(
        "PC-3",
        "src/floorvault/platform_support.py",
        "    return bool(mode & 0o077)",
        "    return mode != 0o600  # MUTANT",
        "Exact-equality bug: any non-0600 owner-only mode refused",
    ),
    Mutation(
        "PC-4",
        "src/floorvault/providers/platform_custody.py",
        'raise ProtectedStoreMissing("protected store not present") from exc',
        'raise ProtectedStoreError("protected store not present") from exc',
        "Loses the absent/unreadable distinction",
    ),
    Mutation(
        "PC-5",
        "src/floorvault/providers/windows_dpapi.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Reintroduces the data-loss bug: corrupt store treated as absent",
    ),
    Mutation(
        "PC-6",
        "src/floorvault/providers/linux_keyring.py",
        "        except ProtectedStoreMissing:",
        "        except ProtectedStoreError:  # MUTANT",
        "Same regression on the Linux provider",
    ),
    Mutation(
        "PC-7",
        "src/floorvault/providers/platform_custody.py",
        "        os.link(temporary, path)",
        "        os.replace(temporary, path)  # MUTANT",
        "Atomic no-clobber replaced by os.replace, which always clobbers",
    ),
    Mutation(
        "PC-8",
        "src/floorvault/providers/adaptive.py",
        "                # custody. This clause is why they are no longer dead code.\n                raise",
        "                # custody. This clause is why they are no longer dead code.\n                return None  # MUTANT",
        "Reinstates swallowing a deliberate provider error (silent custody downgrade)",
    ),
    Mutation(
        "AD-2",
        "src/floorvault/providers/adaptive.py",
        "        if is_windows():\n            return WindowsDPAPIKeyProvider(",
        "        if False:  # MUTANT\n            return WindowsDPAPIKeyProvider(",
        "Adaptive provider stops dispatching Windows native custody",
    ),
    Mutation(
        "AD-3",
        "src/floorvault/providers/adaptive.py",
        "        if is_linux():\n            provider = self._linux_provider()",
        "        if False:  # MUTANT\n            provider = self._linux_provider()",
        "Adaptive provider stops dispatching Linux Secret Service custody",
    ),
    Mutation(
        "AD-1",
        "src/floorvault/providers/adaptive.py",
        '            return read_protected(key_file, header=b"", expected_length=None)\n'
        "        except ProtectedStoreMissing:\n"
        "            return None",
        "            if not key_file.exists():  # MUTANT\n"
        "                return None\n"
        "            return key_file.read_bytes()\n"
        "        except ProtectedStoreMissing:\n"
        "            return None",
        "Adaptive provider stops refusing group/other-accessible (or unverifiable) files",
    ),
    Mutation(
        "WACL-1",
        "src/floorvault/platform_support.py",
        '        except OSError as exc:\n            return (\n                f"key store permissions could not be determined for {path} "',
        '        except OSError as exc:\n            return None  # MUTANT\n            return (\n                f"key store permissions could not be determined for {path} "',
        "Windows ACL query failure fails OPEN: an unverifiable store is trusted",
    ),
    Mutation(
        "WACL-2",
        "src/floorvault/platform_support.py",
        "        offenders = acl_sids_granting_others_access(sids, owner_sid=owner_sid)\n        if offenders:",
        "        offenders = acl_sids_granting_others_access(sids, owner_sid=owner_sid)\n        if False:  # MUTANT",
        "A world-accessible key store ACL is no longer refused on Windows",
    ),
    Mutation(
        "WACL-3",
        "src/floorvault/platform_support.py",
        "    if has_posix_group_or_other_access(mode):",
        "    if False:  # MUTANT",
        "POSIX branch of the store-permission gate disabled",
    ),
    Mutation(
        "MIG-1",
        "src/floorvault/migration.py",
        "            if modern_id is not None:\n                raise LegacyRetiredError(",
        "            if False:  # MUTANT\n                raise LegacyRetiredError(",
        "Retired-fallback refusal disabled: a deleted modern row resurrects the legacy value",
    ),
    Mutation(
        "MIG-2",
        "src/floorvault/migration.py",
        "            self.modern.retire_legacy_id(item_id, meta.id)",
        "            pass  # MUTANT",
        "Migration stops recording the retirement tombstone at all",
    ),
    Mutation(
        "MIG-3",
        "src/floorvault/vaultkit/vault.py",
        "                self._crypto.decrypt(\n"
        "                    cipher,\n"
        "                    table=self._TOMBSTONE_TABLE,\n"
        "                    record_id=legacy_id,\n"
        '                    column="tombstone",',
        "                self._crypto.decrypt(\n"
        "                    cipher,\n"
        "                    table=self._TOMBSTONE_TABLE,\n"
        '                    record_id="unbound",\n'
        '                    column="tombstone",',
        "Tombstone read loses its AAD coordinate binding, so a swapped record is not detected "
        "(the anchor names the read path's own decrypt call: the rotation path carries the "
        "same argument block and would otherwise be mutated instead)",
    ),
    Mutation(
        "MIG-4",
        "src/floorvault/vaultkit/vault.py",
        '        except FloorVaultError as exc:\n            raise VaultError(\n                f"legacy retirement record failed authentication for {legacy_id!r}; "',
        '        except FloorVaultError as exc:\n            return {"legacy_id": legacy_id, "modern_id": ""}  # MUTANT\n            raise VaultError(\n                f"legacy retirement record failed authentication for {legacy_id!r}; "',
        "A tampered tombstone read as 'present but unmapped' instead of failing closed",
        expect="killed",
    ),
    Mutation(
        "MIG-5",
        "src/floorvault/migration.py",
        "            if retired_modern_id is not None:\n                if self.modern.get_meta(retired_modern_id) is None:",
        "            if False:  # MUTANT\n                if self.modern.get_meta(retired_modern_id) is None:",
        "Migration loses its persisted idempotency guard and duplicates legacy records",
    ),
    Mutation(
        "MIG-6",
        "src/floorvault/migration.py",
        '            "item_id": self._stable_modern_id(item_id),',
        '            "item_id": None,  # MUTANT',
        "Interrupted migration retries lose the stable modern identity",
    ),
    Mutation(
        "KR-1",
        "src/floorvault/keyring.py",
        "        except KeyError:\n            raise UnknownKeyIdError(",
        "        except KeyError:\n            return next(iter(self._keys.values()))  # MUTANT\n            raise UnknownKeyIdError(",
        "Ring silently falls back to an arbitrary held key instead of refusing an unknown id",
    ),
    Mutation(
        "KR-2",
        "src/floorvault/keyring.py",
        "            if self._default_key_id is None:\n                raise UnknownKeyIdError(",
        "            if False:  # MUTANT\n                raise UnknownKeyIdError(",
        "Ring guesses a key for a v1 record instead of demanding a declared default",
    ),
    Mutation(
        "KR-3",
        "src/floorvault/keyring.py",
        "            if default_key_id not in checked:",
        "            if False:  # MUTANT",
        "Ring accepts a default_key_id it does not hold, deferring the failure to read time",
    ),
    Mutation(
        "ROT-2",
        "src/floorvault/vaultkit/vault.py",
        "            if cursor.rowcount != 1:\n"
        '                raise VaultError(f"Vault item not found during rotation: {item_id}")\n'
        "            self._write_journal_rows(conn, journal_rows, target_key_id=key_id)",
        "            if cursor.rowcount != 1:\n"
        '                raise VaultError(f"Vault item not found during rotation: {item_id}")\n'
        "            pass  # MUTANT: journal not written with the data",
        "Journal row not written in the write's transaction: an interrupted rotation resumes blind "
        "(the anchor includes the row-count guard so it lands on the item write, not the "
        "tombstone write that shares the same journal call)",
    ),
    Mutation(
        "ROT-3",
        "src/floorvault/vaultkit/vault.py",
        '                payload["modern_id"],\n                vault=new_vault,',
        '                payload["modern_id"],\n                vault=self._crypto,  # MUTANT',
        "Retirement tombstones left under the old key, so F-1 protection stops authenticating",
    ),
    Mutation(
        "ROT-4",
        "src/floorvault/vaultkit/vault.py",
        "            if cursor.rowcount != 1:\n                raise VaultError(",
        "            if False:  # MUTANT\n                raise VaultError(",
        "Rotation journal records missing items as completed",
    ),
    # --- Deep-dive security regression scan (2026-09-18) ----------------------
    Mutation(
        "DS-1",
        "src/floorvault/vaultkit/vault.py",
        '            self._assert_writes_allowed(conn)\n            conn.execute(\n                """\n                INSERT INTO vault_items (',
        '            pass  # MUTANT: writer barrier disabled\n            conn.execute(\n                """\n                INSERT INTO vault_items (',
        "Rotation barrier removed: a late old-key writer is accepted",
    ),
    Mutation(
        "DS-2",
        "src/floorvault/core.py",
        # The \n pins the anchor to line start: the same schema_version check
        # also exists inside _validate_aad_mid at method indent, and a
        # substring anchor would match inside that deeper-indented line.
        "\n    if isinstance(schema_version, bool) or not isinstance(schema_version, int):",
        "\n    if False:  # MUTANT: schema version validation disabled",
        "Non-integer schema versions collapse into integer AAD contexts",
    ),
    Mutation(
        "DS-3",
        "src/floorvault/migration.py",
        "            if (\n                existing.kind != kind",
        "            if False and (  # MUTANT: collision equivalence check disabled\n                existing.kind != kind",
        "Migration retires a legacy id onto unrelated pre-existing data",
    ),
    Mutation(
        "DS-4",
        "src/floorvault/memory.py",
        '        if mode not in {"disabled", "opportunistic", "required"}:',
        "        if False:  # MUTANT: invalid modes accepted",
        "Invalid memory mode silently downgrades from required enforcement",
    ),
    Mutation(
        "DS-5",
        "src/floorvault/providers/platform_custody.py",
        "    os.chmod(directory, 0o700)",
        "    pass  # MUTANT: existing directory is not hardened",
        "Existing permissive vault base bypasses owner-only policy (POSIX-only: "
        "on Windows os.chmod cannot set owner-only modes - ACLs govern access "
        "and WD-* mutants cover that gate - so no test can kill this mutant)",
        expect_on_windows="survived",
    ),
    Mutation(
        "CANARY",
        "src/floorvault/platform_support.py",
        '"""Whether POSIX permission bits grant group or other access.',
        '"""Whether POSIX permission bits grant group or other access. (mutated)',
        "Equivalent docstring mutant: must survive (harness validity check)",
        expect="survived",
    ),
    Mutation(
        "PC-9",
        "src/floorvault/providers/platform_custody.py",
        "    for item in reversed(missing):\n        item.mkdir(mode=0o700, exist_ok=False)",
        "    for item in reversed(missing):\n        item.mkdir(mode=0o777, exist_ok=False)",
        "Ancestor custody directory created world-searchable (0o777)",
    ),
    Mutation(
        "PC-10",
        "src/floorvault/providers/platform_custody.py",
        "    _mkdir_owner_only(path.parent)",
        "    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)",
        "Ancestors revert to Path.mkdir(parents=True) default of 0o777",
    ),
    Mutation(
        "PC-11",
        "src/floorvault/providers/platform_custody.py",
        '    temporary = path.parent / f".{path.name}.{os.urandom(6).hex()}.tmp"',
        '    temporary = Path(os.environ.get("TMPDIR", "/tmp")) / f".{path.name}.{os.urandom(6).hex()}.tmp"',
        "Temp file moved to TMPDIR: cross-device publish (EXDEV) breaks atomicity",
    ),
    Mutation(
        "PC-12",
        "src/floorvault/providers/platform_custody.py",
        '        raise ProtectedStoreInvalidLength("protected store key has an unexpected length")',
        '        raise ProtectedStoreError("protected store key has an unexpected length")',
        "Length failure loses its distinct type and can be masked by another check",
    ),
    Mutation(
        "WD-1",
        "src/floorvault/providers/windows_dpapi.py",
        "        self._assert_store_location_is_private()",
        "        pass  # MUTANT",
        "Windows store-location policy silently disabled (no ACL verification)",
    ),
    Mutation(
        "CR-1",
        "src/floorvault/core.py",
        "encrypt(data_bytes, [aad, header, nonce])",
        "encrypt(data_bytes, [aad, header])  # MUTANT",
        "Static AD vector: SIV becomes deterministic and leaks plaintext equality",
    ),
    Mutation(
        "CR-3",
        "src/floorvault/core.py",
        "encrypt(data_bytes, [aad, header, nonce])",
        "encrypt(data_bytes, [aad, nonce])  # MUTANT",
        "Cleartext header stops being authenticated: a rewritten key id is accepted",
    ),
    Mutation(
        "CR-4",
        "src/floorvault/core.py",
        "        return [aad, header, nonce] if header is not None else [aad, nonce]",
        "        return [aad, header, nonce]  # MUTANT",
        "v1 records read with the v2 AD vector: the compatibility path breaks",
    ),
    Mutation(
        "CR-5",
        "src/floorvault/core.py",
        "        if crypto_version != CRYPTO_VERSION:",
        "        if False:  # MUTANT",
        "Version check removed - refusal moves to the header AD binding, but "
        "the wire vectors pin the documented rejection stage (§4.3 rule 4), "
        "so the stage regression is now detectable",
        expect="killed",
    ),
    Mutation(
        "CR-6",
        "src/floorvault/core.py",
        "out[column] = header + nonce + aead.encrypt(data, [aad, header, nonce])",
        "out[column] = header + nonce + aead.encrypt(data, [aad, header])  # MUTANT",
        "Batch path: static AD vector makes SIV deterministic and leaks plaintext equality",
    ),
    Mutation(
        "CR-7",
        "src/floorvault/core.py",
        "out[column] = header + nonce + aead.encrypt(data, [aad, header, nonce])",
        "out[column] = header + nonce + aead.encrypt(data, [aad, nonce])  # MUTANT",
        "Batch path: cleartext header stops being authenticated",
    ),
    Mutation(
        "PC-13",
        "src/floorvault/providers/platform_custody.py",
        '        raise ProtectedStoreHeaderError("protected store has an unknown or missing header")',
        "        pass  # MUTANT",
        "Header raise deleted; the length check below would mask it for a base-class assertion",
    ),
    Mutation(
        "PC-14",
        "src/floorvault/providers/platform_custody.py",
        "    except OSError as exc:\n"
        "        raise ProtectedStoreError(\n"
        '            f"atomic no-clobber publication is unavailable on the filesystem "\n'
        '            f"holding {path} ({exc}); the store must live on a filesystem that "\n'
        '            "supports hard links - refusing a non-atomic replace that could "\n'
        '            "silently overwrite a concurrent writer\'s key"\n'
        "        ) from exc",
        "    except OSError:\n"
        "        if path.exists():\n"
        '            raise ProtectedStoreError("refusing to overwrite")  # MUTANT\n'
        "        os.replace(temporary, path)  # MUTANT",
        "Non-atomic check-then-replace publication fallback reintroduced: the "
        "no-hard-links tests must kill it",
    ),
    Mutation(
        "PC-15",
        "src/floorvault/providers/platform_custody.py",
        "    for item in reversed(missing):\n        item.mkdir(mode=0o700, exist_ok=False)",
        "    for item in reversed(missing):\n        item.mkdir(mode=0o700, exist_ok=True)",
        "Directory creation loses tolerance for a directory created by another writer; "
        "the new lstat-before-mkdir contract makes this an availability-only mutant "
        "with no covered security distinction",
        expect="survived",
    ),
    Mutation(
        "PC-16",
        "src/floorvault/providers/platform_custody.py",
        "        os.O_RDONLY\n        | binary_mode_flag()",
        "        os.O_RDONLY",
        "Store read loses binary mode: Windows text mode truncates at 0x1A (found by CI)",
    ),
    Mutation(
        "PC-17",
        "src/floorvault/providers/platform_custody.py",
        "        if not stat.S_ISREG(path_stat.st_mode):\n"
        '            raise ProtectedStoreError("protected store is not a regular file")\n'
        "        if (path_stat.st_dev, path_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino):",
        "        if False:  # MUTANT\n"
        '            raise ProtectedStoreError("protected store is not a regular file")\n'
        "        if (path_stat.st_dev, path_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino):",
        "Protected-store reader accepts a non-regular object at the store path "
        "(the anchor includes the identity check that follows it, because the same "
        "two-line check also appears in the OSError/lstat branch and an ambiguous "
        "anchor mutates that one instead)",
    ),
    Mutation(
        "PC-18",
        "src/floorvault/providers/platform_custody.py",
        '        if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():\n            raise ProtectedStoreError(',
        "        if False:  # MUTANT\n            raise ProtectedStoreError(",
        "Protected-store reader accepts a key file owned by another POSIX user "
        "(POSIX-only: os.getuid does not exist on Windows, so the guard is "
        "already dead there - equivalent mutant)",
        expect_on_windows="survived",
    ),
    Mutation(
        "PC-19",
        "src/floorvault/providers/platform_custody.py",
        "            raise ProtectedStoreRaceError(\n"
        '                "protected store changed identity between the path check and the open"',
        "            raise ProtectedStoreError(  # MUTANT\n"
        '                "protected store changed identity between the path check and the open"',
        "A legitimate atomic-replace race is reported as corruption instead of "
        "the retryable race subclass - the generation store can no longer "
        "distinguish pointer replacement from damage",
    ),
    Mutation(
        "WD-2",
        "src/floorvault/providers/windows_dpapi.py",
        "                expected_length=None,\n"
        "                legacy_path=self._legacy_store_path(),",
        "                legacy_path=self._legacy_store_path(),",
        "Windows store reverts to assuming a 32-byte payload and refuses its own DPAPI blob",
    ),
    Mutation(
        "CR-2",
        "src/floorvault/core.py",
        'payload["revision"] = revision',
        "pass  # MUTANT",
        "Revision dropped from the AAD: same-coordinate replay becomes undetectable",
    ),
    # --- Linux Secret Service client (F1, 2026-09-17) ------------------------
    # The shipped defect was a client whose API names did not exist in the real
    # secretstorage package; the ImportError was swallowed and the tier reported
    # "unavailable" forever, so custody silently dropped to a key file while the
    # docs promised native Secret Service custody.
    Mutation(
        "SS-1",
        "src/floorvault/providers/linux_keyring.py",
        "        gap = _secretstorage_api_gap(secretstorage, secretstorage_exceptions)\n"
        "        if gap is not None:\n",
        "        gap = _secretstorage_api_gap(secretstorage, secretstorage_exceptions)\n"
        "        if gap is not None:\n"
        "            return None  # MUTANT\n",
        "A library this build cannot talk to reports as 'unavailable' again, so a "
        "broken tier silently downgrades to file custody (the shipped defect)",
    ),
    Mutation(
        "SS-2",
        "src/floorvault/providers/linux_keyring.py",
        "                if collection.is_locked():\n"
        "                    raise CustodyDowngradeError(",
        "                if False:  # MUTANT\n                    raise CustodyDowngradeError(",
        "Locked collection proceeds anyway (unlock() returns True when the prompt "
        "was DISMISSED), so a failed unlock walks on instead of failing closed",
    ),
    Mutation(
        "SS-3",
        "src/floorvault/providers/linux_keyring.py",
        "            if all(candidate.get_attributes().get(key) == value for key, value "
        "in query.items())\n",
        "            if True  # MUTANT\n",
        "Entry matching stops checking attributes, so any service's item is "
        "accepted as the master key",
    ),
    # --- Custody store paths (F2, 2026-09-17) --------------------------------
    # Three mutually unreadable formats shared ``master.key``, so whichever tier
    # ran first locked the others out of the user's data.
    Mutation(
        "KP-1",
        "src/floorvault/providers/platform_custody.py",
        '    return base / f"{LEGACY_STORE_NAME}.{scheme}"',
        "    return base / LEGACY_STORE_NAME  # MUTANT",
        "Schemes share one key-store path again, so one format's file blocks another",
    ),
    Mutation(
        "KP-2",
        "src/floorvault/providers/platform_custody.py",
        "    except (ProtectedStoreMissing, ProtectedStoreHeaderError):\n"
        "        # Absent, or another scheme's file: neither is this scheme's store.",
        "    except ProtectedStoreMissing:  # MUTANT\n"
        "        # Absent, or another scheme's file: neither is this scheme's store.",
        "A foreign scheme's file at the legacy path is no longer ignored, so a "
        "legitimate create is blocked by another tier's store",
    ),
    Mutation(
        "KP-3",
        "src/floorvault/providers/platform_custody.py",
        "    if legacy_path is None or legacy_path == path:\n"
        '        raise ProtectedStoreMissing("protected store not present")',
        "    if True:  # MUTANT\n"
        '        raise ProtectedStoreMissing("protected store not present")',
        "Pre-split stores stop being adopted, so the split strands existing data "
        "behind a freshly minted key",
    ),
    Mutation(
        "IQ-1",
        "src/floorvault/sqlite_adapter.py",
        '    return ".".join(f"[{part}]" for part in _safe_identifier(name).split("."))',
        "    return _safe_identifier(name)  # MUTANT",
        "SQL boundary loses bracket quoting: allow-listed names like TRUE or "
        "CURRENT_TIMESTAMP resolve as expressions instead of columns again",
    ),
    Mutation(
        "ROT-5",
        "src/floorvault/vaultkit/vault.py",
        "                self._verify_rotation_target(conn, row[2], target_vault, target_key_id)",
        "                pass  # MUTANT: resume binds to the 1-byte key id again",
        "Resume stops authenticating the committed target master: the same key id "
        "under a different master re-seals the remaining records onto the wrong key",
    ),
    Mutation(
        "REC-1",
        "src/floorvault/key_recovery.py",
        "    if hmac.compare_digest(master, recovery):",
        "    if False:  # MUTANT: self-wrapped bundle accepted",
        "Self-wrap guard disabled: the recovery key can be the master key itself",
    ),
    Mutation(
        "DUR-1",
        "src/floorvault/providers/platform_custody.py",
        "        _link_no_clobber(temporary, path)\n        _fsync_directory(path.parent)",
        "        _link_no_clobber(temporary, path)\n        pass",
        "Published key-store name loses its directory durability barrier",
        expect_on_windows="survived",
    ),
    Mutation(
        "DUR-2",
        "src/floorvault/providers/platform_custody.py",
        "        _fsync_directory(item.parent)",
        "        pass",
        "Newly created custody directory loses its parent durability barrier",
        expect_on_windows="survived",
    ),
    Mutation(
        "DUR-3",
        "src/floorvault/providers/platform_custody.py",
        "    try:\n        os.fsync(descriptor)\n    finally:\n        os.close(descriptor)",
        "    try:\n        pass\n    finally:\n        os.close(descriptor)",
        "Directory durability helper opens and closes without flushing metadata",
        expect_on_windows="survived",
    ),
    Mutation(
        "DUR-4",
        "src/floorvault/providers/platform_custody.py",
        "        else:\n            _fsync_directory(path.parent)",
        "        else:\n            pass",
        "Temporary key-store alias cleanup loses its directory durability barrier",
        expect_on_windows="survived",
    ),
    Mutation(
        "BC-1",
        "src/floorvault/beacons.py",
        "    if isinstance(key, HardenedMemoryKey):\n        return key.get_buffer()",
        "    if isinstance(key, HardenedMemoryKey):\n        return key.get_bytes()",
        "Hardened beacon key is flattened into an immutable heap copy",
    ),
    Mutation(
        "BC-2",
        "src/floorvault/beacons.py",
        "    if owner is not None and owner.is_wiped:",
        "    if False:",
        "Beacon snapshot accepts a key whose owner began wiping during the copy",
    ),
    Mutation(
        "BC-3",
        "src/floorvault/beacons.py",
        "        for index in range(len(source)):\n            source[index] = 0",
        "        pass",
        "Beacon derivation leaves its mutable master snapshot unwiped on failure",
    ),
    Mutation(
        "ROT-6",
        "src/floorvault/vaultkit/vault.py",
        "        if stored is None:",
        "        if False:",
        "Legacy active rotation without a commitment loses its explicit fail-closed refusal",
    ),
    Mutation(
        "ROT-7",
        "src/floorvault/vaultkit/vault.py",
        '            column=f"meta:{column}",\n            key_id=self._write_key_id,\n',
        '            column=f"meta:{column}",\n',
        "Metadata written after a rotation is labelled key id 0 again (#103)",
    ),
    Mutation(
        "ROT-8",
        "src/floorvault/vaultkit/vault.py",
        '            column="payload",\n            key_id=self._write_key_id,\n',
        '            column="payload",\n',
        "A new item's payload after a rotation is labelled key id 0 again (#103)",
    ),
    Mutation(
        "ROT-9",
        "src/floorvault/vaultkit/vault.py",
        "        if generation != self._write_key_id:\n",
        "        if False:  # MUTANT\n",
        "A VaultStore opened before a rotation writes old-key records under the new label (#103)",
    ),
    Mutation(
        "ROT-10",
        "src/floorvault/vaultkit/vault.py",
        "        if not self._key_verified:\n            self._verify_key(conn)\n",
        "        if False:  # MUTANT\n            self._verify_key(conn)\n",
        "A VaultStore opened with the old key after a rotation writes under it (#109)",
    ),
    Mutation(
        "VS-1",
        "src/floorvault/vaultkit/vault.py",
        "            if user_version > self._SCHEMA_VERSION:",
        "            if False:",
        "An unsupported future vault schema is opened and downgraded instead of refused",
    ),
    Mutation(
        "VS-2",
        "src/floorvault/vaultkit/vault.py",
        '            conn.execute(f"PRAGMA user_version = {self._SCHEMA_VERSION}")',
        '            conn.execute("PRAGMA user_version = 2")',
        "The target-commitment schema loses its distinct version marker",
    ),
    # --- Wrapped-master generation store (R1, roadmap issue #11) -------------
    Mutation(
        "GS-1",
        "src/floorvault/providers/generation_store.py",
        "            if current != expected_generation:",
        "            if False:  # MUTANT",
        "Expected-generation CAS removed: a writer acting on a stale read "
        "repoints 'active' over someone else's update",
    ),
    Mutation(
        "GS-2",
        "src/floorvault/providers/generation_store.py",
        "        if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):",
        "        if False:  # MUTANT",
        "Pointer stops binding to generation content: a swapped payload is trusted",
    ),
    Mutation(
        "GS-3",
        "src/floorvault/providers/generation_store.py",
        "            descriptor = os.open(\n"
        "                self._lock_path,\n"
        "                os.O_WRONLY\n"
        "                | os.O_CREAT\n"
        "                | os.O_EXCL",
        "            descriptor = os.open(\n"
        "                self._lock_path,\n"
        "                os.O_WRONLY\n"
        "                | os.O_CREAT  # MUTANT",
        "Writer lock loses O_EXCL: concurrent writers both believe they hold it",
    ),
    Mutation(
        "GS-4",
        "src/floorvault/providers/generation_store.py",
        "            raise ProtectedStoreError(\n"
        '                f"pointer references generation {generation} but its file is missing"',
        "            raise ProtectedStoreMissing(  # MUTANT\n"
        '                f"pointer references generation {generation} but its file is missing"',
        "A dangling pointer reports 'no store', so a caller may provision over corruption",
    ),
    Mutation(
        "GS-5",
        "src/floorvault/providers/generation_store.py",
        "            elif orphan != payload:\n"
        "                raise ProtectedStoreError(\n"
        '                    "an unpublished generation 1 exists with different content; "',
        "            elif False:  # MUTANT\n"
        "                raise ProtectedStoreError(\n"
        '                    "an unpublished generation 1 exists with different content; "',
        "Provision adopts an orphan generation whose content differs from the request",
    ),
    Mutation(
        "GS-6",
        "src/floorvault/providers/generation_store.py",
        "            elif orphan != payload:\n"
        "                raise ProtectedStoreError(\n"
        '                    f"an unpublished generation {target} exists with different "',
        "            elif False:  # MUTANT\n"
        "                raise ProtectedStoreError(\n"
        '                    f"an unpublished generation {target} exists with different "',
        "Update adopts an orphan generation whose content differs from the request",
    ),
    Mutation(
        "GS-7",
        "src/floorvault/providers/generation_store.py",
        "            except ProtectedStoreRaceError as exc:",
        "            except ProtectedStoreInvalidLength as exc:  # MUTANT",
        "Pointer reads stop retrying the legitimate atomic-replace race: a "
        "concurrent writer's repoint is reported as corruption",
    ),
    Mutation(
        "GS-8",
        "src/floorvault/providers/generation_store.py",
        "        if len(payload) > MAX_PAYLOAD_BYTES:\n"
        "            raise ProtectedStoreInvalidLength(\n"
        '                f"generation payload is {len(payload)} bytes; the reader caps "\n'
        '                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "\n'
        '                "publish state nothing can read back"\n'
        "            )\n"
        "        with self.writer_lock():",
        "        if False:  # MUTANT\n"
        "            raise ProtectedStoreInvalidLength(\n"
        '                f"generation payload is {len(payload)} bytes; the reader caps "\n'
        '                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "\n'
        '                "publish state nothing can read back"\n'
        "            )\n"
        "        with self.writer_lock():",
        "Provision accepts a payload larger than the reader's cap - published "
        "state that can never be read back",
    ),
    Mutation(
        "GS-9",
        "src/floorvault/providers/generation_store.py",
        "        if len(payload) > MAX_PAYLOAD_BYTES:\n"
        "            raise ProtectedStoreInvalidLength(\n"
        '                f"generation payload is {len(payload)} bytes; the reader caps "\n'
        '                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "\n'
        '                "publish state nothing can read back"\n'
        "            )\n"
        "        if expected_generation < 1:",
        "        if False:  # MUTANT\n"
        "            raise ProtectedStoreInvalidLength(\n"
        '                f"generation payload is {len(payload)} bytes; the reader caps "\n'
        '                f"stores at {MAX_PAYLOAD_BYTES} bytes of payload, so this would "\n'
        '                "publish state nothing can read back"\n'
        "            )\n"
        "        if expected_generation < 1:",
        "Update accepts a payload larger than the reader's cap - published "
        "state that can never be read back",
    ),
    Mutation(
        "GS-10",
        "src/floorvault/providers/generation_store.py",
        "            os.close(descriptor)\n"
        "            try:\n"
        "                os.unlink(self._lock_path)\n"
        "            except FileNotFoundError:\n"
        "                pass\n"
        "            else:\n"
        "                _fsync_directory(self.directory)\n"
        "            raise",
        "            os.close(descriptor)\n"
        "            try:\n"
        "                pass  # MUTANT - the lockfile strands\n"
        "            except FileNotFoundError:\n"
        "                pass\n"
        "            else:\n"
        "                _fsync_directory(self.directory)\n"
        "            raise",
        "Failed lock-metadata writes strand the lockfile: every later writer "
        "is denied until an operator intervenes",
    ),
    # --- Vault Transit provider (R2/R4, roadmap issue #11) -------------------
    Mutation(
        "VT-1",
        "src/floorvault/providers/vault_transit.py",
        "                elif 400 <= code < 500:",
        "                elif False:  # MUTANT",
        "4xx policy answers retried like transient faults instead of refusing",
    ),
    Mutation(
        "VT-2",
        "src/floorvault/providers/vault_transit.py",
        '                    "purpose": PURPOSE,',
        '                    "purpose": "generic-blob-wrap",  # MUTANT',
        "Transit context loses its fixed purpose binding",
    ),
    Mutation(
        "VT-3",
        "src/floorvault/providers/vault_transit.py",
        "        if time.monotonic() - self._cached_at > self._cache_ttl:",
        "        if False:  # MUTANT",
        "Master-key cache never expires: the TTL bound is removed",
    ),
    Mutation(
        "VT-4",
        "src/floorvault/providers/vault_transit.py",
        "        if len(plaintext) != 32:\n"
        "            raise CustodyDowngradeError(\n"
        '                f"Vault decrypt returned',
        "        if False:  # MUTANT\n"
        "            raise CustodyDowngradeError(\n"
        '                f"Vault decrypt returned',
        "Decrypt path accepts a non-32-byte master key",
    ),
    Mutation(
        "VT-5",
        "src/floorvault/providers/vault_transit.py",
        "    if not _BLOB_PATTERN.fullmatch(raw):",
        "    if False:  # MUTANT",
        "Wrapped-blob validation accepts blobs Vault did not version: rewrap "
        "and provision publish state nothing can decrypt",
    ),
    Mutation(
        "VT-6",
        "src/floorvault/providers/vault_transit.py",
        "        if len(plaintext) != 32:\n"
        "            raise CustodyDowngradeError(\n"
        '                f"Vault datakey returned',
        "        if False:  # MUTANT\n"
        "            raise CustodyDowngradeError(\n"
        '                f"Vault datakey returned',
        "Datakey path accepts a non-32-byte master key",
    ),
    Mutation(
        "VT-7",
        "src/floorvault/providers/vault_transit.py",
        "                        and target.hostname in self._allowed_redirect_hosts",
        "                        and True  # MUTANT",
        "Redirect vetting stops checking the standby-host allowlist",
    ),
    Mutation(
        "VT-8",
        "src/floorvault/providers/vault_transit.py",
        '                        and target.scheme == "https"',
        '                        and target.scheme in ("https", "http")  # MUTANT',
        "Redirect vetting accepts a plaintext downgrade target",
    ),
    Mutation(
        "VT-9",
        "src/floorvault/providers/vault_transit.py",
        "                ensure_ascii=False,",
        "                ensure_ascii=True,  # MUTANT",
        "Context serialization escapes non-ASCII app ids, diverging from the "
        "canonical UTF-8 format other implementers produce",
    ),
    Mutation(
        "VT-10",
        "src/floorvault/providers/vault_transit.py",
        '        blob = _require_wrapped_blob(data.get("ciphertext"))',
        '        blob = str(data.get("ciphertext")).encode("utf-8")  # MUTANT',
        "Provisioning publishes a datakey ciphertext without validating its "
        "vault:vN:<base64> shape",
    ),
    Mutation(
        "VT-11",
        "src/floorvault/providers/vault_transit.py",
        '    try:\n        encoded = text.encode("ascii")\n    except UnicodeEncodeError:\n        encoded = None',
        '    try:\n        encoded = text.encode("ascii")\n    except UnicodeEncodeError as exc:  # MUTANT\n        raise ValueError("field is not ASCII") from exc',
        "Non-ASCII field sanitization keeps a chain object whose .object "
        "holds the server-supplied string (token echo)",
    ),
    Mutation(
        "VT-12",
        "src/floorvault/providers/vault_transit.py",
        '    try:\n        raw = value.encode("ascii")\n    except UnicodeEncodeError:\n        raw = None',
        '    try:\n        raw = value.encode("ascii")\n    except UnicodeEncodeError as exc:  # MUTANT\n        raise CustodyDowngradeError("Vault wrapped blob is not ASCII") from exc',
        "Wrapped-blob ASCII failure keeps a chain object whose .object holds "
        "the server-supplied string (token echo)",
    ),
    Mutation(
        "VT-13",
        "src/floorvault/providers/vault_transit.py",
        "            decode_error: str | None = None\n"
        "            try:\n"
        "                decoded = json.loads(raw)\n"
        "            except (ValueError, UnicodeDecodeError) as exc:\n"
        "                decode_error = type(exc).__name__",
        "            try:\n"
        "                decoded = json.loads(raw)\n"
        "            except (ValueError, UnicodeDecodeError) as exc:  # MUTANT\n"
        "                raise CustodyDowngradeError(\n"
        '                    f"Vault response is not valid JSON ({type(exc).__name__})"\n'
        "                ) from exc",
        "Invalid-JSON failure chains a decode error whose .object/.doc holds "
        "server-controlled response bytes (token echo)",
    ),
    # --- SQLAlchemy adapter guards (Phase 2, roadmap issue #11) --------------
    Mutation(
        "SA-1",
        "src/floorvault/sqlalchemy_adapter.py",
        "        try:\n"
        '            return require_envelope(value, where=f"{model.__name__}.{column_key}")',
        "        try:\n            return value  # MUTANT",
        "Set-time validator admits plaintext staged onto a ciphertext column",
    ),
    Mutation(
        "SA-2",
        "src/floorvault/sqlalchemy_adapter.py",
        "        if not (state.is_insert or state.is_update):",
        "        if True:  # MUTANT",
        "Bulk-write guard ignores insert/update statements entirely",
    ),
    Mutation(
        "SA-3",
        "src/floorvault/sqlalchemy_adapter.py",
        "        return bound_record_id(str(pk), None if tenant is None else str(tenant))",
        "        return bound_record_id(str(pk))  # MUTANT",
        "Tenant dropped from the record coordinate: ciphertext becomes "
        "replayable across tenant scopes",
    ),
    Mutation(
        "SA-4",
        "src/floorvault/sqlalchemy_adapter.py",
        "        if pk is None:\n"
        "            raise EncryptedWriteError(\n"
        '                f"{type(obj).__name__}.{self.id_attr} must be set before "',
        "        if False:  # MUTANT\n"
        "            raise EncryptedWriteError(\n"
        '                f"{type(obj).__name__}.{self.id_attr} must be set before "',
        "Missing primary key no longer refuses the encrypted write",
    ),
    Mutation(
        "SA-5",
        "src/floorvault/sqlalchemy_adapter.py",
        "            try:\n"
        '                require_envelope(value, where=f"{model.__name__}.{key}")',
        "            try:\n                pass  # MUTANT",
        "Flush-time barrier stops checking ciphertext-column values: a value "
        "staged around the set event reaches the wire",
    ),
    Mutation(
        "SA-6",
        "src/floorvault/sqlalchemy_adapter.py",
        "    if binding is None:\n"
        "        raise EncryptedWriteError(\n"
        '            f"{type(obj).__name__} has no FloorVault binding; call "',
        "    if False:  # MUTANT\n"
        "        raise EncryptedWriteError(\n"
        '            f"{type(obj).__name__} has no FloorVault binding; call "',
        "An unprotected model's encrypted field fails open instead of closed",
    ),
    Mutation(
        "SA-7",
        "src/floorvault/sqlalchemy_adapter.py",
        "        if isinstance(model, type) and model in self._fv_bindings:",
        "        if False:  # MUTANT",
        "Legacy bulk APIs no longer refuse protected classes: "
        "bulk_insert_mappings/bulk_update_mappings/bulk_save_objects bypass "
        "every event guard",
    ),
    Mutation(
        "SA-8",
        "src/floorvault/sqlalchemy_adapter.py",
        '    for group in getattr(statement, "_multi_values", None) or ():',
        "    for group in ():  # MUTANT",
        "Executemany insert rows in _multi_values are no longer scanned",
    ),
    Mutation(
        "SA-9",
        "src/floorvault/sqlalchemy_adapter.py",
        '    collect(getattr(statement, "_select_names", None))',
        "    collect(())  # MUTANT",
        "insert().from_select target names are no longer scanned",
    ),
    Mutation(
        "SA-10",
        "src/floorvault/sqlalchemy_adapter.py",
        '    for pair in getattr(statement, "_ordered_values", None) or ():',
        "    for pair in ():  # MUTANT",
        "update().ordered_values pairs are no longer scanned",
    ),
    Mutation(
        "SA-11",
        "src/floorvault/sqlalchemy_adapter.py",
        '                for opt in ("default", "server_default", "onupdate", "server_onupdate", "computed"):',
        "                for opt in ():  # MUTANT",
        "Column-level default/server producers on encrypted columns are "
        "accepted - a plaintext write path the validator never sees",
    ),
    Mutation(
        "SA-12",
        "src/floorvault/sqlalchemy_adapter.py",
        "                for alias in (column.key, column.name):\n"
        "                    if isinstance(alias, str):\n"
        "                        ct_names.add(alias)",
        "                pass  # MUTANT",
        "Statement keys using the physical column name bypass the guard when "
        "the SQL column is renamed",
    ),
    Mutation(
        "SA-13",
        "src/floorvault/sqlalchemy_adapter.py",
        "            mapper.local_table.fullname,",
        "            mapper.local_table.name,  # MUTANT",
        "Table coordinate loses schema qualification: ciphertext replays "
        "across same-named tables in different schemas",
    ),
    Mutation(
        "SA-14",
        "src/floorvault/sqlalchemy_adapter.py",
        "                    for key in row:\n"
        "                        named.update(_key_names(key) & binding.ct_names)",
        "                    pass  # MUTANT",
        "Executemany ORM parameter rows are no longer scanned for protected columns",
    ),
    Mutation(
        "LQ-1",
        "src/floorvault/libsql_adapter.py",
        "        _check_connection(connection)",
        "        pass  # MUTANT",
        "libsql connection contract check removed: a non-connection is accepted "
        "and fails at execute-time instead of at construction",
    ),
    Mutation(
        "LQ-2",
        "src/floorvault/libsql_adapter.py",
        "    if inspect.iscoroutinefunction(execute):",
        "    if False:  # MUTANT",
        "Async execute accepted: a coroutine reaches the DBAPI path and fails "
        "mid-operation instead of at the boundary",
    ),
    Mutation(
        "LQ-3",
        "src/floorvault/libsql_adapter.py",
        "    if unsupported:",
        "    if False:  # MUTANT",
        "connect_encrypted forwards any libsql.connect option: sync_url / "
        "auth_token reach a remote or replica mode whose key handling is "
        "unverifiable, and a caller encryption_key='' writes plaintext",
    ),
    Mutation(
        "LQ-4",
        "src/floorvault/libsql_adapter.py",
        "    if _URL_SCHEME.match(path) and not re.match(",
        "    if False and _URL_SCHEME.match(path) and not re.match(",
        "connect_encrypted accepts remote URLs: the key is passed to a server "
        "that may silently ignore it",
    ),
    Mutation(
        "LQ-5",
        "src/floorvault/libsql_adapter.py",
        "    if header == _PLAINTEXT_SQLITE_HEADER:",
        "    if False:  # MUTANT",
        "Existing plaintext SQLite file no longer refused up front: the caller "
        "is told the key is wrong instead of that the file was never encrypted",
    ),
    Mutation(
        "LQ-6",
        "src/floorvault/libsql_adapter.py",
        '_FILE_KEY_INFO = b"floorvault-v1-libsql-file"',
        '_FILE_KEY_INFO = b"floorvault-v1-beacon-index"  # MUTANT',
        "File-layer key derived under the beacon label: the page cipher and "
        "the beacon index share one key",
    ),
    Mutation(
        "LQ-7",
        "src/floorvault/libsql_adapter.py",
        "        if len(source) != _KEY_BYTES:",
        "        if False:  # MUTANT",
        "File-key derivation accepts a master key of any length, so a truncated "
        "or foreign-domain key silently keys the page cipher",
    ),
    Mutation(
        "LQ-8",
        "src/floorvault/libsql_adapter.py",
        '    if not path or path == ":memory:":',
        "    if False:  # MUTANT",
        "In-memory and empty databases accepted: the caller is told the data is "
        "encrypted at rest when there is no file to encrypt",
    ),
    Mutation(
        "LQ-9",
        "src/floorvault/libsql_adapter.py",
        '        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()',
        "        pass  # MUTANT",
        "Connection probe removed: a wrong key is returned as a live connection "
        "and fails on the first query instead of at the boundary",
    ),
    Mutation(
        "LQ-10",
        "src/floorvault/libsql_adapter.py",
        "        connection = libsql.connect(path, encryption_key=file_key, **options)",
        "        connection = libsql.connect(path, **options)  # MUTANT",
        "Derived key never reaches the client: the file is written in plaintext",
    ),
    Mutation(
        "LQ-11",
        "src/floorvault/libsql_adapter.py",
        "        connection.close()\n        raise ValueError(",
        "        raise ValueError(  # MUTANT",
        "Connection refused on a failed probe is leaked open instead of closed",
    ),
    Mutation(
        "VM-1",
        "src/floorvault/vaultkit/vault.py",
        "            if not self._migrate_listing:",
        "            if False:  # MUTANT",
        "Sealed-metadata vault reseals planted cleartext kind/has_otp on an "
        "ordinary open instead of refusing it",
    ),
    Mutation(
        "VM-2",
        "src/floorvault/vaultkit/vault.py",
        "                if kind_sealed or otp_sealed:",
        "                if False:  # MUTANT",
        "A sealed-metadata vault opens without the flag and envelopes are served as kinds",
    ),
    Mutation(
        "VM-3",
        "src/floorvault/vaultkit/vault.py",
        '            derived_otp = kind == "login" and bool(payload.get("otp_secret"))',
        "            derived_otp = bool(has_otp)  # MUTANT",
        "Migration trusts the tampered cleartext has_otp instead of re-deriving "
        "it from the authenticated payload",
    ),
    Mutation(
        "VM-4",
        "src/floorvault/vaultkit/vault.py",
        '        return self._encrypt_metadata(item_id, "kind", kind.ljust(_SEALED_KIND_WIDTH))',
        '        return self._encrypt_metadata(item_id, "kind", kind)  # MUTANT',
        "Sealed kind is unpadded: envelope length tells logins from other kinds",
    ),
    Mutation(
        "VM-5",
        "src/floorvault/vaultkit/vault.py",
        "            if len(padded) != _SEALED_KIND_WIDTH or kind not in VAULT_KINDS:",
        "            if kind not in VAULT_KINDS:  # MUTANT",
        "Non-canonical (length-revealing) sealed kinds are accepted on read",
    ),
    Mutation(
        "VM-6",
        "src/floorvault/vaultkit/vault.py",
        "                *self._SEALED_LISTING_COLUMNS,",
        "                # MUTANT",
        "Rotation leaves sealed kind/has_otp under the retired key",
    ),
    Mutation(
        "PW-1",
        "src/floorvault/providers/passphrase_store.py",
        "    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N or (r, p) != (_R, _P):",
        "    if False:  # MUTANT",
        "Passphrase key file cost parameters trusted from the file: a planted store downgrades the work factor or demands unbounded memory",
    ),
    Mutation(
        "PW-2",
        "src/floorvault/providers/passphrase_store.py",
        "    if not encoded:",
        "    if False:  # MUTANT",
        "Empty passphrase accepted: the wrapped key file is unlockable by anyone",
    ),
    Mutation(
        "PW-3",
        "src/floorvault/providers/adaptive.py",
        "        # it - that would silently fork the master key.\n        if self._read_wrapped_key_file(wrapped_file) is not None:",
        "        # it - that would silently fork the master key.\n        if False:  # MUTANT",
        "Resolving without the passphrase beside a wrapped store silently forks a fresh raw master key",
    ),
    Mutation(
        "PW-4",
        "src/floorvault/providers/adaptive.py",
        "        if raw_present:",
        "        if False:  # MUTANT",
        "A raw master.key beside the wrapped store is ignored: a copy of the directory still yields the key without the passphrase",
    ),
    Mutation(
        "PW-5",
        "src/floorvault/providers/adaptive.py",
        "            allow_file_fallback=self.allow_disk_fallback and self._passphrase is None,",
        "            allow_file_fallback=self.allow_disk_fallback,  # MUTANT",
        "With passphrase= the Linux tier still falls back to the publicly masked master.key.ss",
    ),
    Mutation(
        "PW-6",
        "src/floorvault/providers/adaptive.py",
        "            if self._read_wrapped_key_file(wrapped_file) is not None:\n                raise KeyProviderError(",
        "            if False:  # MUTANT\n                raise KeyProviderError(",
        "Raw key creation does not re-check the wrapped store under the lock: a concurrent passphrase resolver forks the key",
    ),
    Mutation(
        "PW-7",
        "src/floorvault/providers/adaptive.py",
        "                if self._read_raw_key_file(key_file) is not None:",
        "                if False:  # MUTANT",
        "Wrapped key creation does not re-check the raw store under the lock: a concurrent raw resolver forks the key",
    ),
    Mutation(
        "FA-1",
        "src/floorvault/freshness.py",
        "            if hmac.compare_digest(current, committed):",
        "            if True:  # MUTANT",
        "Freshness verify accepts any database state: rollback and replay pass",
    ),
    Mutation(
        "FA-2",
        "src/floorvault/freshness.py",
        "            if pending is not None and hmac.compare_digest(current, pending):",
        "            if pending is not None:  # MUTANT",
        "A pending anchor state accepts any database, not just the pending digest",
    ),
    Mutation(
        "FA-3",
        "src/floorvault/freshness.py",
        "        if not hmac.compare_digest(mac, self._record_mac(committed, pending)):",
        "        if False:  # MUTANT",
        "Anchor record no longer authenticated: whoever can write the store can re-baseline it to a rolled-back database",
    ),
    Mutation(
        "FA-4",
        "src/floorvault/freshness.py",
        "            self._trusted is None\n",
        "            False  # MUTANT\n",
        "Writes advance from an unverified state, blessing a rolled-back database as the new baseline",
    ),
    Mutation(
        "FA-5",
        "src/floorvault/freshness.py",
        "        if not self.store.compare_and_swap(self.name, None, self._encode_record(baseline, None)):",
        "        if False:  # MUTANT",
        "initialize() reports success over an existing anchor instead of refusing to re-baseline",
    ),
    Mutation(
        "FA-6",
        "src/floorvault/freshness.py",
        '        tag = b"t"',
        '        tag = b"b"  # MUTANT',
        "Digest encoding conflates TEXT and BLOB: a type change is not a content change",
    ),
    Mutation(
        "FA-7",
        "src/floorvault/freshness.py",
        "        if not self.store.compare_and_swap(self.name, blob, pending_blob):",
        "        if not self.store.compare_and_swap(self.name, blob, self._encode_record(new_state, None)):  # MUTANT",
        "Commit skips the pending phase: a crash after the database commit raises a false rollback alarm",
    ),
    Mutation(
        "FA-8",
        "src/floorvault/freshness.py",
        "                if pending is not None:\n                    raise RollbackDetectedError(",
        "                if False:  # MUTANT\n                    raise RollbackDetectedError(",
        "An interrupted commit lets the pre-commit state verify: a database-only attacker rolls back the commit that crashed before promotion",
    ),
    Mutation(
        "FA-9",
        "src/floorvault/freshness.py",
        "        if connection is not self._trusted_connection:",
        "        if False:  # MUTANT",
        "Writes accept a connection other than the verified one, so an unverified (rolled-back) database becomes the baseline",
    ),
    Mutation(
        "FA-10",
        "src/floorvault/freshness.py",
        '        connection.execute("BEGIN IMMEDIATE")',
        "        pass  # MUTANT",
        "transaction() verifies without the write lock: a concurrent writer's change lands between the check and the commit",
    ),
    Mutation(
        "FA-11",
        "src/floorvault/freshness.py",
        "                _fsync_directory(self.directory)",
        "                pass  # MUTANT",
        "Anchor rename not flushed: power loss can revert the anchor to an earlier record a restored database matches",
    ),
    Mutation(
        "FA-12",
        "src/floorvault/freshness.py",
        '            if object_type != "trigger" and _fold_sqlite(str(table_name)) not in self._tables:',
        "            if True:  # MUTANT",
        "Schema left out of the digest: a planted trigger silently undoes later writes and is then blessed",
    ),
    Mutation(
        "FA-14",
        "src/floorvault/freshness.py",
        "        self._trust(None, None)\n        for _attempt in range(_CAS_RETRIES):",
        "        pass  # MUTANT\n        for _attempt in range(_CAS_RETRIES):",
        "A failed verify keeps the earlier write authorization: a later write blesses the tampered state",
    ),
    Mutation(
        "FA-15",
        "src/floorvault/freshness.py",
        '        connection.execute("COMMIT")',
        "        connection.commit()  # MUTANT",
        "transaction() commits via connection.commit(): a no-op under autocommit=True, so the write is lost while the anchor advances",
    ),
    Mutation(
        "FA-16",
        "src/floorvault/freshness.py",
        '                connection.execute("ROLLBACK")',
        "                connection.rollback()  # MUTANT",
        "transaction() rolls back via connection.rollback(): a no-op under autocommit=True, leaving the failed write's transaction open",
    ),
    Mutation(
        "FA-17",
        "src/floorvault/freshness.py",
        '        if getattr(connection, "autocommit", None) is False:',
        "        if False:  # MUTANT",
        "autocommit=False connections reach BEGIN IMMEDIATE and get a misleading open-transaction refusal",
    ),
    Mutation(
        "FA-18",
        "src/floorvault/freshness.py",
        "            if total != distinct + min(nulls, 1) or nulls > 1:",
        "            if False:  # MUTANT",
        "A non-unique order column is hashed in physical order: a VACUUM or rebuild raises a false rollback alarm",
    ),
    Mutation(
        "FA-19",
        "src/floorvault/freshness.py",
        '        return self.directory / f"{_validate_name(name)}.fvanchor"',
        '        return self.directory / f"{name}.fvanchor"  # MUTANT',
        "FileAnchorStore accepts path-traversal names and writes outside its directory",
    ),
    Mutation(
        "AD-4",
        "src/floorvault/providers/adaptive.py",
        "        if self._tier3_store_present():\n            return self._read_os_tier_beside_file_key()\n        if not self._os_tier_usable():",
        "        if False:  # MUTANT\n            return self._read_os_tier_beside_file_key()\n        if not self._os_tier_usable():",
        "OS tier gains a key store after Tier-3 file custody: a fresh OS key is created and the file key is silently forked",
    ),
    Mutation(
        "AD-5",
        "src/floorvault/providers/adaptive.py",
        '        if key is _OS_KEY_MISSING:\n            raise KeyProviderError(\n                f"a local key file exists',
        '        if False:  # MUTANT\n            raise KeyProviderError(\n                f"a local key file exists',
        "Usable-but-empty OS tier with a file key present is treated as a key: resolution returns a sentinel instead of refusing",
    ),
    Mutation(
        "AD-6",
        "src/floorvault/providers/adaptive.py",
        "                    return _OS_KEY_MISSING if missing_ok else None",
        "                    return None  # MUTANT",
        "Empty Keychain reads as 'no OS tier': resolution falls through and the fork is hidden, not refused",
    ),
    Mutation(
        "AD-7",
        "src/floorvault/providers/adaptive.py",
        "                os.lstat(self.fallback_dir / name)\n            except FileNotFoundError:",
        "                os.stat(self.fallback_dir / name)  # MUTANT\n            except FileNotFoundError:",
        "A dangling or planted master.key symlink stops counting as a file store, so the OS tier creates a new key",
    ),
    Mutation(
        "AD-8",
        "src/floorvault/providers/adaptive.py",
        "                os.lstat(self.fallback_dir / name)\n            except FileNotFoundError:",
        "                os.lstat(self.fallback_dir / name)\n            except OSError:  # MUTANT",
        "An unsearchable key directory reads as 'no file store': the OS tier creates a key that replaces the unreadable file key",
    ),
    Mutation(
        "AD-9",
        "src/floorvault/providers/adaptive.py",
        "            if self._os_tier_marker_present():\n                raise self._os_tier_marker_refusal()\n            # Re-check",
        "            if False:  # MUTANT\n                raise self._os_tier_marker_refusal()\n            # Re-check",
        "A resolver without the OS tier ignores the OS-tier marker and mints master.key beside an OS-held key (#63 fork)",
    ),
    Mutation(
        "AD-10",
        "src/floorvault/providers/adaptive.py",
        "                if self._os_tier_marker_present():\n                    raise self._os_tier_marker_refusal()",
        "                if False:  # MUTANT\n                    raise self._os_tier_marker_refusal()",
        "Passphrase Tier-3 creation ignores the OS-tier marker: a wrapped file key forks an OS-held key",
    ),
    Mutation(
        "AD-11",
        "src/floorvault/providers/adaptive.py",
        "            if key is not None:\n                self._publish_os_tier_marker()",
        "            if False:  # MUTANT\n                self._publish_os_tier_marker()",
        "OS-tier key created or adopted without recording the marker: a later headless resolver forks it",
    ),
    Mutation(
        "AD-12",
        "src/floorvault/providers/adaptive.py",
        "            if self._tier3_store_present():\n                return self._read_os_tier_beside_file_key()\n            key = self._resolve_os_tier(allow_create=True)",
        "            if False:  # MUTANT\n                return self._read_os_tier_beside_file_key()\n            key = self._resolve_os_tier(allow_create=True)",
        "No re-check under the lock: a file key published since the unlocked check is forked by a new OS key",
    ),
    Mutation(
        "AD-13",
        "src/floorvault/providers/adaptive.py",
        "        except OSError:\n            return True\n        return True\n\n    def _os_tier_marker_refusal",
        "        except OSError:\n            return False  # MUTANT\n        return True\n\n    def _os_tier_marker_refusal",
        "An unreadable OS-tier marker reads as absent, so Tier-3 creation forks the OS-held key",
    ),
    Mutation(
        "AD-14",
        "src/floorvault/providers/adaptive.py",
        '            if key is _OS_KEY_MISSING:\n                raise KeyProviderError(\n                    f"{self.fallback_dir / OS_TIER_MARKER_FILENAME} records',
        '            if False:  # MUTANT\n                raise KeyProviderError(\n                    f"{self.fallback_dir / OS_TIER_MARKER_FILENAME} records',
        "A deleted or reset OS key recorded by the marker is silently replaced: data under the original no longer decrypts",
    ),
    Mutation(
        "AD-15",
        "src/floorvault/providers/adaptive.py",
        "        return len(fields) == 3 and fields[1:] == [self.service_name, self.account_name]",
        "        return len(fields) == 3  # MUTANT",
        "Another service's marker is taken as this one's: a first-time key for this service is refused",
    ),
    Mutation(
        "AD-16",
        "src/floorvault/providers/adaptive.py",
        "            except ValueError:\n                # fallback_dir fails",
        "            except KeyError:  # MUTANT\n                # fallback_dir fails",
        "A fallback_dir refused by the owner-only policy (a symlink) breaks OS-tier resolution of a working key",
    ),
    Mutation(
        "AD-17",
        "src/floorvault/providers/adaptive.py",
        "        except FileExistsError:\n            stack.enter_context(self._tier3_creation_lock())",
        "        except KeyError:  # MUTANT\n            stack.enter_context(self._tier3_creation_lock())",
        "A fallback_dir creation race skips the Tier-3 lock: the OS key is created unrecorded beside the winner's file key",
    ),
    Mutation(
        "BIND-1",
        "src/floorvault/agentenv.py",
        "        entry and os.path.normcase(entry[0]) == program and list(entry[1:]) == rest",
        "        entry and os.path.normcase(entry[0]) == program  # MUTANT",
        "A bound item resolves for its program with any arguments (python3 -c, another package)",
    ),
    Mutation(
        "BIND-2",
        "src/floorvault/agent_cli.py",
        "    if bound and command_line is not None and not problems:",
        "    if False:  # MUTANT",
        "NODE_OPTIONS/LD_PRELOAD no longer block a bound item: the allowed program loads injected code",
    ),
    Mutation(
        "BIND-3",
        "src/floorvault/agent_cli.py",
        "        if command_line is not None and not command_allowed(command_line, allowed):",
        "        if False:  # MUTANT",
        "Bindings are read but never enforced: any command receives a bound item",
    ),
    Mutation(
        "BIND-4",
        "src/floorvault/agent_cli.py",
        '            problems.append(\n                f"vault item {item_id}: its command binding cannot be read "',
        '            continue  # MUTANT\n            problems.append(\n                f"vault item {item_id}: its command binding cannot be read "',
        "A binding that fails to authenticate or decode is treated as unbound (fail open)",
    ),
    Mutation(
        "BIND-5",
        "src/floorvault/vaultkit/vault.py",
        "        if not commands or not isinstance(commands, list):\n            raise VaultError",
        "        if not commands or not isinstance(commands, list):\n            return None  # MUTANT\n            raise VaultError",
        "A sealed but empty or malformed binding reads as unbound instead of an error",
    ),
    Mutation(
        "BIND-6",
        "src/floorvault/agent_cli.py",
        "        if not remaining:\n            # Unbinding widens access",
        "        if False:  # MUTANT\n            # Unbinding widens access",
        "Removing the last command line silently unbinds the item for every command",
    ),
    Mutation(
        "BIND-7",
        "src/floorvault/agent_cli.py",
        "    command_line = [os.path.abspath(path), *command[1:]] if path is not None else None",
        "    command_line = [os.path.realpath(path), *command[1:]] if path is not None else None  # MUTANT",
        "Symlinks are followed: a link to the bound interpreter placed anywhere matches",
        # The only test that can tell abspath from realpath creates a symlink,
        # which Windows test runners cannot do unprivileged.
        expect_on_windows="survived",
    ),
    Mutation(
        "HIM-1",
        "src/floorvault/agent_cli.py",
        "    if missing:\n",
        "    if False:  # MUTANT\n",
        "Hermes import deletes .env lines before config.yaml maps them: Hermes loses the keys",
    ),
    Mutation(
        "HIM-2",
        "src/floorvault/agent_cli.py",
        '    return env_map.get(name) in (f"hv:{item_id}", f"hv:{item_id}:value")\n',
        "    return name in env_map  # MUTANT\n",
        "A config.yaml that maps the variable to another item (or another field) counts as the mapping",
    ),
    Mutation(
        "HIM-8",
        "src/floorvault/agent_cli.py",
        "                service_name=SERVICE_NAME, fallback_dir=directory, environ={}, interactive=False\n",
        "                service_name=SERVICE_NAME, fallback_dir=directory, interactive=False  # MUTANT\n",
        "The removal check reads $FLOOR_VAULT_KEY, which the plugin ignores, to certify deleting .env lines",
    ),
    Mutation(
        "HIM-3",
        "src/floorvault/agent_cli.py",
        "        if not _is_hermes_env_file(path, os.environ):\n",
        "        if False:  # MUTANT\n",
        "Hermes import creates agent-vault beside any .env, not only a Hermes home",
    ),
    Mutation(
        "HIM-4",
        "src/floorvault/agent_cli.py",
        "            if not stat.S_ISREG(path.lstat().st_mode):\n"
        '                _err(prog, f"{path} is not a regular file; --remove-from-env',
        "            if False:  # MUTANT\n"
        '                _err(prog, f"{path} is not a regular file; --remove-from-env',
        "--remove-from-env follows a symlinked .env and rewrites its target",
        # The test that can tell needs a symlink, which Windows runners cannot
        # create unprivileged.
        expect_on_windows="survived",
    ),
    Mutation(
        "HIM-5",
        "src/floorvault/agent_cli.py",
        "        if hermes_environ_view.get(_HERMES_KEY_VAR):",
        "        if False:  # MUTANT",
        "A store set up with the plugin's token_env key is written under a different key",
    ),
    Mutation(
        "SDC-1",
        "src/floorvault/systemd_creds.py",
        "    if version < MIN_SYSTEMD_VERSION:\n",
        "    if False:  # MUTANT\n",
        "A systemd older than 256 is accepted: `--user` is unknown there, so the credential is system-scoped or fails late",
    ),
    Mutation(
        "SDC-2",
        "src/floorvault/systemd_creds.py",
        "    if version >= REFUSE_NULL_SINCE:\n",
        "    if True:  # MUTANT\n",
        "--refuse-null is passed to systemd 256 to 258, where it is an unknown option: every unseal fails",
    ),
    Mutation(
        "SDC-3",
        "src/floorvault/systemd_creds.py",
        "    if version >= REFUSE_NULL_SINCE:\n",
        "    if False:  # MUTANT\n",
        "--refuse-null is never passed: a forged null-key credential (no authentication) unseals to a chosen key",
    ),
    Mutation(
        "SDC-4",
        "src/floorvault/systemd_creds.py",
        'f"--name={CREDENTIAL_NAME}", "-", "-"]',
        'f"--name={CREDENTIAL_NAME}", "--with-key=null", "-", "-"]',
        "A key choice is passed to the helper: --with-key=null would seal the key with no confidentiality or authentication, and other values are ignored or refused for an unprivileged caller",
    ),
    Mutation(
        "SDC-5",
        "src/floorvault/systemd_creds.py",
        "    if _decrypt(binary, version, ciphertext) != plaintext:\n",
        "    if False:  # MUTANT\n",
        "The sealed key is not unsealed again before it is written: a credential that cannot be opened is saved",
    ),
    Mutation(
        "SDC-6",
        "src/floorvault/systemd_creds.py",
        "os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr",
        "os.O_WRONLY | os.O_CREAT | getattr",
        "An existing credential is overwritten: the store's key is replaced and its data is lost",
    ),
    Mutation(
        "SDC-7",
        "src/floorvault/systemd_creds.py",
        "            0o600,\n",
        "            0o644,\n",
        "The sealed credential is created readable by other users",
    ),
    Mutation(
        "SDC-8",
        "src/floorvault/systemd_creds.py",
        "        if st.st_mode & 0o022:\n",
        "        if False:  # MUTANT\n",
        "A group- or world-writable credential file is unsealed",
    ),
    Mutation(
        "SDC-9",
        "src/floorvault/systemd_creds.py",
        "            env=dict(_HELPER_ENV),\n",
        "            env=None,\n",
        "systemd-creds inherits the whole environment, including FLOOR_VAULT_KEY and other secrets",
    ),
    Mutation(
        "SDC-10",
        "src/floorvault/systemd_creds.py",
        '    text = (result.stderr or b"")',
        '    text = (result.stdout or b"")',
        "A failing helper's stdout, which can hold the key, goes into the error message",
    ),
    Mutation(
        "SDC-11",
        "src/floorvault/systemd_creds.py",
        'os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)',
        'os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)',
        "A symlinked credential file is followed",
    ),
    Mutation(
        "SDC-12",
        "src/floorvault/agent_cli.py",
        "        if sealed is not None:\n            return sealed\n",
        "        if False:  # MUTANT\n            return sealed\n",
        "A store with a sealed key ignores it and takes the key from $FLOOR_VAULT_KEY_FILE or default custody",
    ),
    Mutation(
        "SDC-13",
        "src/floorvault/agent_cli.py",
        '    if _is_regular_file(vault_dir / "vault.db"):\n        _err(\n            prog,\n            f"a vault already exists',
        '    if False:  # MUTANT\n        _err(\n            prog,\n            f"a vault already exists',
        "init seals a new key beside an existing vault: its data stays under the old key and becomes unreachable",
    ),
    Mutation(
        "SDC-14",
        "src/floorvault/providers/adaptive.py",
        "        if self._systemd_credential_present():\n",
        "        if False:  # MUTANT\n",
        "Default custody mints a second master key beside a systemd-creds credential",
    ),
    Mutation(
        "SDC-15",
        "src/floorvault/providers/adaptive.py",
        "SYSTEMD_CREDENTIAL_FILENAME)\n        except FileNotFoundError:\n            return False\n        except OSError:\n            return True\n",
        "SYSTEMD_CREDENTIAL_FILENAME)\n        except FileNotFoundError:\n            return False\n        except OSError:\n            return False\n",
        "A credential that cannot be looked up is treated as absent: a second master key can be minted",
    ),
    Mutation(
        "SDC-16",
        "src/floorvault/agent_cli.py",
        "    if sealed and args.key_file is not None:\n",
        "    if False:  # MUTANT\n",
        "`secrets import --hermes --key-file` creates a store under the key file's key beside a sealed credential that holds another: the store's key is forked",
    ),
    Mutation(
        "SDC-17",
        "src/floorvault/agent_cli.py",
        '        and (os.environ.get(KEY_FILE_ENV) or "").strip()\n    ):\n',
        "        and False  # MUTANT\n    ):\n",
        "`secrets import --hermes` stores under $FLOOR_VAULT_KEY_FILE, which the Hermes plugin never reads",
    ),
    Mutation(
        "SDC-18",
        "src/floorvault/systemd_creds.py",
        "        os.lstat(credential_path(vault_dir))\n    except FileNotFoundError:\n        return False\n    except OSError:\n        return True\n",
        "        os.lstat(credential_path(vault_dir))\n    except FileNotFoundError:\n        return False\n    except OSError:\n        return False\n",
        "A credential that cannot be looked up is treated as absent by the Hermes import guard",
    ),
    Mutation(
        "SS-4",
        "src/floorvault/providers/linux_keyring.py",
        "            if self._interactive:\n                # Creates the default collection when there is none (a prompt).\n",
        "            if True:  # MUTANT\n                # Creates the default collection when there is none (a prompt).\n",
        "A non-interactive resolve calls get_default_collection, which creates a missing collection behind a prompt",
    ),
    Mutation(
        "SS-5",
        "src/floorvault/providers/linux_keyring.py",
        "            if collection.is_locked():\n                if not self._interactive:\n",
        "            if collection.is_locked():\n                if False:  # MUTANT\n",
        "A non-interactive resolve unlocks a locked collection, showing a prompt a secret source must not block on",
    ),
    Mutation(
        "SS-6",
        "src/floorvault/providers/linux_keyring.py",
        '                raise MissingKeyError("Secret Service master key not found; recovery is required")\n            if not self._interactive:\n',
        '                raise MissingKeyError("Secret Service master key not found; recovery is required")\n            if False:  # MUTANT\n',
        "A non-interactive resolve creates a new master key through the Secret Service",
    ),
    Mutation(
        "SS-7",
        "src/floorvault/providers/linux_keyring.py",
        "            with exclusive_lock(self._identity_lock_path()):\n                items = self._matching_items(collection, query)\n                if items:\n                    return self._single_key(items)\n",
        "            if True:  # MUTANT\n",
        "First-time creation is not serialized per keyring identity: two stores create two keys under one entry name",
    ),
    Mutation(
        "SS-8",
        "src/floorvault/providers/linux_keyring.py",
        "        if any(secret != secrets[0] for secret in secrets[1:]):\n",
        "        if False:  # MUTANT\n",
        "Duplicate Secret Service entries with different keys resolve to the first one: a store can become unreadable",
    ),
    Mutation(
        "ENV-1",
        "src/floorvault/providers/adaptive.py",
        "                val = self._environ.get(var_name)\n",
        "                val = os.environ.get(var_name)  # MUTANT\n",
        "Tier 1 reads the process environment even when the caller passed its own view: an ambient key unlocks the store",
    ),
    Mutation(
        "HIM-6",
        "src/floorvault/agent_cli.py",
        "    hermes_environ = None if args.key_env else {}\n",
        "    hermes_environ = None  # MUTANT\n",
        "`secrets import --hermes` stores under $FLOOR_VAULT_KEY, which the Hermes plugin does not read",
    ),
    Mutation(
        "HIM-7",
        "src/floorvault/agent_cli.py",
        '    if not key_hex and custody != "os":\n        _require_plugin_custody(home, custody)\n',
        "    if False:  # MUTANT\n        _require_plugin_custody(home, custody)\n",
        "The removal check certifies custody: key_file / systemd-creds for a plugin too old to read it, which then opens the OS key store and cannot read the deleted keys",
    ),
    Mutation(
        "HIM-9",
        "src/floorvault/agent_cli.py",
        "            key = read_key_file(_hermes_key_file(cfg, home))\n",
        "            key = read_key_file(Path(os.environ[KEY_FILE_ENV]))  # MUTANT\n",
        "The removal check reads $FLOOR_VAULT_KEY_FILE instead of the key_file config.yaml names, so a key the plugin never reads certifies deleting .env lines",
    ),
    Mutation(
        "MAC-1",
        "src/floorvault/providers/adaptive.py",
        "                    query[ui_key] = ui_fail\n",
        "                    pass  # MUTANT\n",
        "A non-interactive Keychain read no longer asks the framework to fail instead of prompting",
    ),
    Mutation(
        "MAC-2",
        "src/floorvault/providers/adaptive.py",
        "                if status == -25300 and allow_create and not self.interactive:\n",
        "                if False:  # MUTANT\n",
        "A non-interactive resolve creates a new master key in the macOS Keychain",
    ),
    # CLI audit 2026-10-26 (docs/CLI-AUDIT-2026-10-26.md).
    Mutation(
        "AUD-1",
        "src/floorvault/agent_cli.py",
        'code_injection_variables({**env, **{name: "" for name in refs}})',
        "code_injection_variables(env)  # MUTANT",
        "LD_PRELOAD=fv:x no longer blocks a bound item: the reference sets the variable unchecked",
    ),
    Mutation(
        "AUD-25",
        "src/floorvault/agent_cli.py",
        "            if require_binding:\n",
        "            if False:  # MUTANT\n",
        "With --require-binding, an item whose binding was cleared in vault.db is still released (RUN-9)",
    ),
    Mutation(
        "AUD-19",
        "src/floorvault/agent_cli.py",
        "    if sealed_listing and cleartext_rows and not migrate_listing:\n",
        "    if False:  # MUTANT\n",
        "Asserted sealed listing opens a store turned back to cleartext (SEC-15)",
    ),
    Mutation(
        "AUD-20",
        "src/floorvault/agent_cli.py",
        '        "seal_listing_metadata": bool(sealed_listing or sealed_rows or migrate_listing),\n',
        '        "seal_listing_metadata": bool(sealed_listing or migrate_listing),  # MUTANT\n',
        "The CLI cannot open a store with sealed listing metadata again (SEC-15)",
    ),
    Mutation(
        "AUD-21",
        "src/floorvault/agent_cli.py",
        "    store = _store_for(args, assert_listing=False)\n",
        "    store = None  # MUTANT\n",
        "secrets seal-listing converts a store before checking the key opens it (SEC-15)",
    ),
    Mutation(
        "AUD-23",
        "src/floorvault/vaultkit/vault.py",
        "            if active is not None and bool(active[0]):\n"
        "                raise VaultError(\n"
        '                    "vault rotation is in progress; listing metadata was not converted"\n',
        "            if False:  # MUTANT\n"
        "                raise VaultError(\n"
        '                    "vault rotation is in progress; listing metadata was not converted"\n',
        "Listing metadata is converted while a key rotation is in progress (#98 review)",
    ),
    Mutation(
        "AUD-24",
        "src/floorvault/agent_cli.py",
        "    except sqlite3.Error as exc:\n        # The mode is unknown, so nothing may be assumed about it.\n",
        "    except sqlite3.Error as exc:  # MUTANT\n        return 0, 0\n",
        "An unreadable listing is taken as an unsealed, empty one (#98 review)",
    ),
    Mutation(
        "BG-1",
        "plugins/hermesvault/binding_guard.py",
        "    if any(command_allowed(line, allowed) for line in command_lines):\n",
        "    if True:  # MUTANT\n",
        "The Hermes plugin resolves a bound item for a command it is not bound to",
    ),
    Mutation(
        "BG-2",
        "plugins/hermesvault/binding_guard.py",
        '        if require_binding:\n            return (\n                "has no command binding, and',
        '        if False:  # MUTANT\n            return (\n                "has no command binding, and',
        "The Hermes plugin resolves an unbound item although require_binding is set",
    ),
    Mutation(
        "BG-3",
        "plugins/hermesvault/binding_guard.py",
        '    except Exception:\n        return "has a command binding that cannot be read"\n',
        "    except Exception:\n        return None  # MUTANT\n",
        "The Hermes plugin resolves an item whose binding cannot be read as if it were unbound",
    ),
    Mutation(
        "BG-4",
        "plugins/hermesvault/binding_guard.py",
        "    if argv and argv[0] and os.path.isabs(argv[0]):\n",
        "    if argv and argv[0]:  # MUTANT\n",
        "A relative program path is resolved against the current directory and can match a binding",
    ),
    Mutation(
        "BG-5",
        "plugins/hermesvault/binding_guard.py",
        '        if require_binding:\n            return "cannot be checked for a command binding',
        '        if False:  # MUTANT\n            return "cannot be checked for a command binding',
        "require_binding resolves items even where floorvault cannot read bindings",
    ),
    Mutation(
        "BG-6",
        "plugins/hermesvault/binding_guard.py",
        "    if len(original) > 1 and sys.executable and os.path.isabs(sys.executable):\n",
        "    if len(original) > 1 and sys.executable:  # MUTANT\n",
        "A relative interpreter path is resolved against the current directory and can match a binding",
    ),
    Mutation(
        "AUD-2",
        "src/floorvault/agent_cli.py",
        "    return _launch(command_line[0], command, env)",
        "    return _launch(path, command, env)  # MUTANT",
        "run starts the unnormalised path, which '..' after a symlink resolves to another binary",
        # The only test that can tell needs a symlink, which Windows runners
        # cannot create unprivileged.
        expect_on_windows="survived",
    ),
    Mutation(
        "AUD-3",
        "src/floorvault/agentenv.py",
        "        if hidden:\n",
        "        if False:  # MUTANT\n",
        "An env-file line with U+2028 or a form feed hides a second assignment again",
    ),
    Mutation(
        "AUD-4",
        "src/floorvault/agent_cli.py",
        "        elif line.value.strip().lower() in key_copies:\n",
        "        elif False:  # MUTANT\n",
        "import stores a copy of the master key, which run would then hand to the child",
    ),
    Mutation(
        "AUD-5",
        "src/floorvault/agent_cli.py",
        "        _check_store_key(store, vault_dir)\n",
        "        pass  # MUTANT\n",
        "secrets add under another key writes to an existing store, leaving it sealed under two keys",
    ),
    Mutation(
        "AUD-16",
        "src/floorvault/inspector.py",
        "        master_key = explicit_key(args, os.environ, key_dir)\n",
        "        master_key = None  # MUTANT\n",
        "inspect ignores --key-env / --key-file / --key-dir and uses default custody (INS-8)",
    ),
    Mutation(
        "AUD-17",
        "src/floorvault/inspector.py",
        "                schema_id=args.schema_id,\n",
        "",
        "inspect ignores --schema-id: a record under another schema cannot be read (INS-7)",
    ),
    Mutation(
        "AUD-18",
        "src/floorvault/inspector.py",
        "                schema_version=args.schema_version,\n",
        "",
        "inspect ignores --schema-version (INS-7)",
    ),
    Mutation(
        "AUD-22",
        "src/floorvault/inspector.py",
        "        # A usage error whatever the record holds, so before the lookup.\n"
        "        _check_key_options(args)\n",
        "        pass  # MUTANT\n",
        "inspect accepts --key-env with --key-file when the record is missing or not ciphertext",
    ),
    Mutation(
        "AUD-6",
        "src/floorvault/agent_cli.py",
        '            if not os.path.samefile(path, directory / ".env"):\n',
        "            if False:  # MUTANT\n",
        "Any .ENV beside a Hermes .env counts as Hermes' file, even a different one (SEC-13)",
    ),
    Mutation(
        "AUD-7",
        "src/floorvault/agent_cli.py",
        '            if not os.path.samefile(path, directory / ".env"):\n',
        "            if True:  # MUTANT\n",
        "Import rewrites Hermes' .env when it is named .ENV on a case-insensitive disk (SEC-13)",
    ),
    Mutation(
        "AUD-8",
        "src/floorvault/agent_cli.py",
        "        view[line.name] = line.value\n",
        "        pass  # MUTANT\n",
        "Hermes import takes $HERMES_VAULT_KEY from the shell, not the .env Hermes loads (SEC-14)",
    ),
    Mutation(
        "AUD-9",
        "src/floorvault/agent_cli.py",
        "    except NoCustodyError:\n",
        "    except NoCustodyError if False else ():  # MUTANT\n",
        "With no custody, the CLI shows the library's refusal instead of its own key options (SEC-17)",
    ),
    Mutation(
        "AUD-10",
        "src/floorvault/agent_cli.py",
        "            # VaultStore's own default custody, resolved here before VaultStore\n",
        "            if create and provider_environ is None:  # MUTANT\n"
        "                return VaultStore(vault_dir)\n",
        "A refused secrets add leaves an empty store directory and the library's wording (SEC-17)",
    ),
    Mutation(
        "AUD-11",
        "src/floorvault/agent_cli.py",
        "        if not directory:\n            continue\n",
        "        if False:  # MUTANT\n            continue\n",
        "An empty Windows PATH entry (a trailing ';') searches the working directory (RUN-10)",
    ),
    Mutation(
        "AUD-12",
        "src/floorvault/agent_cli.py",
        '        if os.name == "nt":\n            # Not os.defpath',
        "        if False:  # MUTANT\n            # Not os.defpath",
        "run on Windows finds a node.exe in the working directory before PATH (RUN-10; "
        "the branch is dead off Windows, so this mutant is equivalent there)",
        expect="survived",
        expect_on_windows="killed",
    ),
    Mutation(
        "AUD-13",
        "src/floorvault/agent_cli.py",
        "            previous = signal.signal(sigbreak, signal.SIG_IGN)\n",
        "            previous = signal.getsignal(sigbreak)  # MUTANT\n",
        "Ctrl+Break ends run on Windows and leaves its child running (RUN-11; "
        "SIGBREAK exists only on Windows, so this mutant is equivalent elsewhere)",
        expect="survived",
        expect_on_windows="killed",
    ),
    Mutation(
        "AUD-14",
        "src/floorvault/agentenv.py",
        "        return name.upper() if fold_case else name\n",
        "        return name  # MUTANT\n",
        "On Windows an env file's Path= reaches the child beside the inherited PATH (RUN-12)",
    ),
    Mutation(
        "AUD-15",
        "src/floorvault/agent_cli.py",
        "    if target is not None:\n        # Part of the store",
        "    if False:  # MUTANT\n        # Part of the store",
        "A half-finished rotation is opened with one key and reported as the wrong key (SEC-16)",
    ),
    Mutation(
        "PKG-1",
        "scripts/verify_wheel.py",
        "        if missing:",
        "        if False:  # MUTANT",
        "Wheel verification accepts a metadata-only archive without the package or CLI modules",
    ),
)

# --------------------------------------------------------------------------
# Automatic AST mutation
# --------------------------------------------------------------------------

COMPARE_SWAPS = {
    "==": "!=",
    "!=": "==",
    "<": "<=",
    "<=": "<",
    ">": ">=",
    ">=": ">",
    "is": "is not",
    "is not": "is",
    "in": "not in",
    "not in": "in",
}


@dataclass(frozen=True)
class AutoMutant:
    id: str
    relpath: str
    start: int
    end: int
    replacement: str
    operator: str
    line: int


def _line_offsets(src: str) -> list[int]:
    offsets = [0]
    for line in src.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _node_start(offsets: list[int], node: ast.AST) -> int:
    return offsets[getattr(node, "lineno", 1) - 1] + getattr(node, "col_offset", 0)


def _node_end(offsets: list[int], node: ast.AST) -> int:
    end_lineno = getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)
    end_col = getattr(node, "end_col_offset", None) or 0
    return offsets[end_lineno - 1] + end_col


def _span(offsets: list[int], node: ast.AST) -> tuple[int, int]:
    return _node_start(offsets, node), _node_end(offsets, node)


def generate_mutants(src: str, relpath: str) -> list[AutoMutant]:
    """Yield mutants for one module using standard mutation operators."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    offsets = _line_offsets(src)
    out: list[AutoMutant] = []
    counter = 0

    def add(start: int, end: int, replacement: str, operator: str, line: int) -> None:
        nonlocal counter
        counter += 1
        out.append(
            AutoMutant(
                id=f"{relpath.split('/')[-1]}:{line}:{counter}",
                relpath=relpath,
                start=start,
                end=end,
                replacement=replacement,
                operator=operator,
                line=line,
            )
        )

    for node in ast.walk(tree):
        # `if <cond>:` -> `if not (<cond>):`
        if isinstance(node, ast.If):
            s, e = _span(offsets, node.test)
            add(s, e, f"not ({src[s:e]})", "negate-condition", node.lineno)

        # comparison operator swaps
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left_end = _node_end(offsets, node.left)
            right = node.comparators[0]
            right_start = _node_start(offsets, right)
            between = src[left_end:right_start]
            stripped = between.strip()
            if stripped in COMPARE_SWAPS:
                lead = between[: len(between) - len(between.lstrip())]
                trail = between[len(between.rstrip()) :]
                add(
                    left_end,
                    right_start,
                    lead + COMPARE_SWAPS[stripped] + trail,
                    "compare-swap",
                    node.lineno,
                )

        # and <-> or
        if isinstance(node, ast.BoolOp):
            for a, b in zip(node.values, node.values[1:]):
                a_end = _node_end(offsets, a)
                b_start = _node_start(offsets, b)
                between = src[a_end:b_start]
                stripped = between.strip()
                if stripped in ("and", "or"):
                    new = "or" if stripped == "and" else "and"
                    lead = between[: len(between) - len(between.lstrip())]
                    trail = between[len(between.rstrip()) :]
                    add(a_end, b_start, lead + new + trail, "boolop-swap", node.lineno)

        # True <-> False, and integer off-by-one
        if isinstance(node, ast.Constant):
            s, e = _span(offsets, node)
            if node.value is True:
                add(s, e, "False", "bool-literal-swap", node.lineno)
            elif node.value is False:
                add(s, e, "True", "bool-literal-swap", node.lineno)
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                if node.value % 2 == 0:  # touches sizes/limits/counts
                    add(s, e, str(node.value + 1), "int-offbyone", node.lineno)

        # drop a raise
        if isinstance(node, ast.Raise):
            s, e = _span(offsets, node)
            add(s, e, "pass", "raise-to-pass", node.lineno)

    # de-duplicate identical edits
    seen: set[tuple[int, int, str]] = set()
    unique: list[AutoMutant] = []
    for m in out:
        key = (m.start, m.end, m.replacement)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique


def _source_files(paths: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        target = REPO / raw
        if target.is_file():
            files.append(target)
        else:
            files.extend(sorted(p for p in target.rglob("*.py") if "__pycache__" not in p.parts))
    return files


def _collect_auto_mutants(paths: tuple[str, ...]) -> list[AutoMutant]:
    mutants: list[AutoMutant] = []
    for path in _source_files(paths):
        rel = str(path.relative_to(REPO))
        mutants.extend(generate_mutants(path.read_text(encoding="utf-8"), rel))
    return mutants


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _copy_repo(destination: Path) -> None:
    shutil.copytree(
        REPO,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "dist",
            "build",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            "*.egg-info",
        ),
    )


def _run_tests(workdir: Path, tests: list[str], first_failure_only: bool) -> int:
    argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    if first_failure_only:
        argv.append("-x")
    argv.extend(tests)
    # PYTHONDONTWRITEBYTECODE is load-bearing for correctness, not speed: a .pyc
    # records only the source mtime (whole seconds) and size, so consecutive
    # same-length mutants written within one second can be served from stale
    # bytecode - the mutant then appears to survive because the original code
    # ran. Two full sweeps disagreed by 28 mutants until this was pinned down.
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(  # harness-built argv, no shell  # nosec B603
        argv, cwd=workdir, capture_output=True, text=True, env=env
    ).returncode


def _classify(code: int) -> str:
    if code == 0:
        return "survived"
    if code == 1:
        return "killed"
    if code == 5:
        return "no-tests"
    return "error"


def _auto_worker(payload: tuple[list[AutoMutant], list[str]]) -> list[tuple[AutoMutant, str]]:
    mutants, _ = payload
    results: list[tuple[AutoMutant, str]] = []
    with tempfile.TemporaryDirectory(prefix="fv-mut-auto-") as tmp:
        workdir = Path(tmp) / "repo"
        _copy_repo(workdir)
        # Belt and braces alongside PYTHONDONTWRITEBYTECODE: a copy can arrive
        # with __pycache__ from the source tree, and stale bytecode silently
        # makes mutants look survived.
        for cached in workdir.rglob("__pycache__"):
            shutil.rmtree(cached, ignore_errors=True)
        baseline = _run_tests(workdir, ["tests/"], False)
        if baseline != 0:
            return [(m, "baseline-broken") for m in mutants]
        for mutant in mutants:
            target = workdir / mutant.relpath
            original = target.read_text(encoding="utf-8")
            mutated = original[: mutant.start] + mutant.replacement + original[mutant.end :]
            try:
                compile(mutated, mutant.relpath, "exec")
            except SyntaxError:
                results.append((mutant, "invalid"))
                continue
            target.write_text(mutated, encoding="utf-8")
            try:
                code = _run_tests(workdir, ["tests/"], True)
            finally:
                target.write_text(original, encoding="utf-8")
            results.append((mutant, _classify(code)))
    return results


def _run_auto(mutants: list[AutoMutant], jobs: int, report_path: Path | None = None) -> int:
    if not mutants:
        print("no mutants generated")
        return 0
    jobs = max(1, min(jobs, len(mutants)))
    chunks: list[list[AutoMutant]] = [mutants[i::jobs] for i in range(jobs)]
    print(f"running {len(mutants)} mutants across {jobs} worker(s)...\n")
    collected: list[tuple[AutoMutant, str]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
        for result in pool.map(_auto_worker, [(c, []) for c in chunks]):
            collected.extend(result)

    tally: dict[str, int] = {}
    survivors: list[AutoMutant] = []
    for mutant, outcome in collected:
        tally[outcome] = tally.get(outcome, 0) + 1
        if outcome == "survived":
            survivors.append(mutant)

    print(f"{'operator':20} {'count':>6}")
    print("-" * 40)
    by_op: dict[str, int] = {}
    for mutant, _ in collected:
        by_op[mutant.operator] = by_op.get(mutant.operator, 0) + 1
    for op, count in sorted(by_op.items(), key=lambda kv: -kv[1]):
        print(f"{op:20} {count:>6}")

    print("-" * 40)
    for key in ("killed", "survived", "invalid", "no-tests", "error", "baseline-broken"):
        if tally.get(key):
            print(f"{key:20} {tally[key]:>6}")

    scored = tally.get("killed", 0) + tally.get("survived", 0)
    if scored:
        score = 100.0 * tally.get("killed", 0) / scored
        print(f"\nmutation score: {score:.1f}%  ({tally.get('killed', 0)}/{scored})")

    if survivors:
        print(f"\nsurviving mutants (untested or equivalent behaviour): {len(survivors)}")
        for mutant in survivors[:40]:
            print(f"  {mutant.relpath}:{mutant.line}  {mutant.operator}")
        if len(survivors) > 40:
            print(f"  ... and {len(survivors) - 40} more")
    if report_path:
        import json

        report_path.write_text(
            json.dumps(
                {
                    "total": len(mutants),
                    "tally": tally,
                    "score": (100.0 * tally.get("killed", 0) / scored if scored else None),
                    "survivors": [
                        {
                            "id": m.id,
                            "file": m.relpath,
                            "line": m.line,
                            "operator": m.operator,
                            "replacement": m.replacement[:120],
                        }
                        for m in survivors
                    ],
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        print(f"\nreport written to {report_path}")
    return 0


def parse_shard(spec: str) -> tuple[int, int]:
    """``"3/10"`` -> ``(3, 10)``: shard 3 of 10, counted from 1."""
    try:
        index_text, count_text = spec.split("/")
        index, count = int(index_text), int(count_text)
    except ValueError:
        raise ValueError(f"shard must look like 3/10, not {spec!r}") from None
    if count < 1 or not 1 <= index <= count:
        raise ValueError(f"shard {spec!r} is out of range: need 1 <= index <= count")
    return index, count


def shard_mutations(
    mutations: tuple[Mutation, ...], index: int, count: int
) -> tuple[Mutation, ...]:
    """The mutants shard ``index`` of ``count`` runs, in roster order.

    Every mutant lands in exactly one shard (round-robin over the roster, so
    each shard gets a similar mix), except the equivalent CANARY, which runs in
    every shard: it is what shows a shard's harness can still tell a surviving
    mutant from a killed one. CI derives ``count`` once and feeds the same value
    to every shard, so no mutant can fall between shards.
    """
    canaries = {m.id for m in mutations if m.id == "CANARY"}
    rest = [m for m in mutations if m.id not in canaries]
    if count > len(rest):
        raise ValueError(f"{count} shards for {len(rest)} mutants: some shard would be empty")
    chosen = {m.id for m in rest[index - 1 :: count]} | canaries
    return tuple(m for m in mutations if m.id in chosen)


def curated_mutations(
    scope: str = "all", shard: tuple[int, int] | None = None
) -> tuple[Mutation, ...]:
    """Keep native custody, filesystem and memory mutants on the platform legs.

    Linux still runs every mutant. macOS/Windows repeat the controls whose runtime
    behavior can differ, including every declared platform override and the canary.
    Selecting by module also covers future mutants added to these surfaces.
    """
    if scope not in ("all", "platform"):
        raise ValueError(f"unknown curated scope: {scope}")
    selected = MUTATIONS if scope == "all" else _platform_mutations()
    return selected if shard is None else shard_mutations(selected, *shard)


def _platform_mutations() -> tuple[Mutation, ...]:
    platform_modules = {
        "platform_support.py",
        "memory.py",
        "_filelock.py",
        "adaptive.py",
        "platform_custody.py",
        "windows_dpapi.py",
        "linux_keyring.py",
        "generation_store.py",
    }
    return tuple(
        mutation
        for mutation in MUTATIONS
        if Path(mutation.path).name in platform_modules
        or mutation.expect_on_windows is not None
        or mutation.id == "CANARY"
    )


def _run_curated(verbose: bool, *, scope: str = "all", shard: tuple[int, int] | None = None) -> int:
    mutations = curated_mutations(scope, shard)
    curated_tests = _curated_tests()
    with tempfile.TemporaryDirectory(prefix="fv-mut-curated-") as tmp:
        workdir = Path(tmp) / "repo"
        _copy_repo(workdir)
        if _run_tests(workdir, curated_tests, False) != 0:
            print("[FAIL] the unmutated copy is not green; aborting", file=sys.stderr)
            return 2
        print("[BASELINE] unmutated copy: tests pass\n")
        failures = 0
        print(f"{'id':8} {'result':9} {'expected':9} mutation")
        print("-" * 92)
        for mutation in mutations:
            target = workdir / mutation.path
            original = target.read_text(encoding="utf-8")
            matches = original.count(mutation.find)
            status = anchor_status(matches)
            if status is not None:
                print(f"{mutation.id:8} {status:9} {'-':9} {matches} match(es) in {mutation.path}")
                failures += 1
                continue
            target.write_text(
                original.replace(mutation.find, mutation.replace, 1), encoding="utf-8"
            )
            try:
                # One failing test establishes a kill; survivors still run the
                # complete suite, including the equivalent canary.
                result = _classify(_run_tests(workdir, curated_tests, True))
            finally:
                target.write_text(original, encoding="utf-8")
            expected = expected_result(mutation)
            ok = result == expected
            failures += 0 if ok else 1
            print(
                f"{mutation.id:8} {result:9} {expected:9} [{'OK ' if ok else 'BAD'}] {mutation.why}"
            )
        print("-" * 92)
        if failures:
            print(f"[FAIL] {failures} mutation(s) did not behave as expected")
            return 1
        killed = sum(1 for m in mutations if expected_result(m) == "killed")
        survived = sum(1 for m in mutations if expected_result(m) == "survived")
        print(
            f"[PASS] {killed} behavioural mutants killed; "
            f"{survived} declared equivalent mutant(s) survived"
        )
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("curated", "auto"), default="curated")
    parser.add_argument(
        "--scope", choices=("all", "platform"), default="all", help="curated mutation scope"
    )
    parser.add_argument(
        "--shard",
        metavar="INDEX/COUNT",
        help="curated mode: run only shard INDEX of COUNT (from 1) of the roster",
    )
    parser.add_argument("--paths", nargs="*", default=list(DEFAULT_PATHS))
    parser.add_argument("--list", action="store_true", help="count mutants and exit")
    parser.add_argument("--limit", type=int, default=0, help="cap the number of mutants")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--report", type=Path, default=None, help="write a JSON report")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.mode == "curated":
        try:
            shard = parse_shard(args.shard) if args.shard else None
            mutations = curated_mutations(args.scope, shard)
        except ValueError as exc:
            parser.error(str(exc))
        if args.list:
            for mutation in mutations:
                print(f"{mutation.id} {mutation.path}")
            label = f"{args.scope}, shard {args.shard}" if shard else args.scope
            print(f"TOTAL {len(mutations)} mutants ({label})")
            return 0
        return _run_curated(args.verbose, scope=args.scope, shard=shard)

    if args.scope != "all":
        parser.error("--scope applies only to curated mode")
    if args.shard:
        parser.error("--shard applies only to curated mode")

    mutants = _collect_auto_mutants(tuple(args.paths))
    if args.list:
        per_file: dict[str, int] = {}
        per_op: dict[str, int] = {}
        for mutant in mutants:
            per_file[mutant.relpath] = per_file.get(mutant.relpath, 0) + 1
            per_op[mutant.operator] = per_op.get(mutant.operator, 0) + 1
        for path, count in sorted(per_file.items(), key=lambda kv: -kv[1]):
            print(f"{count:>5}  {path}")
        print()
        for op, count in sorted(per_op.items(), key=lambda kv: -kv[1]):
            print(f"{count:>5}  {op}")
        print(f"\nTOTAL {len(mutants)} mutants")
        return 0

    if args.limit:
        mutants = mutants[: args.limit]
    return _run_auto(mutants, args.jobs, args.report)


if __name__ == "__main__":
    sys.exit(main())

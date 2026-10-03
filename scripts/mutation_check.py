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
        "        if is_linux():\n            provider = LinuxSecretServiceKeyProvider(",
        "        if False:  # MUTANT\n            provider = LinuxSecretServiceKeyProvider(",
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
        "            if crypto_version != CRYPTO_VERSION:",
        "            if False:  # MUTANT",
        "Version check removed - refused anyway by the header AD binding",
        expect="survived",
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
        "                    if all(\n"
        "                        candidate.get_attributes().get(key) == value for key, value "
        "in query.items()\n"
        "                    )",
        "                    if True  # MUTANT",
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
        "DUR-1",
        "src/floorvault/providers/platform_custody.py",
        "        _fsync_directory(path.parent)",
        "        pass  # MUTANT",
        "Published name loses its durability barrier: a power cut after link() "
        "can drop the store entry even though the payload was fsynced",
        expect_on_windows="survived",
    ),
    Mutation(
        "DUR-2",
        "src/floorvault/providers/platform_custody.py",
        "        _fsync_directory(item.parent)",
        "        pass  # MUTANT",
        "A freshly created vault directory's entry is not durable: power loss "
        "can drop the directory the store is about to be published into",
        expect_on_windows="survived",
    ),
    Mutation(
        "DUR-3",
        "src/floorvault/providers/platform_custody.py",
        "    try:\n        os.fsync(descriptor)\n    finally:\n        os.close(descriptor)",
        "    try:\n        pass  # MUTANT\n    finally:\n        os.close(descriptor)",
        "The directory fsync body is neutered: the barrier opens and closes "
        "the directory without flushing its metadata",
        expect_on_windows="survived",
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


def _run_curated(verbose: bool) -> int:
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
        for mutation in MUTATIONS:
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
                result = _classify(_run_tests(workdir, curated_tests, False))
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
        killed = sum(1 for m in MUTATIONS if expected_result(m) == "killed")
        survived = sum(1 for m in MUTATIONS if expected_result(m) == "survived")
        print(
            f"[PASS] {killed} behavioural mutants killed; "
            f"{survived} declared equivalent mutant(s) survived"
        )
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("curated", "auto"), default="curated")
    parser.add_argument("--paths", nargs="*", default=list(DEFAULT_PATHS))
    parser.add_argument("--list", action="store_true", help="count mutants and exit")
    parser.add_argument("--limit", type=int, default=0, help="cap the number of mutants")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--report", type=Path, default=None, help="write a JSON report")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.mode == "curated":
        return _run_curated(args.verbose)

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

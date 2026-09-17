"""Safety tests for the shared protected-file key store.

Two defects are pinned here.

1. Conflation of "unreadable" with "absent". Both platform providers did
   ``except ProtectedStoreError: blob = None``, so ANY read failure - a corrupt
   header, an unexpected key length, a non-0600 mode - was treated as "no store
   yet". The provider then minted a fresh master key and ``write_protected``
   overwrote the existing store via ``os.replace``. Net effect: silent master-key
   rotation and permanent loss of access to everything encrypted under the old
   key. Reproduces on macOS and Linux, not just Windows.

2. A POSIX-only permission test applied unconditionally. ``mode != 0o600`` can
   never pass on Windows, where os.stat() reports a synthesised mode (0o666 for
   a writable file).

The governing rule these tests enforce: a store that exists but cannot be read
must fail loudly, and must never be replaced.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from floorvault import platform_support
from floorvault.providers import linux_keyring as linux_module
from floorvault.providers import platform_custody as custody
from floorvault.providers.base import MissingKeyError
from floorvault.providers.platform_custody import (
    ProtectedStoreError,
    ProtectedStoreHeaderError,
    ProtectedStoreInvalidLength,
    ProtectedStoreMissing,
    read_protected,
    write_protected,
)
from floorvault.providers.windows_dpapi import WindowsDPAPIKeyProvider

_HEADER = b"FLOORWV1"
_KEY = bytes(range(32))


# --------------------------------------------------------------------------
# read_protected: distinguish absent from unreadable
# --------------------------------------------------------------------------


def test_absent_store_raises_the_missing_error(tmp_path):
    with pytest.raises(ProtectedStoreMissing):
        read_protected(tmp_path / "nope.store", header=_HEADER)


def test_missing_error_is_still_a_protected_store_error(tmp_path):
    """Back-compat: existing `except ProtectedStoreError` handlers still catch it."""
    with pytest.raises(ProtectedStoreError):
        read_protected(tmp_path / "nope.store", header=_HEADER)


def test_corrupt_header_is_not_reported_as_missing(tmp_path):
    store = tmp_path / "store"
    store.write_bytes(b"XXXX" + _KEY)
    with pytest.raises(ProtectedStoreError) as excinfo:
        read_protected(store, header=_HEADER)
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_wrong_key_length_is_not_reported_as_missing(tmp_path):
    store = tmp_path / "store"
    store.write_bytes(_HEADER + b"short")
    with pytest.raises(ProtectedStoreError) as excinfo:
        read_protected(store, header=_HEADER)
    assert not isinstance(excinfo.value, ProtectedStoreMissing)


def test_read_protected_round_trips(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    assert read_protected(store, header=_HEADER) == _KEY


def test_read_protected_rejects_non_regular_store(tmp_path):
    store = tmp_path / "store-dir"
    store.mkdir()

    with pytest.raises(ProtectedStoreError, match="regular"):
        read_protected(store, header=_HEADER)


def test_read_protected_normalizes_windows_directory_open_error(tmp_path, monkeypatch):
    """Windows may deny opening a directory before the fstat regular-file check."""
    store = tmp_path / "store-dir"
    store.mkdir()

    real_open = custody.os.open

    def deny_directory(path, flags, *args, **kwargs):
        if Path(path) == store:
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", deny_directory)

    with pytest.raises(ProtectedStoreError, match="regular"):
        read_protected(store, header=_HEADER)


def test_a_symlink_is_refused_where_the_platform_has_no_O_NOFOLLOW(tmp_path, monkeypatch):
    """The flag alone cannot be the control: Windows has no ``O_NOFOLLOW``.

    Found by CI on the windows legs, and it is not a Windows-only defect - it is a
    Windows-only *detection* of a control that was never exercised anywhere.
    ``getattr(os, "O_NOFOLLOW", 0)`` is 0 there, so the reader followed a symlink
    planted at the store path and returned the *target's* bytes as the stored key.
    The path is now ``lstat``-ed and must name the same regular file the descriptor
    holds, which is platform-independent; the flag remains as the POSIX fast path.

    The platform behaviour is simulated on every runner by removing the constant,
    so this cannot silently pass on Linux and macOS again.
    """
    attacker = tmp_path / "attacker-store"
    write_protected(b"A" * 32, attacker, header=_HEADER)
    link = tmp_path / "store"
    link.symlink_to(attacker)

    monkeypatch.delattr(custody.os, "O_NOFOLLOW", raising=False)  # behave like Windows

    with pytest.raises(ProtectedStoreError, match="regular"):
        read_protected(link, header=_HEADER)


def test_read_protected_refuses_a_path_that_reports_a_non_regular_type(tmp_path, monkeypatch):
    """The path-side type check must be killable on every platform, on its own.

    The reader requires the path to name a regular file. On Windows the input that
    used to cover this - a directory - is refused earlier, by the ``except OSError``
    branch of the open, so nothing exercised *this* check there and the mutant that
    deletes it could only die on POSIX. Faking the reported type - and nothing else -
    makes the check observable everywhere: the descriptor still opens the real file,
    so any refusal must come from the path check.
    """
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)

    real_lstat = custody.os.lstat

    def directory_typed(path, *args, **kwargs):
        found = real_lstat(path, *args, **kwargs)
        if Path(path) == store:
            fields = list(found)
            fields[stat.ST_MODE] = stat.S_IFDIR | 0o600
            return os.stat_result(fields)
        return found

    monkeypatch.setattr(custody.os, "lstat", directory_typed)

    with pytest.raises(ProtectedStoreError, match="regular"):
        read_protected(store, header=_HEADER)


def test_store_that_changed_identity_under_the_open_is_refused(tmp_path, monkeypatch):
    """The two stats must agree, so a swap between the check and the open is caught.

    The path is checked with ``lstat`` and the descriptor with ``fstat``; requiring
    them to name the same device and inode closes the window in which the path could
    be repointed after the check. Simulated by reporting a different inode for the
    path than the descriptor holds.
    """
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)

    real_lstat = custody.os.lstat

    def different_object(path, *args, **kwargs):
        found = real_lstat(path, *args, **kwargs)
        if Path(path) == store:
            fields = list(found)
            fields[stat.ST_INO] = found.st_ino + 1
            return os.stat_result(fields)
        return found

    monkeypatch.setattr(custody.os, "lstat", different_object)

    with pytest.raises(ProtectedStoreError, match="identity|changed"):
        read_protected(store, header=_HEADER)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership check")
def test_read_protected_rejects_unexpected_owner(tmp_path, monkeypatch):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    actual_owner = os.stat(store).st_uid
    monkeypatch.setattr(os, "getuid", lambda: actual_owner + 1)

    with pytest.raises(ProtectedStoreError, match="owner"):
        read_protected(store, header=_HEADER)


# --------------------------------------------------------------------------
# read_protected: the permission check is POSIX-only
# --------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_group_or_other_access_is_refused_on_posix(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o640)
    with pytest.raises(ProtectedStoreError, match="0600|group|other"):
        read_protected(store, header=_HEADER)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_owner_only_modes_are_accepted_on_posix(tmp_path):
    for mode in (0o600, 0o400, 0o700):
        store = tmp_path / f"store-{mode:o}"
        write_protected(_KEY, store, header=_HEADER)
        store.chmod(mode)
        assert read_protected(store, header=_HEADER) == _KEY


def test_synthesised_windows_mode_is_not_refused(tmp_path, monkeypatch):
    """Windows reports 0o666 for a writable file whatever its ACL.

    The mode must not be the basis of the decision there. Since the ACL is now
    verified instead, the store is accepted on the strength of an owner-only
    DACL - and the synthesised mode plays no part.
    """
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(
        platform_support,
        "windows_dacl_sids",
        lambda path: (
            frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001"}),
            "S-1-5-21-1-2-3-1001",
        ),
    )
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o666)
    assert read_protected(store, header=_HEADER) == _KEY


def test_windows_store_with_a_world_accessible_acl_is_refused(tmp_path, monkeypatch):
    """The synthesised-mode exemption must not become an ACL exemption."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", True)
    monkeypatch.setattr(
        platform_support,
        "windows_dacl_sids",
        lambda path: (frozenset({"S-1-5-18", "S-1-1-0"}), "S-1-5-18"),
    )
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o600)
    with pytest.raises(ProtectedStoreError, match="ACL"):
        read_protected(store, header=_HEADER)


def test_posix_check_still_refuses_when_not_windows(monkeypatch, tmp_path):
    """Guard against the fix silently disabling the POSIX gate."""
    monkeypatch.setattr(platform_support, "IS_WINDOWS", False)
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.chmod(0o644)
    with pytest.raises(ProtectedStoreError):
        read_protected(store, header=_HEADER)


# --------------------------------------------------------------------------
# write_protected: never clobber an existing store
# --------------------------------------------------------------------------


def test_write_protected_refuses_to_overwrite(tmp_path):
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    before = store.read_bytes()
    with pytest.raises(ProtectedStoreError, match="exist"):
        write_protected(b"\xff" * 32, store, header=_HEADER)
    assert store.read_bytes() == before


def test_write_protected_rejects_a_wrong_length_key(tmp_path):
    store = tmp_path / "store"
    with pytest.raises(ProtectedStoreError, match="32 bytes"):
        write_protected(b"too-short", store, header=_HEADER)
    assert not store.exists()


def test_write_protected_leaves_nothing_behind_when_the_write_fails(tmp_path, monkeypatch):
    """A failure mid-write must not leave a half-written key or a temp file."""
    store = tmp_path / "store"

    def explode(_fd):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(custody.os, "fsync", explode)
    with pytest.raises(OSError):
        write_protected(_KEY, store, header=_HEADER)

    assert not store.exists()
    assert list(tmp_path.glob(".*tmp")) == []


def test_write_protected_does_not_check_then_use_the_destination(tmp_path, monkeypatch):
    """Pin the absence of a TOCTOU-shaped guard.

    The clobber decision must come from ``os.link`` failing (an OS-level atomic
    operation), not from a prior ``path.exists()`` on the destination. If someone
    reintroduces check-then-use, this fails.
    """
    store = tmp_path / "store"
    real_exists = Path.exists

    def guarded_exists(self: Path) -> bool:
        if self == store:
            raise AssertionError("write_protected consulted destination existence (TOCTOU shape)")
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", guarded_exists)
    write_protected(_KEY, store, header=_HEADER)
    assert read_protected(store, header=_HEADER) == _KEY


def test_concurrent_first_run_has_exactly_one_winner(tmp_path):
    """Four processes racing to create the store: exactly one may win.

    This is the realistic failure mode behind the TOCTOU guard - not an
    attacker, just two services starting at once, both seeing "no store yet".
    With check-then-replace all four could report success and the last would
    silently rotate the key.
    """
    store = tmp_path / "store"
    repo_src = str(Path(__file__).resolve().parent.parent / "src")
    env = {**os.environ, "PYTHONPATH": repo_src, "PYTHONDONTWRITEBYTECODE": "1"}

    child = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path
        from floorvault.providers.platform_custody import (
            ProtectedStoreError, write_protected,
        )

        index = int(sys.argv[1])
        try:
            write_protected(bytes([index]) * 32, Path({str(store)!r}), header=b"FLOORWV1")
        except ProtectedStoreError:
            sys.exit(2)
        print(index)
        """
    )

    children = [
        subprocess.Popen(
            [sys.executable, "-c", child, str(i)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(1, 5)
    ]
    outcomes = []
    for process in children:
        out, _err = process.communicate()
        outcomes.append((process.returncode, out.strip()))
    winners = [out for code, out in outcomes if code == 0]

    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {outcomes}"

    stored = read_protected(store, header=b"FLOORWV1")
    assert stored == bytes([int(winners[0])]) * 32, "store does not hold the winner's key"


# --------------------------------------------------------------------------
# Providers: a corrupt store must never rotate the key
# --------------------------------------------------------------------------


def test_windows_dpapi_does_not_rotate_on_a_non_0600_store(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX permission bits")
    store = tmp_path / "winstore"
    provider = WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy")
    provider.resolve_key(allow_create=True)
    store.chmod(0o640)
    corrupted = store.read_bytes()

    with pytest.raises(ProtectedStoreError):
        WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(allow_create=True)
    assert store.read_bytes() == corrupted


def test_windows_dpapi_still_creates_when_genuinely_absent(tmp_path):
    store = tmp_path / "winstore"
    key = WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(
        allow_create=True
    )
    assert len(key.get_bytes()) == 32
    assert store.exists()


def test_windows_dpapi_fails_closed_when_absent_and_create_disallowed(tmp_path):
    from floorvault.providers.base import MissingKeyError

    store = tmp_path / "winstore"
    with pytest.raises(MissingKeyError):
        WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy").resolve_key(
            allow_create=False
        )


def _build(provider_name: str, store):
    if provider_name == "windows_dpapi":
        return WindowsDPAPIKeyProvider(store_path=store, entropy=b"entropy")
    return linux_module.LinuxSecretServiceKeyProvider(store_path=store)


@pytest.mark.parametrize("provider_name", ["windows_dpapi", "linux_keyring"])
def test_corrupt_store_is_never_reported_as_absent(provider_name, tmp_path, monkeypatch):
    """The READ must be what refuses a corrupt store - not the write guard.

    A mutant that swallows the read error takes the create path and only then
    hits write_protected's no-clobber guard, which raises ProtectedStoreError
    too. Asserting merely "a ProtectedStoreError was raised" therefore passes for
    the wrong reason - mutation testing found exactly this gap - so pin both
    halves:

      1. the failure is the read's (header/length/permission), not the guard's;
      2. a corrupt store is not a *missing* one, so allow_create=False must not
         report MissingKeyError.
    """
    monkeypatch.setattr(linux_module, "_looks_interactive_desktop", lambda: False)
    store = tmp_path / "store"
    _build(provider_name, store).resolve_key(allow_create=True)

    # A store that exists but cannot be parsed.
    store.write_bytes(b"XXXX" + b"\x00" * 32)

    # 1. Fails on the read, not on the write guard. The header is asserted
    #    specifically: a base-class assertion here would also be satisfied by the
    #    length check further down, which is how a mutant that removed the header
    #    raise survived.
    with pytest.raises(ProtectedStoreHeaderError, match="header"):
        _build(provider_name, store).resolve_key(allow_create=True)

    # 2. Unreadable is not absent.
    with pytest.raises(ProtectedStoreError) as excinfo:
        _build(provider_name, store).resolve_key(allow_create=False)
    assert not isinstance(excinfo.value, MissingKeyError)


@pytest.mark.parametrize("provider_name", ["windows_dpapi", "linux_keyring"])
def test_corrupt_store_is_left_byte_identical(provider_name, tmp_path, monkeypatch):
    """A failed resolve must never modify the store."""
    monkeypatch.setattr(linux_module, "_looks_interactive_desktop", lambda: False)
    store = tmp_path / "store"
    _build(provider_name, store).resolve_key(allow_create=True)
    store.write_bytes(b"XXXX" + b"not-a-valid-payload")
    corrupted = store.read_bytes()

    with pytest.raises(ProtectedStoreError):
        _build(provider_name, store).resolve_key(allow_create=True)

    assert store.read_bytes() == corrupted


# --------------------------------------------------------------------------
# Filesystem assumptions behind the atomic publish
# --------------------------------------------------------------------------


def test_temporary_file_is_created_in_the_store_directory(tmp_path, monkeypatch):
    """The atomic publish is os.link, which only works within one filesystem.

    A temporary file in TMPDIR could sit on a different mount and would fail
    with EXDEV, forcing the non-atomic fallback. The temp - and therefore the
    link source - must be created next to the store itself.
    """
    store = tmp_path / "store"
    opened: list[str] = []
    links: list[tuple[str, str]] = []
    real_open = os.open
    real_link = os.link

    def recording_open(path, flags, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    def recording_link(source, destination, *args, **kwargs):
        links.append((os.fspath(source), os.fspath(destination)))
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", recording_open)
    monkeypatch.setattr(custody.os, "link", recording_link)
    write_protected(_KEY, store, header=_HEADER)

    assert opened, "no file was opened during the write"
    for path in opened:
        assert Path(path).parent == store.parent, f"temp {path} is not beside the store"

    # The link source is what makes the publish atomic; it must share the
    # store's directory (and so its filesystem) or EXDEV would force the
    # non-atomic fallback.
    assert links, "the atomic publish did not run (hard links unavailable?)"
    for source, destination in links:
        assert Path(source).parent == store.parent, f"link source {source} is not beside the store"
        assert Path(destination) == store


def test_store_directory_is_created_owner_only(tmp_path, monkeypatch):
    """Every created component must be requested 0o700.

    Asserts the mode handed to ``mkdir``, which is meaningful on every platform,
    and additionally the resulting mode on POSIX (Windows ignores the argument
    and synthesises a mode from the ACL, so asserting 0o700 there would fail for
    a reason unrelated to this property).

    Uses umask 022 rather than 077 on purpose: 0o077 would mask an injected
    other-execute bit and hide the regression this asserts against.
    """
    requested: list[tuple[str, int]] = []
    real_mkdir = Path.mkdir

    def recording_mkdir(self, mode=0o777, parents=False, exist_ok=False):
        requested.append((self.name, mode))
        return real_mkdir(self, mode, parents, exist_ok)

    monkeypatch.setattr(Path, "mkdir", recording_mkdir)
    previous = os.umask(0o022)
    try:
        write_protected(_KEY, tmp_path / "nested" / "deep" / "store", header=_HEADER)
    finally:
        os.umask(previous)

    assert requested, "no directory was created"
    for name, mode in requested:
        assert stat.S_IMODE(mode) == 0o700, f"{name} was requested mode {oct(mode)}"

    if not platform_support.is_windows():
        for directory in (tmp_path / "nested", tmp_path / "nested" / "deep"):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700, directory


def test_writing_into_an_existing_directory_is_allowed(tmp_path):
    """`exist_ok=True`: the directory may already exist (store deleted, dir left)."""
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    store.unlink()
    assert store.parent.is_dir()

    write_protected(b"\x22" * 32, store, header=_HEADER)
    assert read_protected(store, header=_HEADER) == b"\x22" * 32


def test_invalid_key_length_raises_its_own_error_type(tmp_path):
    """A distinct type so a test can pin *which* check fired.

    The store is chmod'd to 0600 first: otherwise the permission check would
    raise a generic ProtectedStoreError and mask a broken length check.
    """
    store = tmp_path / "store"
    store.write_bytes(_HEADER + b"short")
    store.chmod(0o600)

    with pytest.raises(ProtectedStoreInvalidLength):
        read_protected(store, header=_HEADER)


def test_invalid_length_is_also_a_protected_store_error(tmp_path):
    """Back-compat: existing `except ProtectedStoreError` handlers still catch it."""
    store = tmp_path / "store"
    store.write_bytes(_HEADER + b"short")
    store.chmod(0o600)

    with pytest.raises(ProtectedStoreError):
        read_protected(store, header=_HEADER)


def test_invalid_header_raises_its_own_error_type(tmp_path):
    """The header check runs first, so it cannot be pinned by the base class.

    With a base-class assertion the length check below satisfies the expectation
    instead, and a mutant that deletes the header raise survives.
    """
    store = tmp_path / "store"
    store.write_bytes(b"XXXXXXXX" + b"\x00" * 32)
    store.chmod(0o600)

    with pytest.raises(ProtectedStoreHeaderError):
        read_protected(store, header=_HEADER)


def test_opaque_payload_store_round_trips_a_variable_length_blob(tmp_path):
    """The Windows DPAPI blob is not 32 bytes, but the store must carry it.

    CryptProtectData chooses the payload size, so the Windows provider stores an
    opaque blob. The 32-byte invariant still applies to the RECOVERED key, which
    the provider verifies after unprotection - the correct place for it. This
    mismatch is what made every Windows DPAPI test fail on the windows-latest CI
    leg with "master key must be exactly 32 bytes".
    """
    store = tmp_path / "store"
    blob = b"\x01" + os.urandom(180)
    assert len(blob) != 32

    write_protected(blob, store, header=_HEADER, expected_length=None)

    assert read_protected(store, header=_HEADER, expected_length=None) == blob


def test_default_expectation_still_refuses_a_wrong_length_payload(tmp_path):
    """The strong 32-byte check must stay the default for key material."""
    store = tmp_path / "store"

    with pytest.raises(ProtectedStoreInvalidLength):
        write_protected(b"\x02" * 180, store, header=_HEADER)


def test_opaque_payload_store_refuses_an_empty_payload(tmp_path):
    """Opting out of the length check must not mean accepting nothing."""
    store = tmp_path / "store"

    with pytest.raises(ProtectedStoreInvalidLength, match="empty"):
        write_protected(b"", store, header=_HEADER, expected_length=None)


def test_store_larger_than_the_read_buffer_is_refused(tmp_path):
    """A partial read must never be validated as though it were the whole store.

    With a fixed expected length a truncated read failed the length check anyway;
    with an opaque payload it would otherwise be a silent truncation.
    """
    store = tmp_path / "store"
    store.write_bytes(_HEADER + b"\x03" * 8192)
    store.chmod(0o600)

    with pytest.raises(ProtectedStoreError, match="read buffer"):
        read_protected(store, header=_HEADER, expected_length=None)


def test_fallback_publish_refuses_to_replace_an_existing_store(tmp_path, monkeypatch):
    """Without hard links the publish is check-then-replace, so it must still refuse.

    Monkeypatches os.link to raise OSError, the way a FAT or some network volume
    behaves. The no-clobber check in that fallback is the only thing standing
    between a second writer and the first writer's key.
    """
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    original = store.read_bytes()

    def hard_links_unavailable(*_args, **_kwargs):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(custody.os, "link", hard_links_unavailable)

    with pytest.raises(ProtectedStoreError, match="refusing to overwrite"):
        write_protected(b"\x33" * 32, store, header=_HEADER)

    assert store.read_bytes() == original, "the fallback clobbered an existing store"


def test_store_io_requests_binary_mode_on_windows(tmp_path, monkeypatch):
    """Windows text mode would mangle or truncate key material.

    os.open without O_BINARY leaves the descriptor in TEXT mode on Windows: the C
    runtime expands "\\n" to "\\r\\n" on write and stops reading at the 0x1A
    (Ctrl-Z) byte. Key stores are uniformly random bytes, so this broke the
    windows-latest CI leg with "unexpected length" on read and "must be exactly
    32 bytes" on the next write.

    The helper is substituted with a synthetic bit that is stripped again before
    the real syscall: every plausible sentinel is a genuine flag somewhere
    (0x8000 is O_BINARY on Windows but O_EVTONLY on macOS), so passing it through
    to a live os.open would make the test depend on unrelated kernel behaviour.
    """
    sentinel = 0x40000000  # a bit no platform treats as a harmless no-op
    monkeypatch.setattr(custody, "binary_mode_flag", lambda: sentinel)

    seen: list[int] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        seen.append(flags)
        # Record what the code asked for, then substitute the platform's REAL
        # binary flag for the simulated one before the syscall. Stripping the
        # sentinel without restoring O_BINARY would leave the descriptor in text
        # mode on Windows and the round-trip below would fail for the very reason
        # this test is about.
        real_flags = (flags & ~sentinel) | getattr(os, "O_BINARY", 0)
        return real_open(path, real_flags, *args, **kwargs)

    monkeypatch.setattr(custody.os, "open", recording_open)
    store = tmp_path / "store"
    write_protected(_KEY, store, header=_HEADER)
    assert read_protected(store, header=_HEADER) == _KEY

    assert seen, "no os.open was recorded"
    for flags in seen:
        assert flags & sentinel, f"store opened without the binary-mode flag: {flags:#x}"


def test_creation_tolerates_a_directory_appearing_after_the_check(tmp_path, monkeypatch):
    """exist_ok=True exists for a real race, not as decoration.

    Another process can create the directory between our existence scan and our
    mkdir; without the flag that raises FileExistsError and the store cannot be
    created at all. Simulated by making the scan report a directory as missing
    while it is really there.
    """
    target = tmp_path / "nested"
    target.mkdir()
    real_exists = Path.exists

    def lying_exists(self):
        if self == target:
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", lying_exists)

    write_protected(_KEY, target / "store", header=_HEADER)
    assert read_protected(target / "store", header=_HEADER) == _KEY

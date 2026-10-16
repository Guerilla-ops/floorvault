"""Passphrase-wrapped Tier-3 custody (FVPW1, SPEC.md §10.8).

Regression for the SECURITY.md §5 limit "the file-based key fallbacks are not a
confidentiality boundary": with ``passphrase=`` a copy of the key directory
alone must not yield the master key.
"""

from __future__ import annotations

import os
import warnings

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from floorvault.providers import adaptive as adaptive_module
from floorvault.providers import passphrase_store
from floorvault.providers.adaptive import (
    TIER3_LOCK_FILENAME,
    WRAPPED_KEY_FILENAME,
    AdaptiveKeyProvider,
    protect_key_file,
)
from floorvault.providers.base import KeyProviderError

PASSPHRASE = "correct horse battery staple"
_MODULE_DEFAULT_LOG2_N = passphrase_store.DEFAULT_LOG2_N


@pytest.fixture(autouse=True)
def _tier3_only(monkeypatch):
    """Reach Tier 3 deterministically, at the cheapest permitted work factor."""
    for name in ("FLOOR_VAULT_KEY", "VAULT_MASTER_KEY", "APPSTATE_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(adaptive_module, "is_macos", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_windows", lambda: False)
    monkeypatch.setattr(adaptive_module, "is_linux", lambda: False)
    monkeypatch.setattr(passphrase_store, "DEFAULT_LOG2_N", passphrase_store.MIN_LOG2_N)
    warnings.simplefilter("ignore", UserWarning)


def _provider(tmp_path, **kwargs):
    return AdaptiveKeyProvider(fallback_dir=tmp_path, allow_disk_fallback=True, **kwargs)


def _key(handle) -> bytes:
    return bytes(handle.get_buffer())


def _stores(directory) -> list[str]:
    """Key-store files in ``directory``, ignoring the creation lock file."""
    return sorted(p.name for p in directory.iterdir() if p.name != TIER3_LOCK_FILENAME)


def test_new_key_is_written_wrapped_only(tmp_path):
    key = _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key())

    assert _stores(tmp_path) == [WRAPPED_KEY_FILENAME]
    stored = (tmp_path / WRAPPED_KEY_FILENAME).read_bytes()
    assert stored.startswith(b"FVPW1")
    assert len(stored) == 5 + passphrase_store.PAYLOAD_BYTES
    assert key not in stored


def test_same_passphrase_recovers_the_same_key(tmp_path):
    first = _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key())
    second = _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key(allow_create=False))
    assert first == second


def test_wrong_passphrase_is_refused(tmp_path):
    _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
    with pytest.raises(KeyProviderError, match="wrong passphrase"):
        _provider(tmp_path, passphrase="not it").resolve_key()


def test_wrapped_store_without_passphrase_never_forks_a_raw_key(tmp_path):
    """Resolving without the passphrase must refuse, not create master.key."""
    _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
    with pytest.raises(KeyProviderError, match="passphrase-protected"):
        _provider(tmp_path).resolve_key()
    assert not (tmp_path / "master.key").exists()


def test_raw_key_beside_wrapped_store_is_refused(tmp_path):
    raw = _key(_provider(tmp_path).resolve_key())
    with pytest.raises(KeyProviderError, match="unwrapped key file exists"):
        _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
    # Nothing was created: the raw key is still the only store.
    assert _stores(tmp_path) == ["master.key"]
    assert (tmp_path / "master.key").read_bytes() == raw


@pytest.mark.parametrize("passphrase", [None, PASSPHRASE])
def test_both_stores_present_is_refused_either_way(tmp_path, passphrase):
    """A raw copy beside the wrapped store is refused with or without the passphrase."""
    raw = _key(_provider(tmp_path).resolve_key())
    protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    (tmp_path / "master.key").write_bytes(raw)
    os.chmod(tmp_path / "master.key", 0o600)
    with pytest.raises(KeyProviderError, match="passphrase-protected|unwrapped key file exists"):
        _provider(tmp_path, passphrase=passphrase).resolve_key()


def test_allow_create_false_does_not_create(tmp_path):
    with pytest.raises(KeyProviderError, match="not found"):
        _provider(tmp_path, passphrase=PASSPHRASE).resolve_key(allow_create=False)
    assert _stores(tmp_path) == []


@pytest.mark.parametrize("bad", ["", b""])
def test_empty_passphrase_is_refused_at_construction(tmp_path, bad):
    with pytest.raises(ValueError, match="must not be empty"):
        _provider(tmp_path, passphrase=bad)


def test_strict_mode_still_refuses_tier3(tmp_path):
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True, passphrase=PASSPHRASE)
    with pytest.raises(KeyProviderError):
        provider.resolve_key()
    assert _stores(tmp_path) == []


def test_protect_key_file_keeps_the_key_and_removes_the_raw_copy(tmp_path):
    raw = _key(_provider(tmp_path).resolve_key())

    wrapped = protect_key_file(PASSPHRASE, fallback_dir=tmp_path)

    assert wrapped == tmp_path / WRAPPED_KEY_FILENAME
    assert _stores(tmp_path) == [WRAPPED_KEY_FILENAME]
    assert _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key()) == raw


def test_protect_key_file_accepts_a_hex_key_file(tmp_path):
    hex_key = os.urandom(32)
    (tmp_path / "master.key").write_bytes(hex_key.hex().encode("ascii"))
    os.chmod(tmp_path / "master.key", 0o600)
    protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    assert _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key()) == hex_key


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="needs POSIX permissions enforced on the owner (root bypasses mode 0400)",
)
def test_protect_key_file_on_a_read_only_key_changes_nothing(tmp_path):
    """Review finding: a 0400 raw key must fail before the wrapped copy exists."""
    raw = _key(_provider(tmp_path).resolve_key())
    os.chmod(tmp_path / "master.key", 0o400)

    with pytest.raises(KeyProviderError, match="nothing was changed"):
        protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    assert _stores(tmp_path) == ["master.key"]

    os.chmod(tmp_path / "master.key", 0o600)
    protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    assert _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key()) == raw


def test_protect_key_file_refuses_without_a_raw_key(tmp_path):
    with pytest.raises(KeyProviderError, match="no raw key file"):
        protect_key_file(PASSPHRASE, fallback_dir=tmp_path)


def test_protect_key_file_refuses_an_existing_wrapped_store(tmp_path):
    _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
    (tmp_path / "master.key").write_bytes(os.urandom(32))
    os.chmod(tmp_path / "master.key", 0o600)
    with pytest.raises(KeyProviderError, match="overwrite"):
        protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    # The raw copy is left for the operator to resolve, not destroyed.
    assert (tmp_path / "master.key").exists()


# -- format -------------------------------------------------------------------


def test_format_matches_an_independent_derivation():
    """Pin SPEC §10.8 byte layout with a from-spec unwrap."""
    master = bytes(range(32))
    payload = passphrase_store.wrap(master, PASSPHRASE, log2_n=15)
    log2_n, r, p, salt, siv = payload[0], payload[1], payload[2], payload[3:19], payload[19:]
    assert (log2_n, r, p, len(salt), len(siv)) == (15, 8, 1, 16, 48)
    kek = Scrypt(salt=salt, length=64, n=2**15, r=8, p=1).derive(PASSPHRASE.encode())
    assert AESSIV(kek).decrypt(siv, [b"FVPW1" + payload[:19]]) == master


def test_text_passphrases_are_nfc_normalised():
    decomposed, composed = "café", "café"
    payload = passphrase_store.wrap(b"k" * 32, decomposed, log2_n=15)
    assert bytes(passphrase_store.unwrap(payload, composed)) == b"k" * 32


@pytest.mark.parametrize("offset", [0, 1, 2, 3, 18, 19, 66])
def test_any_flipped_byte_fails_closed(offset):
    payload = bytearray(passphrase_store.wrap(b"k" * 32, PASSPHRASE, log2_n=15))
    payload[offset] ^= 0x01
    with pytest.raises(passphrase_store.PassphraseStoreError):
        passphrase_store.unwrap(bytes(payload), PASSPHRASE)


@pytest.mark.parametrize(
    "params",
    [
        bytes([passphrase_store.MIN_LOG2_N - 1, 8, 1]),  # downgraded work factor
        bytes([passphrase_store.MAX_LOG2_N + 1, 8, 1]),  # memory-exhaustion lever
        bytes([15, 1, 1]),
        bytes([15, 8, 2]),
    ],
)
def test_out_of_bounds_parameters_are_refused_before_deriving(params, monkeypatch):
    def _no_derive(*_args, **_kwargs):
        raise AssertionError("scrypt must not run on out-of-bounds parameters")

    payload = params + bytes(16 + 48)
    monkeypatch.setattr(passphrase_store, "_kek", _no_derive)
    with pytest.raises(passphrase_store.PassphraseStoreError, match="out-of-bounds"):
        passphrase_store.unwrap(payload, PASSPHRASE)


def test_wrong_length_payload_is_refused():
    with pytest.raises(passphrase_store.PassphraseStoreError, match="wrong length"):
        passphrase_store.unwrap(b"\x0f\x08\x01", PASSPHRASE)


def test_wrap_refuses_bad_inputs():
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        passphrase_store.wrap(b"k" * 31, PASSPHRASE)
    with pytest.raises(ValueError, match="log2_n"):
        passphrase_store.wrap(b"k" * 32, PASSPHRASE, log2_n=passphrase_store.MIN_LOG2_N - 1)
    with pytest.raises(TypeError):
        passphrase_store.wrap(b"k" * 32, 1234)


def test_default_work_factor_is_owasp_minimum():
    # Captured at import, before the autouse fixture lowers it for speed.
    assert _MODULE_DEFAULT_LOG2_N == 17
    assert passphrase_store.MIN_LOG2_N <= _MODULE_DEFAULT_LOG2_N <= passphrase_store.MAX_LOG2_N


def test_mixed_mode_creation_race_cannot_fork_the_key(tmp_path, monkeypatch):
    """Review finding: a passphrase resolver and a raw resolver racing on first
    creation must not each publish a different key under different names."""
    real_lock = AdaptiveKeyProvider._tier3_creation_lock

    def lock_after_rival_created_wrapped(self):
        # The rival (passphrase) resolver wins the race while this raw
        # resolver is between its absence check and taking the lock.
        monkeypatch.setattr(AdaptiveKeyProvider, "_tier3_creation_lock", real_lock)
        _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
        return real_lock(self)

    monkeypatch.setattr(
        AdaptiveKeyProvider, "_tier3_creation_lock", lock_after_rival_created_wrapped
    )
    with pytest.raises(KeyProviderError, match="passphrase-protected"):
        _provider(tmp_path).resolve_key()
    assert _stores(tmp_path) == [WRAPPED_KEY_FILENAME]


def test_mixed_mode_race_the_other_way_round(tmp_path, monkeypatch):
    real_lock = AdaptiveKeyProvider._tier3_creation_lock

    def lock_after_rival_created_raw(self):
        monkeypatch.setattr(AdaptiveKeyProvider, "_tier3_creation_lock", real_lock)
        _provider(tmp_path).resolve_key()
        return real_lock(self)

    monkeypatch.setattr(AdaptiveKeyProvider, "_tier3_creation_lock", lock_after_rival_created_raw)
    with pytest.raises(KeyProviderError, match="unwrapped key file exists"):
        _provider(tmp_path, passphrase=PASSPHRASE).resolve_key()
    assert _stores(tmp_path) == ["master.key"]


@pytest.mark.parametrize(("passphrase", "expected"), [(None, True), (PASSPHRASE, False)])
def test_linux_masked_file_fallback_is_off_with_a_passphrase(
    tmp_path, monkeypatch, passphrase, expected
):
    """Review finding: with passphrase=, the Secret Service tier must not fall
    back to its publicly masked master.key.ss."""
    seen = {}

    class _FakeSecretService:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        @staticmethod
        def default_store_path(directory):
            return directory / "master.key.ss"

        def _secret_service_available(self):
            return False

    monkeypatch.setattr(adaptive_module, "is_linux", lambda: True)
    monkeypatch.setattr(adaptive_module, "LinuxSecretServiceKeyProvider", _FakeSecretService)
    _provider(tmp_path, passphrase=passphrase).resolve_key()
    assert seen["allow_file_fallback"] is expected

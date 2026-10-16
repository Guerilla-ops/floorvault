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


def test_new_key_is_written_wrapped_only(tmp_path):
    key = _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key())

    assert sorted(p.name for p in tmp_path.iterdir()) == [WRAPPED_KEY_FILENAME]
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
    assert sorted(p.name for p in tmp_path.iterdir()) == ["master.key"]
    assert (tmp_path / "master.key").read_bytes() == raw


def test_allow_create_false_does_not_create(tmp_path):
    with pytest.raises(KeyProviderError, match="not found"):
        _provider(tmp_path, passphrase=PASSPHRASE).resolve_key(allow_create=False)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("bad", ["", b""])
def test_empty_passphrase_is_refused_at_construction(tmp_path, bad):
    with pytest.raises(ValueError, match="must not be empty"):
        _provider(tmp_path, passphrase=bad)


def test_strict_mode_still_refuses_tier3(tmp_path):
    provider = AdaptiveKeyProvider(fallback_dir=tmp_path, strict=True, passphrase=PASSPHRASE)
    with pytest.raises(KeyProviderError):
        provider.resolve_key()
    assert list(tmp_path.iterdir()) == []


def test_protect_key_file_keeps_the_key_and_removes_the_raw_copy(tmp_path):
    raw = _key(_provider(tmp_path).resolve_key())

    wrapped = protect_key_file(PASSPHRASE, fallback_dir=tmp_path)

    assert wrapped == tmp_path / WRAPPED_KEY_FILENAME
    assert sorted(p.name for p in tmp_path.iterdir()) == [WRAPPED_KEY_FILENAME]
    assert _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key()) == raw


def test_protect_key_file_accepts_a_hex_key_file(tmp_path):
    hex_key = os.urandom(32)
    (tmp_path / "master.key").write_bytes(hex_key.hex().encode("ascii"))
    os.chmod(tmp_path / "master.key", 0o600)
    protect_key_file(PASSPHRASE, fallback_dir=tmp_path)
    assert _key(_provider(tmp_path, passphrase=PASSPHRASE).resolve_key()) == hex_key


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

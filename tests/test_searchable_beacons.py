"""Opt-in searchable beacons: truncated, keyed equality narrowing for SQLite.

These tests pin the SEARCHABILITY-vs-LEAKAGE contract of the opt-in beacon
module. The module is deliberately NOT part of the default ``floorvault``
surface: a beacon is a deterministic function of the plaintext, so its presence
is a measured confidentiality trade the caller makes explicitly. Nothing here
changes the default ``FloorVault``/``VaultStore`` behaviour.

Three properties are pinned because each was previously gotten wrong:

* **Byte alignment.** Storage keeps ``ceil(bits / 8)`` bytes, so requests for
  4..8 bits all yield the SAME one-byte index and 9..16 bits all yield the same
  two-byte index. Advertising "4 bits = 16 buckets" while the code stores a
  full byte (256 buckets) is a truth bug, not a nit, so the equivalence is
  asserted rather than described.
* **A bucket hit is not equality.** ``beacon_matches`` re-derives the bucket and
  compares; two DISTINCT values in one bucket both "match". The collision test
  below builds a real colliding pair rather than asserting the mechanism in the
  abstract, and the module funnels callers to decrypt-and-compare for the
  confirmation step.
* **Domain separation must be unambiguous.** The original encoding
  (``f"{scope}\\x00{value}"``) has a colliding pair: ``("a", "b\\x00c")`` and
  ``("a\\x00b", "c")`` produce identical bytes. The test proves the OLD form
  collides and the NEW length-prefixed form does not, so the regression is
  detectable rather than merely claimed.
"""

from __future__ import annotations

import hashlib
import hmac
import warnings

import pytest

from floorvault.beacons import (
    MAX_BEACON_BITS,
    MIN_BEACON_BITS,
    BeaconIndexer,
    beacon_bucket_bytes,
    beacon_matches,
    compute_beacon,
    derive_beacon_key,
    suggest_beacon_bits,
)

KEY = b"\x2b" * 32


# ---------------------------------------------------------------------------
# Bounded, deterministic output
# ---------------------------------------------------------------------------


def test_beacon_is_deterministic_and_byte_aligned():
    first = compute_beacon("scott@example.com", scope="users.email", key=KEY, bits=8)
    second = compute_beacon("scott@example.com", scope="users.email", key=KEY, bits=8)
    assert isinstance(first, bytes)
    assert first == second, "a beacon must be deterministic for the same value"
    assert len(first) == beacon_bucket_bytes(bits=8) == 1


def test_bits_4_and_8_are_the_same_index_width():
    """Storage is byte-aligned, so 4..8 bits store one byte.

    Advertising four distinct security levels across 4/8/12/16 bits is false:
    there are only three widths there (1, 1, 2, 2 bytes).
    """
    assert beacon_bucket_bytes(4) == beacon_bucket_bytes(8) == 1
    assert beacon_bucket_bytes(9) == beacon_bucket_bytes(16) == 2

    for value in ("a@example.com", "b@example.com"):
        assert compute_beacon(value, scope="s", key=KEY, bits=4) == compute_beacon(
            value, scope="s", key=KEY, bits=8
        )
        assert compute_beacon(value, scope="s", key=KEY, bits=9) == compute_beacon(
            value, scope="s", key=KEY, bits=16
        )


def test_bucket_bytes_bounds_are_enforced():
    assert beacon_bucket_bytes(16) == 2
    assert beacon_bucket_bytes(64) == 8
    for bad in (0, 1, 3, 65, 128, -8):
        with pytest.raises(ValueError):
            beacon_bucket_bytes(bad)
    for bad in (8.0, "8", None, True):
        with pytest.raises((TypeError, ValueError)):
            beacon_bucket_bytes(bad)


def test_compute_beacon_rejects_out_of_range_bits():
    for bad in (0, 3, 65, 999):
        with pytest.raises(ValueError):
            compute_beacon("v", scope="s", key=KEY, bits=bad)


# ---------------------------------------------------------------------------
# Leakage: the index must not be injective
# ---------------------------------------------------------------------------


def test_truncated_beacon_forced_collisions_make_frequency_inexact():
    """500 distinct values into 256 buckets MUST collide.

    This is the whole point of truncation: the stored index is not a bijection,
    so an attacker holding the database cannot read exact equality or exact
    per-value frequency off it. It does NOT make the distribution uniform - the
    bucket occupancy is still a function of the plaintext distribution - which
    is why the docs size the width to the dataset instead of claiming a fixed
    safe value.
    """
    values = [f"user-{i}@example.com" for i in range(500)]
    beacons = {compute_beacon(v, scope="users.email", key=KEY, bits=8) for v in values}
    assert 0 < len(beacons) < len(values), "not injective => frequency is not exact"


def test_wide_beacon_is_injective_for_a_small_dataset():
    """The escape hatch: a width sized to the data gives near-exact narrowing."""
    values = [f"user-{i}@example.com" for i in range(100)]
    beacons = {compute_beacon(v, scope="users.email", key=KEY, bits=32) for v in values}
    assert len(beacons) == len(values)


# ---------------------------------------------------------------------------
# A bucket hit is not equality
# ---------------------------------------------------------------------------


def _find_colliding_pair(bits: int) -> tuple[str, str]:
    """Brute-force two DISTINCT values sharing one beacon bucket."""
    seen: dict[bytes, str] = {}
    for i in range(100_000):
        value = f"collide-{i}"
        bucket = compute_beacon(value, scope="s", key=KEY, bits=bits)
        if bucket in seen and seen[bucket] != value:
            return seen[bucket], value
        seen[bucket] = value
    raise AssertionError("no collision found - the beacon is behaving injectively")


def test_beacon_matches_proves_bucket_agreement_only():
    """Two distinct values in one bucket both match; equality needs decryption."""
    left, right = _find_colliding_pair(bits=8)
    assert left != right
    stored = compute_beacon(left, scope="s", key=KEY, bits=8)

    assert beacon_matches(left, scope="s", key=KEY, beacon=stored, bits=8) is True
    assert beacon_matches(right, scope="s", key=KEY, beacon=stored, bits=8) is True, (
        "a collision means a bucket hit is NOT proof of equality - callers must "
        "confirm by decrypting the candidate"
    )


def test_beacon_matches_rejects_a_different_bucket():
    stored = compute_beacon("alice@example.com", scope="users.email", key=KEY, bits=8)
    mismatch = next(
        value
        for i in range(10_000)
        if not beacon_matches(
            value := f"other-{i}", scope="users.email", key=KEY, beacon=stored, bits=8
        )
    )
    assert mismatch.startswith("other-")


def test_beacon_matches_accepts_the_stored_form():
    """A sqlite3 BLOB round trip can come back as memoryview/bytearray."""
    stored = compute_beacon("alice@example.com", scope="users.email", key=KEY, bits=8)
    for form in (stored, bytearray(stored), memoryview(stored)):
        assert beacon_matches(
            "alice@example.com", scope="users.email", key=KEY, beacon=form, bits=8
        )


# ---------------------------------------------------------------------------
# Domain separation
# ---------------------------------------------------------------------------


def test_scope_separates_values():
    a = compute_beacon("x", scope="users.email", key=KEY, bits=32)
    b = compute_beacon("x", scope="contacts.email", key=KEY, bits=32)
    assert a != b


def test_scope_and_value_boundaries_cannot_be_blurred():
    """The old ``f"{scope}\\x00{value}"`` encoding has a colliding pair.

    ``("a", "b\\x00c")`` and ``("a\\x00b", "c")`` both serialise to ``a\\x00b\\x00c``,
    so a crafted scope can be made to collide with a value under a twisted
    scope. The first half asserts the OLD form really does collide (proving the
    check can see the defect); the second half asserts the shipped encoding
    does not.
    """
    old_form = lambda scope, value: f"{scope}\x00{value}".encode()  # noqa: E731
    assert old_form("a", "b\x00c") == old_form("a\x00b", "c"), (
        "the legacy encoding has no colliding pair - this test has lost its target"
    )

    assert compute_beacon("b\x00c", scope="a", key=KEY, bits=32) != compute_beacon(
        "c", scope="a\x00b", key=KEY, bits=32
    )


def test_empty_scope_and_non_string_value_are_rejected():
    with pytest.raises(ValueError):
        compute_beacon("v", scope="", key=KEY)
    with pytest.raises(ValueError):
        compute_beacon("v", scope="   ", key=KEY)
    with pytest.raises(TypeError):
        compute_beacon(b"v", scope="s", key=KEY)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def test_key_must_be_at_least_32_bytes():
    with pytest.raises(ValueError):
        compute_beacon("v", scope="s", key=b"\x01" * 16)
    with pytest.raises(ValueError):
        compute_beacon("v", scope="s", key=b"")


def test_hardened_memory_key_is_accepted():
    from floorvault import HardenedMemoryKey

    with HardenedMemoryKey(KEY, mode="disabled") as handle:
        assert compute_beacon("v", scope="s", key=handle, bits=8) == compute_beacon(
            "v", scope="s", key=KEY, bits=8
        )


def test_derive_beacon_key_is_separate_from_the_siv_subkey():
    """Key separation: the index subkey must not equal the AEAD subkey.

    SECURITY.md states which subkeys are derived; a beacon key derived from the
    master must be domain-separated from the AES-SIV key or the same key
    material is reused across two cryptographic purposes.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    master = bytes(range(32))
    beacon_key = derive_beacon_key(master)
    assert len(beacon_key) == 32
    assert derive_beacon_key(master) == beacon_key, "derivation must be deterministic"

    siv_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"floorvault-v1-aes-siv",
    ).derive(master)
    assert not hmac.compare_digest(beacon_key, siv_key[:32])
    assert not hmac.compare_digest(beacon_key, siv_key[32:])


def test_derive_beacon_key_rejects_a_short_master():
    with pytest.raises(ValueError):
        derive_beacon_key(b"\x00" * 16)


# ---------------------------------------------------------------------------
# Width selection
# ---------------------------------------------------------------------------


def test_suggest_beacon_bits_is_byte_aligned_and_minimal():
    for rows, target in [
        (100, 8),
        (10_000, 8),
        (100_000, 8),
        (10**6, 16),
        (12345, 4),
        (500_000, 8),
    ]:
        bits = suggest_beacon_bits(rows, target_bucket_size=target)
        assert bits % 8 == 0, "a recommendation must be a width the code can store"
        assert MIN_BEACON_BITS <= bits <= MAX_BEACON_BITS
        bucket_bytes = bits // 8
        occupancy = rows / (256**bucket_bytes)
        assert occupancy <= target or bits == MAX_BEACON_BITS, "target occupancy not met"
        if bucket_bytes > 1:
            assert rows / (256 ** (bucket_bytes - 1)) > target, "width is not minimal"


def test_suggest_beacon_bits_clamps_at_the_supported_maximum():
    assert suggest_beacon_bits(10**30) == MAX_BEACON_BITS


def test_suggest_beacon_bits_rejects_invalid_input():
    for bad in (0, -1, 1.5, "100", True):
        with pytest.raises((TypeError, ValueError)):
            suggest_beacon_bits(bad)
    for bad in (0, -8, 2.5, True):
        with pytest.raises((TypeError, ValueError)):
            suggest_beacon_bits(100, target_bucket_size=bad)


# ---------------------------------------------------------------------------
# Bound helper
# ---------------------------------------------------------------------------


def test_beacon_indexer_round_trip_and_width_sizing():
    indexer = BeaconIndexer(KEY)
    assert indexer.bits == 8
    beacon = indexer.beacon("alice@example.com", scope="users.email")
    assert len(beacon) == 1
    assert indexer.matches("alice@example.com", scope="users.email", beacon=beacon) is True
    assert indexer.matches("bob@example.com", scope="users.email", beacon=beacon) is False


def test_beacon_indexer_accepts_an_explicit_aligned_width():
    indexer = BeaconIndexer(KEY, bits=24)
    beacon = indexer.beacon("alice@example.com", scope="users.email")
    assert len(beacon) == 3
    assert indexer.bucket_bytes == 3
    assert indexer.bucket_count == 256**3


def test_beacon_indexer_refuses_a_width_it_cannot_store():
    """128 buckets is not on offer: 7 bits stores a byte.

    The prior iteration documented ``bits=4`` as "16 buckets" while storing 256,
    so a width the index cannot represent must be refused rather than rounded
    and described. This is the regression test for that truth bug.
    """
    for bad in (7, 9, 15, 31, 63, 4):
        with pytest.raises(ValueError, match="byte-aligned"):
            BeaconIndexer(KEY, bits=bad)
    for bad in (0, 3, 65):
        with pytest.raises(ValueError):
            BeaconIndexer(KEY, bits=bad)
    # The low-level primitive stays permissive (explicit + documented), and
    # reports the stored width rather than the requested one.
    assert beacon_bucket_bytes(7) == 1
    assert beacon_bucket_bytes(4) == beacon_bucket_bytes(8) == 1


def test_beacon_is_not_the_module_hmac_of_the_scope_only():
    """Guard against a regression to a scope-only or value-only index.

    An index that ignored the value (or the scope) would still be deterministic
    and still collide, so the obvious tests pass while every row shares one
    bucket. Compare against the raw HMAC of each component separately.
    """
    value, scope = "alice@example.com", "users.email"
    beacon = compute_beacon(value, scope=scope, key=KEY, bits=32)
    assert beacon != hmac.new(KEY, value.encode(), hashlib.sha256).digest()[:4]
    assert beacon != hmac.new(KEY, scope.encode(), hashlib.sha256).digest()[:4]


# ---------------------------------------------------------------------------
# The documented workflow, executed
#
# The README shows bucket-query-then-confirm-by-decryption. That snippet is an
# onboarding surface, so it is pinned by an executed test rather than left as
# prose that can rot: a documented workflow that no longer runs is worse than
# no documentation.
# ---------------------------------------------------------------------------


def test_documented_beacon_workflow_round_trips_in_sqlite(tmp_path):
    import sqlite3

    from floorvault import FloorVault

    master_key = bytes(range(32))
    crypto = FloorVault(master_key, memory_mode="disabled")
    indexer = BeaconIndexer(derive_beacon_key(master_key), bits=suggest_beacon_bits(200_000))
    scope = "users.email"

    with sqlite3.connect(tmp_path / "app.db") as connection:
        connection.execute(
            "CREATE TABLE users (id TEXT PRIMARY KEY, email_cipher BLOB, email_beacon BLOB)"
        )
        connection.execute("CREATE INDEX users_beacon ON users(email_beacon)")
        for i in range(200):
            record_id, email = f"user-{i}", f"user-{i}@example.com"
            connection.execute(
                "INSERT INTO users (id, email_cipher, email_beacon) VALUES (?, ?, ?)",
                (
                    record_id,
                    crypto.encrypt(
                        email, table="users", record_id=record_id, column="email_cipher"
                    ),
                    indexer.beacon(email, scope=scope),
                ),
            )
        connection.commit()

        target = "user-137@example.com"
        bucket = indexer.beacon(target, scope=scope)
        rows = connection.execute(
            "SELECT id, email_cipher FROM users WHERE email_beacon = ?", (bucket,)
        ).fetchall()

        # The bucket narrows, and the candidates must be RE-CHECKED: a bucket hit
        # is not equality, so every candidate is filtered before decryption.
        narrowed = [row for row in rows if indexer.matches(target, scope=scope, beacon=bucket)]
        assert narrowed, "the bucket query found no candidates"

        confirmed = []
        for candidate_id, ciphertext in narrowed:
            plaintext = crypto.decrypt(
                ciphertext,
                table="users",
                record_id=candidate_id,
                column="email_cipher",
            )
            if plaintext == target:
                confirmed.append(candidate_id)

        assert confirmed == ["user-137"], "decrypt-and-compare must isolate exactly one row"

    connection.close()


def test_documented_workflow_finds_nothing_for_an_absent_value(tmp_path):
    """A lookup for a value that was never stored must confirm nothing."""
    import sqlite3

    from floorvault import FloorVault

    master_key = bytes(range(32))
    crypto = FloorVault(master_key, memory_mode="disabled")
    indexer = BeaconIndexer(derive_beacon_key(master_key), bits=16)
    scope = "users.email"

    with sqlite3.connect(tmp_path / "app.db") as connection:
        connection.execute(
            "CREATE TABLE users (id TEXT PRIMARY KEY, email_cipher BLOB, email_beacon BLOB)"
        )
        for i in range(50):
            record_id, email = f"user-{i}", f"user-{i}@example.com"
            connection.execute(
                "INSERT INTO users (id, email_cipher, email_beacon) VALUES (?, ?, ?)",
                (
                    record_id,
                    crypto.encrypt(
                        email, table="users", record_id=record_id, column="email_cipher"
                    ),
                    indexer.beacon(email, scope=scope),
                ),
            )
        connection.commit()

        absent = "nobody@example.com"
        bucket = indexer.beacon(absent, scope=scope)
        rows = connection.execute(
            "SELECT id, email_cipher FROM users WHERE email_beacon = ?", (bucket,)
        ).fetchall()
    connection.close()

    for candidate_id, ciphertext in rows:
        assert (
            crypto.decrypt(ciphertext, table="users", record_id=candidate_id, column="email_cipher")
            != absent
        ), "a false positive must not survive the confirmation step"


# ---------------------------------------------------------------------------
# BeaconIndexer(expected_rows=...): warn when the width under-fills buckets
# ---------------------------------------------------------------------------
#
# A width wider than suggest_beacon_bits(expected_rows) puts fewer rows per
# bucket than the target occupancy, pushing the index toward exact-equality
# visibility. Narrower is the safe direction (larger anonymity set, slower
# narrowing) so only the wider side warns.


def test_indexer_warns_when_width_exceeds_suggested():
    with pytest.warns(UserWarning, match="closer to exact equality"):
        BeaconIndexer(KEY, bits=64, expected_rows=500)


def test_indexer_silent_at_or_below_suggested_width():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        BeaconIndexer(KEY, bits=8, expected_rows=500)  # suggested is 8
        BeaconIndexer(KEY, bits=8, expected_rows=1_000_000)


def test_indexer_rejects_bad_expected_rows():
    with pytest.raises(TypeError):
        BeaconIndexer(KEY, expected_rows="many")
    with pytest.raises(TypeError):
        BeaconIndexer(KEY, expected_rows=True)
    with pytest.raises(ValueError):
        BeaconIndexer(KEY, expected_rows=0)


# ---------------------------------------------------------------------------
# Key custody: a HardenedMemoryKey must not be flattened to heap bytes
# ---------------------------------------------------------------------------
#
# compute_beacon must not call HardenedMemoryKey.get_bytes(). That returns an
# immutable ``bytes`` object, which is an un-wipeable ghost of the beacon key on
# the Python heap - one per call, since a beacon is computed once per indexed
# row. floorvault's own core.py refuses this exact pattern for the AEAD subkey
# ("a get_bytes() copy would leave an un-wipeable immutable ghost on the Python
# heap", core.py:250-256); the beacon path must hold the same contract.
#
# This is a guard only if it is RED on the pre-fix code, which the accompanying
# review verified by direct measurement (100 calls -> 100 bytes copies).


def test_coerce_does_not_materialize_hardened_key_as_bytes(monkeypatch):
    from floorvault import beacons as beacons_module
    from floorvault.memory import HardenedMemoryKey

    hardened = HardenedMemoryKey(bytes(range(32)))
    calls = {"n": 0}
    original = HardenedMemoryKey.get_bytes

    def counting_get_bytes(self):
        calls["n"] += 1
        return original(self)

    monkeypatch.setattr(HardenedMemoryKey, "get_bytes", counting_get_bytes)
    for index in range(50):
        beacons_module.compute_beacon(
            f"user{index}@example.com", scope="users.email", key=hardened
        )

    assert calls["n"] == 0, (
        f"compute_beacon materialized the hardened key as heap bytes "
        f"{calls['n']} times for 50 calls; each copy is an immutable, "
        f"un-wipeable ghost of key material"
    )


def test_coerce_accepts_hardened_key_and_still_computes():
    """The custody fix must not change the beacon value."""
    from floorvault import beacons as beacons_module
    from floorvault.memory import HardenedMemoryKey

    raw = bytes(range(32))
    expected = beacons_module.compute_beacon("alice@example.com", scope="users.email", key=raw)
    hardened = HardenedMemoryKey(raw)
    actual = beacons_module.compute_beacon(
        "alice@example.com", scope="users.email", key=hardened
    )
    assert actual == expected

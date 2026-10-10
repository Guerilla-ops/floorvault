"""Opt-in truncated search beacons: equality narrowing over encrypted fields.

**This module is a deliberate, measured confidentiality trade. Read this before
using it, and see ``SECURITY.md`` §5 for the threat model it modifies.**

A beacon is a deterministic, keyed function of a plaintext value. Storing one
beside a ciphertext therefore discloses information that omitting it would not:

* **Equality, coarsely.** Two rows hold the same value only if their beacons are
  equal — collisions go one way only. Unequal beacons prove unequal values.
* **Bucket frequency.** The stored index is truncated to ``ceil(bits / 8)``
  bytes, so at most ``256 ** ceil(bits / 8)`` distinct buckets exist and multiple
  plaintext values share each one. Truncation makes the index non-injective, so
  exact per-value frequency is not readable from it. It does **not** make the
  distribution uniform: bucket occupancy remains a deterministic function of the
  plaintext distribution, so a field whose values are heavily skewed still shows
  a correspondingly skewed beacon histogram. Truncation raises the anonymity set
  to roughly ``rows / buckets``; it does not conceal the shape of the data.
* **Access patterns.** Whatever the application does with ``WHERE beacon = ?``
  is visible to anyone who can observe queries or read query logs.

Consequences for choosing a width — ``bits`` and dataset size are a joint
decision, not a constant:

* A width is only as strong as its bucket occupancy. On a 500-row table one byte
  gives ~2 rows per bucket, which is close to exact equality; on a million rows
  it gives ~4000. Call :func:`suggest_beacon_bits` with the real row count.
* Storage is byte-aligned, so **4 and 8 bits are the same index**, and 9..16 bits
  are the same index. There are not four levels between 4 and 16 bits; there are
  two widths. Do not describe 4-bit and 8-bit beacons as different strengths.
* Do not beacon a low-cardinality column (a status flag, a country, a boolean).
  With a handful of distinct values the bucket histogram mirrors the plaintext
  histogram no matter how the bits are spent.
* Do not beacon a column that is never the subject of an equality lookup.

**A beacon hit is not proof of equality.** Collisions are by design, so
:func:`beacon_matches` proves only that two values landed in the same bucket.
The confirmation step is to decrypt the shortlisted row and compare the
plaintext. Look up the bucket, narrow with ``beacon_matches``, confirm by
decryption.

Nothing here is wired into the default ``FloorVault`` surface: importing this
module cannot add a beacon to anything, and the index subkey is derived only
when a caller asks for it via :func:`derive_beacon_key`.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import warnings
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .memory import HardenedMemoryKey

#: Narrowest supportable beacon. Bits below 8 all store one byte, so this is a
#: floor for error messages rather than a distinct width.
MIN_BEACON_BITS = 4

#: Widest supportable beacon (8 bytes of HMAC-SHA256 output).
MAX_BEACON_BITS = 64

#: HKDF domain-separation label for the beacon subkey. Distinct from the
#: ``floorvault-v1-aes-siv`` label so the index key and the AEAD key are
#: independent: reusing one key across two cryptographic purposes is exactly
#: the class of defect the subkey separation exists to prevent.
_BEACON_KEY_INFO = b"floorvault-v1-beacon-index"

_KEY_BYTES = 32


def _coerce_key_material(
    key: Union[bytes, bytearray, HardenedMemoryKey], *, what: str
) -> Union[bytes, bytearray, memoryview]:
    """Coerce a key argument to a bytes-like buffer, accepting a hardened handle.

    Shared by :func:`compute_beacon` (key, exactly ``_KEY_BYTES``) and
    :func:`derive_beacon_key` (master key, exactly ``_KEY_BYTES``) so the
    isinstance dispatch and type error live in one place. Callers apply their
    own length contract on top.

    A hardened handle is consumed through :meth:`HardenedMemoryKey.get_buffer`,
    NOT ``get_bytes()``. ``get_bytes()`` returns an immutable ``bytes`` object,
    which is an un-wipeable ghost of key material on the Python heap - and a
    beacon is computed once per indexed row, so that ghost is per-call, not
    once. ``get_buffer()`` is a zero-copy view over the locked mapping, the same
    choice ``core.py:250-256`` makes for the AEAD subkey and for the same
    reason.

    Callers that need a mutable buffer (HMAC) copy into a ``bytearray`` and wipe
    it, which is cheap and still bounded; nothing here hands back an immutable
    copy of secret key material.
    """
    if isinstance(key, HardenedMemoryKey):
        return key.get_buffer()
    if isinstance(key, (bytes, bytearray, memoryview)):
        return key
    raise TypeError(f"{what} must be bytes, bytearray, or HardenedMemoryKey")


def _validate_key(
    key: Union[bytes, bytearray, HardenedMemoryKey],
) -> Union[bytes, bytearray, memoryview]:
    """Return exactly ``_KEY_BYTES`` of key material, accepting a hardened handle.

    Returns the buffer as-is rather than re-wrapping it in ``bytes``: for a
    hardened handle that re-wrap would reintroduce exactly the un-wipeable heap
    copy this function exists to avoid.

    The length must be EXACTLY ``_KEY_BYTES``: the AEAD path's 64-byte SIV
    subkey otherwise passes as a "beacon key", and reusing one key across the
    encryption and index purposes is precisely the cross-domain defect
    :func:`derive_beacon_key` exists to prevent. Anything longer than the
    derived subkey is overwhelmingly another domain's key.
    """
    key_bytes = _coerce_key_material(key, what="beacon key")
    if len(key_bytes) != _KEY_BYTES:
        raise ValueError(
            f"beacon key must be exactly {_KEY_BYTES} bytes "
            f"(use derive_beacon_key to derive the index subkey)"
        )
    return key_bytes


def _snapshot_key(
    key_material: Union[bytes, bytearray, memoryview],
    *,
    owner: HardenedMemoryKey | None = None,
) -> bytearray:
    """Copy key material into a MUTABLE buffer for immediate use.

    Returns a ``bytearray`` rather than ``bytes`` so the caller can zero it: an
    immutable copy would reintroduce exactly the un-wipeable heap ghost this
    module avoids. Every caller treats the returned buffer as its own to wipe.

    :meth:`HardenedMemoryKey.get_buffer` hands out a *live* view of the locked
    mapping, and ``wipe()`` zeroes that mapping in place. ``wipe()`` sets
    ``is_wiped`` BEFORE the memset, so a caller that obtains a view and copies
    it a moment later has a window in which a concurrent ``wipe()`` has already
    begun - or finished - while the view still reads pre-zeroed key bytes.

    The dangerous part is that the failure is SILENT: an HMAC over 32 zero bytes
    is a perfectly well-formed beacon of the correct length, so it indexes
    cleanly and every later equality lookup simply misses the row. Nothing
    raises, nothing looks corrupt.

    So the copy checks afterwards instead. When ``owner`` is given and reports
    ``is_wiped`` once the copy has completed, the snapshot is wiped and refused
    with ``RuntimeError``, matching what ``get_bytes()`` already does when
    called on a wiped key. This closes the corruption without holding a lock
    across the HMAC operation, which would serialise the hot path, and a
    snapshot that completed before a later wipe remains valid to use.

    The owner flag - never the bytes - identifies a wipe: an all-zero buffer is
    a legitimate key value the public API must compute under, so the bytes
    cannot tell "the key is zero" from "the handle was wiped".
    """
    snapshot = bytearray(key_material)
    if owner is not None and owner.is_wiped:
        for index in range(len(snapshot)):
            snapshot[index] = 0
        raise RuntimeError(
            "beacon key owner was wiped between obtaining the buffer and "
            "copying it; refusing to compute a beacon under a wiped key (such "
            "a beacon is well-formed but wrong, and would silently miss every "
            "lookup)"
        )
    return snapshot


def beacon_bucket_bytes(bits: int) -> int:
    """Bytes needed to store ``bits`` of beacon entropy (1..8 bytes for 4..64).

    Storage is byte-aligned, so the mapping is many-to-one: 4..8 bits all store
    one byte and 9..16 bits all store two. Callers that report a width to a user
    must report the stored size, not the requested ``bits``.

    Raises:
        TypeError: ``bits`` is not an ``int`` (``bool`` included, deliberately).
        ValueError: ``bits`` is outside ``[MIN_BEACON_BITS, MAX_BEACON_BITS]``.
    """
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError("beacon bits must be an integer")
    if not MIN_BEACON_BITS <= bits <= MAX_BEACON_BITS:
        raise ValueError(f"beacon bits must be in [{MIN_BEACON_BITS}, {MAX_BEACON_BITS}]")
    return (bits + 7) // 8


def _canonical_payload(value: str, *, scope: str) -> bytes:
    """Length-prefixed ``scope`` then ``value``, so boundaries cannot be blurred.

    A plain ``f"{scope}\\x00{value}"`` separator is ambiguous: ``("a", "b\\x00c")``
    and ``("a\\x00b", "c")`` serialise identically, so a caller controlling the
    scope can collide with a value under a twisted scope. Prefixing the scope
    with its own length makes the encoding injective over the pair.
    """
    if not isinstance(value, str):
        raise TypeError(f"beacon value must be str, got {type(value).__name__}")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("beacon scope must be a non-empty string for domain separation")
    scope_bytes = scope.encode("utf-8")
    return struct.pack(">I", len(scope_bytes)) + scope_bytes + value.encode("utf-8")


def compute_beacon(
    value: str,
    *,
    scope: str,
    key: Union[bytes, bytearray, HardenedMemoryKey],
    bits: int,
) -> bytes:
    """Return the truncated, keyed equality beacon for ``value`` under ``scope``.

    The result is a deterministic prefix of HMAC-SHA256 over the length-prefixed
    ``(scope, value)`` pair, truncated to ``beacon_bucket_bytes(bits)`` bytes.
    Store it in an indexed column beside the ciphertext, look the bucket up with
    an ordinary SQL equality predicate, narrow candidates with
    :func:`beacon_matches`, and confirm the match by decrypting.

    Args:
        value: Plaintext value to index.
        scope: Domain separator, e.g. ``"users.email"``. Must be non-empty.
        key: Beacon subkey, exactly 32 bytes. Use :func:`derive_beacon_key`.
        bits: Requested width in ``[4, 64]``; storage rounds up to whole bytes.
            Required, not defaulted: no width is universally safe, so choose
            with :func:`suggest_beacon_bits`.

    Returns:
        ``ceil(bits / 8)`` bytes.
    """
    bucket_size = beacon_bucket_bytes(bits)
    # _snapshot_key returns a MUTABLE buffer (refusing a wiped live view) that
    # this call owns; zero it as soon as the HMAC has consumed it.
    key_buffer = _snapshot_key(
        _validate_key(key), owner=key if isinstance(key, HardenedMemoryKey) else None
    )
    try:
        digest = hmac.new(key_buffer, _canonical_payload(value, scope=scope), hashlib.sha256)
        return digest.digest()[:bucket_size]
    finally:
        for index in range(len(key_buffer)):
            key_buffer[index] = 0


def beacon_matches(
    value: str,
    *,
    scope: str,
    key: Union[bytes, bytearray, HardenedMemoryKey],
    beacon: Union[bytes, bytearray, memoryview],
    bits: int,
) -> bool:
    """True iff ``value``'s beacon equals ``beacon`` — bucket agreement, only.

    Used to discard candidate rows whose bucket disagrees before attempting a
    decryption. A ``True`` result means the two values share a bucket, which
    collisions make non-unique: **confirm equality by decrypting the candidate
    and comparing the plaintext.** Never treat the result as an equality proof.
    """
    candidate = compute_beacon(value, scope=scope, key=key, bits=bits)
    return hmac.compare_digest(candidate, bytes(beacon))


def derive_beacon_key(master_key: Union[bytes, bytearray, HardenedMemoryKey]) -> bytes:
    """Derive the 32-byte beacon subkey from a 32-byte master key.

    HKDF-SHA256 with the domain-separating label ``floorvault-v1-beacon-index``,
    which is distinct from the ``floorvault-v1-aes-siv`` label used for the AEAD
    subkey. There is no structural collision resistance between the two HFDF
    outputs in general, so the two must not be derived with the same label; this
    function exists so callers do not invent one.

    Returns the key as ``bytes``. If the caller's master key is a hardened
    handle, the derived key is returned to the caller and is that caller's to
    wipe; :class:`BeaconIndexer` never retains more than the object it is given.
    """
    source = _snapshot_key(
        _coerce_key_material(master_key, what="master key"),
        owner=master_key if isinstance(master_key, HardenedMemoryKey) else None,
    )
    try:
        if len(source) != _KEY_BYTES:
            raise ValueError(f"master key must be exactly {_KEY_BYTES} bytes")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_BYTES,
            salt=None,
            info=_BEACON_KEY_INFO,
        ).derive(source)
    finally:
        # The snapshot is ours; zero it rather than leaving key-derived material
        # on the heap. The returned subkey is the caller's to wipe.
        for index in range(len(source)):
            source[index] = 0


def suggest_beacon_bits(expected_rows: int, target_bucket_size: int = 8) -> int:
    """Recommend a stored width sized to a dataset.

    There is no universally safe width: the index must be coarse enough that an
    observer cannot read exact equality or frequency, and fine enough that a
    lookup does not have to decrypt most of the table. Given ``expected_rows``
    indexed values and a target average bucket occupancy, this returns the
    smallest byte-aligned width whose average occupancy (``rows / 256**bytes``)
    is at or below the target.

    The result is a multiple of 8 in ``[8, 64]``. At very large ``expected_rows``
    it clamps to 64 and the requested occupancy may be unreachable — the caller
    should then stop trusting the beacon as a narrow filter.

    Args:
        expected_rows: Number of indexed rows.
        target_bucket_size: Desired average rows per bucket (coarser = larger).
    """
    for name, val in (("expected_rows", expected_rows), ("target_bucket_size", target_bucket_size)):
        if isinstance(val, bool) or not isinstance(val, int):
            raise TypeError(f"{name} must be an integer")
        if val < 1:
            raise ValueError(f"{name} must be a positive integer")

    max_bytes = MAX_BEACON_BITS // 8
    bucket_bytes = 1
    while bucket_bytes < max_bytes:
        if expected_rows / (256**bucket_bytes) <= target_bucket_size:
            break
        bucket_bytes += 1
    return bucket_bytes * 8


class BeaconIndexer:
    """A beacon subkey bound once, with a default width.

    Convenience wrapper for callers that compute many beacons under one key.
    Holds the key object it was given (a ``HardenedMemoryKey`` stays the
    caller's to wipe; a ``bytes`` key cannot be wiped from here).

    Unlike :func:`compute_beacon`, this constructor **refuses a width that is
    not byte-aligned**. A caller asking for 7 bits believes it gets 128 buckets
    and actually stores 256, which is a security claim that does not match the
    index; refusing the request is cheaper than documenting around it. Use
    :attr:`bucket_bytes` to report the width the index really has.
    """

    def __init__(
        self,
        key: Union[bytes, bytearray, HardenedMemoryKey],
        *,
        bits: int,
        expected_rows: int | None = None,
    ) -> None:
        beacon_bucket_bytes(bits)  # range check first, for the clearer message
        if bits % 8 != 0:
            raise ValueError(
                f"beacon width must be byte-aligned (8, 16, ... 64), got {bits}: "
                f"{bits} bits stores {beacon_bucket_bytes(bits)} byte(s), i.e. "
                f"{256 ** beacon_bucket_bytes(bits)} buckets, not {2**bits}"
            )
        _validate_key(key)  # fail on absent/short key material at construction
        self._key = key
        self.bits = bits
        if expected_rows is not None:
            if isinstance(expected_rows, bool) or not isinstance(expected_rows, int):
                raise TypeError("expected_rows must be an integer")
            if expected_rows < 1:
                raise ValueError("expected_rows must be a positive integer")
            # A width wider than suggested puts fewer rows in each bucket than
            # the target occupancy, i.e. moves the index nearer exact-equality
            # visibility for an observer of the beacon column. Narrower is the
            # safe direction (larger anonymity set, slower narrowing) and earns
            # no warning.
            suggested = suggest_beacon_bits(expected_rows)
            if bits > suggested:
                occupancy = expected_rows / self.bucket_count
                warnings.warn(
                    f"bits={bits} on ~{expected_rows} rows leaves ~{occupancy:.1f} "
                    f"rows per beacon bucket, below the suggested occupancy - "
                    f"the index is closer to exact equality than "
                    f"suggest_beacon_bits({expected_rows}) -> {suggested} bits",
                    UserWarning,
                    stacklevel=2,
                )

    @property
    def bucket_bytes(self) -> int:
        """Bytes actually stored per beacon — the width that decides leakage."""
        return beacon_bucket_bytes(self.bits)

    @property
    def bucket_count(self) -> int:
        """Number of distinct buckets, i.e. ``256 ** bucket_bytes``."""
        return 256**self.bucket_bytes

    def beacon(self, value: str, *, scope: str) -> bytes:
        """Stored beacon for ``value`` at this indexer's width."""
        return compute_beacon(value, scope=scope, key=self._key, bits=self.bits)

    def matches(
        self, value: str, *, scope: str, beacon: Union[bytes, bytearray, memoryview]
    ) -> bool:
        """Bucket agreement only — confirm equality by decrypting the candidate."""
        return beacon_matches(value, scope=scope, key=self._key, beacon=beacon, bits=self.bits)


__all__ = [
    "MAX_BEACON_BITS",
    "MIN_BEACON_BITS",
    "BeaconIndexer",
    "beacon_bucket_bytes",
    "beacon_matches",
    "compute_beacon",
    "derive_beacon_key",
    "suggest_beacon_bits",
]

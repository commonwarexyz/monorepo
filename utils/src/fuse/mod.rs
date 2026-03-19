//! Binary Fuse Filter: a space-efficient probabilistic set-membership structure.
//!
//! # Status
//!
//! `ALPHA`: Expect breaking changes.
//!
//! # Overview
//!
//! A [`BinaryFuseFilter`] answers set-membership queries in constant time using
//! three array lookups and an XOR fingerprint check. It is built from a static,
//! immutable key set and cannot be modified after construction.
//!
//! Compared with a Bloom filter:
//! - ~20% smaller in memory
//! - Faster lookups (exactly 3 array reads, cache-friendly)
//! - The full key set must be known at construction time; incremental
//!   insertions are not supported
//!
//! Two fingerprint widths are supported:
//! - [`u8`] fingerprints: ~9 bits per key, ~0.4% false-positive rate
//! - [`u16`] fingerprints: ~18 bits per key, ~0.0015% false-positive rate
//!
//! Keys must be provided as [`u64`]. Callers are responsible for hashing their
//! own types to `u64` before calling [`BinaryFuseFilter::contains`].
//!
//! # Adversarial Environments
//!
//! Construction can fail if an adversary can control both the key set and the
//! internal seed. Pass a seed that the adversary cannot predict (e.g. a VRF
//! output or a random beacon) so that they cannot craft a key set that causes
//! construction to fail.
//!
//! # Examples
//!
//! ```
//! use commonware_utils::fuse::BinaryFuseFilter;
//!
//! let seed = 42u64;
//! let keys: Vec<u64> = (0u64..1_000).collect();
//! let filter = BinaryFuseFilter::<u8>::new(seed, 32, &keys).expect("construction failed");
//!
//! // Every inserted key is always found (no false negatives).
//! for &k in &keys {
//!     assert!(filter.contains(k));
//! }
//! ```

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, Write};

/// Number of positions each key maps to in the filter array.
const ARITY: u32 = 3;

/// Error returned by [`BinaryFuseFilter::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The key set is empty. A filter over zero keys is not useful.
    #[error("key set is empty")]
    Empty,

    /// The key set is too large to construct a filter.
    ///
    /// Triggered when the unique key count or the computed array size overflows
    /// a `u32`. In practice, filters with more than a few billion keys are not
    /// feasible anyway due to memory requirements.
    #[error("key set too large")]
    TooLarge,

    /// Construction did not converge within the allowed retries.
    ///
    /// This is practically impossible for random key sets with a secret seed.
    /// It may occur with adversarially crafted inputs when the seed is known.
    /// Try a different seed or increase `max_retries`.
    #[error("construction failed; try a different seed or increase max_retries")]
    ConstructionFailed,
}

/// A type that can serve as a fingerprint stored in a [`BinaryFuseFilter`].
///
/// Implemented for [`u8`] (1 byte) and [`u16`] (2 bytes).
pub trait Fingerprint:
    Copy
    + Default
    + PartialEq
    + core::ops::BitXor<Output = Self>
    + Write
    + EncodeSize
    + FixedSize
    + Read<Cfg = ()>
{
    /// Extract a fingerprint from a 64-bit hash value.
    fn from_hash(hash: u64) -> Self;
}

impl Fingerprint for u8 {
    #[inline]
    fn from_hash(hash: u64) -> Self {
        // XOR upper and lower 32-bit halves for better bit mixing.
        (hash ^ (hash >> 32)) as Self
    }
}

impl Fingerprint for u16 {
    #[inline]
    fn from_hash(hash: u64) -> Self {
        (hash ^ (hash >> 32)) as Self
    }
}

/// A space-efficient probabilistic set-membership filter over a static key set.
///
/// See the [module documentation](self) for an overview.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryFuseFilter<F: Fingerprint> {
    seed: u64,
    segment_length: u32,
    // Number of "pure" segments. The filter array has (segment_count + ARITY - 1)
    // segments totalling (segment_count + ARITY - 1) * segment_length entries.
    segment_count: u32,
    data: Vec<F>,
}

impl<F: Fingerprint> BinaryFuseFilter<F> {
    /// Builds a filter from a set of keys.
    ///
    /// `seed` is mixed into the hash function and should not be controllable
    /// by the party that supplies `keys` (e.g. use a VRF output or random beacon).
    ///
    /// `max_retries` is the maximum number of construction attempts. Each attempt
    /// uses a seed derived deterministically from `seed` and the attempt index.
    /// A value of 32 is sufficient for random key sets; higher values provide
    /// additional safety against adversarial inputs.
    ///
    /// Duplicate keys are silently removed. Key ordering does not affect the result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Empty`] if `keys` is empty (or all duplicates reduce to empty).
    /// Returns [`Error::TooLarge`] if the unique key count exceeds `u32::MAX`.
    /// Returns [`Error::ConstructionFailed`] if construction does not converge.
    pub fn new(seed: u64, max_retries: u32, keys: &[u64]) -> Result<Self, Error> {
        // Canonicalize: sort and dedup for determinism and correct peeling.
        let mut owned: Vec<u64> = keys.to_vec();
        owned.sort_unstable();
        owned.dedup();

        if owned.is_empty() {
            return Err(Error::Empty);
        }
        let n = u32::try_from(owned.len()).map_err(|_| Error::TooLarge)?;

        let segment_length = segment_length_for(n);

        // Capacity and segment_count are computed in u64 to detect overflow before
        // truncating to u32. Both values are stored on the wire, so they must fit.
        let capacity = capacity_for(n);
        let segment_count = capacity
            .div_ceil(segment_length as u64)
            .saturating_sub((ARITY - 1) as u64)
            .max(1);
        let segment_count =
            u32::try_from(segment_count).map_err(|_| Error::TooLarge)?;

        // array_length = (segment_count + ARITY - 1) * segment_length must also fit in u32.
        // This is the number of fingerprint slots in the backing array.
        let array_length = (segment_count as u64 + (ARITY - 1) as u64)
            .checked_mul(segment_length as u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(Error::TooLarge)?;

        // Pre-allocate working buffers once and reset them on each attempt.
        // Reusing avoids (max_retries + 1) pairs of heap allocations; on failure-prone
        // inputs (adversarial keys) this matters since we may exhaust all retries.
        let al = array_length as usize;
        let mut count = vec![0u32; al];
        let mut xor_mask = vec![0u64; al];

        for attempt in 0..=max_retries {
            // Derive a distinct seed for each attempt deterministically.
            let attempt_seed = seed.wrapping_add((attempt as u64).wrapping_mul(0x517cc1b727220a95));
            if let Some(data) = try_construct::<F>(
                &owned,
                attempt_seed,
                segment_length,
                segment_count,
                &mut count,
                &mut xor_mask,
            ) {
                return Ok(Self {
                    seed: attempt_seed,
                    segment_length,
                    segment_count,
                    data,
                });
            }
        }

        Err(Error::ConstructionFailed)
    }

    /// Returns `true` if `key` is probably in the set.
    ///
    /// There are no false negatives: a key inserted via [`new`](Self::new)
    /// always returns `true`. False positives occur with probability
    /// approximately `1 / 2^(F::SIZE * 8)`.
    #[inline]
    pub fn contains(&self, key: u64) -> bool {
        let hash = splitmix(key.wrapping_add(self.seed));
        let fp = F::from_hash(hash);
        let [h0, h1, h2] = positions(hash, self.segment_count, self.segment_length);
        fp == self.data[h0] ^ self.data[h1] ^ self.data[h2]
    }
}

impl<F: Fingerprint> Write for BinaryFuseFilter<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
        self.segment_length.write(buf);
        self.segment_count.write(buf);
        for fp in &self.data {
            fp.write(buf);
        }
    }
}

impl<F: Fingerprint> EncodeSize for BinaryFuseFilter<F> {
    fn encode_size(&self) -> usize {
        // seed(8) + segment_length(4) + segment_count(4) + data
        8 + 4 + 4 + self.data.len() * F::SIZE
    }
}

impl<F: Fingerprint> Read for BinaryFuseFilter<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let seed = u64::read_cfg(buf, &())?;
        let segment_length = u32::read_cfg(buf, &())?;
        let segment_count = u32::read_cfg(buf, &())?;

        if segment_length < 4 || !segment_length.is_power_of_two() {
            return Err(CodecError::Invalid(
                "BinaryFuseFilter",
                "segment_length must be a power of 2 and at least 4",
            ));
        }
        // segment_count must be at least 1 so the array is non-empty.
        if segment_count == 0 {
            return Err(CodecError::Invalid(
                "BinaryFuseFilter",
                "segment_count must be at least 1",
            ));
        }

        let array_length = (segment_count as usize + ARITY as usize - 1)
            .checked_mul(segment_length as usize)
            .ok_or(CodecError::Invalid(
                "BinaryFuseFilter",
                "array_length overflow",
            ))?;

        // Reject before allocating: the buffer must contain at least array_length
        // fingerprints. Without this check a 16-byte payload with large segment_count
        // and segment_length values would trigger a multi-gigabyte allocation.
        let expected_bytes = array_length
            .checked_mul(F::SIZE)
            .ok_or(CodecError::Invalid(
                "BinaryFuseFilter",
                "fingerprint data size overflow",
            ))?;
        if buf.remaining() < expected_bytes {
            return Err(CodecError::Invalid(
                "BinaryFuseFilter",
                "buffer too small for declared array_length",
            ));
        }

        let mut data = Vec::with_capacity(array_length);
        for _ in 0..array_length {
            data.push(F::read_cfg(buf, &())?);
        }

        Ok(Self {
            seed,
            segment_length,
            segment_count,
            data,
        })
    }
}

/// Attempts one construction pass. Returns the fingerprint array on success,
/// or `None` if peeling got stuck (triggering a retry with a new seed).
///
/// `count` and `xor_mask` are pre-allocated working buffers of length `array_length`;
/// they are zeroed at the start of each call so callers can reuse them across retries.
fn try_construct<F: Fingerprint>(
    keys: &[u64],
    seed: u64,
    segment_length: u32,
    segment_count: u32,
    count: &mut [u32], // length == array_length
    xor_mask: &mut [u64],
) -> Option<Vec<F>> {
    let n = keys.len();

    // Reset working state from any previous attempt.
    count.fill(0);
    xor_mask.fill(0);

    for &key in keys {
        let hash = splitmix(key.wrapping_add(seed));
        let [h0, h1, h2] = positions(hash, segment_count, segment_length);
        count[h0] += 1;
        xor_mask[h0] ^= hash;
        count[h1] += 1;
        xor_mask[h1] ^= hash;
        count[h2] += 1;
        xor_mask[h2] ^= hash;
    }

    // Seed the queue with every position that starts at degree 1.
    let mut queue: Vec<usize> = (0..count.len()).filter(|&i| count[i] == 1).collect();
    let mut stack: Vec<(usize, u64)> = Vec::with_capacity(n);

    // Iteratively peel keys that are alone at exactly one position.
    while let Some(pos) = queue.pop() {
        if count[pos] != 1 {
            // Already processed or further reduced by a concurrent peel.
            continue;
        }
        // Mark as done so a duplicate queue entry skips it.
        count[pos] = 0;

        let hash = xor_mask[pos]; // sole remaining key's hash
        stack.push((pos, hash));

        // Remove this key from its other two positions.
        let [h0, h1, h2] = positions(hash, segment_count, segment_length);
        for &h in &[h0, h1, h2] {
            if h == pos || count[h] == 0 {
                continue;
            }
            count[h] -= 1;
            xor_mask[h] ^= hash;
            if count[h] == 1 {
                queue.push(h);
            }
        }
    }

    // All keys must have been peeled for construction to succeed.
    if stack.len() != n {
        return None;
    }

    // Assignment phase: walk the stack in reverse order.
    // For each key, assign data[pos] so that data[h0] ^ data[h1] ^ data[h2] == fp.
    // The two other positions already have their final values; data[pos] starts at
    // F::default() (zero), so including it in the XOR is a no-op.
    let mut data = vec![F::default(); count.len()];
    for (pos, hash) in stack.into_iter().rev() {
        let fp = F::from_hash(hash);
        let [h0, h1, h2] = positions(hash, segment_count, segment_length);
        data[pos] = fp ^ data[h0] ^ data[h1] ^ data[h2];
    }

    Some(data)
}

/// Returns the three array positions for a 64-bit hash value.
///
/// Uses the Binary Fuse Filter formula from the reference implementation:
/// - `h0 = mulhi(hash, segment_count * segment_length)` -- uniform in [0, sc*sl)
/// - `h1 = h0 + segment_length`, offset-mixed with bits 18..29 of hash
/// - `h2 = h1 + segment_length`, offset-mixed with bits 0..11 of hash
///
/// This places h0 in segment band [0, sc), h1 in [1, sc+1), and h2 in [2, sc+2),
/// ensuring the union covers the full array [0, (sc+2)*sl).
#[inline]
const fn positions(hash: u64, sc: u32, sl: u32) -> [usize; 3] {
    let sc_sl = sc as u64 * sl as u64;
    let sl_mask = (sl - 1) as u64;

    // h0: uniform in [0, sc * sl); segment from upper bits, offset from lower.
    let h0 = mulhi(hash, sc_sl) as u32;
    // h1: segment = h0's segment + 1; within-segment offset mixed with hash bits 18..
    let h1_raw = h0 + sl;
    let h1 = (h1_raw as u64 ^ ((hash >> 18) & sl_mask)) as usize;
    // h2: segment = h0's segment + 2; within-segment offset mixed with hash bits 0..
    let h2_raw = h1_raw + sl;
    let h2 = (h2_raw as u64 ^ (hash & sl_mask)) as usize;

    [h0 as usize, h1, h2]
}

/// splitmix64 finalizer: maps `key` to a high-quality 64-bit hash.
///
/// This matches the reference Binary Fuse Filter mixing function and provides
/// strong avalanche behaviour.
#[inline]
const fn splitmix(key: u64) -> u64 {
    let z = key.wrapping_add(0x9e3779b97f4a7c15);
    let z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Returns the high 64 bits of the 128-bit product `a * b`.
///
/// Used to map a 64-bit hash uniformly into [0, b) for any `b`.
#[inline]
const fn mulhi(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

/// Returns the segment length for `n` keys using a precomputed lookup table.
///
/// The table implements `2^ceil(ln(n) / ln(3.33) + 2.25)` (the formula from the
/// Binary Fuse Filter paper for arity 3) using only integer comparisons.
/// Each entry is the largest `n` for which the corresponding power of 2 applies.
/// All thresholds were derived from `floor(3.33^(exp - 2.25))` for exp = 3..18.
fn segment_length_for(n: u32) -> u32 {
    // (max_n_inclusive, segment_length)
    const TABLE: &[(u32, u32)] = &[
        (1, 4),
        (2, 8),
        (8, 16),
        (27, 32),
        (91, 64),
        (303, 128),
        (1_009, 256),
        (3_361, 512),
        (11_193, 1_024),
        (37_271, 2_048),
        (124_102, 4_096),
        (413_259, 8_192),
        (1_376_152, 16_384),
        (4_582_587, 32_768),
        (15_259_214, 65_536),
        (50_813_183, 131_072),
    ];
    for &(max_n, sl) in TABLE {
        if n <= max_n {
            return sl;
        }
    }
    262_144 // 2^18, maximum
}

/// Returns the target array capacity for `n` keys using integer-only arithmetic.
///
/// Returns a `u64` so the caller can detect overflow before truncating to `u32`.
///
/// Implements an integer approximation of
/// `n * max(1.125, 0.875 + 0.25 * log2(10^6) / log2(n))`
/// from the Binary Fuse Filter paper.
///
/// Scaling by 64 instead of 8 reduces rounding error from integer division
/// enough to match the floating-point formula within one segment for all
/// practical key-set sizes (verified up to n = 10^8).
fn capacity_for(n: u32) -> u64 {
    if n <= 1 {
        return n as u64;
    }
    // floor_log2(n), at least 1 to avoid division by zero.
    let log2_n = n.ilog2().max(1) as u64;
    // Compute size_factor * 64, clamped to at least 72 (= 1.125 * 64).
    // 56 + 320 / log2_n  approximates (7/8 + 5/log2_n) * 64
    //                  = (0.875 + 0.25 * 20 / log2_n) * 64
    //                  = 64 * size_factor.
    // Using 20 as an integer approximation of log2(10^6) ~= 19.93.
    let factor_x64 = (56u64 + 320 / log2_n).max(72);
    // Round to nearest: add 32 (= 64/2) before dividing.
    ((n as u64 * factor_x64 + 32) / 64).max(n as u64)
}

#[cfg(feature = "arbitrary")]
impl<'a, F: Fingerprint> arbitrary::Arbitrary<'a> for BinaryFuseFilter<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: u64 = u.arbitrary()?;
        // Generate a non-empty key set and build the filter from it.
        let keys: Vec<u64> = u.arbitrary()?;
        if keys.is_empty() {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Self::new(seed, 32, &keys).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_contains_all_keys_u8() {
        let keys: Vec<u64> = (0u64..1_000).collect();
        let filter = BinaryFuseFilter::<u8>::new(0, 32, &keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k), "false negative for key {k}");
        }
    }

    #[test]
    fn test_contains_all_keys_u16() {
        let keys: Vec<u64> = (0u64..1_000).collect();
        let filter = BinaryFuseFilter::<u16>::new(0, 32, &keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k), "false negative for key {k}");
        }
    }

    #[test]
    fn test_empty_returns_error() {
        let result = BinaryFuseFilter::<u8>::new(0, 32, &[]);
        assert_eq!(result, Err(Error::Empty));
    }

    #[test]
    fn test_single_key() {
        let filter = BinaryFuseFilter::<u8>::new(0, 32, &[42u64]).unwrap();
        assert!(filter.contains(42));
    }

    #[test]
    fn test_duplicate_keys_deduplicated() {
        // Duplicate keys should be silently removed; the filter still finds the key.
        let keys = vec![7u64, 7, 7, 7];
        let filter = BinaryFuseFilter::<u8>::new(0, 32, &keys).unwrap();
        assert!(filter.contains(7));
    }

    #[test]
    fn test_unsorted_keys() {
        // Key order must not affect the result.
        let mut keys: Vec<u64> = (0u64..500).collect();
        let filter_sorted = BinaryFuseFilter::<u8>::new(1, 32, &keys).unwrap();
        keys.reverse();
        let filter_reversed = BinaryFuseFilter::<u8>::new(1, 32, &keys).unwrap();
        assert_eq!(filter_sorted, filter_reversed);
    }

    #[test]
    fn test_false_positive_rate_u8() {
        // Build a filter on even keys, then probe odd keys.
        // Expect roughly 0.4% false positives; we use a generous threshold.
        let keys: Vec<u64> = (0u64..10_000).map(|i| i * 2).collect();
        let filter = BinaryFuseFilter::<u8>::new(0, 32, &keys).unwrap();

        let probes: Vec<u64> = (0u64..10_000).map(|i| i * 2 + 1).collect();
        let false_positives = probes.iter().filter(|&&k| filter.contains(k)).count();

        // Theoretical rate ~0.4% -> expect at most ~5% in any reasonable run.
        assert!(
            false_positives < probes.len() / 20,
            "false positive rate too high: {false_positives}/{} positives",
            probes.len()
        );
    }

    #[test]
    fn test_encode_decode_u8() {
        let keys: Vec<u64> = (0u64..500).collect();
        let original = BinaryFuseFilter::<u8>::new(0, 32, &keys).unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), original.encode_size());
        let decoded = BinaryFuseFilter::<u8>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        for &k in &keys {
            assert!(decoded.contains(k));
        }
    }

    #[test]
    fn test_encode_decode_u16() {
        let keys: Vec<u64> = (0u64..500).collect();
        let original = BinaryFuseFilter::<u16>::new(0, 32, &keys).unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), original.encode_size());
        let decoded = BinaryFuseFilter::<u16>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        for &k in &keys {
            assert!(decoded.contains(k));
        }
    }

    #[test]
    fn test_decode_rejects_invalid_segment_length() {
        // segment_length = 3 is not a power of 2.
        let mut buf = Vec::new();
        1u64.write(&mut buf); // seed
        3u32.write(&mut buf); // segment_length (invalid)
        4u32.write(&mut buf); // segment_count
        assert!(BinaryFuseFilter::<u8>::decode(bytes::Bytes::from(buf)).is_err());
    }

    #[test]
    fn test_decode_rejects_zero_segment_count() {
        let mut buf = Vec::new();
        1u64.write(&mut buf); // seed
        4u32.write(&mut buf); // segment_length
        0u32.write(&mut buf); // segment_count (invalid: must be >= 1)
        assert!(BinaryFuseFilter::<u8>::decode(bytes::Bytes::from(buf)).is_err());
    }

    #[test]
    fn test_decode_rejects_oversized_allocation() {
        // A crafted 16-byte payload with max segment_count and segment_length would
        // request a ~16 GB allocation before reading any fingerprint data. The decoder
        // must reject this without allocating.
        let mut buf = Vec::new();
        1u64.write(&mut buf); // seed
        (1u32 << 18).write(&mut buf); // segment_length = 262144 (max allowed power of 2)
        u32::MAX.write(&mut buf); // segment_count = 4294967295
        // no fingerprint data follows
        assert!(BinaryFuseFilter::<u8>::decode(bytes::Bytes::from(buf)).is_err());
    }

    #[test]
    fn test_large_key_set() {
        let keys: Vec<u64> = (0u64..100_000).collect();
        let filter = BinaryFuseFilter::<u8>::new(0, 32, &keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k));
        }
    }

    #[test]
    fn test_different_seeds_produce_different_filters() {
        let keys: Vec<u64> = (0u64..1_000).collect();
        let f1 = BinaryFuseFilter::<u8>::new(1, 32, &keys).unwrap();
        let f2 = BinaryFuseFilter::<u8>::new(2, 32, &keys).unwrap();
        // Different seeds must produce different internal state.
        assert_ne!(f1, f2);
        // Both must still contain all keys.
        for &k in &keys {
            assert!(f1.contains(k));
            assert!(f2.contains(k));
        }
    }

    #[test]
    fn test_segment_length_table_boundaries() {
        // Spot-check the lookup table boundaries.
        assert_eq!(segment_length_for(1), 4);
        assert_eq!(segment_length_for(2), 8);
        assert_eq!(segment_length_for(3), 16);
        assert_eq!(segment_length_for(8), 16);
        assert_eq!(segment_length_for(9), 32);
        assert_eq!(segment_length_for(91), 64);
        assert_eq!(segment_length_for(92), 128);
        assert_eq!(segment_length_for(303), 128);
        assert_eq!(segment_length_for(304), 256);
        assert_eq!(segment_length_for(u32::MAX), 262_144);
    }

    #[test]
    fn test_capacity_overflow_returns_too_large() {
        // capacity_for(u32::MAX) overflows u32, so new() must return TooLarge
        // rather than panicking or silently truncating.
        // We can't actually pass u32::MAX unique keys, but we can verify that
        // capacity_for produces a value that exceeds u32::MAX for large n.
        let cap = capacity_for(u32::MAX);
        assert!(cap > u32::MAX as u64, "capacity_for(u32::MAX) should overflow u32");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<BinaryFuseFilter<u8>>,
            CodecConformance<BinaryFuseFilter<u16>>,
        }
    }
}

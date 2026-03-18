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
//! # Examples
//!
//! ```
//! use commonware_utils::fuse::BinaryFuseFilter;
//!
//! let keys: Vec<u64> = (0u64..1_000).collect();
//! let filter = BinaryFuseFilter::<u8>::new(&keys).expect("construction failed");
//!
//! // Every inserted key is always found (no false negatives).
//! for &k in &keys {
//!     assert!(filter.contains(k));
//! }
//! ```

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, Write};

/// Number of positions each key maps to in the filter array.
const ARITY: usize = 3;

/// Maximum number of construction attempts before giving up.
const MAX_ITERATIONS: u32 = 100;

/// Error returned by [`BinaryFuseFilter::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The key set is empty. A filter over zero keys is not useful.
    #[error("key set is empty")]
    Empty,

    /// Construction did not converge after the maximum number of attempts.
    ///
    /// This is practically impossible for random key sets. It may occur with
    /// adversarially crafted inputs.
    #[error("construction failed after {MAX_ITERATIONS} attempts")]
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
    /// Every key in `keys` is guaranteed to be found by [`contains`](Self::contains).
    /// The false-positive rate is approximately `1 / 2^(F::SIZE * 8)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Empty`] if `keys` is empty.
    /// Returns [`Error::ConstructionFailed`] if construction does not converge
    /// (practically impossible for random key sets).
    pub fn new(keys: &[u64]) -> Result<Self, Error> {
        let n = keys.len();
        if n == 0 {
            return Err(Error::Empty);
        }

        let segment_length = segment_length_for(n);
        let size_factor = size_factor_for(n);
        let capacity = ((n as f64 * size_factor).round() as u32).max(n as u32);

        // Number of pure segments. The array has (sc + ARITY - 1) segments total.
        // saturating_sub guards small n where capacity < 2 * segment_length.
        let segment_count = capacity
            .div_ceil(segment_length)
            .saturating_sub(ARITY as u32 - 1)
            .max(1);
        let array_length = (segment_count + ARITY as u32 - 1) * segment_length;

        let mut seed = 1u64;
        for _ in 0..MAX_ITERATIONS {
            if let Some(data) =
                try_construct::<F>(keys, seed, segment_length, segment_count, array_length)
            {
                return Ok(Self {
                    seed,
                    segment_length,
                    segment_count,
                    data,
                });
            }
            // Advance seed with a large odd increment to vary the hash function.
            seed = seed.wrapping_add(0x517cc1b727220a95);
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

        let array_length = (segment_count as usize + ARITY - 1)
            .checked_mul(segment_length as usize)
            .ok_or(CodecError::Invalid(
                "BinaryFuseFilter",
                "array_length overflow",
            ))?;

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
fn try_construct<F: Fingerprint>(
    keys: &[u64],
    seed: u64,
    segment_length: u32,
    segment_count: u32,
    array_length: u32,
) -> Option<Vec<F>> {
    let n = keys.len();
    let al = array_length as usize;

    // count[i] = number of keys that map to position i.
    // xor_mask[i] = XOR of hashes of all keys at position i.
    let mut count = vec![0u32; al];
    let mut xor_mask = vec![0u64; al];

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
    let mut queue: Vec<usize> = (0..al).filter(|&i| count[i] == 1).collect();
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
    let mut data = vec![F::default(); al];
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

/// Computes the segment length for `n` keys.
///
/// Uses the formula from the Binary Fuse Filter paper for arity 3:
/// `2^ceil(log(n) / log(3.33) + 2.25)`, clamped to `[4, 2^18]`.
fn segment_length_for(n: usize) -> u32 {
    if n <= 1 {
        return 4;
    }
    let exponent = ((n as f64).ln() / 3.33_f64.ln() + 2.25).ceil() as u32;
    (1u32 << exponent.min(18)).max(4)
}

/// Computes the size factor for `n` keys.
///
/// Larger values increase the array size and construction reliability.
/// The formula from the paper ensures near-certain construction success.
fn size_factor_for(n: usize) -> f64 {
    if n <= 1 {
        return 1.125;
    }
    // max(1.125, 0.875 + 0.25 * log(1_000_000) / log(n))
    let factor = 0.875 + 0.25 * (1_000_000_f64).ln() / (n as f64).ln();
    factor.max(1.125)
}

#[cfg(feature = "arbitrary")]
impl<'a, F: Fingerprint> arbitrary::Arbitrary<'a> for BinaryFuseFilter<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a non-empty key set and build the filter from it.
        let keys: Vec<u64> = u.arbitrary()?;
        if keys.is_empty() {
            return Err(arbitrary::Error::IncorrectFormat);
        }
        Self::new(&keys).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_contains_all_keys_u8() {
        let keys: Vec<u64> = (0u64..1_000).collect();
        let filter = BinaryFuseFilter::<u8>::new(&keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k), "false negative for key {k}");
        }
    }

    #[test]
    fn test_contains_all_keys_u16() {
        let keys: Vec<u64> = (0u64..1_000).collect();
        let filter = BinaryFuseFilter::<u16>::new(&keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k), "false negative for key {k}");
        }
    }

    #[test]
    fn test_empty_returns_error() {
        let result = BinaryFuseFilter::<u8>::new(&[]);
        assert_eq!(result, Err(Error::Empty));
    }

    #[test]
    fn test_single_key() {
        let filter = BinaryFuseFilter::<u8>::new(&[42u64]).unwrap();
        assert!(filter.contains(42));
    }

    #[test]
    fn test_false_positive_rate_u8() {
        // Build a filter on even keys, then probe odd keys.
        // Expect roughly 0.4% false positives; we use a generous threshold.
        let keys: Vec<u64> = (0u64..10_000).map(|i| i * 2).collect();
        let filter = BinaryFuseFilter::<u8>::new(&keys).unwrap();

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
        let original = BinaryFuseFilter::<u8>::new(&keys).unwrap();
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
        let original = BinaryFuseFilter::<u16>::new(&keys).unwrap();
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
    fn test_large_key_set() {
        let keys: Vec<u64> = (0u64..100_000).collect();
        let filter = BinaryFuseFilter::<u8>::new(&keys).unwrap();
        for &k in &keys {
            assert!(filter.contains(k));
        }
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

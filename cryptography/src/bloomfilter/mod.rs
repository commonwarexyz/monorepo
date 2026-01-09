//! An implementation of a [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

use crate::{sha256::Sha256, Hasher};
use bytes::{Buf, BufMut};
use commonware_codec::{
    codec::{Read, Write},
    error::Error as CodecError,
    EncodeSize, FixedSize,
};
use commonware_utils::bitmap::BitMap;
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroU8, NonZeroUsize},
};

/// ln(2) in Q16.16 fixed-point format.
/// Used for computing optimal number of hash functions.
const LN2_Q16: u64 = 45_426;

/// Scale factor for false positive rate normalization (4 decimal places).
const FP_RATE_SCALE: u64 = 10_000;

/// Bits-per-element constants in Q16.16 fixed-point format.
/// Pre-computed as `bpe = round(-ln(p) / (ln(2))^2 * 65536)` for common false positive
/// rates. See `test_q16_constants` for verification.
mod bpe {
    pub const FP_1E1: u64 = 314_083; // ~10% FP rate (4.79 bits/element)
    pub const FP_1E2: u64 = 628_166; // ~1% FP rate (9.59 bits/element)
    pub const FP_1E3: u64 = 942_250; // ~0.1% FP rate (14.38 bits/element)
    pub const FP_1E4: u64 = 1_256_333; // ~0.01% FP rate (19.17 bits/element)
}

/// Convert false positive rate to normalized integer (4 decimal places).
/// Uses explicit round-half-up for determinism.
///
/// # Determinism
///
/// This function is deterministic across platforms because:
/// - Clamping to 0.0001-0.9999 keeps values in a safe range where f64 arithmetic
///   is well-behaved (no subnormals, no precision loss near 0 or 1)
/// - After scaling by 10000, results are in range 1-9999 which are all exactly
///   representable as f64 (integers up to 2^53 are exact)
/// - All operations (*, +, floor) are IEEE 754 basic operations, which are
///   required to be correctly rounded to the same result on all compliant systems
/// - We use round-half-up (`+ 0.5` then `floor`) instead of `f64::round()` which
///   uses "round half to even" (banker's rounding) that could theoretically vary
///
/// # Panics
///
/// Panics if `p` is not between 0.0 and 1.0 (exclusive).
#[inline]
#[cfg(feature = "std")]
fn normalize_fp_rate(p: f64) -> u64 {
    assert!(p > 0.0 && p < 1.0);
    // Clamp to supported bucket range
    let p = p.clamp(0.0001, 0.9999);
    // Round-half-up: add 0.5 then floor
    ((p * FP_RATE_SCALE as f64) + 0.5).floor() as u64
}

/// Map normalized false positive rate to bits-per-element bucket.
/// Uses discrete buckets for simplicity and robustness.
#[inline]
const fn bpe_for_rate(p_normalized: u64) -> u64 {
    match p_normalized {
        0..=1 => bpe::FP_1E4,    // <= 0.0001
        2..=10 => bpe::FP_1E3,   // <= 0.001
        11..=100 => bpe::FP_1E2, // <= 0.01
        _ => bpe::FP_1E1,        // > 0.01 (loose filter)
    }
}

/// A [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).
///
/// This implementation uses the Kirsch-Mitzenmacher optimization to derive `k` hash functions
/// from two hash values, which are in turn derived from a single hash digest. This provides
/// efficient hashing for [BloomFilter::insert] and [BloomFilter::contains] operations.
///
/// # Hasher Selection
///
/// The `H` type parameter specifies the hash function to use. It defaults to [Sha256].
/// The hasher's digest must be at least 16 bytes (128 bits) long, this is enforced at
/// compile time.
///
/// When choosing a hasher, consider:
///
/// - **Security**: If the bloom filter accepts untrusted input, use a cryptographically
///   secure hash function to prevent attackers from crafting inputs that cause excessive
///   collisions (degrading the filter to always return `true`).
///
/// - **Determinism**: If the bloom filter must produce consistent results across runs
///   or machines (e.g. for serialization or consensus-critical applications), avoid keyed
///   or randomized hash functions. Both [Sha256] and [Blake3](crate::blake3::Blake3)
///   are deterministic.
///
/// - **Performance**: Hash function performance varies with the size of items inserted
///   and queried. [Sha256] is faster for smaller items (up to ~2KB), while
///   [Blake3](crate::blake3::Blake3) is faster for larger items (4KB+).
#[derive(Clone, Debug)]
pub struct BloomFilter<H: Hasher = Sha256> {
    hashers: u8,
    bits: BitMap,
    _marker: PhantomData<H>,
}

impl<H: Hasher> PartialEq for BloomFilter<H> {
    fn eq(&self, other: &Self) -> bool {
        self.hashers == other.hashers && self.bits == other.bits
    }
}

impl<H: Hasher> Eq for BloomFilter<H> {}

impl<H: Hasher> BloomFilter<H> {
    /// Compile-time assertion that the digest is at least 16 bytes.
    const _ASSERT_DIGEST_AT_LEAST_16_BYTES: () = assert!(
        <H::Digest as FixedSize>::SIZE >= 16,
        "digest must be at least 128 bits (16 bytes)"
    );

    /// Creates a new [BloomFilter] with `hashers` hash functions and `bits` bits.
    ///
    /// The number of bits will be rounded up to the next power of 2. If that would
    /// overflow, the maximum power of 2 for the platform (2^63 on 64-bit) is used.
    pub fn new(hashers: NonZeroU8, bits: NonZeroUsize) -> Self {
        let bits = bits
            .get()
            .checked_next_power_of_two()
            .unwrap_or(1 << (usize::BITS - 1));
        Self {
            hashers: hashers.get(),
            bits: BitMap::zeroes(bits as u64),
            _marker: PhantomData,
        }
    }

    /// Creates a new [BloomFilter] with optimal parameters for the expected number
    /// of items and desired false positive rate.
    ///
    /// The false positive rate is quantized to one of four buckets (~10%, ~1%, ~0.1%, ~0.01%)
    /// using integer math for determinism across all platforms.
    ///
    /// # Panics
    ///
    /// Panics if `false_positive_rate` is not between 0.0 and 1.0 (exclusive).
    #[cfg(feature = "std")]
    pub fn with_rate(expected_items: NonZeroUsize, false_positive_rate: f64) -> Self {
        let bits = Self::optimal_bits(expected_items.get(), false_positive_rate);
        let hashers = Self::optimal_hashers(expected_items.get(), bits);
        Self {
            hashers,
            bits: BitMap::zeroes(bits as u64),
            _marker: PhantomData,
        }
    }

    /// Returns the number of hashers used by the filter.
    pub const fn hashers(&self) -> NonZeroU8 {
        NonZeroU8::new(self.hashers).expect("hashers is never zero")
    }

    /// Returns the number of bits used by the filter.
    pub const fn bits(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.bits.len() as usize).expect("bits is never zero")
    }

    /// Generate `num_hashers` bit indices for a given item.
    fn indices(&self, item: &[u8]) -> impl Iterator<Item = u64> {
        #[allow(path_statements)]
        Self::_ASSERT_DIGEST_AT_LEAST_16_BYTES;

        // Extract two 64-bit hash values from the digest of the item
        let digest = H::hash(item);
        let h1 = u64::from_be_bytes(digest[0..8].try_into().unwrap());
        let mut h2 = u64::from_be_bytes(digest[8..16].try_into().unwrap());
        h2 |= 1; // make sure h2 is non-zero

        // Generate `hashers` hashes using the Kirsch-Mitzenmacher optimization:
        //
        // `h_i(x) = (h1(x) + i * h2(x)) mod m`
        let hashers = self.hashers as u64;
        let mask = self.bits.len() - 1;
        (0..hashers).map(move |hasher| h1.wrapping_add(hasher.wrapping_mul(h2)) & mask)
    }

    /// Inserts an item into the [BloomFilter].
    pub fn insert(&mut self, item: &[u8]) {
        let indices = self.indices(item);
        for index in indices {
            self.bits.set(index, true);
        }
    }

    /// Checks if an item is possibly in the [BloomFilter].
    ///
    /// Returns `true` if the item is probably in the set, and `false` if it is definitely not.
    pub fn contains(&self, item: &[u8]) -> bool {
        let indices = self.indices(item);
        for index in indices {
            if !self.bits.get(index) {
                return false;
            }
        }
        true
    }

    /// Estimates the current false positive probability.
    ///
    /// This approximates the false positive rate as `f^k` where `f` is the fill ratio
    /// (proportion of bits set to 1) and `k` is the number of hash functions.
    ///
    /// # Determinism
    ///
    /// This method is deterministic across platforms because:
    /// - Integer to f64 conversion is exact for values < 2^53 (our bit counts qualify)
    /// - Division is an IEEE 754 basic operation (correctly rounded, deterministic)
    /// - `powi` is repeated multiplication of IEEE 754 basic operations
    #[cfg(feature = "std")]
    pub fn estimated_false_positive_rate(&self) -> f64 {
        let fill_ratio = self.bits.count_ones() as f64 / self.bits.len() as f64;
        fill_ratio.powi(self.hashers as i32)
    }

    /// Estimates the number of items that have been inserted.
    ///
    /// Uses the formula `n = -(m/k) * ln(1 - x/m)` where `m` is the number of bits,
    /// `k` is the number of hash functions, and `x` is the number of bits set to 1.
    ///
    /// # Warning
    ///
    /// This method uses `ln()` which is NOT an IEEE 754 basic operation. Results may differ
    /// across platforms/architectures. Do not use in consensus-critical code paths.
    #[cfg(feature = "std")]
    pub fn estimated_count(&self) -> f64 {
        let m = self.bits.len() as f64;
        let x = self.bits.count_ones() as f64;
        let k = self.hashers as f64;
        if x >= m {
            return f64::INFINITY;
        }
        -(m / k) * (1.0 - x / m).ln()
    }

    /// Calculates the optimal number of hash functions for a given capacity and bit count.
    ///
    /// Uses integer math with Q16.16 fixed-point for determinism. The result is clamped to
    /// [1, 16] since beyond ~10-12 hashes provides negligible improvement while increasing
    /// CPU cost.
    #[cfg(feature = "std")]
    pub fn optimal_hashers(expected_items: usize, bits: usize) -> u8 {
        if expected_items == 0 {
            return 1;
        }

        // k = (m/n) * ln(2) using Q16.16 fixed-point
        let n_scaled = (expected_items as u64).saturating_mul(1 << 16);
        let k = (bits as u64).saturating_mul(LN2_Q16) / n_scaled;
        k.clamp(1, 16) as u8
    }

    /// Calculates the optimal number of bits for a given capacity and false positive rate.
    ///
    /// Uses pre-computed bits-per-element values and integer math for determinism. The
    /// false positive rate is quantized to one of four buckets (~10%, ~1%, ~0.1%, ~0.01%).
    /// The result is rounded up to the next power of 2. If that would overflow, the maximum
    /// power of 2 for the platform (2^63 on 64-bit) is used.
    ///
    /// # Panics
    ///
    /// Panics if `false_positive_rate` is not between 0.0 and 1.0 (exclusive).
    #[cfg(feature = "std")]
    pub fn optimal_bits(expected_items: usize, false_positive_rate: f64) -> usize {
        let fp_normalized = normalize_fp_rate(false_positive_rate);
        let bpe = bpe_for_rate(fp_normalized);
        // ceil(n * bpe) using Q16.16 fixed-point, with overflow protection
        let raw = (expected_items as u64)
            .saturating_mul(bpe)
            .saturating_add(0xFFFF)
            >> 16;
        (raw as usize)
            .checked_next_power_of_two()
            .unwrap_or(1 << (usize::BITS - 1))
    }
}

impl<H: Hasher> Write for BloomFilter<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.hashers.write(buf);
        self.bits.write(buf);
    }
}

impl<H: Hasher> Read for BloomFilter<H> {
    // The number of hashers and the number of bits that the bitmap must have.
    type Cfg = (NonZeroU8, NonZeroU64);

    fn read_cfg(
        buf: &mut impl Buf,
        (hashers_cfg, bits_cfg): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        if !bits_cfg.get().is_power_of_two() {
            return Err(CodecError::Invalid(
                "BloomFilter",
                "bits must be a power of 2",
            ));
        }
        let hashers = u8::read_cfg(buf, &())?;
        if hashers != hashers_cfg.get() {
            return Err(CodecError::Invalid(
                "BloomFilter",
                "hashers doesn't match config",
            ));
        }
        let bits = BitMap::read_cfg(buf, &bits_cfg.get())?;
        if bits.len() != bits_cfg.get() {
            return Err(CodecError::Invalid(
                "BloomFilter",
                "bitmap length doesn't match config",
            ));
        }
        Ok(Self {
            hashers,
            bits,
            _marker: PhantomData,
        })
    }
}

impl<H: Hasher> EncodeSize for BloomFilter<H> {
    fn encode_size(&self) -> usize {
        self.hashers.encode_size() + self.bits.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<H: Hasher> arbitrary::Arbitrary<'_> for BloomFilter<H> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Ensure at least 1 hasher
        let hashers = u8::arbitrary(u)?.max(1);
        // Fallback to highest power of two in u16 on overflow,
        // we restrict to u16 to avoid OOM
        let bits_len = u
            .arbitrary::<u16>()?
            .checked_next_power_of_two()
            .unwrap_or(1 << 15) as usize;
        let mut bits = BitMap::with_capacity(bits_len as u64);
        for _ in 0..bits_len {
            bits.push(u.arbitrary::<bool>()?);
        }
        Ok(Self {
            hashers,
            bits,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_utils::{NZUsize, NZU64, NZU8};

    #[test]
    fn test_insert_and_contains() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(10), NZUsize!(1000));
        let item1 = b"hello";
        let item2 = b"world";
        let item3 = b"bloomfilter";

        bf.insert(item1);
        bf.insert(item2);

        assert!(bf.contains(item1));
        assert!(bf.contains(item2));
        assert!(!bf.contains(item3));
    }

    #[test]
    fn test_empty() {
        let bf = BloomFilter::<Sha256>::new(NZU8!(5), NZUsize!(100));
        assert!(!bf.contains(b"anything"));
    }

    #[test]
    fn test_false_positives() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(10), NZUsize!(100));
        for i in 0..10usize {
            bf.insert(&i.to_be_bytes());
        }

        // Check for inserted items
        for i in 0..10usize {
            assert!(bf.contains(&i.to_be_bytes()));
        }

        // Check for non-inserted items and count false positives
        let mut false_positives = 0;
        for i in 100..1100usize {
            if bf.contains(&i.to_be_bytes()) {
                false_positives += 1;
            }
        }

        // A small bloom filter with many items will have some false positives.
        // The exact number is probabilistic, but it should not be zero and not all should be FPs.
        assert!(false_positives > 0);
        assert!(false_positives < 1000);
    }

    #[test]
    fn test_codec_roundtrip() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        bf.insert(b"test2");

        let cfg = (NZU8!(5), NZU64!(128));

        let encoded = bf.encode();
        let decoded = BloomFilter::<Sha256>::decode_cfg(encoded, &cfg).unwrap();

        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_empty() {
        let bf = BloomFilter::<Sha256>::new(NZU8!(4), NZUsize!(128));
        let cfg = (NZU8!(4), NZU64!(128));
        let encoded = bf.encode();
        let decoded = BloomFilter::<Sha256>::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_with_invalid_hashers() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        let encoded = bf.encode();

        // Too large
        let cfg = (NZU8!(10), NZU64!(128));
        let decoded = BloomFilter::<Sha256>::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid(
                "BloomFilter",
                "hashers doesn't match config"
            ))
        ));

        // Too small
        let cfg = (NZU8!(4), NZU64!(128));
        let decoded = BloomFilter::<Sha256>::decode_cfg(encoded, &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid(
                "BloomFilter",
                "hashers doesn't match config"
            ))
        ));
    }

    #[test]
    fn test_codec_with_invalid_bits() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        let encoded = bf.encode();

        // Wrong bit count
        let cfg = (NZU8!(5), NZU64!(64));
        let result = BloomFilter::<Sha256>::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(result, Err(CodecError::InvalidLength(128))));

        let cfg = (NZU8!(5), NZU64!(256));
        let result = BloomFilter::<Sha256>::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "BloomFilter",
                "bitmap length doesn't match config"
            ))
        ));

        // Non-power-of-2 bits
        let cfg = (NZU8!(5), NZU64!(100));
        let result = BloomFilter::<Sha256>::decode_cfg(encoded, &cfg);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "BloomFilter",
                "bits must be a power of 2"
            ))
        ));
    }

    #[test]
    fn test_statistics() {
        let mut bf = BloomFilter::<Sha256>::new(NZU8!(7), NZUsize!(1024));

        // Empty filter should have 0 estimated count and FP rate
        assert_eq!(bf.estimated_count(), 0.0);
        assert_eq!(bf.estimated_false_positive_rate(), 0.0);

        // Insert some items
        for i in 0..100usize {
            bf.insert(&i.to_be_bytes());
        }

        // Estimated count should be reasonably close to 100
        let estimated = bf.estimated_count();
        assert!(estimated > 75.0 && estimated < 125.0);

        // FP rate should be non-zero after insertions
        assert!(bf.estimated_false_positive_rate() > 0.0);
        assert!(bf.estimated_false_positive_rate() < 1.0);
    }

    #[test]
    fn test_with_rate() {
        // Create a filter for 1000 items with 1% false positive rate
        let mut bf = BloomFilter::<Sha256>::with_rate(NZUsize!(1000), 0.01);

        // Verify getters return expected values
        let expected_bits = BloomFilter::<Sha256>::optimal_bits(1000, 0.01);
        let expected_hashers = BloomFilter::<Sha256>::optimal_hashers(1000, expected_bits);
        assert_eq!(bf.bits().get(), expected_bits);
        assert_eq!(bf.hashers().get(), expected_hashers);

        // Insert 1000 items
        for i in 0..1000usize {
            bf.insert(&i.to_be_bytes());
        }

        // All inserted items should be found
        for i in 0..1000usize {
            assert!(bf.contains(&i.to_be_bytes()));
        }

        // Count false positives on non-inserted items
        let mut false_positives = 0;
        for i in 1000..2000usize {
            if bf.contains(&i.to_be_bytes()) {
                false_positives += 1;
            }
        }

        // With 1% target FP rate, we expect around 10 false positives out of 1000
        // Allow some variance (should be well under 2%)
        assert!(false_positives < 20);
    }

    #[test]
    fn test_optimal_hashers() {
        // For 1000 items in 10000 bits, optimal k = (10000/1000) * ln(2) = 6.93
        // Integer math truncates to 6
        let k = BloomFilter::<Sha256>::optimal_hashers(1000, 10000);
        assert_eq!(k, 6);

        // For 100 items in 1000 bits, optimal k = (1000/100) * ln(2) = 6.93
        // Integer math truncates to 6
        let k = BloomFilter::<Sha256>::optimal_hashers(100, 1000);
        assert_eq!(k, 6);

        // Edge case: very few bits per item, clamped to 1
        let k = BloomFilter::<Sha256>::optimal_hashers(1000, 100);
        assert_eq!(k, 1);

        // Edge case: many bits per item, clamped to 16
        let k = BloomFilter::<Sha256>::optimal_hashers(100, 100000);
        assert_eq!(k, 16);

        // Edge case: zero items returns 1
        let k = BloomFilter::<Sha256>::optimal_hashers(0, 1000);
        assert_eq!(k, 1);

        // Edge case: extreme values that would overflow (n << 16 wraps to 0 for n >= 2^48)
        // Should not panic, should return clamped value
        let k = BloomFilter::<Sha256>::optimal_hashers(1 << 48, 1000);
        assert_eq!(k, 1);
        let k = BloomFilter::<Sha256>::optimal_hashers(usize::MAX, usize::MAX);
        assert!((1..=16).contains(&k));
    }

    #[test]
    fn test_optimal_bits() {
        // For 1000 items with 1% FP rate
        // Formula: m = -n * ln(p) / (ln(2))^2 = -1000 * ln(0.01) / 0.4804 = 9585
        // Rounded to next power of 2 = 16384
        let bits = BloomFilter::<Sha256>::optimal_bits(1000, 0.01);
        assert_eq!(bits, 16384);
        assert!(bits.is_power_of_two());

        // For 10000 items with 0.001% FP rate (need significantly more bits)
        // Formula: m = -10000 * ln(0.00001) / 0.4804 = 239627
        // Rounded to next power of 2 = 262144
        let bits_lower_fp = BloomFilter::<Sha256>::optimal_bits(10000, 0.00001);
        assert_eq!(bits_lower_fp, 262144);
        assert!(bits_lower_fp.is_power_of_two());
    }

    #[test]
    fn test_bits_extreme_values() {
        // Very large expected_items, uses saturation arithmetic
        let bits = BloomFilter::<Sha256>::optimal_bits(usize::MAX / 2, 0.0001);
        assert!(bits.is_power_of_two());
        assert!(bits > 0);

        // Large but reasonable values
        let bits = BloomFilter::<Sha256>::optimal_bits(1_000_000_000, 0.0001);
        assert!(bits.is_power_of_two());

        // Zero items
        let bits = BloomFilter::<Sha256>::optimal_bits(0, 0.01);
        assert!(bits.is_power_of_two());
        assert_eq!(bits, 1); // 0 * bpe rounds up to 1
    }

    #[test]
    fn test_q16_constants() {
        // Verify Q16.16 fixed-point constants match the formulas

        // LN2_Q16 = ln(2) * 65536
        let ln2 = core::f64::consts::LN_2;
        let expected_ln2_q16 = (ln2 * 65536.0).round() as u64;
        assert_eq!(LN2_Q16, expected_ln2_q16);

        // bpe = -ln(p) / (ln(2))^2
        // bpe_q16 = bpe * 65536
        let ln2_sq = ln2 * ln2;

        let bpe_1e1 = -0.1_f64.ln() / ln2_sq;
        let bpe_1e2 = -0.01_f64.ln() / ln2_sq;
        let bpe_1e3 = -0.001_f64.ln() / ln2_sq;
        let bpe_1e4 = -0.0001_f64.ln() / ln2_sq;

        assert_eq!(bpe::FP_1E1, (bpe_1e1 * 65536.0).round() as u64);
        assert_eq!(bpe::FP_1E2, (bpe_1e2 * 65536.0).round() as u64);
        assert_eq!(bpe::FP_1E3, (bpe_1e3 * 65536.0).round() as u64);
        assert_eq!(bpe::FP_1E4, (bpe_1e4 * 65536.0).round() as u64);
    }
}

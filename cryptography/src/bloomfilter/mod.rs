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
#[cfg(feature = "std")]
use {
    commonware_utils::rational::BigRationalExt,
    num_rational::BigRational,
    num_traits::{One, ToPrimitive, Zero},
};

/// Rational approximation of ln(2) with 6 digits of precision: 14397/20769.
#[cfg(feature = "std")]
const LN2: (u64, u64) = (14397, 20769);

/// Rational approximation of 1/ln(2) with 6 digits of precision: 29145/20201.
#[cfg(feature = "std")]
const LN2_INV: (u64, u64) = (29145, 20201);

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
    /// Uses exact rational arithmetic for full determinism across all platforms.
    ///
    /// # Arguments
    ///
    /// * `expected_items` - Number of items expected to be inserted
    /// * `fp_rate` - False positive rate as a rational (e.g., `BigRational::from_frac_u64(1, 100)` for 1%)
    ///
    /// # Panics
    ///
    /// Panics if `fp_rate` is not in (0, 1).
    #[cfg(feature = "std")]
    pub fn with_rate(expected_items: NonZeroUsize, fp_rate: BigRational) -> Self {
        let bits = Self::optimal_bits(expected_items.get(), &fp_rate);
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

        // Ensure h2 is odd (non-zero). If h2 were 0, all k hash functions would
        // produce the same index (h1), defeating the purpose of multiple hashers.
        h2 |= 1;

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
    /// Returns a [`BigRational`] for exact representation and cross-platform determinism.
    #[cfg(feature = "std")]
    pub fn estimated_false_positive_rate(&self) -> BigRational {
        let ones = self.bits.count_ones();
        let len = self.bits.len();
        let fill_ratio = BigRational::new(ones.into(), len.into());
        fill_ratio.pow(self.hashers as i32)
    }

    /// Estimates the number of items that have been inserted.
    ///
    /// Uses the formula `n = -(m/k) * ln(1 - x/m)` where `m` is the number of bits,
    /// `k` is the number of hash functions, and `x` is the number of bits set to 1.
    ///
    /// Returns a [`BigRational`] using `log2_floor` for the logarithm computation.
    #[cfg(feature = "std")]
    pub fn estimated_count(&self) -> BigRational {
        let m = self.bits.len();
        let x = self.bits.count_ones();
        let k = self.hashers as u64;
        if x >= m {
            return BigRational::from_usize(usize::MAX);
        }

        // ln(1 - x/m) = log2(1 - x/m) * ln(2)
        let one_minus_fill = BigRational::new((m - x).into(), m.into());
        let log2_val = one_minus_fill.log2_floor(16);
        let ln2 = BigRational::from_frac_u64(LN2.0, LN2.1);
        let ln_result = &log2_val * &ln2;

        // n = -(m/k) * ln(1 - x/m)
        let m_over_k = BigRational::new(m.into(), k.into());
        -m_over_k * ln_result
    }

    /// Calculates the optimal number of hash functions for a given capacity and bit count.
    ///
    /// Uses [`BigRational`] for determinism. The result is clamped to [1, 16] since
    /// beyond ~10-12 hashes provides negligible improvement while increasing CPU cost.
    #[cfg(feature = "std")]
    pub fn optimal_hashers(expected_items: usize, bits: usize) -> u8 {
        if expected_items == 0 {
            return 1;
        }

        // k = (m/n) * ln(2)
        let ln2 = BigRational::from_frac_u64(LN2.0, LN2.1);
        let k_ratio = BigRational::from_usize(bits) * ln2 / BigRational::from_usize(expected_items);
        k_ratio.to_integer().to_u8().unwrap_or(16).clamp(1, 16)
    }

    /// Calculates the optimal number of bits for a given capacity and false positive rate.
    ///
    /// Uses exact rational arithmetic for full determinism across all platforms.
    /// The result is rounded up to the next power of 2. If that would overflow, the maximum
    /// power of 2 for the platform (2^63 on 64-bit) is used.
    ///
    /// Formula: m = -n * log2(p) / ln(2)
    ///
    /// # Panics
    ///
    /// Panics if `fp_rate` is not in (0, 1).
    #[cfg(feature = "std")]
    pub fn optimal_bits(expected_items: usize, fp_rate: &BigRational) -> usize {
        assert!(
            fp_rate > &BigRational::zero() && fp_rate < &BigRational::one(),
            "false positive rate must be in (0, 1)"
        );

        // log2(p) is negative for p < 1. Use floor to get a more negative value,
        // which results in more bits (conservative choice to not exceed target FP rate).
        let log2_p = fp_rate.log2_floor(16);

        // m = -n * log2(p) / ln(2) = -n * log2(p) * (1/ln(2))
        // Since log2(p) < 0 for p < 1, -log2(p) > 0
        let n = BigRational::from_usize(expected_items);
        let ln2_inv = BigRational::from_frac_u64(LN2_INV.0, LN2_INV.1);
        let bits_rational = -(&n * &log2_p * &ln2_inv);

        let raw = bits_rational.ceil_to_u128().unwrap_or(1) as usize;
        raw.max(1)
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
        // Generate u64 in u16 range to avoid OOM, then round to power of two
        let bits_len = u.int_in_range(0..=u16::MAX as u64)?.next_power_of_two();
        let mut bits = BitMap::with_capacity(bits_len);
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
        assert_eq!(bf.estimated_count(), BigRational::zero());
        assert_eq!(bf.estimated_false_positive_rate(), BigRational::zero());

        // Insert some items
        for i in 0..100usize {
            bf.insert(&i.to_be_bytes());
        }

        // Estimated count should be reasonably close to 100
        let estimated = bf.estimated_count();
        let lower = BigRational::from_usize(75);
        let upper = BigRational::from_usize(125);
        assert!(estimated > lower && estimated < upper);

        // FP rate should be non-zero after insertions
        assert!(bf.estimated_false_positive_rate() > BigRational::zero());
        assert!(bf.estimated_false_positive_rate() < BigRational::one());
    }

    #[test]
    fn test_with_rate() {
        // Create a filter for 1000 items with 1% false positive rate
        let fp_rate = BigRational::from_frac_u64(1, 100);
        let mut bf = BloomFilter::<Sha256>::with_rate(NZUsize!(1000), fp_rate.clone());

        // Verify getters return expected values
        let expected_bits = BloomFilter::<Sha256>::optimal_bits(1000, &fp_rate);
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
        let fp_1pct = BigRational::from_frac_u64(1, 100);
        let bits = BloomFilter::<Sha256>::optimal_bits(1000, &fp_1pct);
        assert_eq!(bits, 16384);
        assert!(bits.is_power_of_two());

        // For 10000 items with 0.001% FP rate (need significantly more bits)
        // Formula: m = -10000 * ln(0.00001) / 0.4804 = 239627
        // Rounded to next power of 2 = 262144
        let fp_001pct = BigRational::from_frac_u64(1, 100_000);
        let bits_lower_fp = BloomFilter::<Sha256>::optimal_bits(10000, &fp_001pct);
        assert_eq!(bits_lower_fp, 262144);
        assert!(bits_lower_fp.is_power_of_two());
    }

    #[test]
    fn test_bits_extreme_values() {
        let fp_001pct = BigRational::from_frac_u64(1, 10_000);
        let fp_1pct = BigRational::from_frac_u64(1, 100);

        // Very large expected_items
        let bits = BloomFilter::<Sha256>::optimal_bits(usize::MAX / 2, &fp_001pct);
        assert!(bits.is_power_of_two());
        assert!(bits > 0);

        // Large but reasonable values
        let bits = BloomFilter::<Sha256>::optimal_bits(1_000_000_000, &fp_001pct);
        assert!(bits.is_power_of_two());

        // Zero items
        let bits = BloomFilter::<Sha256>::optimal_bits(0, &fp_1pct);
        assert!(bits.is_power_of_two());
        assert_eq!(bits, 1); // 0 * bpe rounds up to 1
    }

    #[test]
    fn test_with_rate_deterministic() {
        let fp_rate = BigRational::from_frac_u64(1, 100);
        let bf1 = BloomFilter::<Sha256>::with_rate(NZUsize!(1000), fp_rate.clone());
        let bf2 = BloomFilter::<Sha256>::with_rate(NZUsize!(1000), fp_rate);
        assert_eq!(bf1.bits(), bf2.bits());
        assert_eq!(bf1.hashers(), bf2.hashers());
    }

    #[test]
    fn test_optimal_bits_matches_formula() {
        // For 1000 items at 1% FP rate
        // m = -1000 * log2(0.01) / ln(2) = 9585
        // Rounded to power of 2 = 16384
        let fp_rate = BigRational::from_frac_u64(1, 100);
        let bits = BloomFilter::<Sha256>::optimal_bits(1000, &fp_rate);
        assert_eq!(bits, 16384);
    }
}

//! An implementation of a [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).

use crate::{
    sha256::{Digest, Sha256},
    Hasher,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    codec::{Read, Write},
    error::Error as CodecError,
    EncodeSize, FixedSize,
};
use commonware_utils::bitmap::BitMap;
use core::num::{NonZeroU64, NonZeroU8, NonZeroUsize};

/// The length of a [Digest] in bytes.
const DIGEST_LEN: usize = Digest::SIZE;

/// A [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).
///
/// This implementation uses the Kirsch-Mitzenmacher optimization to derive `k` hash functions
/// from two hash values, which are in turn derived from a single [Digest]. This provides
/// efficient hashing for [BloomFilter::insert] and [BloomFilter::contains] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    hashers: u8,
    bits: BitMap,
}

impl BloomFilter {
    const _ASSERT_DIGEST_AT_LEAST_16_BYTES: () = assert!(
        DIGEST_LEN >= 16,
        "digest must be at least 128 bits (16 bytes)"
    );

    /// Creates a new [BloomFilter] with `hashers` hash functions and `bits` bits.
    ///
    /// The number of bits will be rounded up to the next power of 2.
    pub fn new(hashers: NonZeroU8, bits: NonZeroUsize) -> Self {
        let bits = bits.get().next_power_of_two();
        Self {
            hashers: hashers.get(),
            bits: BitMap::zeroes(bits as u64),
        }
    }

    /// Creates a new [BloomFilter] with optimal parameters for the expected number
    /// of items and desired false positive rate.
    ///
    /// # Panics
    ///
    /// Panics if `false_positive_rate` is not between 0.0 and 1.0 (exclusive).
    #[cfg(feature = "std")]
    pub fn with_rate(expected_items: usize, false_positive_rate: f64) -> Self {
        let bits = Self::optimal_bits(expected_items, false_positive_rate);
        let hashers = Self::optimal_hashers(expected_items, bits);
        Self {
            hashers,
            bits: BitMap::zeroes(bits as u64),
        }
    }

    /// Generate `num_hashers` bit indices for a given item.
    fn indices(&self, item: &[u8]) -> impl Iterator<Item = u64> {
        #[allow(path_statements)]
        Self::_ASSERT_DIGEST_AT_LEAST_16_BYTES;

        // Extract two 64-bit hash values from the SHA256 digest of the item
        let digest = Sha256::hash(item);
        let h1 = u64::from_be_bytes(digest[0..8].try_into().unwrap());
        let h2 = u64::from_be_bytes(digest[8..16].try_into().unwrap());

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
    #[cfg(feature = "std")]
    pub fn estimated_false_positive_rate(&self) -> f64 {
        let fill_ratio = self.bits.count_ones() as f64 / self.bits.len() as f64;
        fill_ratio.powi(self.hashers as i32)
    }

    /// Estimates the number of items that have been inserted.
    ///
    /// Uses the formula `n = -(m/k) * ln(1 - x/m)` where `m` is the number of bits,
    /// `k` is the number of hash functions, and `x` is the number of bits set to 1.
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
    /// Uses the formula `k = (m/n) * ln(2)` where `m` is the number of bits and `n` is
    /// the expected number of items.
    #[cfg(feature = "std")]
    pub fn optimal_hashers(expected_items: usize, bits: usize) -> u8 {
        let k = (bits as f64 / expected_items as f64) * core::f64::consts::LN_2;
        (k.round() as u8).clamp(1, 255)
    }

    /// Calculates the optimal number of bits for a given capacity and false positive rate.
    ///
    /// Uses the formula `m = -n * ln(p) / (ln(2))^2` where `n` is the expected number
    /// of items and `p` is the desired false positive rate.
    ///
    /// # Panics
    ///
    /// Panics if `false_positive_rate` is not between 0.0 and 1.0 (exclusive).
    #[cfg(feature = "std")]
    pub fn optimal_bits(expected_items: usize, false_positive_rate: f64) -> usize {
        assert!(false_positive_rate > 0.0 && false_positive_rate < 1.0);
        let ln2_sq = core::f64::consts::LN_2 * core::f64::consts::LN_2;
        let m = -(expected_items as f64) * false_positive_rate.ln() / ln2_sq;
        (m.ceil() as usize).next_power_of_two()
    }
}

impl Write for BloomFilter {
    fn write(&self, buf: &mut impl BufMut) {
        self.hashers.write(buf);
        self.bits.write(buf);
    }
}

impl Read for BloomFilter {
    // The number of hashers and the number of bits that the bitmap must have.
    type Cfg = (NonZeroU8, NonZeroU64);

    fn read_cfg(
        buf: &mut impl Buf,
        (hashers_cfg, bits_cfg): &Self::Cfg,
    ) -> Result<Self, CodecError> {
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
        Ok(Self { hashers, bits })
    }
}

impl EncodeSize for BloomFilter {
    fn encode_size(&self) -> usize {
        self.hashers.encode_size() + self.bits.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for BloomFilter {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Ensure at least 1 hasher
        let hashers = u8::arbitrary(u)?.max(1);
        // Ensure at least 1 bit to avoid empty bitmap, and a power of 2
        let bits_len = u.arbitrary_len::<u64>()?.max(1).next_power_of_two();
        let mut bits = BitMap::with_capacity(bits_len as u64);
        for _ in 0..bits_len {
            bits.push(u.arbitrary::<bool>()?);
        }
        Ok(Self { hashers, bits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_utils::{NZUsize, NZU64, NZU8};

    #[test]
    fn test_insert_and_contains() {
        let mut bf = BloomFilter::new(NZU8!(10), NZUsize!(1000));
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
        let bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        assert!(!bf.contains(b"anything"));
    }

    #[test]
    fn test_false_positives() {
        let mut bf = BloomFilter::new(NZU8!(10), NZUsize!(100));
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
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        bf.insert(b"test2");

        let cfg = (NZU8!(5), NZU64!(128));

        let encoded = bf.encode();
        let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();

        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_empty() {
        let bf = BloomFilter::new(NZU8!(4), NZUsize!(128));
        let cfg = (NZU8!(4), NZU64!(128));
        let encoded = bf.encode();
        let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_with_invalid_hashers() {
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        let encoded = bf.encode();

        // Too large
        let cfg = (NZU8!(10), NZU64!(128));
        let decoded = BloomFilter::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid(
                "BloomFilter",
                "hashers doesn't match config"
            ))
        ));

        // Too small
        let cfg = (NZU8!(4), NZU64!(128));
        let decoded = BloomFilter::decode_cfg(encoded, &cfg);
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
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(128));
        bf.insert(b"test1");
        let encoded = bf.encode();

        // Wrong bit count
        let cfg = (NZU8!(5), NZU64!(64));
        let result = BloomFilter::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(result, Err(CodecError::InvalidLength(128))));

        let cfg = (NZU8!(5), NZU64!(256));
        let result = BloomFilter::decode_cfg(encoded, &cfg);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "BloomFilter",
                "bitmap length doesn't match config"
            ))
        ));
    }

    #[test]
    fn test_statistics() {
        let mut bf = BloomFilter::new(NZU8!(7), NZUsize!(1024));

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
        let mut bf = BloomFilter::with_rate(1000, 0.01);

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
        // For 1000 items in 10000 bits, optimal k = (10000/1000) * ln(2) = 6.93 -> 7
        let k = BloomFilter::optimal_hashers(1000, 10000);
        assert_eq!(k, 7);

        // For 100 items in 1000 bits, optimal k = (1000/100) * ln(2) = 6.93 -> 7
        let k = BloomFilter::optimal_hashers(100, 1000);
        assert_eq!(k, 7);

        // Edge case: very few bits per item
        let k = BloomFilter::optimal_hashers(1000, 100);
        assert!(k >= 1);
    }

    #[test]
    fn test_optimal_bits() {
        // For 1000 items with 1% FP rate
        // Formula: m = -n * ln(p) / (ln(2))^2 = -1000 * ln(0.01) / 0.4804 = 9585
        // Rounded to next power of 2 = 16384
        let bits = BloomFilter::optimal_bits(1000, 0.01);
        assert_eq!(bits, 16384);
        assert!(bits.is_power_of_two());

        // For 10000 items with 0.001% FP rate (need significantly more bits)
        // Formula: m = -10000 * ln(0.00001) / 0.4804 = 239627
        // Rounded to next power of 2 = 262144
        let bits_lower_fp = BloomFilter::optimal_bits(10000, 0.00001);
        assert_eq!(bits_lower_fp, 262144);
        assert!(bits_lower_fp.is_power_of_two());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<BloomFilter>,
        }
    }
}

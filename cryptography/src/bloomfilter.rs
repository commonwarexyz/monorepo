//! An implementation of a [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).

use crate::{hash, sha256::Digest};
use bytes::{Buf, BufMut};
use commonware_codec::{
    codec::{Read, Write},
    config::RangeCfg,
    error::Error as CodecError,
    EncodeSize,
};
use commonware_utils::BitVec;
use std::num::{NonZeroU8, NonZeroUsize};

/// A [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).
///
/// This implementation uses the Kirsch-Mitzenmacher optimization to derive `k` hash functions
/// from two hash values, which are in turn derived from a single SHA-256 digest. This provides
/// efficient hashing for [BloomFilter::insert] and [BloomFilter::contains] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    hashers: u8,
    bits: BitVec,
}

impl BloomFilter {
    /// Creates a new bloom filter with `hashers` hash functions and `bits` bits.
    pub fn new(hashers: NonZeroU8, bits: NonZeroUsize) -> Self {
        Self {
            hashers: hashers.get(),
            bits: BitVec::zeroes(bits.get()),
        }
    }

    /// Creates a new bloom filter optimized for a given capacity and false positive rate.
    ///
    /// The false positive rate is specified as a fraction: `fp_numerator / fp_denominator`.
    /// For example, for a 1% false positive rate, use fp_numerator=1, fp_denominator=100.
    ///
    /// This implementation uses integer arithmetic only to ensure deterministic behavior.
    pub fn with_capacity(
        capacity: NonZeroUsize,
        fp_numerator: NonZeroUsize,
        fp_denominator: NonZeroUsize,
    ) -> Result<Self, &'static str> {
        let n = capacity.get();
        let fp_num = fp_numerator.get();
        let fp_den = fp_denominator.get();

        // Validate false positive rate
        if fp_num >= fp_den {
            return Err("false positive rate must be less than 1");
        }

        // Calculate optimal number of bits (m) and hash functions (k)
        // Using approximations to avoid floating point:
        // m ≈ -n * ln(p) / (ln(2)^2)
        // k ≈ (m/n) * ln(2)

        // We use the approximation: -ln(p) ≈ ln(1/p) = ln(fp_den/fp_num)
        // For small p, we can use: ln(1/p) ≈ 1/p - 1 (but this is less accurate)
        // Instead, we'll use a more accurate integer-based approach

        // Calculate bits using integer math
        // We use the fact that ln(2) ≈ 0.693147 and ln(2)^2 ≈ 0.480453
        // Scaling by 1000000 for precision:
        // ln(2) * 1000000 ≈ 693147
        // ln(2)^2 * 1000000 ≈ 480453

        // Calculate -ln(p) using integer approximation
        // For a fraction p = num/den, -ln(p) = ln(den/num)
        let ln_inv_p = Self::int_ln_ratio(fp_den, fp_num)?;

        // Calculate m = n * ln(1/p) / ln(2)^2
        // Using scaling factor of 1000000
        let bits_scaled = (n as u128)
            .saturating_mul(ln_inv_p as u128)
            .saturating_mul(1000000)
            / 480453;
        let bits = (bits_scaled / 1000000) as usize;

        // Ensure we have at least n bits and at most reasonable limit
        let bits = bits.max(n).min(n.saturating_mul(100));

        // Calculate k = (m/n) * ln(2)
        // k = m * ln(2) / n
        // Using ln(2) * 1000000 ≈ 693147
        let hashers_scaled = (bits as u128).saturating_mul(693147) / (n as u128);
        let hashers = (hashers_scaled / 1000000) as u8;

        // Ensure we have at least 1 hasher and at most 255
        let hashers = hashers.max(1).min(30);

        Ok(Self::new(
            NonZeroU8::new(hashers).unwrap(),
            NonZeroUsize::new(bits).unwrap(),
        ))
    }

    /// Integer approximation of ln(a/b) where a > b > 0
    /// Returns ln(a/b) * 1000000 (scaled by 10^6 for precision)
    fn int_ln_ratio(a: usize, b: usize) -> Result<usize, &'static str> {
        if a <= b || b == 0 {
            return Err("invalid ratio for logarithm");
        }

        // Use the fact that ln(a/b) = ln(a) - ln(b)
        // We'll use a simple approximation based on bit positions and linear interpolation

        // For integer ln approximation, we can use:
        // ln(x) ≈ (bit_position - 1) * ln(2) + ln(mantissa)
        // where x = 2^bit_position * mantissa, and 1 <= mantissa < 2

        let ln_a = Self::int_ln(a);
        let ln_b = Self::int_ln(b);

        Ok(ln_a.saturating_sub(ln_b))
    }

    /// Integer approximation of ln(x) * 1000000
    fn int_ln(x: usize) -> usize {
        if x == 0 {
            return 0;
        }

        // Find the highest set bit position (0-indexed)
        let bit_pos = (usize::BITS - x.leading_zeros() - 1) as usize;

        // Calculate mantissa: x / 2^bit_pos
        // This gives us a value in range [1, 2)
        let shift = if bit_pos >= 10 { bit_pos - 10 } else { 0 };
        let mantissa = if shift > 0 {
            x >> shift
        } else {
            x << (10 - bit_pos)
        };

        // ln(x) = bit_pos * ln(2) + ln(mantissa)
        // ln(2) * 1000000 ≈ 693147
        let ln_2_scaled = 693147;
        let bit_contribution = bit_pos * ln_2_scaled;

        // For mantissa in [1, 2), we use linear approximation:
        // ln(1 + f) ≈ f - f^2/2 + f^3/3 - ...
        // For our purposes, linear is sufficient: ln(1 + f) ≈ f
        // mantissa = 1 + f, where f is in [0, 1)
        // f = (mantissa - 1024) / 1024 (since mantissa is scaled by 1024)

        let f_scaled = if mantissa >= 1024 {
            ((mantissa - 1024) * 1000000) / 1024
        } else {
            0
        };

        bit_contribution + f_scaled
    }

    /// Inserts an item into the [BloomFilter].
    pub fn insert(&mut self, item: &[u8]) {
        let hashes = self.hashes(item);
        for hash in hashes {
            let index = (hash % self.bits.len() as u128) as usize;
            self.bits.set(index);
        }
    }

    /// Checks if an item is possibly in the [BloomFilter].
    ///
    /// Returns `true` if the item is probably in the set, and `false` if it is definitely not.
    pub fn contains(&self, item: &[u8]) -> bool {
        let hashes = self.hashes(item);
        for hash in hashes {
            let index = (hash % self.bits.len() as u128) as usize;
            if !self.bits.get(index).unwrap_or(false) {
                return false;
            }
        }
        true
    }

    /// Returns the number of bits in the [BloomFilter].
    pub fn bits(&self) -> usize {
        self.bits.len()
    }

    /// Returns the number of hash functions used in the [BloomFilter].
    pub fn hashers(&self) -> u8 {
        self.hashers
    }

    /// Get two 128-bit hash values from a 32-byte [Digest].
    fn get_two_hashes(digest: &Digest) -> (u128, u128) {
        let mut h1_bytes = [0u8; 16];
        h1_bytes.copy_from_slice(&digest[0..16]);
        let h1 = u128::from_be_bytes(h1_bytes);

        let mut h2_bytes = [0u8; 16];
        h2_bytes.copy_from_slice(&digest[16..32]);
        let h2 = u128::from_be_bytes(h2_bytes);

        (h1, h2)
    }

    /// Generate `num_hashers` hashes for the given item.
    ///
    /// It uses the Kirsch-Mitzenmacher optimization:
    /// `h_i(x) = (h1(x) + i * h2(x)) mod m`
    /// `h1` and `h2` are derived from the SHA256 digest of the item.
    fn hashes(&self, item: &[u8]) -> impl Iterator<Item = u128> {
        let digest = hash(item);
        let (h1, h2) = Self::get_two_hashes(&digest);

        let hashers = self.hashers;
        (0..hashers).map(move |i| h1.wrapping_add(u128::from(i).wrapping_mul(h2)))
    }
}

impl Write for BloomFilter {
    fn write(&self, buf: &mut impl BufMut) {
        self.hashers.write(buf);
        self.bits.write(buf);
    }
}

impl Read for BloomFilter {
    type Cfg = (RangeCfg, RangeCfg);

    fn read_cfg(
        buf: &mut impl Buf,
        (hashers_cfg, bits_cfg): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let hashers = u8::read_cfg(buf, &())?;
        if !hashers_cfg.contains(&(hashers as usize)) {
            return Err(CodecError::Invalid("bloomfilter", "invalid hashers"));
        }
        let bits = BitVec::read_cfg(buf, bits_cfg)?;
        Ok(Self { hashers, bits })
    }
}

impl EncodeSize for BloomFilter {
    fn encode_size(&self) -> usize {
        self.hashers.encode_size() + self.bits.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_utils::{NZUsize, NZU8};

    #[test]
    fn test_new() {
        let bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        assert_eq!(bf.bits(), 100);
        assert_eq!(bf.hashers(), 5);
        assert_eq!(bf.bits.count_ones(), 0);
    }

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
    fn test_empty_filter() {
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
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        bf.insert(b"test1");
        bf.insert(b"test2");

        let cfg = ((1..=100).into(), (100..=100).into());

        let encoded = bf.encode();
        let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();

        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_empty_roundtrip() {
        let bf = BloomFilter::new(NZU8!(4), NZUsize!(128));
        let cfg = ((1..=100).into(), (128..=128).into());
        let encoded = bf.encode();
        let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_with_invalid_hashers() {
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        bf.insert(b"test1");

        let encoded = bf.encode();

        // Too small
        let cfg = ((0..=0).into(), (100..=100).into());
        let decoded = BloomFilter::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid("bloomfilter", "invalid hashers"))
        ));

        // Too large
        let cfg = ((10..=10).into(), (100..=100).into());
        let decoded = BloomFilter::decode_cfg(encoded, &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid("bloomfilter", "invalid hashers"))
        ));
    }

    #[test]
    fn test_codec_with_invalid_bits() {
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        bf.insert(b"test1");

        let encoded = bf.encode();

        // Too small
        let cfg_small = ((5..=5).into(), (0..100).into());
        let result_small = BloomFilter::decode_cfg(encoded.clone(), &cfg_small);
        assert!(matches!(result_small, Err(CodecError::InvalidLength(100))));

        // Too large
        let cfg_large = ((5..=5).into(), (101..).into());
        let result_large = BloomFilter::decode_cfg(encoded.clone(), &cfg_large);
        assert!(matches!(result_large, Err(CodecError::InvalidLength(100))));
    }

    #[test]
    fn test_with_capacity() {
        // Test with 1% false positive rate (1/100)
        let bf = BloomFilter::with_capacity(NZUsize!(1000), NZUsize!(1), NZUsize!(100)).unwrap();
        assert_eq!(bf.bits(), 9826);
        assert_eq!(bf.hashers(), 6);

        // Test with 0.1% false positive rate (1/1000)
        let bf = BloomFilter::with_capacity(NZUsize!(1000), NZUsize!(1), NZUsize!(1000)).unwrap();
        assert_eq!(bf.bits(), 14968);
        assert_eq!(bf.hashers(), 10);

        // Test with very small capacity
        let bf = BloomFilter::with_capacity(NZUsize!(10), NZUsize!(1), NZUsize!(100)).unwrap();
        assert_eq!(bf.bits(), 98);
        assert_eq!(bf.hashers(), 6);

        // Test with 5% false positive rate (5/100)
        let bf = BloomFilter::with_capacity(NZUsize!(131_072), NZUsize!(5), NZUsize!(100)).unwrap();
        assert_eq!(bf.bits(), 841640);
        assert_eq!(bf.hashers(), 4);
    }

    #[test]
    fn test_with_capacity_invalid_fp_rate() {
        // Test with FP rate >= 1
        let result = BloomFilter::with_capacity(NZUsize!(1000), NZUsize!(100), NZUsize!(100));
        assert!(matches!(
            result,
            Err("false positive rate must be less than 1")
        ));

        let result = BloomFilter::with_capacity(NZUsize!(1000), NZUsize!(101), NZUsize!(100));
        assert!(matches!(
            result,
            Err("false positive rate must be less than 1")
        ));
    }

    #[test]
    fn test_with_capacity_deterministic() {
        // Test that the same parameters always produce the same result
        let bf1 = BloomFilter::with_capacity(NZUsize!(5000), NZUsize!(1), NZUsize!(200)).unwrap();
        let bf2 = BloomFilter::with_capacity(NZUsize!(5000), NZUsize!(1), NZUsize!(200)).unwrap();

        assert_eq!(bf1.bits(), bf2.bits());
        assert_eq!(bf1.hashers(), bf2.hashers());
    }

    #[test]
    fn test_with_capacity_false_positive_rate() {
        // Create a bloom filter and test actual false positive rate
        let capacity = 10000;

        let mut bf =
            BloomFilter::with_capacity(NZUsize!(capacity), NZUsize!(1), NZUsize!(100)).unwrap();

        // Insert items
        for i in 0..capacity {
            bf.insert(&i.to_be_bytes());
        }

        // Check false positive rate with non-inserted items
        let mut false_positives = 0;
        let test_count = 10000;
        for i in capacity..(capacity + test_count) {
            if bf.contains(&i.to_be_bytes()) {
                false_positives += 1;
            }
        }

        // The actual FP rate should be reasonably close to target (1%)
        // We expect around 100 false positives out of 10000 tests
        // Allow margin up to 3x (300 false positives) due to integer approximations
        assert!(
            false_positives < 300,
            "Too many false positives: {false_positives} out of {test_count}"
        );
    }
}

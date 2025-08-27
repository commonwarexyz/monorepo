//! An implementation of a [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).

use crate::{
    sha256::{Digest, Sha256},
    Hasher,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    codec::{Read, Write},
    config::RangeCfg,
    error::Error as CodecError,
    EncodeSize, FixedSize,
};
use commonware_utils::BitVec;
use std::num::{NonZeroU8, NonZeroUsize};

/// The length of a half of a [Digest].
const HALF_DIGEST_LEN: usize = 16;

/// The length of a full [Digest].
const FULL_DIGEST_LEN: usize = Digest::SIZE;

/// A [Bloom Filter](https://en.wikipedia.org/wiki/Bloom_filter).
///
/// This implementation uses the Kirsch-Mitzenmacher optimization to derive `k` hash functions
/// from two hash values, which are in turn derived from a single [Digest]. This provides
/// efficient hashing for [BloomFilter::insert] and [BloomFilter::contains] operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    hashers: u8,
    bits: BitVec,
}

impl BloomFilter {
    /// Creates a new [BloomFilter] with `hashers` hash functions and `bits` bits.
    pub fn new(hashers: NonZeroU8, bits: NonZeroUsize) -> Self {
        Self {
            hashers: hashers.get(),
            bits: BitVec::zeroes(bits.get()),
        }
    }

    /// Generate `num_hashers` bit indices for a given item.
    fn indices(&self, item: &[u8], bits: usize) -> impl Iterator<Item = usize> {
        // Extract two 128-bit hash values from the SHA256 digest of the item
        let digest = Sha256::hash(item);
        let mut h1_bytes = [0u8; HALF_DIGEST_LEN];
        h1_bytes.copy_from_slice(&digest[0..HALF_DIGEST_LEN]);
        let h1 = u128::from_be_bytes(h1_bytes);
        let mut h2_bytes = [0u8; HALF_DIGEST_LEN];
        h2_bytes.copy_from_slice(&digest[HALF_DIGEST_LEN..FULL_DIGEST_LEN]);
        let h2 = u128::from_be_bytes(h2_bytes);

        // Generate `hashers` hashes using the Kirsch-Mitzenmacher optimization:
        //
        // `h_i(x) = (h1(x) + i * h2(x)) mod m`
        let hashers = self.hashers as u128;
        let bits = bits as u128;
        (0..hashers)
            .map(move |hasher| h1.wrapping_add(hasher.wrapping_mul(h2)) % bits)
            .map(|index| index as usize)
    }

    /// Inserts an item into the [BloomFilter].
    pub fn insert(&mut self, item: &[u8]) {
        let indices = self.indices(item, self.bits.len());
        for index in indices {
            self.bits.set(index);
        }
    }

    /// Checks if an item is possibly in the [BloomFilter].
    ///
    /// Returns `true` if the item is probably in the set, and `false` if it is definitely not.
    pub fn contains(&self, item: &[u8]) -> bool {
        let indices = self.indices(item, self.bits.len());
        for index in indices {
            if !self.bits.get(index).expect("index out of bounds") {
                return false;
            }
        }
        true
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
            return Err(CodecError::Invalid("BloomFilter", "invalid hashers"));
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
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        bf.insert(b"test1");
        bf.insert(b"test2");

        let cfg = ((1..=100).into(), (100..=100).into());

        let encoded = bf.encode();
        let decoded = BloomFilter::decode_cfg(encoded, &cfg).unwrap();

        assert_eq!(bf, decoded);
    }

    #[test]
    fn test_codec_empty() {
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
        let cfg = ((10..=10).into(), (100..=100).into());
        let decoded = BloomFilter::decode_cfg(encoded.clone(), &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid("BloomFilter", "invalid hashers"))
        ));

        // Too large
        let cfg = ((0..5).into(), (100..=100).into());
        let decoded = BloomFilter::decode_cfg(encoded, &cfg);
        assert!(matches!(
            decoded,
            Err(CodecError::Invalid("BloomFilter", "invalid hashers"))
        ));
    }

    #[test]
    fn test_codec_with_invalid_bits() {
        let mut bf = BloomFilter::new(NZU8!(5), NZUsize!(100));
        bf.insert(b"test1");
        let encoded = bf.encode();

        // Too small
        let cfg_small = ((5..=5).into(), (101..=110).into());
        let result_small = BloomFilter::decode_cfg(encoded.clone(), &cfg_small);
        assert!(matches!(result_small, Err(CodecError::InvalidLength(100))));

        // Too large
        let cfg_large = ((5..=5).into(), (0..100).into());
        let result_large = BloomFilter::decode_cfg(encoded.clone(), &cfg_large);
        assert!(matches!(result_large, Err(CodecError::InvalidLength(100))));
    }
}

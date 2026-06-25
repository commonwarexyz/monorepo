//! SHA-256 implementation of the `Hasher` trait.
//!
//! This implementation uses the `sha2` crate to generate SHA-256 digests.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, Sha256};
//!
//! // Create a new SHA-256 hasher
//! let mut hasher = Sha256::new();
//!
//! // Update the hasher with some messages
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//!
//! // Finalize the hasher to get the digest
//! let digest = hasher.finalize();
//!
//! // Print the digest
//! println!("digest: {:?}", digest);
//! ```

use crate::{FixedHasher, Hasher};
#[cfg(not(feature = "std"))]
use alloc::vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write,
};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRngCore;
use sha2::{block_api::compress256, Digest as _, Sha256 as ISha256};
use zeroize::Zeroize;

/// Re-export `sha2::Sha256` as `CoreSha256` for external use if needed.
pub type CoreSha256 = ISha256;

const DIGEST_LENGTH: usize = 32;
const BLOCK_LENGTH: usize = 64;
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

/// SHA-256 hasher.
#[derive(Debug, Default)]
pub struct Sha256 {
    hasher: ISha256,
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        // We manually implement `Clone` to avoid cloning the hasher state.
        Self::default()
    }
}

impl Sha256 {
    /// Convenience function for testing that creates an easily recognizable digest by repeating a
    /// single byte.
    pub fn fill(b: u8) -> <Self as Hasher>::Digest {
        <Self as Hasher>::Digest::decode(vec![b; DIGEST_LENGTH].as_ref()).unwrap()
    }
}

impl Hasher for Sha256 {
    type Digest = Digest;

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    fn finalize(&mut self) -> Self::Digest {
        let finalized = self.hasher.finalize_reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        Self::Digest::from(array)
    }

    fn reset(&mut self) -> &mut Self {
        self.hasher = ISha256::new();
        self
    }

    fn hash_pair(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        let mut blocks = [[0u8; BLOCK_LENGTH]; 2];
        blocks[0][..DIGEST_LENGTH].copy_from_slice(left.as_ref());
        blocks[0][DIGEST_LENGTH..].copy_from_slice(right.as_ref());
        finalize_two_blocks(blocks, 2 * DIGEST_LENGTH)
    }

    fn hash_u32_with_digest(prefix: u32, digest: &Self::Digest) -> Self::Digest {
        let prefix = prefix.to_be_bytes();
        let mut block = [0u8; BLOCK_LENGTH];
        block[..prefix.len()].copy_from_slice(&prefix);
        block[prefix.len()..prefix.len() + DIGEST_LENGTH].copy_from_slice(digest.as_ref());
        finalize_one_block(block, prefix.len() + DIGEST_LENGTH)
    }

    fn hash_u32_with_bytes(prefix: u32, bytes: &[u8]) -> Self::Digest {
        if bytes.len() == DIGEST_LENGTH {
            let prefix = prefix.to_be_bytes();
            let mut block = [0u8; BLOCK_LENGTH];
            block[..prefix.len()].copy_from_slice(&prefix);
            block[prefix.len()..prefix.len() + DIGEST_LENGTH].copy_from_slice(bytes);
            finalize_one_block(block, prefix.len() + DIGEST_LENGTH)
        } else {
            let prefix = prefix.to_be_bytes();
            Self::hash_parts([prefix.as_slice(), bytes])
        }
    }

    fn hash_u64_with_digest(prefix: u64, digest: &Self::Digest) -> Self::Digest {
        let prefix = prefix.to_be_bytes();
        let mut block = [0u8; BLOCK_LENGTH];
        block[..prefix.len()].copy_from_slice(&prefix);
        block[prefix.len()..prefix.len() + DIGEST_LENGTH].copy_from_slice(digest.as_ref());
        finalize_one_block(block, prefix.len() + DIGEST_LENGTH)
    }

    fn hash_u64_with_bytes(prefix: u64, bytes: &[u8]) -> Self::Digest {
        if bytes.len() == DIGEST_LENGTH {
            let prefix = prefix.to_be_bytes();
            let mut block = [0u8; BLOCK_LENGTH];
            block[..prefix.len()].copy_from_slice(&prefix);
            block[prefix.len()..prefix.len() + DIGEST_LENGTH].copy_from_slice(bytes);
            finalize_one_block(block, prefix.len() + DIGEST_LENGTH)
        } else {
            let prefix = prefix.to_be_bytes();
            Self::hash_parts([prefix.as_slice(), bytes])
        }
    }

    fn hash_u64_with_pair(
        prefix: u64,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        let prefix = prefix.to_be_bytes();
        let mut blocks = [[0u8; BLOCK_LENGTH]; 2];
        blocks[0][..prefix.len()].copy_from_slice(&prefix);
        blocks[0][prefix.len()..prefix.len() + DIGEST_LENGTH].copy_from_slice(left.as_ref());
        blocks[0][prefix.len() + DIGEST_LENGTH..].copy_from_slice(&right.as_ref()[..24]);
        blocks[1][..8].copy_from_slice(&right.as_ref()[24..]);
        finalize_two_blocks(blocks, prefix.len() + 2 * DIGEST_LENGTH)
    }

    fn hash_u64_u64_with_digest(
        first: u64,
        second: u64,
        digest: &Self::Digest,
    ) -> Self::Digest {
        let first = first.to_be_bytes();
        let second = second.to_be_bytes();
        let mut block = [0u8; BLOCK_LENGTH];
        block[..first.len()].copy_from_slice(&first);
        block[first.len()..first.len() + second.len()].copy_from_slice(&second);
        block[first.len() + second.len()..first.len() + second.len() + DIGEST_LENGTH]
            .copy_from_slice(digest.as_ref());
        finalize_one_block(block, first.len() + second.len() + DIGEST_LENGTH)
    }
}

impl FixedHasher for Sha256 {}

fn finalize_one_block(mut block: [u8; BLOCK_LENGTH], message_len: usize) -> Digest {
    debug_assert!(message_len <= 55);
    finish_padding(&mut block, message_len, message_len);
    finalize_blocks(&[block])
}

fn finalize_two_blocks(mut blocks: [[u8; BLOCK_LENGTH]; 2], message_len: usize) -> Digest {
    debug_assert!((56..=119).contains(&message_len));
    let block = message_len / BLOCK_LENGTH;
    let offset = message_len % BLOCK_LENGTH;
    blocks[block][offset] = 0x80;
    blocks[1][56..].copy_from_slice(&((message_len as u64) * 8).to_be_bytes());
    finalize_blocks(&blocks)
}

fn finish_padding(block: &mut [u8; BLOCK_LENGTH], offset: usize, message_len: usize) {
    block[offset] = 0x80;
    block[56..].copy_from_slice(&((message_len as u64) * 8).to_be_bytes());
}

fn finalize_blocks(blocks: &[[u8; BLOCK_LENGTH]]) -> Digest {
    let mut state = INITIAL_STATE;
    compress256(&mut state, blocks);

    let mut digest = [0u8; DIGEST_LENGTH];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    Digest(digest)
}

/// Digest of a SHA-256 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
#[fixed_array(infallible)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Digest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate random bytes and compute their Sha256 hash
        let len = u.int_in_range(0..=256)?;
        let data = u.bytes(len)?;
        Ok(Sha256::hash(data))
    }
}

impl Write for Digest {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Digest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let array = <[u8; DIGEST_LENGTH]>::read(buf)?;
        Ok(Self(array))
    }
}

impl FixedSize for Digest {
    const SIZE: usize = DIGEST_LENGTH;
}

impl Span for Digest {}

impl Array for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl crate::Digest for Digest {
    const EMPTY: Self = Self([0u8; DIGEST_LENGTH]);
}

impl Random for Digest {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut array = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut array);
        Self(array)
    }
}

impl Zeroize for Digest {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    const HELLO_DIGEST: [u8; DIGEST_LENGTH] = commonware_formatting::hex!(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    #[test]
    fn test_sha256() {
        let msg = b"hello world";

        // Generate initial hash
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Reuse hasher
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Test simple hasher
        let hash = Sha256::hash(msg);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
    }

    #[test]
    fn test_codec() {
        let msg = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();

        let encoded = digest.encode();
        assert_eq!(encoded.len(), DIGEST_LENGTH);
        assert_eq!(encoded, digest.as_ref());

        let decoded = Digest::decode(encoded).unwrap();
        assert_eq!(digest, decoded);
    }

    fn standard_hash<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Digest {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    #[test]
    fn test_fixed_hashes_match_standard_sha256() {
        let left = Sha256::hash(b"left");
        let right = Sha256::hash(b"right");
        let payload = b"payload";

        assert_eq!(
            Sha256::hash_pair(&left, &right),
            standard_hash([left.as_ref(), right.as_ref()])
        );
        assert_eq!(
            Sha256::hash_u32_with_digest(7, &left),
            standard_hash([7u32.to_be_bytes().as_slice(), left.as_ref()])
        );
        assert_eq!(
            Sha256::hash_u32_with_bytes(7, left.as_ref()),
            standard_hash([7u32.to_be_bytes().as_slice(), left.as_ref()])
        );
        assert_eq!(
            Sha256::hash_u32_with_bytes(7, payload),
            standard_hash([7u32.to_be_bytes().as_slice(), payload])
        );
        assert_eq!(
            Sha256::hash_u64_with_digest(9, &left),
            standard_hash([9u64.to_be_bytes().as_slice(), left.as_ref()])
        );
        assert_eq!(
            Sha256::hash_u64_with_bytes(9, left.as_ref()),
            standard_hash([9u64.to_be_bytes().as_slice(), left.as_ref()])
        );
        assert_eq!(
            Sha256::hash_u64_with_bytes(9, payload),
            standard_hash([9u64.to_be_bytes().as_slice(), payload])
        );
        assert_eq!(
            Sha256::hash_u64_with_pair(11, &left, &right),
            standard_hash([
                11u64.to_be_bytes().as_slice(),
                left.as_ref(),
                right.as_ref()
            ])
        );
        assert_eq!(
            Sha256::hash_u64_u64_with_digest(13, 17, &left),
            standard_hash([
                13u64.to_be_bytes().as_slice(),
                17u64.to_be_bytes().as_slice(),
                left.as_ref()
            ])
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Digest>,
        }
    }
}

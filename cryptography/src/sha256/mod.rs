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
//! // Hash messages by chaining updates
//! let digest = hasher.begin().update(b"hello,").update(b"world!").finalize();
//!
//! // Print the digest
//! println!("digest: {:?}", digest);
//! ```

use crate::{CodecHasher, Hasher};
#[cfg(not(feature = "std"))]
use alloc::vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write,
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
const SCRATCH_LEN: usize = 2 * BLOCK_LENGTH;
const MAX_FIXED_PREIMAGE: usize = SCRATCH_LEN - 9;
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 hasher.
#[derive(Debug)]
pub struct Sha256 {
    hasher: ISha256,
    scratch: [u8; SCRATCH_LEN],
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            hasher: ISha256::new(),
            scratch: [0u8; SCRATCH_LEN],
        }
    }
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

    fn update_inner(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    fn finalize_inner(&mut self) -> Self::Digest {
        let finalized = self.hasher.finalize_reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        Self::Digest::from(array)
    }

    fn reset(&mut self) -> &mut Self {
        self.hasher.reset();
        self
    }

    #[inline]
    fn hash(message: &[u8]) -> Self::Digest {
        digest_from_output(ISha256::digest(message).into())
    }
}

impl CodecHasher for Sha256 {
    #[inline]
    fn hash_parts<'a>(&mut self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        let mut len = 0usize;
        let mut parts = parts.into_iter();
        while let Some(part) = parts.next() {
            let Some(end) = len.checked_add(part.len()) else {
                self.hasher.update(&self.scratch[..len]);
                self.hasher.update(part);
                for part in parts {
                    self.hasher.update(part);
                }
                return digest_from_output(self.hasher.finalize_reset().into());
            };
            if end > MAX_FIXED_PREIMAGE {
                self.hasher.update(&self.scratch[..len]);
                self.hasher.update(part);
                for part in parts {
                    self.hasher.update(part);
                }
                return digest_from_output(self.hasher.finalize_reset().into());
            }
            write_scratch(&mut self.scratch[len..end], part);
            len = end;
        }

        finalize_fixed(&mut self.scratch, len)
    }

    #[inline]
    fn hash_encoded<E: Encode>(&mut self, value: &E) -> Self::Digest {
        self.hash_prefixed(&[], value)
    }

    #[inline]
    fn hash_prefixed<E: Encode>(&mut self, prefix: &[u8], value: &E) -> Self::Digest {
        let Some(len) = prefix.len().checked_add(value.encode_size()) else {
            self.hasher.update(prefix);
            self.hasher.update(value.encode().as_ref());
            return digest_from_output(self.hasher.finalize_reset().into());
        };
        if len > MAX_FIXED_PREIMAGE {
            self.hasher.update(prefix);
            self.hasher.update(value.encode().as_ref());
            return digest_from_output(self.hasher.finalize_reset().into());
        }

        write_scratch(&mut self.scratch[..prefix.len()], prefix);
        let mut tail: &mut [u8] = &mut self.scratch[prefix.len()..len];
        value.write(&mut tail);
        assert_eq!(tail.len(), 0, "encode_size() did not match write()");
        finalize_fixed(&mut self.scratch, len)
    }

    #[inline]
    fn hash_empty(&mut self) -> Self::Digest {
        finalize_fixed(&mut self.scratch, 0)
    }

    #[inline]
    fn hash_u32_digest(&mut self, prefix: u32, digest: &Self::Digest) -> Self::Digest {
        write_scratch(&mut self.scratch[..4], &prefix.to_be_bytes());
        write_scratch(&mut self.scratch[4..36], digest.as_ref());
        finalize_fixed_36(&mut self.scratch)
    }

    #[inline]
    fn hash_digest_pair(&mut self, left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        write_scratch(&mut self.scratch[..32], left.as_ref());
        write_scratch(&mut self.scratch[32..64], right.as_ref());
        finalize_fixed_64(&mut self.scratch)
    }

    #[inline]
    fn hash_u64_digest_pair(
        &mut self,
        prefix: u64,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        write_scratch(&mut self.scratch[..8], &prefix.to_be_bytes());
        write_scratch(&mut self.scratch[8..40], left.as_ref());
        write_scratch(&mut self.scratch[40..72], right.as_ref());
        finalize_fixed_72(&mut self.scratch)
    }
}

#[inline]
fn finalize_fixed_36(scratch: &mut [u8; SCRATCH_LEN]) -> Digest {
    scratch[36] = 0x80;
    scratch[37..56].fill(0);
    write_scratch(&mut scratch[56..64], &[0, 0, 0, 0, 0, 0, 0x01, 0x20]);

    let mut state = INITIAL_STATE;
    let (blocks, remainder) = scratch[..BLOCK_LENGTH].as_chunks::<BLOCK_LENGTH>();
    assert!(remainder.is_empty());
    compress256(&mut state, blocks);
    digest_from_state(state)
}

#[inline]
fn finalize_fixed_64(scratch: &mut [u8; SCRATCH_LEN]) -> Digest {
    scratch[64] = 0x80;
    scratch[65..120].fill(0);
    write_scratch(&mut scratch[120..128], &[0, 0, 0, 0, 0, 0, 0x02, 0x00]);

    let mut state = INITIAL_STATE;
    let (blocks, remainder) = scratch[..SCRATCH_LEN].as_chunks::<BLOCK_LENGTH>();
    assert!(remainder.is_empty());
    compress256(&mut state, blocks);
    digest_from_state(state)
}

#[inline]
fn finalize_fixed_72(scratch: &mut [u8; SCRATCH_LEN]) -> Digest {
    scratch[72] = 0x80;
    scratch[73..120].fill(0);
    write_scratch(&mut scratch[120..128], &[0, 0, 0, 0, 0, 0, 0x02, 0x40]);

    let mut state = INITIAL_STATE;
    let (blocks, remainder) = scratch[..SCRATCH_LEN].as_chunks::<BLOCK_LENGTH>();
    assert!(remainder.is_empty());
    compress256(&mut state, blocks);
    digest_from_state(state)
}

#[inline]
fn finalize_fixed(scratch: &mut [u8; SCRATCH_LEN], message_len: usize) -> Digest {
    let bit_len = ((message_len as u64) * 8).to_be_bytes();
    scratch[message_len] = 0x80;

    let mut state = INITIAL_STATE;
    if message_len < 56 {
        scratch[message_len + 1..56].fill(0);
        write_scratch(&mut scratch[56..64], &bit_len);
        let (blocks, remainder) = scratch[..BLOCK_LENGTH].as_chunks::<BLOCK_LENGTH>();
        assert!(remainder.is_empty());
        compress256(&mut state, blocks);
    } else {
        scratch[message_len + 1..120].fill(0);
        write_scratch(&mut scratch[120..128], &bit_len);
        let (blocks, remainder) = scratch[..SCRATCH_LEN].as_chunks::<BLOCK_LENGTH>();
        assert!(remainder.is_empty());
        compress256(&mut state, blocks);
    }
    digest_from_state(state)
}

#[inline]
fn write_scratch(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    dst.copy_from_slice(src);
}

#[inline]
fn digest_from_state(state: [u32; 8]) -> Digest {
    let mut digest = [0u8; DIGEST_LENGTH];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    Digest(digest)
}

#[inline]
const fn digest_from_output(output: [u8; DIGEST_LENGTH]) -> Digest {
    Digest(output)
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
        let digest = hasher.begin().update(msg).finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Reuse hasher
        let digest = hasher.begin().update(msg).finalize();
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
        let digest = hasher.begin().update(msg).finalize();

        let encoded = digest.encode();
        assert_eq!(encoded.len(), DIGEST_LENGTH);
        assert_eq!(encoded, digest.as_ref());

        let decoded = Digest::decode(encoded).unwrap();
        assert_eq!(digest, decoded);
    }

    fn streaming_hash_parts(parts: &[&[u8]]) -> Digest {
        let mut hasher = Sha256::new();
        let mut pending = hasher.begin();
        for part in parts {
            pending = pending.update(part);
        }
        pending.finalize()
    }

    #[test]
    fn test_hash_parts_matches_streaming() {
        let left = Sha256::hash(b"left");
        let right = Sha256::hash(b"right");
        let mut hasher = Sha256::new();

        for len in [
            0usize, 1, 54, 55, 56, 63, 64, 71, 72, 118, 119, 120, 200, 1000,
        ] {
            let blob = vec![0xABu8; len];
            assert_eq!(
                hasher.hash_parts([blob.as_slice()]),
                streaming_hash_parts(&[blob.as_slice()]),
                "hash_parts mismatch for {len} bytes",
            );
        }

        assert_eq!(
            hasher.hash_parts([b"hello".as_slice(), b" ".as_slice(), b"world".as_slice()]),
            streaming_hash_parts(&[b"hello".as_slice(), b" ".as_slice(), b"world".as_slice()])
        );
        assert_eq!(
            hasher.hash_parts([left.as_ref(), right.as_ref()]),
            streaming_hash_parts(&[left.as_ref(), right.as_ref()])
        );

        drop(hasher.begin().update(b"discarded"));
        assert_eq!(
            hasher.hash_parts([b"fresh".as_slice()]),
            streaming_hash_parts(&[b"fresh".as_slice()])
        );
    }

    #[test]
    fn test_hash_encoded_matches_streaming() {
        let mut hasher = Sha256::new();
        let value = (7u32, Sha256::hash(b"leaf"));
        let prefix = 42u64.to_be_bytes();
        let mut encoded = prefix.to_vec();
        encoded.extend_from_slice(value.encode().as_ref());

        assert_eq!(
            hasher.hash_encoded(&value),
            Sha256::hash(value.encode().as_ref())
        );
        assert_eq!(
            hasher.hash_prefixed(&prefix, &value),
            Sha256::hash(&encoded)
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

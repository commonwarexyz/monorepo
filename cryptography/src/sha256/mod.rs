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

use crate::Hasher;
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

/// Number of whole SHA-256 compression blocks backing the fixed (non-streaming) hashing path. Two
/// blocks (128 bytes) cover every short fixed-shape Merkle preimage in the library.
const FIXED_BLOCKS: usize = 2;

/// Bytes of scratch backing the fixed (non-streaming) hashing path: [`FIXED_BLOCKS`] whole blocks.
const SCRATCH_LEN: usize = FIXED_BLOCKS * BLOCK_LENGTH;

/// The largest preimage the fixed path hashes without streaming. [`SCRATCH_LEN`] holds the preimage
/// plus the 9 mandatory SHA-256 padding bytes (a `0x80` terminator and an 8-byte length).
const MAX_FIXED_PREIMAGE: usize = SCRATCH_LEN - 9;

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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

    fn hash_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        // Buffer the concatenated chunks into a stack scratch and compress the one or two whole
        // blocks directly, avoiding the streaming hasher's per-call setup and buffering. If the
        // preimage exceeds the fixed path, fall back to the streaming hasher mid-iteration. Either
        // way the digest is identical to feeding the same bytes through `update`/`finalize`.
        let mut scratch = [0u8; SCRATCH_LEN];
        let mut len = 0usize;
        let mut overflow: Option<ISha256> = None;
        for chunk in chunks {
            if let Some(hasher) = overflow.as_mut() {
                hasher.update(chunk);
                continue;
            }
            if len + chunk.len() > MAX_FIXED_PREIMAGE {
                let mut hasher = ISha256::new();
                hasher.update(&scratch[..len]);
                hasher.update(chunk);
                overflow = Some(hasher);
                continue;
            }
            scratch[len..len + chunk.len()].copy_from_slice(chunk);
            len += chunk.len();
        }
        overflow.map_or_else(
            || finalize_fixed(&mut scratch, len),
            |mut hasher| {
                let array: [u8; DIGEST_LENGTH] = hasher.finalize_reset().into();
                Self::Digest::from(array)
            },
        )
    }
}

/// Append SHA-256 padding to the `message_len` bytes already written at the start of `scratch`, then
/// compress the resulting one or two blocks into a digest. The padding (a `0x80` byte, zero fill,
/// and the 64-bit big-endian bit length) overwrites every byte of the compressed blocks past
/// `message_len`, so stale scratch data cannot leak into the result.
#[inline]
fn finalize_fixed(scratch: &mut [u8; SCRATCH_LEN], message_len: usize) -> Digest {
    let bit_len = ((message_len as u64) * 8).to_be_bytes();
    scratch[message_len] = 0x80;
    let mut state = INITIAL_STATE;
    if message_len < 56 {
        scratch[message_len + 1..56].fill(0);
        scratch[56..64].copy_from_slice(&bit_len);
        compress256(&mut state, scratch[..64].as_chunks::<BLOCK_LENGTH>().0);
    } else {
        scratch[message_len + 1..120].fill(0);
        scratch[120..128].copy_from_slice(&bit_len);
        compress256(&mut state, scratch[..128].as_chunks::<BLOCK_LENGTH>().0);
    }
    digest_from_state(state)
}

#[inline]
fn digest_from_state(state: [u32; 8]) -> Digest {
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

    /// The fixed fast path in `hash_chunks` must produce the exact same digest as streaming the
    /// same bytes through `update`/`finalize`, across the one-block, two-block, boundary, and
    /// streaming-fallback cases.
    #[test]
    fn test_hash_chunks_matches_streaming() {
        fn streamed(chunks: &[&[u8]]) -> Digest {
            let mut hasher = Sha256::new();
            for chunk in chunks {
                hasher.update(chunk);
            }
            hasher.finalize()
        }
        let big = vec![0xABu8; 200];
        let pos = 8u64.to_be_bytes();
        let cases: Vec<Vec<&[u8]>> = vec![
            vec![],
            vec![b"".as_slice()],
            vec![b"hello world".as_slice()],
            vec![&pos, b"left-32-byte-digest-padding-x!!!"],
            vec![
                &pos,
                b"left-32-byte-digest-padding-x!!!",
                b"right-32-byte-digest-paddingx!!!",
            ],
            vec![&[0u8; 55]],
            vec![&[0u8; 56]],
            vec![&[0u8; 119]],
            vec![&[0u8; 120]],
            vec![big.as_slice()],
            vec![&pos, big.as_slice()],
        ];
        for chunks in &cases {
            assert_eq!(
                Sha256::hash_chunks(chunks.iter().copied()),
                streamed(chunks),
                "hash_chunks mismatch for {} bytes",
                chunks.iter().map(|c| c.len()).sum::<usize>(),
            );
        }
    }

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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Digest>,
        }
    }
}

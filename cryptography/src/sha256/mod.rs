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

use crate::{Hasher, MAX_CODEC_PREIMAGE};
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

/// Bytes of scratch backing the fixed (non-streaming) hashing path: enough whole compression blocks
/// to hold the largest supported preimage ([`MAX_CODEC_PREIMAGE`]) plus its 9 mandatory padding
/// bytes (a `0x80` terminator and an 8-byte length). Inputs longer than [`MAX_CODEC_PREIMAGE`] fall
/// back to the streaming hasher.
const SCRATCH_LEN: usize = (MAX_CODEC_PREIMAGE + 9).div_ceil(BLOCK_LENGTH) * BLOCK_LENGTH;

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 hasher.
#[derive(Debug)]
pub struct Sha256 {
    /// Streaming state backing [`Hasher::update`], [`Hasher::finalize`], and [`Hasher::reset`].
    hasher: ISha256,
    /// Reusable buffer for the fixed (non-streaming) hashing path. Reusing it across calls avoids
    /// re-zeroing a fresh buffer on every short hash.
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

    #[inline]
    fn hash_codec<E: Encode>(&mut self, value: E) -> Self::Digest {
        let len = value.encode_size();
        if len > MAX_CODEC_PREIMAGE {
            let encoded = value.encode();
            let mut hasher = ISha256::new();
            hasher.update(encoded.as_ref());
            let array: [u8; DIGEST_LENGTH] = hasher.finalize().into();
            return Digest(array);
        }

        // Write directly into the scratch. For fixed-size values `len` folds to a compile-time
        // constant, so `finalize_fixed` const-folds at the call site.
        let mut tail: &mut [u8] = &mut self.scratch[..len];
        value.write(&mut tail);
        assert_eq!(tail.len(), 0, "encode_size() did not match write()");
        finalize_fixed(&mut self.scratch, len)
    }
}

/// Append SHA-256 padding to the `message_len` encoded bytes already written at the start of
/// `scratch`, then compress the resulting one or two blocks into a digest.
///
/// The padding (a `0x80` byte, zero fill, and the 64-bit big-endian bit length) fully overwrites
/// every byte of the compressed blocks past `message_len`, so stale data left in `scratch` by a
/// previous call cannot leak into the result.
#[inline]
fn finalize_fixed(scratch: &mut [u8; SCRATCH_LEN], message_len: usize) -> Digest {
    // SAFETY: `hash_codec` uses the streaming fallback for values larger than
    // `MAX_CODEC_PREIMAGE`. Surfacing this invariant lets the compiler prove every padding write
    // below is in-bounds and drop the panic paths, which is what makes the fixed path competitive
    // with hand-unrolled per-shape hashing. In debug builds this still panics if the invariant is
    // ever violated.
    unsafe { core::hint::assert_unchecked(message_len <= MAX_CODEC_PREIMAGE) };
    // Smallest number of blocks holding the message plus its 9 mandatory padding bytes (the `0x80`
    // terminator and the 8-byte length field).
    let blocks = (message_len + 9).div_ceil(BLOCK_LENGTH);
    let used = blocks * BLOCK_LENGTH;
    scratch[message_len] = 0x80;
    scratch[message_len + 1..used - 8].fill(0);
    scratch[used - 8..used].copy_from_slice(&((message_len as u64) * 8).to_be_bytes());

    let mut state = INITIAL_STATE;
    compress256(&mut state, scratch[..used].as_chunks::<BLOCK_LENGTH>().0);
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

    #[test]
    fn test_sha256() {
        let msg = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);
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

    fn standard_codec_hash<E: Encode + ?Sized>(value: &E) -> Digest {
        let encoded = value.encode();
        standard_hash([encoded.as_ref()])
    }

    fn assert_codec_match<E: Encode>(hasher: &mut Sha256, value: E) {
        let len = value.encode_size();
        let expected = standard_codec_hash(&value);
        assert_eq!(
            hasher.hash_codec(value),
            expected,
            "hash_codec mismatch for {len} encoded bytes",
        );
    }

    #[test]
    fn test_codec_hashes_match_standard_sha256() {
        let left = Sha256::hash(b"left");
        let right = Sha256::hash(b"right");
        let mut hasher = Sha256::new();
        assert_codec_match(&mut hasher, (7u32, left));
        assert_codec_match(&mut hasher, (9u64, left));
        assert_codec_match(&mut hasher, (9u64, b"payload".as_slice()));
        assert_codec_match(&mut hasher, (11u64, left, right));
        assert_codec_match(&mut hasher, (13u64, 17u64, left));
        assert_codec_match(&mut hasher, ());
        assert_codec_match(&mut hasher, [b'x']);
        for len in [
            0usize, 1, 54, 55, 56, 63, 64, 71, 72, 118, 119, 120, 200, 1000,
        ] {
            let blob = vec![0xABu8; len];
            assert_codec_match(&mut hasher, blob.as_slice());
            assert_codec_match(&mut hasher, blob);
        }
        hasher.update(b"streamed");
        let _ = hasher.hash_codec((left, right));
        let _ = hasher.hash_codec((b"unrelated".as_slice(), [0xCD; 200]));
        assert_eq!(hasher.finalize(), standard_hash([b"streamed".as_slice()]));
    }

    #[test]
    fn test_hash_codec_matches_standard_sha256() {
        let left = Sha256::hash(b"left");
        let right = Sha256::hash(b"right");
        let mut hasher = Sha256::new();

        // Each `hash_codec` call must hash exactly the codec encoding of its value.
        assert_eq!(
            hasher.hash_codec((left, right)),
            standard_codec_hash(&(left, right))
        );
        assert_eq!(
            hasher.hash_codec((7u32, left)),
            standard_codec_hash(&(7u32, left))
        );
        assert_eq!(
            hasher.hash_codec((9u64, left)),
            standard_codec_hash(&(9u64, left))
        );
        assert_eq!(
            hasher.hash_codec((11u64, left, right)),
            standard_codec_hash(&(11u64, left, right)),
        );
        assert_eq!(
            hasher.hash_codec((13u64, 17u64, left)),
            standard_codec_hash(&(13u64, 17u64, left)),
        );
        assert_eq!(
            hasher.hash_codec((9u64, b"payload".as_slice())),
            standard_codec_hash(&(9u64, b"payload".as_slice())),
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

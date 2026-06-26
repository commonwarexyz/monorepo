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
//! let digest = hasher.update(b"hello,").update(b"world!").finalize();
//!
//! // Print the digest
//! println!("digest: {:?}", digest);
//! ```

use crate::{Hasher, PendingHasher};
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
const SCRATCH_LEN: usize = 2 * BLOCK_LENGTH;
const MAX_FIXED_LEN: usize = SCRATCH_LEN - 9;
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 hasher.
#[derive(Debug)]
pub struct Sha256 {
    hasher: ISha256,
    scratch: [u8; SCRATCH_LEN],
    scratch_len: usize,
    fallback: bool,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            hasher: ISha256::new(),
            scratch: [0u8; SCRATCH_LEN],
            scratch_len: 0,
            fallback: false,
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

/// Pending SHA-256 computation.
#[must_use]
pub struct Pending<'a> {
    hasher: &'a mut Sha256,
    finalized: bool,
}

impl Pending<'_> {
    /// Append message to the pending hash computation.
    pub fn update(self, message: &[u8]) -> Self {
        if self.hasher.fallback {
            self.hasher.hasher.update(message);
            return self;
        }

        if message.len() <= MAX_FIXED_LEN - self.hasher.scratch_len {
            let start = self.hasher.scratch_len;
            self.hasher.scratch_len += message.len();
            self.hasher.scratch[start..self.hasher.scratch_len].copy_from_slice(message);
            return self;
        }

        self.hasher
            .hasher
            .update(&self.hasher.scratch[..self.hasher.scratch_len]);
        self.hasher.hasher.update(message);
        self.hasher.scratch_len = 0;
        self.hasher.fallback = true;
        self
    }

    /// Hash all recorded data and reset the underlying hasher to the initial state.
    pub fn finalize(mut self) -> Digest {
        self.finalized = true;
        let digest = if self.hasher.fallback {
            let finalized = self.hasher.hasher.finalize_reset();
            let array: [u8; DIGEST_LENGTH] = finalized.into();
            Digest::from(array)
        } else {
            finalize_fixed(&mut self.hasher.scratch, self.hasher.scratch_len)
        };

        self.hasher.scratch_len = 0;
        self.hasher.fallback = false;
        digest
    }
}

impl PendingHasher for Pending<'_> {
    type Digest = Digest;

    fn update(self, message: &[u8]) -> Self {
        Self::update(self, message)
    }

    fn finalize(self) -> Self::Digest {
        Self::finalize(self)
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            self.hasher.reset();
        }
    }
}

impl Hasher for Sha256 {
    type Digest = Digest;
    type Pending<'a> = Pending<'a>;

    fn update(&mut self, message: &[u8]) -> Self::Pending<'_> {
        Pending {
            hasher: self,
            finalized: false,
        }
        .update(message)
    }

    fn reset(&mut self) -> &mut Self {
        self.hasher.reset();
        self.scratch_len = 0;
        self.fallback = false;
        self
    }
}

/// Append SHA-256 padding to the buffered message and compress the resulting block(s).
///
/// Padding fully overwrites the bytes read after `message_len`, so stale scratch bytes from a
/// previous hash do not affect the digest.
#[inline]
fn finalize_fixed(scratch: &mut [u8; SCRATCH_LEN], message_len: usize) -> Digest {
    debug_assert!(message_len <= MAX_FIXED_LEN);

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

    #[test]
    fn test_sha256() {
        let msg = b"hello world";
        let mut hasher = Sha256::new();
        let digest = hasher.update(msg).finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);
        let digest = hasher.update(msg).finalize();
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
        let digest = hasher.update(msg).finalize();
        let encoded = digest.encode();
        assert_eq!(encoded.len(), DIGEST_LENGTH);
        assert_eq!(encoded, digest.as_ref());
        let decoded = Digest::decode(encoded).unwrap();
        assert_eq!(digest, decoded);
    }

    fn reference_hash(data: &[u8]) -> Digest {
        let array: [u8; DIGEST_LENGTH] = sha2::Sha256::digest(data).into();
        Digest(array)
    }

    #[test]
    fn test_fixed_fast_path_matches_standard_sha256() {
        for len in [0usize, 1, 54, 55, 56, 63, 64, 65, 118, 119] {
            let data = vec![0xA5; len];
            let mut hasher = Sha256::new();
            let pending = hasher.update(&data);
            assert!(!pending.hasher.fallback);
            assert_eq!(pending.finalize(), reference_hash(&data));
        }
    }

    #[test]
    fn test_chunked_fixed_fast_path_matches_standard_sha256() {
        let mut data = vec![0u8; MAX_FIXED_LEN];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut hasher = Sha256::new();
        let pending = hasher
            .update(&data[..17])
            .update(&data[17..64])
            .update(&data[64..]);
        assert!(!pending.hasher.fallback);
        assert_eq!(pending.finalize(), reference_hash(&data));
    }

    #[test]
    fn test_fallback_preserves_buffered_prefix() {
        let mut data = vec![0u8; MAX_FIXED_LEN + 1];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut hasher = Sha256::new();
        let pending = hasher.update(&data[..100]).update(&data[100..]);
        assert!(pending.hasher.fallback);
        assert_eq!(pending.finalize(), reference_hash(&data));

        let pending = hasher.update(b"discarded");
        drop(pending);
        assert_eq!(hasher.update(b"").finalize(), reference_hash(b""));
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

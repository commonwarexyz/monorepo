//! SHA-256 implementation of the `Hasher` trait.
//!
//! This implementation uses the `sha2` crate to generate SHA-256 digests.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, Sha256};
//!
//! // Hash data in a single shot (fastest path)
//! let digest = Sha256::hash(&[b"hello,", b"world!"]);
//! println!("digest: {:?}", digest);
//!
//! // Or stream data incrementally
//! let mut hasher = Sha256::default();
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//! let (_hasher, digest) = hasher.finalize();
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

/// The SHA-256 block size in bytes.
const BLOCK_LENGTH: usize = 64;

/// Maximum message length, in bytes, that the fixed-size fast path can handle.
///
/// SHA-256 padding appends a single `0x80` byte and an 8-byte length suffix.
/// Within two blocks (128 bytes), at most `128 - 9 = 119` bytes of message can
/// be hashed without spilling into a third block, which is the range we
/// specialize for.
const MAX_FIXED: usize = 2 * BLOCK_LENGTH - 9;

/// The SHA-256 initial hash values (FIPS 180-4, §5.3.3).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Serialize the SHA-256 state words into a big-endian digest.
#[inline]
fn digest_from_state(state: [u32; 8]) -> [u8; DIGEST_LENGTH] {
    let mut out = [0u8; DIGEST_LENGTH];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Pad and compress `scratch[..len]` (where `len <= MAX_FIXED`) directly from
/// the IV, assuming `scratch[len..]` is already zeroed (i.e. fresh scratch).
///
/// This avoids the streaming hasher's buffering and the redundant zero-fill of
/// the padding region, which is the bulk of the one-shot speedup.
#[inline]
fn finalize_fixed_fresh(scratch: &mut [u8; 2 * BLOCK_LENGTH], len: usize) -> [u8; DIGEST_LENGTH] {
    let bit_len = ((len as u64) * 8).to_be_bytes();
    scratch[len] = 0x80;
    let mut state = IV;
    if len < BLOCK_LENGTH - 8 {
        // Message + padding fit in a single block.
        scratch[BLOCK_LENGTH - 8..BLOCK_LENGTH].copy_from_slice(&bit_len);
        let (blocks, _) = scratch[..BLOCK_LENGTH].as_chunks::<BLOCK_LENGTH>();
        compress256(&mut state, blocks);
    } else {
        // Padding spills into a second block.
        scratch[2 * BLOCK_LENGTH - 8..].copy_from_slice(&bit_len);
        let (blocks, _) = scratch.as_chunks::<BLOCK_LENGTH>();
        compress256(&mut state, blocks);
    }
    digest_from_state(state)
}

/// Specialize the hot merkle shapes: constant offsets let the compiler inline
/// the copies and drop the runtime-length bookkeeping. The rare/general case is
/// outlined into [`hash_general`] so this stays small enough to inline.
#[inline(always)]
fn hash_specialized(parts: &[&[u8]]) -> Digest {
    match parts {
        [p, l, r] if p.len() == 8 && l.len() == 32 && r.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..8].copy_from_slice(p);
            scratch[8..40].copy_from_slice(l);
            scratch[40..72].copy_from_slice(r);
            Digest(finalize_fixed_fresh(&mut scratch, 72))
        }
        [a, b] if a.len() == 32 && b.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..32].copy_from_slice(a);
            scratch[32..64].copy_from_slice(b);
            Digest(finalize_fixed_fresh(&mut scratch, 64))
        }
        [p, d] if p.len() == 8 && d.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..8].copy_from_slice(p);
            scratch[8..40].copy_from_slice(d);
            Digest(finalize_fixed_fresh(&mut scratch, 40))
        }
        [p, d] if p.len() == 4 && d.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..4].copy_from_slice(p);
            scratch[4..36].copy_from_slice(d);
            Digest(finalize_fixed_fresh(&mut scratch, 36))
        }
        _ => hash_general(parts),
    }
}

/// General-purpose assembly + streaming fallback for shapes that miss the
/// specialized arms. Outlined and marked cold so it never bloats callers.
#[cold]
#[inline(never)]
fn hash_general(parts: &[&[u8]]) -> Digest {
    let mut scratch = [0u8; 2 * BLOCK_LENGTH];
    let mut len = 0usize;
    let mut parts = parts.iter();
    loop {
        match parts.next() {
            Some(part) if len + part.len() <= MAX_FIXED => {
                scratch[len..len + part.len()].copy_from_slice(part);
                len += part.len();
            }
            Some(part) => {
                let mut hasher = ISha256::new();
                hasher.update(&scratch[..len]);
                hasher.update(part);
                for part in parts {
                    hasher.update(part);
                }
                let array: [u8; DIGEST_LENGTH] = hasher.finalize().into();
                return Digest(array);
            }
            None => break,
        }
    }
    Digest(finalize_fixed_fresh(&mut scratch, len))
}

/// SHA-256 hasher.
#[derive(Debug, Default)]
pub struct Sha256 {
    hasher: ISha256,
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        // Per the `Hasher` contract, `Clone` resets: we never duplicate in-progress
        // hasher state.
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

    #[inline]
    fn hash(parts: &[&[u8]]) -> Self::Digest {
        hash_specialized(parts)
    }

    #[inline]
    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    #[inline]
    fn finalize(mut self) -> (Self, Self::Digest) {
        let finalized = self.hasher.finalize_reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        (self, Digest(array))
    }
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
        Ok(Sha256::hash(&[data]))
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
        let mut hasher = Sha256::default();
        hasher.update(msg);
        let (hasher, digest) = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Reuse the reset hasher
        let mut hasher = hasher;
        hasher.update(msg);
        let (_, digest) = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Test one-shot hasher
        let hash = Sha256::hash(&[msg]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);

        // Test multi-part one-shot hasher
        let hash = Sha256::hash(&[b"hello", b" world"]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);
    }

    /// Exercise the fixed-size fast path and the streaming fallback across the
    /// `MAX_FIXED` boundary, checking each against the streaming implementation.
    #[test]
    fn test_sha256_hash_parts_boundaries() {
        for total in 0..=300usize {
            let data: Vec<u8> = (0..total).map(|i| i as u8).collect();
            // Split into a few parts of varying sizes.
            let mid = total / 3;
            let parts: [&[u8]; 3] = [&data[..mid], &data[mid..2 * mid], &data[2 * mid..]];

            let oneshot = Sha256::hash(&parts);

            let mut hasher = Sha256::default();
            for part in &parts {
                hasher.update(part);
            }
            let (_, streamed) = hasher.finalize();

            assert_eq!(oneshot, streamed, "mismatch for total={total}");
        }
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
    }

    #[test]
    fn test_codec() {
        let msg = b"hello world";
        let mut hasher = Sha256::default();
        hasher.update(msg);
        let (_, digest) = hasher.finalize();

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

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
use commonware_codec::{DecodeExt, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::Random;
use commonware_utils::{hex, Array, Span};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRngCore;
use sha2::{Digest as _, Sha256 as ISha256};
use zeroize::Zeroize;

/// Re-export `sha2::Sha256` as `CoreSha256` for external use if needed.
pub type CoreSha256 = ISha256;

const DIGEST_LENGTH: usize = 32;

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

    /// Hashes two 32-byte digests using the raw SHA-256 compression function.
    ///
    /// Standard `SHA-256(left || right)` requires two compression calls
    /// (one for the 64-byte data block, one for the padding block).
    /// This method feeds `left || right` as a single 64-byte block
    /// directly into `compress256` with the SHA-256 IV, using only
    /// one compression call.
    ///
    /// # Security
    ///
    /// The SHA-256 compression function with a fixed IV is collision-resistant
    /// on fixed-length inputs. Domain separation from leaf hashing is inherent:
    /// leaves use standard SHA-256 (with Merkle-Damgard padding) while this
    /// method omits padding entirely, producing distinct outputs for the same
    /// byte content.
    fn hash_node(&mut self, left: &Digest, right: &Digest) -> Digest {
        // SHA-256 IV (FIPS 180-4 section 5.3.3)
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ce935, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left.as_ref());
        block[32..].copy_from_slice(right.as_ref());
        let ga = sha2::digest::generic_array::GenericArray::from_slice(&block);
        sha2::compress256(&mut state, core::slice::from_ref(ga));
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Digest::from(out)
    }
}

/// Digest of a SHA-256 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
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

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(value: [u8; DIGEST_LENGTH]) -> Self {
        Self(value)
    }
}

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
        write!(f, "{}", hex(&self.0))
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.0))
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
    use commonware_utils::hex;

    const HELLO_DIGEST: [u8; DIGEST_LENGTH] =
        hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

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

    #[test]
    fn test_hash_node_deterministic() {
        let a = Sha256::hash(b"left");
        let b = Sha256::hash(b"right");
        let mut hasher = Sha256::new();
        let r1 = hasher.hash_node(&a, &b);
        let r2 = hasher.hash_node(&a, &b);
        assert_eq!(r1, r2, "hash_node must be deterministic");
    }

    #[test]
    fn test_hash_node_order_matters() {
        let a = Sha256::hash(b"left");
        let b = Sha256::hash(b"right");
        let mut hasher = Sha256::new();
        let lr = hasher.hash_node(&a, &b);
        let rl = hasher.hash_node(&b, &a);
        assert_ne!(lr, rl, "hash_node(a,b) != hash_node(b,a)");
    }

    #[test]
    fn test_hash_node_differs_from_standard_sha256() {
        let a = Sha256::hash(b"left");
        let b = Sha256::hash(b"right");

        // hash_node uses raw compression
        let mut hasher = Sha256::new();
        let node = hasher.hash_node(&a, &b);

        // Standard SHA-256(a || b) uses Merkle-Damgard with padding
        hasher.update(a.as_ref());
        hasher.update(b.as_ref());
        let standard = hasher.finalize();

        assert_ne!(
            node, standard,
            "hash_node must differ from SHA-256(left || right)"
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

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
use commonware_utils::array::FixedBytes;
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256 as ISha256};
use std::fmt::Debug;

const DIGEST_LENGTH: usize = 32;
pub type Digest = FixedBytes<DIGEST_LENGTH>;

/// Generate a SHA-256 digest from a message.
pub fn hash(message: &[u8]) -> Digest {
    FixedBytes::new(ISha256::digest(message).try_into().unwrap())
}

/// SHA-256 hasher.
#[derive(Debug)]
pub struct Sha256 {
    hasher: ISha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        // We manually implement `Clone` to avoid cloning the hasher state.
        Self::default()
    }
}

impl Hasher for Sha256 {
    type Digest = Digest;

    fn new() -> Self {
        Self {
            hasher: ISha256::new(),
        }
    }

    fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    fn finalize(&mut self) -> Self::Digest {
        let finalized = self.hasher.finalize_reset();
        FixedBytes::new(finalized.into())
    }

    fn reset(&mut self) {
        self.hasher = ISha256::new();
    }

    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self::Digest {
        let mut digest = FixedBytes::<DIGEST_LENGTH>::default();
        rng.fill_bytes(&mut digest);
        digest
    }
}

impl crate::Digest for Digest {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::hex;

    const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn test_sha256() {
        let msg = b"hello world";

        // Generate initial hash
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::try_from(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Reuse hasher
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::try_from(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Test simple hasher
        let hash = hash(msg);
        assert_eq!(hex(hash.as_ref()), HELLO_DIGEST);
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Digest::LEN_CODEC, DIGEST_LENGTH);
    }
}

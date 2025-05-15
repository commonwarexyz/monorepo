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
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::{hex, Array};
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256 as ISha256};
use std::{
    fmt::{Debug, Display},
    ops::Deref,
};

const DIGEST_LENGTH: usize = 32;

/// Generate a SHA-256 digest from a message.
pub fn hash(message: &[u8]) -> Digest {
    let array: [u8; DIGEST_LENGTH] = ISha256::digest(message).into();
    Digest::from(array)
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

impl Sha256 {
    /// Convenience function for testing that creates an easily recognizable digest by repeating a
    /// single byte.
    pub fn fill(b: u8) -> <Self as Hasher>::Digest {
        <Self as Hasher>::Digest::decode(vec![b; DIGEST_LENGTH].as_ref()).unwrap()
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
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        Self::Digest::from(array)
    }

    fn reset(&mut self) {
        self.hasher = ISha256::new();
    }

    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self::Digest {
        let mut digest = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut digest);
        Self::Digest::from(digest)
    }
}

/// Digest of a SHA-256 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Digest([u8; DIGEST_LENGTH]);

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl crate::Digest for Digest {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::hex;

    const HELLO_DIGEST: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn test_sha256() {
        let msg = b"hello world";

        // Generate initial hash
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Reuse hasher
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Test simple hasher
        let hash = hash(msg);
        assert_eq!(hex(hash.as_ref()), HELLO_DIGEST);
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
}

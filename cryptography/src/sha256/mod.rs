//! SHA-256 implementation of the `Hasher` trait.

use crate::{Digest as CDigest, Error, Hasher};
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256 as ISha256};
use std::ops::{Deref, DerefMut};

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
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Digest([u8; DIGEST_LENGTH]);

impl CDigest for Digest {}

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(value: [u8; DIGEST_LENGTH]) -> Self {
        Digest(value)
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != DIGEST_LENGTH {
            return Err(Error::InvalidDigestLength);
        }
        let mut v = [0u8; DIGEST_LENGTH];
        v.copy_from_slice(value);
        Ok(Self(v))
    }
}

impl TryFrom<&Vec<u8>> for Digest {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
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

impl DerefMut for Digest {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self([0u8; DIGEST_LENGTH])
    }
}

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
        assert_eq!(size_of::<Digest>(), DIGEST_LENGTH);
    }
}

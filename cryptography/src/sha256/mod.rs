//! SHA-256 implementation of the `Hasher` trait.

use crate::{Error, Hasher};
use bytes::Bytes;
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256 as ISha256};
use std::ops::Deref;

const DIGEST_LENGTH: usize = 32;

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
    const DIGEST_LENGTH: usize = DIGEST_LENGTH;

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
        let mut digest = [0u8; Self::DIGEST_LENGTH];
        rng.fill_bytes(&mut digest);
        Self::Digest::from(digest)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Digest([u8; DIGEST_LENGTH]);

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

impl TryFrom<&Bytes> for Digest {
    type Error = Error;
    fn try_from(value: &Bytes) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&Vec<u8>> for Digest {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

#[allow(clippy::from_over_into)]
impl Into<Bytes> for Digest {
    fn into(self) -> Bytes {
        Bytes::copy_from_slice(self.as_ref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::hex;

    #[test]
    fn test_sha256() {
        let digest = b"hello world";

        // Generate initial hash
        let mut hasher = Sha256::new();
        hasher.update(digest);
        let hash = hasher.finalize();
        assert!(Digest::try_from(hash.as_ref()).is_ok());
        assert_eq!(
            hex(hash.as_ref()),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        // Reuse hasher
        hasher.update(digest);
        let hash = hasher.finalize();
        assert!(Digest::try_from(hash.as_ref()).is_ok());
        assert_eq!(
            hex(hash.as_ref()),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Sha256::DIGEST_LENGTH, DIGEST_LENGTH);
    }
}

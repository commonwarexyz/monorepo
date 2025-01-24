//! SHA-256 implementation of the `Hasher` trait.

use crate::{Hasher, Validator};
use sha2::{Digest as _, Sha256 as ISha256};
use std::ops::{Deref, DerefMut};

pub const DIGEST_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Digest([u8; DIGEST_LENGTH]);

impl Validator<Digest> for Digest {
    fn validate(msg: &[u8]) -> Option<Digest> {
        if msg.len() == DIGEST_LENGTH {
            let mut result = [0u8; DIGEST_LENGTH];
            result.copy_from_slice(msg);
            Some(Digest(result))
        } else {
            None
        }
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Digest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<sha2::digest::Output<ISha256>> for Digest {
    fn from(output: sha2::digest::Output<ISha256>) -> Self {
        let result: [u8; DIGEST_LENGTH] = output.into();
        Digest(result)
    }
}

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(slice: [u8; DIGEST_LENGTH]) -> Self {
        Digest(slice)
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self([0; DIGEST_LENGTH])
    }
}

/// SHA-256 hasher.
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
        self.hasher.finalize_reset().into()
    }

    fn reset(&mut self) {
        self.hasher = ISha256::new();
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
        Digest::validate(&hash).unwrap();
        assert_eq!(
            hex(hash.as_ref()),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        // Reuse hasher
        hasher.update(digest);
        let hash = hasher.finalize();
        Digest::validate(&hash).unwrap();
        assert_eq!(
            hex(hash.as_ref()),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}

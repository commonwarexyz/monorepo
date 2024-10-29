//! SHA-256 implementation of the `Hasher` trait.

use crate::{Digest, Hasher};
use sha2::{Digest as _, Sha256 as ISha256};

const DIGEST_LENGTH: usize = 32;

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
    fn new() -> Self {
        Self {
            hasher: ISha256::new(),
        }
    }

    fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    fn finalize(&mut self) -> Digest {
        self.hasher.finalize_reset().to_vec().into()
    }

    fn reset(&mut self) {
        self.hasher = ISha256::new();
    }

    fn validate(digest: &Digest) -> bool {
        digest.len() == DIGEST_LENGTH
    }

    fn len() -> usize {
        DIGEST_LENGTH
    }

    fn random<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Digest {
        let mut digest = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut digest);
        digest.to_vec().into()
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
        assert!(Sha256::validate(&hash));
        assert_eq!(
            hex(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        // Reuse hasher
        hasher.update(digest);
        let hash = hasher.finalize();
        assert!(Sha256::validate(&hash));
        assert_eq!(
            hex(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Sha256::len(), DIGEST_LENGTH);
    }
}

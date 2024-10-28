use crate::{Digest, Hasher};
use sha2::{Digest as _, Sha256 as ISha256};

const DIGEST_SIZE: usize = 32;

#[derive(Clone)]
pub struct Sha256 {
    hasher: Option<ISha256>,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            hasher: Some(ISha256::new()),
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha256 {
    fn update(&mut self, message: &[u8]) {
        self.hasher.as_mut().unwrap().update(message);
    }

    fn finalize(&mut self) -> Digest {
        let hash = self.hasher.take().unwrap().finalize().to_vec().into();
        self.reset();
        hash
    }

    fn reset(&mut self) {
        self.hasher = Some(ISha256::new());
    }

    fn validate(digest: &Digest) -> bool {
        digest.len() == DIGEST_SIZE
    }

    fn size() -> usize {
        DIGEST_SIZE
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
    fn test_sha256_size() {
        assert_eq!(Sha256::size(), DIGEST_SIZE);
    }
}

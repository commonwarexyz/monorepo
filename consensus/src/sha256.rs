use crate::{Hash, Hasher};
use sha2::{Digest, Sha256 as ISha256};

const HASH_LENGTH: usize = 32;

#[derive(Clone)]
pub struct Sha256 {}

impl Sha256 {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha256 {
    fn validate(hash: &Hash) -> bool {
        hash.len() == HASH_LENGTH
    }

    fn hash(&mut self, data: &[u8]) -> Hash {
        // We do not use self in this implementation but we could use it in the future
        // to avoid allocating memory for a new hasher every time.
        let mut hasher = ISha256::new();
        hasher.update(data);
        hasher.finalize().to_vec().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::hex;

    #[test]
    fn test_sha256() {
        let digest = b"hello world";
        let mut hasher = Sha256::new();
        let hash = hasher.hash(digest);
        assert!(Sha256::validate(&hash));
        assert_eq!(
            hex(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}

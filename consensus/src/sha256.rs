use crate::{Hash, Hasher};
use sha2::{Digest, Sha256 as InnerSha256};

const HASH_LENGTH: usize = 32;

#[derive(Clone)]
pub struct Sha256 {
    hasher: InnerSha256,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            hasher: InnerSha256::new(),
        }
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
        self.hasher.update(data);
        let result = self.hasher.finalize().to_vec();
        self.hasher.reset();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Initialize test
        let digest = b"hello world";
        let expected = vec![
            0x2b, 0x10, 0x9f, 0x3b, 0x6d, 0x9e, 0x9d, 0x4d, 0x9b, 0x0b, 0x3a, 0x3e, 0x73, 0x2d,
            0x6f, 0x0d, 0x6a, 0x7f, 0x6f, 0x9d, 0x0d, 0x7f, 0x9e, 0x0d, 0x7f, 0x9e, 0x0d, 0x7f,
            0x9e, 0x0d, 0x7f,
        ];

        // Hash "hello world"
        let mut hasher = Sha256::new();
        let hash = hasher.hash(digest);
        assert!(Sha256::validate(&hash));
        assert_eq!(hash, expected);

        // Hash "hello world" again (to ensure reset works)
        let hash = hasher.hash(digest);
        assert!(Sha256::validate(&hash));
        assert_eq!(hash, expected,);
    }
}

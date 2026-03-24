//! Store module containing the unauthenticated key-value store and test helpers.

pub mod db;

#[cfg(test)]
pub(crate) mod tests {
    use commonware_codec::Codec;
    use commonware_cryptography::{sha256, Hasher};
    use commonware_utils::Array;
    use core::fmt::Debug;

    pub trait TestKey: Array + Copy + Send + Sync {
        fn from_seed(seed: u64) -> Self;
    }

    pub trait TestValue: Codec + Eq + PartialEq + Debug + Send + Sync {
        fn from_seed(seed: u64) -> Self;
    }

    impl TestKey for sha256::Digest {
        fn from_seed(seed: u64) -> Self {
            commonware_cryptography::Sha256::hash(&seed.to_be_bytes())
        }
    }

    impl<D: TestKey> TestValue for D {
        fn from_seed(seed: u64) -> Self {
            D::from_seed(seed)
        }
    }

    impl TestValue for Vec<u8> {
        fn from_seed(seed: u64) -> Self {
            vec![seed as u8; 32]
        }
    }
}

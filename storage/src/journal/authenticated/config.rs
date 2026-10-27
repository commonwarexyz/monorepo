use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Memory policy for Merkle digests.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Lowest node height kept in memory, at most eight. Resident memory is about `2 / 2^height`
    /// digests per retained operation. Height zero keeps every node.
    pub resident_height: u32,
}

impl CacheConfig {
    /// Reject a resident height above eight.
    pub(crate) const fn validate(&self) -> Result<(), &'static str> {
        if self.resident_height > 8 {
            return Err("resident height exceeds eight");
        }
        Ok(())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { resident_height: 5 }
    }
}

/// Configuration for an authenticated journal.
#[derive(Clone)]
pub struct Config<S: Strategy> {
    /// Metadata partition holding the frontier.
    pub metadata_partition: String,
    /// Memory policy for Merkle digests.
    pub cache: CacheConfig,
    /// Read buffer size for replaying operations.
    pub replay_buffer: NonZeroUsize,
    /// Strategy used for Merkle hashing.
    pub strategy: S,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A low resident height, so small test databases rebuild digests from their operations.
    pub(crate) const fn low_resident_height() -> CacheConfig {
        CacheConfig { resident_height: 2 }
    }

    #[test]
    fn validate() {
        assert!(CacheConfig { resident_height: 8 }.validate().is_ok());
        assert!(CacheConfig { resident_height: 9 }.validate().is_err());
    }
}

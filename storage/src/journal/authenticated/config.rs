use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Memory policy for Merkle digests.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Lowest node height kept in memory, at most eight. Resident memory is about `2 / 2^height`
    /// digests per retained operation. Height zero keeps every node. Current databases cap it at
    /// their grafting height.
    pub resident_height: u32,
    /// Budget for cached regions of digests rebuilt from operations. Zero disables the cache, and a
    /// nonzero budget must hold at least one region (see [Self::with_regions]).
    pub region_cache_bytes: usize,
}

impl CacheConfig {
    /// A cache holding `regions` regions of `D` digests for `resident_height`.
    pub fn with_regions<D: Digest>(resident_height: u32, regions: usize) -> Self {
        Self {
            resident_height,
            region_cache_bytes: regions.saturating_mul(region_bytes::<D>(resident_height.min(8))),
        }
    }

    /// The number of regions the cache holds, or `None` when it is disabled.
    pub(crate) fn capacity<D: Digest>(&self) -> Result<Option<NonZeroUsize>, &'static str> {
        if self.resident_height > 8 {
            return Err("resident height exceeds eight");
        }
        if self.resident_height == 0 || self.region_cache_bytes == 0 {
            return Ok(None);
        }
        NonZeroUsize::new(self.region_cache_bytes / region_bytes::<D>(self.resident_height))
            .map(Some)
            .ok_or("region cache cannot hold one region")
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            resident_height: 5,
            region_cache_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Bytes charged for one region of optional digest slots. A resident height of at most eight
/// gives at most 511 slots, so this cannot overflow.
const fn region_bytes<D: Digest>(resident_height: u32) -> usize {
    ((2usize << resident_height) - 1) * size_of::<Option<D>>()
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
    use commonware_cryptography::sha256::Digest;

    /// A cache of one region of SHA-256 digests, so reads evict and rebuild digests.
    pub(crate) fn single_region_cache() -> CacheConfig {
        CacheConfig::with_regions::<Digest>(2, 1)
    }

    #[test]
    fn capacity() {
        let config = |resident_height, region_cache_bytes| CacheConfig {
            resident_height,
            region_cache_bytes,
        };
        assert!(config(9, 1024 * 1024).capacity::<Digest>().is_err());
        assert!(config(5, 1).capacity::<Digest>().is_err());
        assert_eq!(config(5, 0).capacity::<Digest>(), Ok(None));
        assert_eq!(config(0, 1024 * 1024).capacity::<Digest>(), Ok(None));
        assert_eq!(
            CacheConfig::with_regions::<Digest>(5, 3).capacity::<Digest>(),
            Ok(NonZeroUsize::new(3))
        );
    }
}

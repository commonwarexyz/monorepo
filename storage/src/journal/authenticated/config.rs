use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Memory policy for reconstructed Merkle digests.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Lowest node height kept in memory, at most eight. Resident memory is about `2 / 2^height`
    /// digests per retained operation. Height zero keeps every node. Current databases lower it
    /// to their grafting height.
    pub resident_height: u32,
    /// Budget for cached regions of rebuilt digests below the resident height. Zero disables the
    /// cache, and a nonzero budget must hold at least one region (see [Self::with_regions]).
    pub region_cache_bytes: usize,
}

impl CacheConfig {
    /// A cache holding `regions` regions of `D` digests below `resident_height`.
    pub fn with_regions<D: Digest>(resident_height: u32, regions: usize) -> Self {
        Self {
            resident_height,
            region_cache_bytes: regions.saturating_mul(region_bytes::<D>(resident_height.min(8))),
        }
    }

    pub(crate) fn capacity<D: Digest>(&self) -> Result<Option<NonZeroUsize>, &'static str> {
        if self.resident_height > 8 {
            return Err("resident height exceeds eight");
        }
        let bytes = region_bytes::<D>(self.resident_height);
        if bytes == 0 || self.region_cache_bytes == 0 {
            return Ok(None);
        }
        NonZeroUsize::new(self.region_cache_bytes / bytes)
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

/// Bytes charged for one region: its digest slots plus a validity bitmap. A resident height
/// of at most eight gives at most 510 slots, so this cannot overflow.
const fn region_bytes<D: Digest>(resident_height: u32) -> usize {
    let slots = (2usize << resident_height) - 2;
    slots * size_of::<D>() + slots.div_ceil(64) * 8
}

/// Configuration for an operation-backed authenticated journal.
#[derive(Clone)]
pub struct Config<S: Strategy> {
    /// Partition containing the versioned pruning frontier.
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
        assert!(config(9, 1 << 20).capacity::<Digest>().is_err());
        assert!(config(5, 1).capacity::<Digest>().is_err());
        assert_eq!(config(5, 0).capacity::<Digest>(), Ok(None));
        assert_eq!(config(0, 1 << 20).capacity::<Digest>(), Ok(None));
        assert_eq!(
            CacheConfig::with_regions::<Digest>(5, 3).capacity::<Digest>(),
            Ok(NonZeroUsize::new(3))
        );
    }
}

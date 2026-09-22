use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Memory policy for reconstructed Merkle digests.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Lowest node height retained unconditionally. Must be at most eight.
    /// Height zero retains every node and disables the lower cache.
    /// Upper digest memory grows with retained operations, approximately `2 / 2^height`
    /// digests per operation. Current databases also retain their grafting-height nodes.
    pub resident_height: u32,
    /// Budget for lower-region digest and validity arrays, excluding index bookkeeping.
    /// Zero disables lower caching. Partial regions are charged for their full allocation.
    /// A nonzero budget must hold at least one region: `(2 << resident_height) - 2`
    /// digest slots plus a validity bitmap. Temporary reconstruction buffers and outstanding
    /// readers holding evicted regions are additional memory.
    pub lower_cache_bytes: usize,
}

impl CacheConfig {
    pub(crate) fn capacity<D: Digest>(&self) -> Result<Option<NonZeroUsize>, &'static str> {
        if self.resident_height > 8 {
            return Err("resident height exceeds eight");
        }
        let slots = (2usize << self.resident_height) - 2;
        let bytes = slots
            .checked_mul(size_of::<D>())
            .and_then(|n| n.checked_add(slots.div_ceil(64) * 8))
            .ok_or("cache size overflow")?;
        if slots == 0 || self.lower_cache_bytes == 0 {
            return Ok(None);
        }
        NonZeroUsize::new(self.lower_cache_bytes / bytes)
            .filter(|n| n.get().checked_mul(2).is_some())
            .map(Some)
            .ok_or("lower cache cannot hold one region")
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            resident_height: 5,
            lower_cache_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Configuration for an operation-backed authenticated journal.
#[derive(Clone)]
pub struct Config<S: Strategy> {
    /// Partition containing the versioned pruning frontier.
    pub metadata_partition: String,
    /// Memory policy for Merkle digests.
    pub cache: CacheConfig,
    /// Byte budget for replay and reconstruction batches.
    /// A single encoded item may exceed this budget.
    pub replay_buffer: NonZeroUsize,
    /// Strategy used for Merkle hashing.
    pub strategy: S,
}

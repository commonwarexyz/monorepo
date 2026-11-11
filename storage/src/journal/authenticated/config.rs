use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Lowest Merkle node height kept in memory. A lower node is rebuilt from the `2^height`
/// operations of its region, and resident memory is about `2 / 2^height` digests per retained
/// operation. Height zero keeps every node.
#[derive(Clone, Copy, Debug)]
pub struct ResidentHeight(u32);

impl ResidentHeight {
    /// The largest height, so that rebuilding a node reads at most 256 operations.
    pub const MAX: u32 = 8;

    /// Returns `None` if `height` exceeds [Self::MAX].
    pub const fn new(height: u32) -> Option<Self> {
        if height > Self::MAX {
            return None;
        }
        Some(Self(height))
    }

    /// The height.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for ResidentHeight {
    fn default() -> Self {
        Self(5)
    }
}

/// Configuration for an authenticated journal.
#[derive(Clone)]
pub struct Config<S: Strategy> {
    /// Metadata partition holding the frontier. It must stay the same for the life of the journal
    /// and must not be shared with any other store.
    pub partition: String,
    /// Lowest Merkle node height kept in memory.
    pub resident_height: ResidentHeight,
    /// Read buffer size for replaying operations.
    pub replay_buffer: NonZeroUsize,
    /// Chunks of operations a startup replay reads and hashes at once, each on a task of its own,
    /// including when a snapshot build's decode tasks hash them. Set it to the cores startup may
    /// use.
    pub replay_concurrency: NonZeroUsize,
    /// Strategy used for Merkle hashing.
    pub strategy: S,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A low resident height, so small test databases rebuild digests from their operations.
    pub(crate) const fn low_resident_height() -> ResidentHeight {
        ResidentHeight(2)
    }

    #[test]
    fn new() {
        assert_eq!(ResidentHeight::new(8).map(ResidentHeight::get), Some(8));
        assert!(ResidentHeight::new(9).is_none());
    }
}

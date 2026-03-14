//! Shared read-only trait re-export plus MMR-specific batch-chain helpers.

use crate::merkle::mmr::Position;
pub use crate::merkle::Readable;
use alloc::collections::BTreeMap;
use commonware_cryptography::Digest;

/// Information needed to flatten a chain of batches into a single [`super::batch::Changeset`].
pub trait BatchChainInfo: Send + Sync {
    /// The digest type used by this MMR.
    type Digest: Digest;

    /// Number of nodes in the original MMR that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position;

    /// Collect all overwrites that target nodes in the original MMR
    /// (i.e. positions < `base_size()`), walking from the deepest
    /// ancestor to the current batch. Later batches overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position, Self::Digest>);
}

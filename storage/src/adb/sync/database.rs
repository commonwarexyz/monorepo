use crate::{adb::sync::Journal, mmr::Location};
use commonware_cryptography::Digest;
use std::{future::Future, ops::Range};

/// A database that can be synced
pub trait Database: Sized {
    type Op;
    type Journal: Journal<Op = Self::Op>;
    type Config;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + Clone;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Create/open a journal for syncing the given range.
    ///
    /// The implementation must:
    /// - Reuse any on-disk data whose logical locations lie within the range.
    /// - Discard/ignore any data outside the range.
    /// - Report `size()` equal to the next location to be filled.
    fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> impl Future<Output = Result<Self::Journal, crate::adb::Error>>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::adb::Error>>;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;

    /// Resize an existing journal to a new range.
    ///
    /// The implementation must:
    /// - If current `size() <= range.start`: close the journal and return a newly prepared one
    ///   (equivalent to `create_journal`).
    /// - Else: prune/discard data outside the range.
    /// - Report `size()` as the next location to be set by the sync engine.
    fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> impl Future<Output = Result<Self::Journal, crate::adb::Error>>;
}

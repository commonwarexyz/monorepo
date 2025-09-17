use crate::adb::sync::Journal;
use commonware_cryptography::Digest;
use std::future::Future;

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

    /// Create/open a journal for syncing range [lower_bound, upper_bound].
    ///
    /// The implementation must:
    /// - Reuse any on-disk data whose logical locations lie within [lower_bound, upper_bound].
    /// - Discard/ignore any data strictly below `lower_bound` and strictly above `upper_bound`.
    /// - Report `size()` equal to the next location to be filled.
    fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<Self::Journal, crate::adb::Error>>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        lower_bound: u64,
        upper_bound: u64,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::adb::Error>>;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;

    /// Resize an existing journal to a new inclusive range [lower_bound, upper_bound].
    ///
    /// The implementation must:
    /// - If current `size() <= lower_bound`: close the journal and return a newly prepared one
    ///   (equivalent to `create_journal`).
    /// - Else: prune/discard data strictly below `lower_bound` and strictly above `upper_bound`.
    /// - Report `size()` as the next location to be set by the sync engine.
    fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<Self::Journal, crate::adb::Error>>;
}

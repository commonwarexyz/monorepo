use crate::adb::sync::Journal;
use commonware_cryptography::Digest;
use std::future::Future;

/// A database that can be synced
pub trait Database: Sized {
    /// The increment of data synced by the [Database]
    type Data;
    /// A proof over Data received from the Resolver
    type Proof;
    /// Pinned nodes derived from the Data received from the Resolver
    type PinnedNodes;
    /// The underlying storage of the Database populated by the sync engine
    type Journal: Journal<Data = Self::Data>;
    /// Error type returned by the [Database]
    type Error: std::error::Error + Send + From<<Self::Journal as Journal>::Error> + 'static;
    /// Configuration options for the [Database]
    type Config;
    /// Runtime context required for the [Database]
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + Clone;
    /// Digest type for MMR nodes
    type Digest: Digest;
    /// Used to hash MMR nodes and data
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
    ) -> impl Future<Output = Result<Self::Journal, <Self::Journal as Journal>::Error>>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Self::PinnedNodes>,
        lower_bound: u64,
        upper_bound: u64,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

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
    ) -> impl Future<Output = Result<Self::Journal, Self::Error>>;

    /// Verify a proof that the given data is in the database with the given root
    /// starting at the given location.
    fn verify_proof(
        proof: &Self::Proof,
        data: &[Self::Data],
        start_loc: u64,
        root: Self::Digest,
    ) -> bool;

    /// Extract pinned nodes from a proof
    fn extract_pinned_nodes(
        proof: &Self::Proof,
        start_loc: u64,
        data_len: u64,
    ) -> Result<Self::PinnedNodes, Self::Error>;
}

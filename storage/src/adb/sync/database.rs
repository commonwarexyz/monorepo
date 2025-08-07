use crate::adb::sync::{Journal, Target, Verifier};
use commonware_cryptography::Digest;
use std::future::Future;

/// A database that can be synced
pub trait Database: Sized {
    // Core associated types - determined by database implementation
    type Op;
    type Journal: Journal<Op = Self::Op>;
    type Verifier: Verifier<Self::Op, Self::Digest>;
    type Error: std::error::Error + Send + From<<Self::Journal as Journal>::Error> + 'static;
    type Config;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + Clone;

    /// Create a journal for syncing with the given bounds
    fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<Self::Journal, <Self::Journal as Journal>::Error>>;

    /// Create a verifier for proof validation  
    fn create_verifier() -> Self::Verifier;

    /// Build a database from a completed sync journal and configuration
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: Target<Self::Digest>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;

    /// Resize journal for target update - close and recreate if needed, prune otherwise.
    // TODO should this be a method on the journal?
    fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<Self::Journal, Self::Error>>;
}

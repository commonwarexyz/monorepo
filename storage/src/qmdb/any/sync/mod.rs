//! Shared synchronization logic for any databases.

pub(crate) mod fixed;
pub(crate) mod impls;

#[cfg(test)]
pub(crate) mod tests;

use crate::mmr::journaled::Config as MmrConfig;
use commonware_codec::Encode;
use commonware_runtime::{Clock, Metrics, Storage};
use std::future::Future;

/// Database configurations that support sync operations.
///
/// Both `FixedConfig` and `VariableConfig` implement this trait,
/// allowing the sync implementation to extract common configuration
/// without knowing the specific config type.
pub trait SyncConfig: Clone {
    /// Extract the MMR configuration for sync initialization.
    fn mmr_config(&self) -> MmrConfig;
}

/// Indexes that can be constructed during sync operations.
///
/// Both `ordered::Index` and `unordered::Index` have the same
/// constructor signature: `fn new(ctx: impl Metrics, translator: T)`
pub trait SyncIndex: Sized {
    type Translator: crate::translator::Translator + Clone;
    /// Create a new index for use during sync.
    fn new_for_sync(ctx: impl Metrics, translator: Self::Translator) -> Self;
}

/// Logic for reconstructing a database from its components.
///
/// This trait abstracts over `ordered::Db` and `unordered::Db`, which have
/// identical `from_components` signatures but are distinct inherent methods.
pub trait Reconstructable<E, C, H>: Sized
where
    E: Storage + Clock + Metrics,
    C: crate::journal::contiguous::MutableContiguous,
    C::Item: Encode,
    H: commonware_cryptography::Hasher,
{
    /// The index type used by this database.
    type Index;

    /// Reconstruct the database from a log and index.
    fn reconstruct(
        range: std::ops::Range<crate::mmr::Location>,
        log: crate::journal::authenticated::Journal<E, C, H, crate::mmr::mem::Clean<H::Digest>>,
        index: Self::Index,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error>>;
}

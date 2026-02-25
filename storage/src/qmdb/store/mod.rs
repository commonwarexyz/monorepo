//! Traits for interacting with stores whose state is derived from an append-only log of
//! state-changing operations.
//!
//! # Pruning
//!
//! Maintains a location before which all operations are inactive, called the _inactivity floor_.
//! These operations can be cleaned from storage by calling [PrunableStore::prune].

use crate::{
    mmr::{Location, Proof},
    qmdb::Error,
};
use commonware_codec::CodecShared;
use commonware_cryptography::Digest;
use core::future::Future;
use std::num::NonZeroU64;

mod batch;
pub mod db;
#[cfg(test)]
pub use batch::tests as batch_tests;

/// A trait for a store based on an append-only log of operations.
pub trait LogStore: Send + Sync {
    type Value: CodecShared + Clone;

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    fn bounds(&self) -> impl Future<Output = std::ops::Range<Location>> + Send;

    /// Return the Location of the next operation appended to this db.
    fn size(&self) -> impl Future<Output = Location> + Send {
        async { self.bounds().await.end }
    }

    /// Get the metadata associated with the last commit.
    fn get_metadata(&self) -> impl Future<Output = Result<Option<Self::Value>, Error>> + Send;
}

/// A trait for stores that can be pruned.
pub trait PrunableStore: LogStore {
    /// Prune historical operations prior to `loc`.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Error>> + Send;

    /// The location before which all operations can be pruned without affecting the state of the
    /// database.
    fn inactivity_floor_loc(&self) -> impl Future<Output = Location> + Send;
}

/// A trait for stores that support authentication through merkleization and inclusion proofs.
pub trait MerkleizedStore: LogStore {
    /// The digest type used for authentication.
    type Digest: Digest;

    /// The operation type stored in the log.
    type Operation;

    /// Returns the root digest of the authenticated store.
    fn root(&self) -> Self::Digest;

    /// Generate and return:
    ///  1. a proof of all operations applied to the store in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
    #[allow(clippy::type_complexity)]
    fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>> + Send
    {
        async move {
            self.historical_proof(self.bounds().await.end, start_loc, max_ops)
                .await
        }
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the store in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// for the store when it had `historical_size` operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count`.
    #[allow(clippy::type_complexity)]
    fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>> + Send;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{LogStore, MerkleizedStore, PrunableStore};
    use crate::mmr::Location;
    use commonware_utils::NZU64;

    pub fn assert_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    pub fn assert_log_store<T: LogStore>(db: &T) {
        assert_send(db.get_metadata());
    }

    #[allow(dead_code)]
    pub fn assert_prunable_store<T: PrunableStore>(db: &mut T, loc: Location) {
        assert_send(db.prune(loc));
    }

    #[allow(dead_code)]
    pub fn assert_merkleized_store<T: MerkleizedStore>(db: &T, loc: Location) {
        assert_send(db.proof(loc, NZU64!(1)));
    }
}

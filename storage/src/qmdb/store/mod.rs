//! Traits for interacting with log based key value stores.
//!
//! # Terminology
//!
//! A _key_ in a database either has a _value_ or it doesn't. The _update_ operation gives a key a
//! specific value whether it previously had no value or had a different value.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is an update operation, and (3) it is the most recent operation for that key.
//!
//! # Pruning
//!
//! A database maintains a location before which all operations are inactive, called the _inactivity
//! floor_. These items can be cleaned from storage by calling [Store::prune].

use crate::{
    mmr::{Location, Proof},
    qmdb::Error,
};
use commonware_codec::Codec;
use commonware_cryptography::Digest;
use core::{future::Future, ops::Range};
use std::num::NonZeroU64;

mod batch;
pub mod db;
#[cfg(test)]
pub use batch::tests as batch_tests;
pub use batch::{Batch, Batchable, Getter};

/// Sealed trait for store state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid store state types.
pub trait State: private::Sealed + Sized {}

/// Marker type for a store in a "clean" state (no uncommitted operations).
#[derive(Clone, Copy, Debug)]
pub struct Clean;

impl private::Sealed for Clean {}
impl State for Clean {}

/// Marker type for a store in a "dirty" state (may contain uncommitted operations).
#[derive(Clone, Debug, Default)]
pub struct Dirty {
    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,
}

impl private::Sealed for Dirty {}
impl State for Dirty {}

/// A trait for any key-value store based on an append-only log of operations.
pub trait LogStore {
    type Value: Codec + Clone;

    /// Returns true if there are no active keys in the database.
    fn is_empty(&self) -> bool;

    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    fn op_count(&self) -> Location;

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    fn inactivity_floor_loc(&self) -> Location;

    /// Get the metadata associated with the last commit.
    fn get_metadata(&self) -> impl Future<Output = Result<Option<Self::Value>, Error>>;
}

/// A trait for stores that can be pruned.
pub trait PrunableStore: LogStore {
    /// Prune historical operations prior to `loc`.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Error>>;
}

/// A trait for stores in a "dirty" state (mutations allowed, may have uncommitted operations).
pub trait DirtyStore: LogStore {
    /// The operation type stored in the log.
    type Operation;

    /// The clean state type that this dirty store transitions to.
    type Clean: CleanStore<Operation = Self::Operation, Dirty = Self, Value = Self::Value>;

    /// Commit the dirty store and transition it to a clean one, returning the range of operations
    /// that were committed.
    fn commit(
        self,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>>;
}

/// A trait for authenticated stores in a "clean" state where the MMR root is computed.
pub trait CleanStore: LogStore {
    /// The operation type stored in the log.
    type Operation;

    /// The dirty state type that this clean store transitions to.
    type Dirty: DirtyStore<Operation = Self::Operation, Clean = Self, Value = Self::Value>;

    /// Convert this clean store into its dirty counterpart for making updates.
    fn into_dirty(self) -> Self::Dirty;
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
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>>;

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
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>>;
}

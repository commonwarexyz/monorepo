//! Traits representing the possible states of an Any database. These are used to share test and
//! benchmark code across the variants.

use crate::{
    kv::{Batchable, Gettable},
    mmr::{Location, Proof},
    qmdb::{
        operation::Key,
        store::{LogStore, MerkleizedStore, PrunableStore},
        Error,
    },
    Persistable,
};
use commonware_codec::Codec;
use commonware_cryptography::Digest;
use std::{future::Future, num::NonZeroU64, ops::Range};

/// Trait for the Durable state (Clean).
///
/// This state allows authentication (root, proofs), pruning, and persistence operations
/// (sync/close/destroy). Use `into_mutable` to transition to the NonDurable (Mutable) state.
pub trait CleanAny:
    MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Gettable<Key: Key, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The mutable state type (NonDurable).
    type Mutable: MutableAny<
            Key = Self::Key,
            Digest = <Self as MerkleizedStore>::Digest,
            Operation = <Self as MerkleizedStore>::Operation,
            Clean = Self,
        > + LogStore<Value = <Self as LogStore>::Value>;

    /// Convert this database into the mutable (NonDurable) state.
    fn into_mutable(self) -> Self::Mutable;
}

/// Trait for the NonDurable (Mutable) state.
///
/// This is the only state that allows mutations via write_batch. Use `commit` to transition
/// to the Durable (Clean) state.
pub trait MutableAny:
    LogStore + Batchable<Key: Key, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The digest type used for merkleization.
    type Digest: Digest;

    /// The operation type used for merkleization.
    type Operation: Codec;

    /// The clean state type (Durable).
    type Clean: CleanAny<Key = Self::Key, Mutable = Self>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = Self::Digest,
            Operation = Self::Operation,
        >;

    /// Commit any pending operations to the database, ensuring their durability. Returns the db in
    /// its durable state and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self::Clean, Range<Location>), Error>> + Send;

    /// Returns the number of steps to raise the inactivity floor on the next commit.
    fn steps(&self) -> u64;
}

/// A unified trait for testing Any databases.
///
/// `any::Db` supports both reads and writes in a single state. This is a
/// self-contained trait that avoids supertrait conflicts.
pub trait TestableAny: Send + Sync {
    /// The key type.
    type Key: Key;

    /// The value type.
    type Value: Clone + PartialEq + std::fmt::Debug + Send + Sync + 'static;

    /// The digest type.
    type Digest: Digest;

    /// The operation type stored in the log.
    type Operation: Send + Sync;

    /// Returns the number of steps to raise the inactivity floor on the next commit.
    fn steps(&self) -> u64;

    /// Commit pending operations to disk.
    fn commit(
        &mut self,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Result<Range<Location>, Error>> + Send;

    /// Return the number of operations in the log.
    fn size(&self) -> impl Future<Output = Location> + Send;

    /// Get the journal bounds (start..end locations).
    fn bounds(&self) -> impl Future<Output = Range<Location>> + Send;

    /// Get a value by key.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error>> + Send;

    /// Write a batch of mutations.
    fn write_batch(
        &mut self,
        batch: Vec<(Self::Key, Option<Self::Value>)>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Get the metadata for the last commit.
    fn get_metadata(&self) -> impl Future<Output = Result<Option<Self::Value>, Error>> + Send;

    /// Get the root digest.
    fn root(&self) -> Self::Digest;

    /// Generate a proof of operations starting at `start_loc`.
    #[allow(clippy::type_complexity)]
    fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>> + Send;

    /// Generate a historical proof of operations starting at `start_loc` for the store
    /// when it had `historical_size` operations.
    #[allow(clippy::type_complexity)]
    fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>> + Send;

    /// Flush data to durable storage.
    fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// Prune operations before the given location.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Error>> + Send;

    /// Get the inactivity floor location.
    fn inactivity_floor_loc(&self) -> impl Future<Output = Location> + Send;

    /// Destroy the database.
    fn destroy(self) -> impl Future<Output = Result<(), Error>> + Send;
}

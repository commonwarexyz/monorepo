//! Traits representing the 2 possible states of an Any database. These are used to share test and
//! benchmark code across the variants.

use crate::{
    journal::contiguous::Mutable,
    kv::{Batchable, Gettable},
    mmr::Location,
    qmdb::{
        operation::Key,
        store::{LogStore, MerkleizedStore, PrunableStore},
        Error,
    },
    Persistable,
};
use commonware_codec::Codec;
use commonware_cryptography::Digest;
use std::{future::Future, ops::Range};

/// A mutable operation log that can be durably persisted.
pub(crate) trait PersistableMutableLog<O>:
    Mutable<Item = O> + Persistable<Error = crate::journal::Error>
{
}

impl<T, O> PersistableMutableLog<O> for T where
    T: Mutable<Item = O> + Persistable<Error = crate::journal::Error>
{
}

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

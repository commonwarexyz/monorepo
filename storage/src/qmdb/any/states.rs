//! Traits representing the 4 possible states of an Any database. These are used to share test and
//! benchmark code across the variants.

use crate::{
    kv::{Batchable, Deletable, Gettable},
    mmr::Location,
    qmdb::{
        store::{LogStore, MerkleizedStore, PrunableStore},
        Error,
    },
    Persistable,
};
use commonware_codec::Codec;
use commonware_cryptography::Digest;
use commonware_utils::Array;
use std::{future::Future, ops::Range};

/// Trait for the (Merkleized,Durable) state.
///
/// This state allows authentication (root, proofs), pruning, and persistence operations
/// (sync/close/destroy). Use `into_mutable` to transition to the (Unmerkleized,Non-durable) state.
pub trait CleanAny:
    MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Gettable<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The mutable state type (Unmerkleized,Non-durable).
    type Mutable: MutableAny<
            Key = Self::Key,
            Digest = <Self as MerkleizedStore>::Digest,
            Operation = <Self as MerkleizedStore>::Operation,
            // Cycle constraint for path: into_merkleized() then commit()
            Merkleized: MerkleizedNonDurableAny<Durable = Self>,
            // Cycle constraint for path: commit() then into_merkleized() or into_mutable()
            Durable: UnmerkleizedDurableAny<Merkleized = Self, Mutable = Self::Mutable>,
        > + LogStore<Value = <Self as LogStore>::Value>;

    /// Convert this database into the mutable (Unmerkleized, Non-durable) state.
    fn into_mutable(self) -> Self::Mutable;
}

/// Trait for the (Unmerkleized,Durable) state.
///
/// Use `into_mutable` to transition to the (Unmerkleized,NonDurable) state, or `into_merkleized` to
/// transition to the (Merkleized,Durable) state.
pub trait UnmerkleizedDurableAny:
    LogStore + Gettable<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The digest type used by Merkleized states in this database's state machine.
    type Digest: Digest;

    /// The operation type used by Merkleized states in this database's state machine.
    type Operation: Codec;

    /// The mutable state type (Unmerkleized,NonDurable).
    type Mutable: MutableAny<Key = Self::Key, Digest = Self::Digest, Operation = Self::Operation>
        + LogStore<Value = <Self as LogStore>::Value>;

    /// The provable state type (Merkleized,Durable).
    type Merkleized: CleanAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = Self::Digest,
            Operation = Self::Operation,
        >;

    /// Convert this database into the mutable state.
    fn into_mutable(self) -> Self::Mutable;

    /// Convert this database into the provable (Merkleized,Durable) state.
    fn into_merkleized(self) -> impl Future<Output = Result<Self::Merkleized, Error>> + Send;
}

/// Trait for the (Merkleized,NonDurable) state.
///
/// This state allows authentication (root, proofs) and pruning. Use `commit` to transition to the
/// Merkleized, Durable state.
pub trait MerkleizedNonDurableAny:
    MerkleizedStore
    + PrunableStore
    + Gettable<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The mutable state type (Unmerkleized,NonDurable).
    type Mutable: MutableAny<Key = Self::Key>;

    /// The durable state type (Merkleized,Durable).
    type Durable: CleanAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = <Self as MerkleizedStore>::Digest,
            Operation = <Self as MerkleizedStore>::Operation,
        >;

    /// Commit any pending operations to the database, ensuring their durability. Returns the
    /// durable state and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self::Durable, Range<Location>), Error>> + Send;

    /// Convert this database into the mutable (Unmerkleized, NonDurable) state.
    fn into_mutable(self) -> Self::Mutable;
}

/// Trait for the (Unmerkleized,NonDurable) state.
///
/// This is the only state that allows mutations (create/update/delete). Use `commit` to transition
/// to the Unmerkleized, Durable state, or `into_merkleized` to transition to the Merkleized,
/// NonDurable state.
pub trait MutableAny:
    LogStore + Deletable<Key: Array, Value = <Self as LogStore>::Value, Error = Error> + Batchable
{
    /// The digest type used by Merkleized states in this database's state machine.
    type Digest: Digest;

    /// The operation type used by Merkleized states in this database's state machine.
    type Operation: Codec;

    /// The durable state type (Unmerkleized,Durable).
    type Durable: UnmerkleizedDurableAny<Key = Self::Key, Digest = Self::Digest, Operation = Self::Operation>
        + LogStore<Value = <Self as LogStore>::Value>;

    /// The provable state type (Merkleized,NonDurable).
    type Merkleized: MerkleizedNonDurableAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = Self::Digest,
            Operation = Self::Operation,
        >;

    /// Commit any pending operations to the database, ensuring their durability. Returns the
    /// durable state and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self::Durable, Range<Location>), Error>> + Send;

    /// Convert this database into the provable (Merkleized, Non-durable) state.
    fn into_merkleized(self) -> impl Future<Output = Result<Self::Merkleized, Error>> + Send;

    /// Returns the number of steps to raise the inactivity floor on the next commit.
    fn steps(&self) -> u64;
}

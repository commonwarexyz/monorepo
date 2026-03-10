//! Trait providing a unified test/benchmark interface across all Any database variants.

use crate::{
    journal::contiguous::Mutable,
    kv::Gettable,
    mmr::Location,
    qmdb::{
        operation::Key,
        store::{LogStore, MerkleizedStore, PrunableStore},
        Error,
    },
    Persistable,
};
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

/// Unmerkleized batch of operations.
pub trait UnmerkleizedBatch: Sized {
    type K;
    type V;
    type Metadata;
    type Merkleized: MerkleizedBatch;

    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    fn write(self, key: Self::K, value: Option<Self::V>) -> Self;

    /// Resolve mutations, compute the new root, and return a merkleized batch.
    fn merkleize(
        self,
        metadata: Option<Self::Metadata>,
    ) -> impl Future<Output = Result<Self::Merkleized, Error>>;
}

/// Merkleized batch of operations.
pub trait MerkleizedBatch: Sized {
    type Digest: Digest;
    type Changeset: Send;

    /// Return the committed root.
    fn root(&self) -> Self::Digest;

    /// Consume this batch, producing an owned changeset.
    fn finalize(self) -> Self::Changeset;
}

/// Db that supports updates through a batch API.
pub trait BatchableDb {
    type K;
    type V;
    type Changeset: Send;
    type Batch<'a>: UnmerkleizedBatch<
        K = Self::K,
        V = Self::V,
        Metadata = Self::V,
        Merkleized: MerkleizedBatch<Changeset = Self::Changeset>,
    >
    where
        Self: 'a;

    /// Create a new speculative batch of operations with this database as its parent.
    fn new_batch(&self) -> Self::Batch<'_>;

    /// Apply a changeset.
    fn apply_batch(
        &mut self,
        batch: Self::Changeset,
    ) -> impl Future<Output = Result<Range<Location>, Error>>;
}

/// Unified trait for an authenticated database.
///
/// This trait provides access to authentication (root, proofs), pruning, persistence,
/// reads, and batch mutations.
pub trait DbAny:
    BatchableDb<K = <Self as Gettable>::Key, V = <Self as LogStore>::Value>
    + MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Gettable<Key: Key, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The digest type used for merkleization.
    type Digest: Digest;
}

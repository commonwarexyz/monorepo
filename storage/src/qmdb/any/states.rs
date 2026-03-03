//! Trait providing a unified test/benchmark interface across all Any database variants.

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

/// Unified trait for an authenticated database.
///
/// This trait provides access to authentication (root, proofs), pruning, persistence,
/// reads, writes, and commits.
pub trait DbAny:
    MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Gettable<Key: Key, Value = <Self as LogStore>::Value, Error = Error>
    + Batchable<Key: Key, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The digest type used for merkleization.
    type Digest: Digest;

    /// Commit any pending operations to the database, ensuring their durability. Returns the
    /// location range of committed operations.
    fn commit(
        &mut self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<Range<Location>, Error>> + Send;

    /// Returns the number of steps to raise the inactivity floor on the next commit.
    fn steps(&self) -> u64;
}

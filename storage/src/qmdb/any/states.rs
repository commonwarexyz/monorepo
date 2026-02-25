//! Trait representing the test interface of an Any database. This is used to share test and
//! benchmark code across the variants (ordered/unordered, fixed/variable).

use crate::{
    kv::Gettable,
    mmr::Location,
    qmdb::{
        store::{LogStore, MerkleizedStore, PrunableStore},
        Error,
    },
    Persistable,
};
use commonware_utils::Array;
use std::{future::Future, ops::Range};

/// Test trait unifying all Any database variants.
///
/// Since type-state has been removed, all state transitions are identity operations.
/// The `into_mutable` and `into_merkleized` methods exist for backward compatibility
/// with existing test code. Types implementing this trait should also implement
/// [`crate::kv::Batchable`] for `write_batch` and `start_batch` support.
pub trait CleanAny:
    MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Gettable<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
    + Sized
{
    /// Identity transition (was consuming type-state transition to mutable).
    fn into_mutable(self) -> Self;

    /// Identity transition (was consuming type-state transition to merkleized).
    fn into_merkleized(self) -> impl Future<Output = Result<Self, Error>> + Send;

    /// Consuming commit. Returns self and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self, Range<Location>), Error>> + Send;

    /// Returns accumulated floor-raising steps.
    fn steps(&self) -> u64;
}

//! Trait providing a unified test/benchmark interface across all Any database variants.

use crate::{
    journal::contiguous::Mutable,
    mmr::{Location, Proof},
    qmdb::{operation::Key, Error},
    Persistable,
};
use commonware_codec::CodecShared;
use commonware_cryptography::Digest;
use core::num::NonZeroU64;
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
/// This trait provides access to authentication (root), pruning, persistence,
/// reads, and batch mutations.
pub trait DbAny:
    BatchableDb<K = <Self as DbAny>::Key, V = <Self as DbAny>::Value>
    + Persistable<Error = Error>
    + Send
    + Sync
{
    /// The key type used to look up values.
    type Key: Key;

    /// The value type stored in the database.
    type Value: CodecShared + Clone;

    /// The digest type used for merkleization.
    type Digest: Digest;

    /// Get the value of a key.
    fn get<'a>(
        &'a self,
        key: &'a Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error>> + Send + use<'a, Self>;

    /// Returns the root digest of the authenticated store.
    fn root(&self) -> Self::Digest;

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    fn bounds(&self) -> impl Future<Output = Range<Location>> + Send;

    /// Return the Location of the next operation appended to this db.
    fn size(&self) -> impl Future<Output = Location> + Send {
        async { self.bounds().await.end }
    }

    /// Get the metadata associated with the last commit.
    fn get_metadata(
        &self,
    ) -> impl Future<Output = Result<Option<<Self as DbAny>::Value>, Error>> + Send;

    /// Prune historical operations prior to `loc`.
    fn prune(&mut self, loc: Location) -> impl Future<Output = Result<(), Error>> + Send;

    /// The location before which all operations can be pruned.
    fn inactivity_floor_loc(&self) -> impl Future<Output = Location> + Send;
}

/// Proof generation for Any database variants.
///
/// Only Any variants implement this trait. Current variants have a different
/// proof structure (grafted MMR + activity bitmap) that is incompatible with
/// the ops-level MMR proofs returned here.
pub trait Provable: DbAny {
    /// The operation type stored in the log.
    type Operation;

    /// Generate a proof of operations starting at `start_loc`.
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

    /// Generate a proof of operations starting at `start_loc` for a historical size.
    #[allow(clippy::type_complexity)]
    fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error>> + Send;
}

/// Implements [`DbAny`] by delegating each method to an identically-named inherent method.
///
/// # Syntax
///
/// ```ignore
/// impl_db_any! {
///     [$($generics)*] TypeName
///     where { $where_clause }
///     Key = .., Value = .., Digest = ..
/// }
/// ```
macro_rules! impl_db_any {
    (
        [$($gen:tt)*] $ty:ty
        where { $($where_clause:tt)* }
        Key = $key:ty, Value = $val:ty, Digest = $dig:ty
    ) => {
        impl<$($gen)*> $crate::qmdb::any::traits::DbAny for $ty
        where $($where_clause)*
        {
            type Key = $key;
            type Value = $val;
            type Digest = $dig;

            async fn get(&self, key: &$key) -> ::core::result::Result<Option<$val>, $crate::qmdb::Error> {
                self.get(key).await
            }

            fn root(&self) -> $dig {
                self.root()
            }

            async fn bounds(&self) -> ::std::ops::Range<$crate::mmr::Location> {
                self.bounds().await
            }

            async fn get_metadata(
                &self,
            ) -> ::core::result::Result<Option<$val>, $crate::qmdb::Error> {
                self.get_metadata().await
            }

            async fn prune(
                &mut self,
                loc: $crate::mmr::Location,
            ) -> ::core::result::Result<(), $crate::qmdb::Error> {
                self.prune(loc).await
            }

            async fn inactivity_floor_loc(&self) -> $crate::mmr::Location {
                self.inactivity_floor_loc()
            }
        }
    };
}

pub(crate) use impl_db_any;

/// Implements [`Provable`] by delegating each method to an identically-named inherent method.
macro_rules! impl_provable {
    (
        [$($gen:tt)*] $ty:ty
        where { $($where_clause:tt)* }
        Operation = $op:ty
    ) => {
        impl<$($gen)*> $crate::qmdb::any::traits::Provable for $ty
        where $($where_clause)*
        {
            type Operation = $op;

            async fn historical_proof(
                &self,
                historical_size: $crate::mmr::Location,
                start_loc: $crate::mmr::Location,
                max_ops: ::core::num::NonZeroU64,
            ) -> ::core::result::Result<
                ($crate::mmr::Proof<<Self as $crate::qmdb::any::traits::DbAny>::Digest>, Vec<$op>),
                $crate::qmdb::Error,
            > {
                self.historical_proof(historical_size, start_loc, max_ops)
                    .await
            }
        }
    };
}

pub(crate) use impl_provable;

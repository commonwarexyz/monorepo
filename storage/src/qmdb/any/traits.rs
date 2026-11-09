//! Trait providing a unified test/benchmark interface across all Any database variants.

use crate::{
    merkle::{Family, Location, Proof},
    qmdb::{
        Error,
        floor::{Policy, Proportional},
        operation::Key,
    },
};
use commonware_codec::CodecShared;
use commonware_cryptography::Digest;
use commonware_runtime::Handle;
use core::{borrow::Borrow, num::NonZeroU64};
use std::{future::Future, ops::Range};

/// Unmerkleized batch of operations.
pub trait UnmerkleizedBatch<Db: ?Sized>: Sized {
    /// The Merkle family used for operation locations and proofs.
    type Family: Family;
    /// The key type used to look up values.
    type Key;
    /// The value type stored in the database.
    type Value;
    /// The metadata type recorded in the batch's commit.
    type Metadata;
    /// The batch that merkleizing this one produces.
    type Merkleized: MerkleizedBatch;

    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    fn write(self, key: Self::Key, value: Option<Self::Value>) -> Self;

    /// Set the metadata recorded in this batch's commit. Defaults to `None`.
    fn with_metadata(self, metadata: impl Into<Option<Self::Metadata>>) -> Self;

    /// Merkleize, advancing the inactivity floor with [`Proportional`].
    fn merkleize(
        self,
        db: &Db,
    ) -> impl Future<Output = Result<Self::Merkleized, Error<Self::Family>>> {
        async move { self.merkleize_with(db, &mut Proportional).await }
    }

    /// Resolve mutations, advance the inactivity floor with [`Policy`], compute the new root, and
    /// return a merkleized batch.
    fn merkleize_with<P: Policy<Self::Family, Self::Key, Self::Value> + Send>(
        self,
        db: &Db,
        policy: &mut P,
    ) -> impl Future<Output = Result<Self::Merkleized, Error<Self::Family>>>;
}

/// Merkleized batch of operations.
pub trait MerkleizedBatch: Sized {
    /// The digest type of the batch's root.
    type Digest: Digest;

    /// Return the committed root.
    fn root(&self) -> Self::Digest;
}

/// Db that supports updates through a batch API.
pub trait BatchableDb: Sized {
    /// The Merkle family used for operation locations and proofs.
    type Family: Family;
    /// The key type used to look up values.
    type Key;
    /// The value type stored in the database.
    type Value;
    /// The merkleized batch the database applies.
    type Merkleized: MerkleizedBatch;
    /// The unmerkleized batch the database creates.
    type Batch: UnmerkleizedBatch<
            Self,
            Family = Self::Family,
            Key = Self::Key,
            Value = Self::Value,
            Metadata = Self::Value,
            Merkleized = Self::Merkleized,
        >;

    /// Create a new speculative batch of operations with this database as its parent.
    fn new_batch(&self) -> Self::Batch;

    /// Apply a merkleized batch.
    fn apply_batch(
        self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>>;
}

/// Unified trait for an authenticated database.
///
/// This trait provides access to authentication (root), pruning, persistence,
/// reads, and batch mutations.
pub trait DbAny: BatchableDb<Key: Key, Value: CodecShared + Clone> + Send + Sync {
    /// The digest type used for merkleization.
    type Digest: Digest;

    /// Get the value of a key.
    fn get<'a>(
        &'a self,
        key: &'a Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error<Self::Family>>> + Send + use<'a, Self>;

    /// Get the values of multiple keys, returned in the same order as the input keys.
    fn get_many<'a, Q: Borrow<Self::Key> + Sync>(
        &'a self,
        keys: &'a [Q],
    ) -> impl Future<Output = Result<Vec<Option<Self::Value>>, Error<Self::Family>>>
    + Send
    + use<'a, Self, Q>;

    /// Returns the root digest of the authenticated store.
    fn root(&self) -> Self::Digest;

    /// Return the retained operation range `[start, end)`.
    ///
    /// Proof generation also requires the necessary Merkle nodes to be retained.
    fn bounds(&self) -> Range<Location<Self::Family>>;

    /// Get the metadata associated with the last commit.
    fn get_metadata(
        &self,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error<Self::Family>>> + Send;

    /// Prune historical operations prior to `prune_loc`.
    ///
    /// The retained start in [`Self::bounds`] can remain below `prune_loc`.
    fn prune(
        self,
        prune_loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Begin durably persisting the database.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit]
    /// for the state applied before the call, plus a best-effort attempt to bound the recovery
    /// needed on startup. Use [Self::sync] to guarantee none is needed.
    fn start_sync(
        self,
    ) -> impl Future<Output = Result<(Self, Handle<()>), Error<Self::Family>>> + Send;

    /// Durably persist the database, guaranteeing the current state will survive a crash.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(self) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Durably persist the database, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(self) -> impl Future<Output = Result<Self, Error<Self::Family>>> + Send;

    /// Destroy the database, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error<Self::Family>>> + Send
    where
        Self: Sized;

    /// The location before which all operations are known to be inactive.
    fn inactivity_floor(&self) -> Location<Self::Family>;

    /// The maximum location that [`Self::prune`] accepts and the most recent location from which
    /// this database can be safely synced.
    fn sync_boundary(&self) -> Location<Self::Family>;
}

/// Proof generation for Any database variants.
///
/// Only Any variants implement this trait. Current variants have a different
/// proof structure (grafted MMR + activity bitmap) that is incompatible with
/// the ops-level proofs returned here.
pub trait Provable: DbAny {
    /// The operation type stored in the log.
    type Operation;

    /// Generate a proof of operations starting at `start_loc`.
    #[allow(clippy::type_complexity)]
    fn proof(
        &self,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
    ) -> impl Future<
        Output = Result<
            (Proof<Self::Family, Self::Digest>, Vec<Self::Operation>),
            Error<Self::Family>,
        >,
    > + Send {
        async move {
            self.historical_proof(self.bounds().end, start_loc, max_ops)
                .await
        }
    }

    /// Generate a proof of operations starting at `start_loc` for a historical size.
    #[allow(clippy::type_complexity)]
    fn historical_proof(
        &self,
        historical_size: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
    ) -> impl Future<
        Output = Result<
            (Proof<Self::Family, Self::Digest>, Vec<Self::Operation>),
            Error<Self::Family>,
        >,
    > + Send;
}

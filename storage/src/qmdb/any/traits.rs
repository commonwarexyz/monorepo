//! Trait providing a unified test/benchmark interface across all Any database variants.

use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::Mutable,
    merkle::{Family, Location, Proof},
    qmdb::{
        Error,
        any::{
            db::Db,
            operation::{Operation, Update},
        },
        floor::Policy,
        operation::Key,
    },
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use core::num::NonZeroU64;
use std::{future::Future, ops::Range};

/// Unmerkleized batch of operations.
pub trait UnmerkleizedBatch<Db: ?Sized>: Sized {
    type Family: Family;
    type K;
    type V;
    type Metadata;
    type Merkleized: MerkleizedBatch;

    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    fn write(self, key: Self::K, value: Option<Self::V>) -> Self;

    /// Resolve mutations, advance the inactivity floor with [`Policy`], compute the new root, and
    /// return a merkleized batch.
    fn merkleize<P: Policy<Self::Family, Self::K, Self::V> + Send>(
        self,
        db: &Db,
        metadata: Option<Self::Metadata>,
        policy: &mut P,
    ) -> impl Future<Output = Result<Self::Merkleized, Error<Self::Family>>>;
}

/// Merkleized batch of operations.
pub trait MerkleizedBatch: Sized {
    type Digest: Digest;

    /// Return the committed root.
    fn root(&self) -> Self::Digest;
}

/// Db that supports updates through a batch API.
pub trait BatchableDb: Sized {
    type Family: Family;
    type K;
    type V;
    type Merkleized: MerkleizedBatch;
    type Batch: UnmerkleizedBatch<
            Self,
            Family = Self::Family,
            K = Self::K,
            V = Self::V,
            Metadata = Self::V,
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
pub trait DbAny<F: Family>:
    BatchableDb<Family = F, K = <Self as DbAny<F>>::Key, V = <Self as DbAny<F>>::Value> + Send + Sync
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
    ) -> impl Future<Output = Result<Option<Self::Value>, Error<F>>> + Send + use<'a, F, Self>;

    /// Get the values of multiple keys, returned in the same order as the input keys.
    fn get_many<'a>(
        &'a self,
        keys: &'a [&'a Self::Key],
    ) -> impl Future<Output = Result<Vec<Option<Self::Value>>, Error<F>>> + Send + use<'a, F, Self>;

    /// Returns the root digest of the authenticated store.
    fn root(&self) -> Self::Digest;

    /// Return the retained operation range `[start, end)`.
    ///
    /// Proof generation also requires the necessary Merkle nodes to be retained.
    fn bounds(&self) -> Range<Location<F>>;

    /// Return the Location of the next operation appended to this db.
    fn size(&self) -> Location<F> {
        self.bounds().end
    }

    /// Get the metadata associated with the last commit.
    fn get_metadata(
        &self,
    ) -> impl Future<Output = Result<Option<<Self as DbAny<F>>::Value>, Error<F>>> + Send;

    /// Prune historical operations prior to `loc`.
    ///
    /// The retained start in [`Self::bounds`] can remain below `loc`.
    fn prune(self, loc: Location<F>) -> impl Future<Output = Result<Self, Error<F>>> + Send;

    /// Begin durably persisting the database.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit]
    /// for the state applied before the call, plus a best-effort attempt to bound the recovery
    /// needed on startup. Use [Self::sync] to guarantee none is needed.
    fn start_sync(self) -> impl Future<Output = Result<(Self, Handle<()>), Error<F>>> + Send;

    /// Durably persist the database, guaranteeing the current state will survive a crash.
    ///
    /// For a stronger guarantee that eliminates potential recovery, use [Self::sync] instead.
    fn commit(self) -> impl Future<Output = Result<Self, Error<F>>> + Send;

    /// Durably persist the database, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This provides a stronger guarantee than [Self::commit] but may be slower.
    fn sync(self) -> impl Future<Output = Result<Self, Error<F>>> + Send;

    /// Destroy the database, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error<F>>> + Send
    where
        Self: Sized;

    /// The location before which all operations are known to be inactive.
    fn inactivity_floor_loc(&self) -> Location<F>;

    /// The maximum location that [`Self::prune`] accepts and the most recent location from which
    /// this database can be safely synced.
    fn sync_boundary(&self) -> Location<F>;
}

/// Proof generation for Any database variants.
///
/// Only Any variants implement this trait. Current variants have a different
/// proof structure (grafted MMR + activity bitmap) that is incompatible with
/// the ops-level proofs returned here.
pub trait Provable<F: Family>: DbAny<F> {
    /// The operation type stored in the log.
    type Operation;

    /// Generate a proof of operations starting at `start_loc`.
    #[allow(clippy::type_complexity)]
    fn proof(
        &self,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<F, Self::Digest>, Vec<Self::Operation>), Error<F>>> + Send
    {
        async move {
            self.historical_proof(self.bounds().end, start_loc, max_ops)
                .await
        }
    }

    /// Generate a proof of operations starting at `start_loc` for a historical size.
    #[allow(clippy::type_complexity)]
    fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> impl Future<Output = Result<(Proof<F, Self::Digest>, Vec<Self::Operation>), Error<F>>> + Send;
}

impl<F, E, C, I, H, U, const N: usize, S> DbAny<F> for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
    Self: BatchableDb<Family = F, K = U::Key, V = U::Value>,
{
    type Key = U::Key;
    type Value = U::Value;
    type Digest = H::Digest;

    async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        Self::get(self, key).await
    }

    async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        Self::get_many(self, keys).await
    }

    fn root(&self) -> H::Digest {
        Self::root(self)
    }

    fn bounds(&self) -> Range<Location<F>> {
        Self::bounds(self)
    }

    async fn get_metadata(&self) -> Result<Option<U::Value>, Error<F>> {
        Self::get_metadata(self).await
    }

    async fn prune(self, loc: Location<F>) -> Result<Self, Error<F>> {
        Self::prune(self, loc).await
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        Self::start_sync(self).await
    }

    async fn commit(self) -> Result<Self, Error<F>> {
        Self::commit(self).await
    }

    async fn sync(self) -> Result<Self, Error<F>> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error<F>> {
        Self::destroy(self).await
    }

    fn inactivity_floor_loc(&self) -> Location<F> {
        Self::inactivity_floor_loc(self)
    }

    fn sync_boundary(&self) -> Location<F> {
        Self::sync_boundary(self)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Provable<F> for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
    Self: BatchableDb<Family = F, K = U::Key, V = U::Value>,
{
    type Operation = Operation<F, U>;

    async fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, U>>), Error<F>> {
        Self::historical_proof(self, historical_size, start_loc, max_ops).await
    }
}

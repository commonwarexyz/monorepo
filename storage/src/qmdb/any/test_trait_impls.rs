//! Test trait implementations for the Any QMDB.

use super::{
    ValueEncoding,
    batch::{MerkleizedBatch, UnmerkleizedBatch},
    db::Db,
    operation::{Operation, Update, update},
    traits::{
        BatchableDb, DbAny, MerkleizedBatch as MerkleizedBatchTrait, Provable,
        UnmerkleizedBatch as UnmerkleizedBatchTrait,
    },
};
use crate::{
    Context,
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::contiguous::Mutable,
    merkle::{Family, Location, Proof},
    qmdb::{Error, floor::Policy, operation::Key},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use core::num::NonZeroU64;
use std::{future::Future, ops::Range, sync::Arc};

impl<F, K, V, H, E, C, I, const N: usize, S>
    UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Unordered<K, V>, N, S>>
    for UnmerkleizedBatch<F, H, update::Unordered<K, V>, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    E: Context,
    C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location<F>>,
    S: Strategy,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    type Family = F;
    type K = K;
    type V = V::Value;
    type Metadata = V::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>;

    fn with_metadata(self, metadata: impl Into<Option<V::Value>>) -> Self {
        Self::with_metadata(self, metadata)
    }

    fn write(self, key: K, value: Option<V::Value>) -> Self {
        Self::write(self, key, value)
    }

    fn merkleize_with<P: Policy<F, K, V::Value> + Send>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        policy: &mut P,
    ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
        self.merkleize_with(db, policy)
    }
}

impl<F, K, V, H, E, C, I, const N: usize, S>
    UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Ordered<K, V>, N, S>>
    for UnmerkleizedBatch<F, H, update::Ordered<K, V>, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    E: Context,
    C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
    I: OrderedIndex<Value = Location<F>>,
    S: Strategy,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    type Family = F;
    type K = K;
    type V = V::Value;
    type Metadata = V::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>;

    fn with_metadata(self, metadata: impl Into<Option<V::Value>>) -> Self {
        Self::with_metadata(self, metadata)
    }

    fn write(self, key: K, value: Option<V::Value>) -> Self {
        Self::write(self, key, value)
    }

    fn merkleize_with<P: Policy<F, K, V::Value> + Send>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        policy: &mut P,
    ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
        self.merkleize_with(db, policy)
    }
}

impl<F: Family, D: Digest, U: update::Update, S: Strategy> MerkleizedBatchTrait
    for Arc<MerkleizedBatch<F, D, U, S>>
where
    Operation<F, U>: Codec,
{
    type Digest = D;

    fn root(&self) -> D {
        MerkleizedBatch::root(self)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> BatchableDb for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
    UnmerkleizedBatch<F, H, U, S>: UnmerkleizedBatchTrait<
            Self,
            Family = F,
            K = U::Key,
            V = U::Value,
            Metadata = U::Value,
            Merkleized = Arc<MerkleizedBatch<F, H::Digest, U, S>>,
        >,
{
    type Family = F;
    type K = U::Key;
    type V = U::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, U, S>>;
    type Batch = UnmerkleizedBatch<F, H, U, S>;

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    fn apply_batch(
        self,
        batch: Self::Merkleized,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<F>>> {
        self.apply_batch(batch)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> DbAny<F> for Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
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

    fn inactivity_floor(&self) -> Location<F> {
        Self::inactivity_floor(self)
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
    I: UnorderedIndex<Value = Location<F>>,
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

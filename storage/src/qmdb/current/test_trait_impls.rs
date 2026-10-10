//! Test trait implementations for the Current QMDB.

use super::{
    BitmapPrunedBits,
    batch::{MerkleizedBatch, UnmerkleizedBatch},
    db::Db,
};
use crate::{
    Context,
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::contiguous::{Contiguous, Mutable},
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{
            ValueEncoding,
            operation::{Operation, Update, update},
            traits::{
                BatchableDb, DbAny, MerkleizedBatch as MerkleizedBatchTrait,
                UnmerkleizedBatch as UnmerkleizedBatchTrait,
            },
        },
        floor::Policy,
        operation::Key,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use std::{ops::Range, sync::Arc};

impl<F, E, C, I, H, U, const N: usize, S> BitmapPrunedBits for Db<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    fn pruned_bits(&self) -> u64 {
        self.any.bitmap.pruned_bits()
    }

    fn get_bit(&self, index: u64) -> bool {
        self.any.bitmap.get_bit(index)
    }
}

impl<F, K, V, H, E, C, I, const N: usize, S>
    UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Unordered<K, V>, N, S>>
    for UnmerkleizedBatch<F, H, update::Unordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    E: Context,
    C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    S: Strategy,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    type Family = F;
    type K = K;
    type V = V::Value;
    type Metadata = V::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N, S>>;

    fn write(self, key: K, value: Option<V::Value>) -> Self {
        Self::write(self, key, value)
    }

    async fn merkleize<P: Policy<F, K, V::Value> + Send>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        policy: &mut P,
    ) -> Result<Self::Merkleized, crate::qmdb::Error<F>> {
        self.merkleize(db, metadata, policy).await
    }
}

impl<F, K, V, H, E, C, I, const N: usize, S>
    UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Ordered<K, V>, N, S>>
    for UnmerkleizedBatch<F, H, update::Ordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    E: Context,
    C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    S: Strategy,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    type Family = F;
    type K = K;
    type V = V::Value;
    type Metadata = V::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N, S>>;

    fn write(self, key: K, value: Option<V::Value>) -> Self {
        Self::write(self, key, value)
    }

    async fn merkleize<P: Policy<F, K, V::Value> + Send>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        policy: &mut P,
    ) -> Result<Self::Merkleized, crate::qmdb::Error<F>> {
        self.merkleize(db, metadata, policy).await
    }
}

impl<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy> MerkleizedBatchTrait
    for Arc<MerkleizedBatch<F, D, U, N, S>>
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
    F: Graftable,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
    UnmerkleizedBatch<F, H, U, N, S>: UnmerkleizedBatchTrait<
            Self,
            Family = F,
            K = U::Key,
            V = U::Value,
            Metadata = U::Value,
            Merkleized = Arc<MerkleizedBatch<F, H::Digest, U, N, S>>,
        >,
{
    type Family = F;
    type K = U::Key;
    type V = U::Value;
    type Merkleized = Arc<MerkleizedBatch<F, H::Digest, U, N, S>>;
    type Batch = UnmerkleizedBatch<F, H, U, N, S>;

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
    F: Graftable,
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

    fn prefetch(
        &self,
        keys: &[&U::Key],
    ) -> impl Future<Output = ()> + Send + 'static + use<F, E, C, I, H, U, N, S> {
        Self::prefetch(self, keys)
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

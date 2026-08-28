//! [`Qmdb`] implementations for journaled
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.

use crate::stateful::db::qmdb::{Merkleized, Qmdb, Unmerkleized};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    journal::contiguous::Mutable,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::ValueEncoding,
        immutable::{
            Immutable, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
        },
        operation::Key,
        sync,
    },
    translator::Translator,
};
use std::sync::Arc;

impl<F, E, K, V, C, H, T, S> Unmerkleized<Immutable<F, E, K, V, C, H, T, S>>
where
    Immutable<F, E, K, V, C, H, T, S>: Qmdb<Batch = UnmerkleizedBatch<F, H, K, V, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

impl<F, E, K, V, C, H, T, S> Merkleized<Immutable<F, E, K, V, C, H, T, S>>
where
    Immutable<F, E, K, V, C, H, T, S>:
        Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, K, V, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
    }
}

impl<F, E, K, V, C, H, T, S> Qmdb for Immutable<F, E, K, V, C, H, T, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    H: Hasher,
    T: Translator,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    type Batch = UnmerkleizedBatch<F, H, K, V, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, K, V, S>;
    type Metadata = V::Value;
    type Floor = Option<Location<F>>;

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    async fn merkleize(
        &self,
        batch: Self::Batch,
        metadata: Option<Self::Metadata>,
        floor: Option<Location<F>>,
    ) -> Result<Arc<Self::MerkleizedBatch>, Error<F>> {
        let floor = floor.unwrap_or_default();
        Ok(batch.merkleize(self, metadata, floor).await)
    }

    async fn apply_batch(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch).await?;
        Ok(db)
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &sync::Target<F, H::Digest>) -> Result<Self, Error<F>> {
        self.prune(target.range.start()).await
    }

    async fn rewind(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await?.sync().await
    }
}

#[cfg(test)]
mod tests {
    use crate::stateful::db::{
        ManagedDb, Shared, Unmerkleized as _, tests::configs::immutable::fixed_config,
    };
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{merkle::mmr, qmdb::immutable::fixed, translator::TwoCap};
    use commonware_utils::sequence::U64;

    type FixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, U64, Sha256, TwoCap, Sequential>;

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_immutable_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[b"key"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .set(key, U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = batch.merkleize().await.unwrap();
            assert_eq!(merkleized.get(&key).await.unwrap(), Some(U64::new(7)));
            let target = merkleized.target();
            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.get(&key).await.unwrap(), Some(U64::new(7)));
            assert_eq!(guard.get_metadata().await.unwrap(), Some(U64::new(9)));
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&guard), target);
        });
    }
}

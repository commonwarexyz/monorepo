//! [`Qmdb`] implementation for QMDB [`immutable`](commonware_storage::qmdb::immutable)
//! databases.
//!
//! Immutable databases accept new keyed values but no updates or deletions. Batch reads consult
//! the database at the time of the read for keys their batch chain does not write, and return a
//! `StaleRead` error once the database is at no state of that chain.

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
        immutable::{
            Db, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
        },
        operation::Key,
        sync,
        value::ValueEncoding,
    },
    translator::Translator,
};
use core::borrow::Borrow;
use std::sync::Arc;

impl<F, E, K, V, C, H, T, S> Unmerkleized<Db<F, E, K, V, C, H, T, S>>
where
    Db<F, E, K, V, C, H, T, S>: Qmdb<Batch = UnmerkleizedBatch<F, H, K, V, S>>,
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
    /// Sets the metadata committed by [`merkleize`](crate::stateful::db::Unmerkleized::merkleize).
    /// `None` clears it.
    pub fn with_metadata(mut self, metadata: impl Into<Option<V::Value>>) -> Self {
        self.batch = self.batch.with_metadata(metadata);
        self
    }

    /// Sets the inactivity floor committed by
    /// [`merkleize`](crate::stateful::db::Unmerkleized::merkleize) (inherited from the database or
    /// parent batch when unset).
    pub fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.batch = self.batch.with_inactivity_floor(floor);
        self
    }

    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<K> + Sync],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Sets `key` to `value` in the batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

impl<F, E, K, V, C, H, T, S> Merkleized<Db<F, E, K, V, C, H, T, S>>
where
    Db<F, E, K, V, C, H, T, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, K, V, S>>,
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
    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<K> + Sync],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
    }
}

impl<F, E, K, V, C, H, T, S> Qmdb for Db<F, E, K, V, C, H, T, S>
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

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    fn new_child(parent: &Arc<Self::MerkleizedBatch>) -> Self::Batch {
        parent.new_batch::<H>()
    }

    async fn merkleize(&self, batch: Self::Batch) -> Result<Arc<Self::MerkleizedBatch>, Error<F>> {
        batch.merkleize(self).await
    }

    async fn apply_batch(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        self.apply_batch(batch).await
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{ManagedDb, Merkleized as MerkleizedTrait, Shared};
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::{
            authenticated::Config as MerkleConfig, contiguous::fixed::Config as FixedJournalConfig,
        },
        merkle::mmr,
        qmdb::immutable::fixed,
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    type FixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    fn fixed_config(suffix: &str) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::new(NZU16!(101), NZUsize!(11));
        fixed::Config {
            merkle: MerkleConfig {
                partition: format!("stateful-immutable-metadata-{suffix}"),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                resident_height: Default::default(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-immutable-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: NZUsize!(2),
        }
    }

    #[test]
    fn unset_inactivity_floor_inherits_parent_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("inherit-parent-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let parent = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_inactivity_floor(mmr::Location::new(1));
            let parent = crate::stateful::db::Unmerkleized::merkleize(parent)
                .await
                .unwrap();
            let child = MerkleizedTrait::new_batch(&parent)
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]));
            let child = crate::stateful::db::Unmerkleized::merkleize(child)
                .await
                .unwrap();
            assert_eq!(child.bounds().inactivity_floor, mmr::Location::new(1));
        });
    }

    #[test]
    fn unset_inactivity_floor_inherits_applied_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("inherit-applied-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_inactivity_floor(mmr::Location::new(1));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, first)
                    .await
                    .unwrap();
                slot.put(database);
            }

            let next = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]));
            let next = crate::stateful::db::Unmerkleized::merkleize(next)
                .await
                .unwrap();
            assert_eq!(next.bounds().inactivity_floor, mmr::Location::new(1));
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, next)
                .await
                .unwrap();
            assert_eq!(database.inactivity_floor(), mmr::Location::new(1));
            slot.put(database);
        });
    }
}

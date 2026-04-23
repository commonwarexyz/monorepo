//! [`ManagedDb`] implementation for unjournaled QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! These databases retain only the current Merkle peaks, so the glue adapters
//! expose set and merkleization operations but no historical reads.
//! Startup state sync is stubbed out because unjournaled immutable databases do
//! not currently support syncing from peers.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::{
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        immutable::{
            fixed, variable, Operation, UnjournaledDb, UnjournaledMerkleizedBatch,
            UnjournaledUnmerkleizedBatch,
        },
        operation::Key,
        sync::{self, SyncProgress},
        Error,
    },
};
use commonware_utils::{channel::mpsc, non_empty_range, sync::AsyncRwLock, Array};
use std::{ops::Deref, sync::Arc};

type ImmutableUnjournaledDbHandle<F, E, K, V, H, C> =
    Arc<AsyncRwLock<UnjournaledDb<F, E, K, V, H, C>>>;

/// Wraps an unjournaled immutable batch before merkleization.
pub struct ImmutableUnjournaledUnmerkleized<F, E, K, V, H, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    batch: UnjournaledUnmerkleizedBatch<F, H, K, V>,
    db: ImmutableUnjournaledDbHandle<F, E, K, V, H, C>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, K, V, H, C> Deref for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Target = UnjournaledUnmerkleizedBatch<F, H, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, K, V, H, C> ImmutableUnjournaledUnmerkleized<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    /// Set commit metadata included in the next merkleization.
    pub fn with_metadata(mut self, metadata: V::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the inactivity floor included in the next merkleization.
    pub const fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.inactivity_floor = Some(floor);
        self
    }

    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

/// Wraps an unjournaled immutable batch after merkleization.
pub struct ImmutableUnjournaledMerkleized<F, E, K, V, H, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    inner: Arc<UnjournaledMerkleizedBatch<F, H::Digest, K, V>>,
    db: ImmutableUnjournaledDbHandle<F, E, K, V, H, C>,
}

impl<F, E, K, V, H, C> Deref for ImmutableUnjournaledMerkleized<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Target = UnjournaledMerkleizedBatch<F, H::Digest, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, K, V, H, C> UnmerkleizedTrait
    for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, V, H, C>;
    type Error = Error<F>;

    async fn merkleize(self) -> Result<Self::Merkleized, Error<F>> {
        let db = self.db.read().await;
        let merkleized = self.batch.merkleize(
            &*db,
            self.metadata,
            self.inactivity_floor.unwrap_or_default(),
        );
        Ok(ImmutableUnjournaledMerkleized {
            inner: merkleized,
            db: self.db.clone(),
        })
    }
}

impl<F, E, K, V, H, C> MerkleizedTrait
    for ImmutableUnjournaledMerkleized<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Option<V::Value>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, V, H, C>;

    fn root(&self) -> H::Digest {
        self.inner.root()
    }

    fn new_batch(&self) -> Self::Unmerkleized {
        ImmutableUnjournaledUnmerkleized {
            batch: self.inner.new_batch::<H>(),
            db: self.db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }
}

impl<F, E, K, V, H> ManagedDb<E> for fixed::UnjournaledDb<F, E, K, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, FixedEncoding<V>>: EncodeShared,
    Option<V>: CodecRead<Cfg = ()>,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, FixedEncoding<V>, H>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, FixedEncoding<V>, H>;
    type Error = Error<F>;
    type Config = fixed::UnjournaledConfig;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        ImmutableUnjournaledUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner)?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        sync::Target {
            root: self.root(),
            range: non_empty_range!(self.inactivity_floor_loc(), self.size()),
        }
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Unjournaled storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, K, V, H, C> ManagedDb<E> for variable::UnjournaledDb<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared,
    Option<V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, VariableEncoding<V>, H, C>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, VariableEncoding<V>, H, C>;
    type Error = Error<F>;
    type Config = variable::UnjournaledConfig<C>;
    type SyncTarget = sync::Target<F, H::Digest>;

    async fn init(context: E, config: Self::Config) -> Result<Self, Error<F>> {
        <Self>::init(context, config).await
    }

    async fn new_batch(db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
        let inner = db.read().await;
        ImmutableUnjournaledUnmerkleized {
            batch: inner.new_batch(),
            db: db.clone(),
            metadata: None,
            inactivity_floor: None,
        }
    }

    async fn finalize(&mut self, batch: Self::Merkleized) -> Result<(), Error<F>> {
        self.apply_batch(batch.inner)?;
        self.sync().await?;
        Ok(())
    }

    async fn sync_target(&self) -> Self::SyncTarget {
        sync::Target {
            root: self.root(),
            range: non_empty_range!(self.inactivity_floor_loc(), self.size()),
        }
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Unjournaled storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, K, V, H, R> StateSyncDb<E, R> for fixed::UnjournaledDb<F, E, K, V, H>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, FixedEncoding<V>>: EncodeShared,
    Option<V>: CodecRead<Cfg = ()>,
    R: Send,
{
    type SyncError = Error<F>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        _resolver: R,
        target: Self::SyncTarget,
        _tip_updates: mpsc::Receiver<Self::SyncTarget>,
        _finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
        _progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> Result<Self, Self::SyncError> {
        let db = <Self>::init(context, config).await?;
        if let Some(reached_target) = reached_target {
            let _ = reached_target.send(target).await;
        }
        Ok(db)
    }
}

impl<F, E, K, V, H, C, R> StateSyncDb<E, R> for variable::UnjournaledDb<F, E, K, V, H, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared,
    Option<V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    R: Send,
{
    type SyncError = Error<F>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        _resolver: R,
        target: Self::SyncTarget,
        _tip_updates: mpsc::Receiver<Self::SyncTarget>,
        _finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
        _progress_tx: Option<mpsc::Sender<SyncProgress>>,
    ) -> Result<Self, Self::SyncError> {
        let db = <Self>::init(context, config).await?;
        if let Some(reached_target) = reached_target {
            let _ = reached_target.send(target).await;
        }
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::merkle::{mmr, unjournaled::Config as MerkleConfig};

    type FixedDb = fixed::UnjournaledDb<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
    >;
    type VariableDb = variable::UnjournaledDb<
        mmr::Family,
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        (commonware_codec::RangeCfg<usize>, ()),
    >;

    fn fixed_config(suffix: &str) -> fixed::UnjournaledConfig {
        fixed::UnjournaledConfig {
            merkle: MerkleConfig {
                partition: format!("stateful-immutable-unjournaled-{suffix}"),
                thread_pool: None,
            },
            metadata_codec_config: (),
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    #[test]
    fn immutable_unjournaled_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, ()>();
        assert_state_sync_db::<VariableDb, ()>();
    }

    #[test]
    fn managed_db_finalize_commits_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("managed-db");
            let db = FixedDb::init(context.with_label("db"), config)
                .await
                .unwrap();
            let db = Arc::new(AsyncRwLock::new(db));
            let key = Sha256::hash(&[1]);
            let value = Sha256::hash(&[2]);
            let metadata = Sha256::hash(&[3]);

            let batch = <FixedDb as ManagedDb<_>>::new_batch(&db)
                .await
                .set(key, value)
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let mut guard = db.write().await;
                <FixedDb as ManagedDb<_>>::finalize(&mut *guard, merkleized)
                    .await
                    .unwrap();
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(metadata));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&*guard).await;
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.start(), mmr::Location::new(1));
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_rewinds_fixed_immutable_unjournaled_one_commit_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("rewind");
            let mut db = FixedDb::init(context.with_label("db"), config)
                .await
                .unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&db, Some(Sha256::hash(&[11])), floor);
            db.apply_batch(batch).unwrap();
            db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[3]), Sha256::hash(&[4]))
                .merkleize(&db, Some(Sha256::hash(&[22])), floor);
            db.apply_batch(batch).unwrap();
            db.sync().await.unwrap();
            let second_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;
            assert_ne!(second_target, first_target);

            <FixedDb as ManagedDb<_>>::rewind_to_target(&mut db, first_target.clone())
                .await
                .unwrap();

            let rewound_target = <FixedDb as ManagedDb<_>>::sync_target(&db).await;
            assert_eq!(rewound_target, first_target);
            assert_eq!(db.get_metadata(), Some(Sha256::hash(&[11])));
        });
    }
}

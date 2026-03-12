//! [`ManagedDb`] implementation for unjournaled QMDB
//! [`immutable`](commonware_storage::qmdb::immutable) databases.
//!
//! These compact databases retain only the current Merkle peaks, so the glue
//! adapters expose set and merkleization operations but no historical reads.

use crate::stateful::db::{
    ManagedDb, Merkleized as MerkleizedTrait, StateSyncDb, SyncEngineConfig,
    Unmerkleized as UnmerkleizedTrait,
};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::{
        any::value::{FixedEncoding, FixedValue, ValueEncoding, VariableEncoding, VariableValue},
        immutable::{
            fixed, variable, CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation,
        },
        operation::Key,
        sync::{self},
        Error,
    },
};
use commonware_utils::{channel::mpsc, sync::AsyncRwLock, Array};
use std::{ops::Deref, sync::Arc};

type ImmutableUnjournaledDbHandle<F, E, K, V, H, C, S> =
    Arc<AsyncRwLock<CompactDb<F, E, K, V, H, C, S>>>;

fn drain_latest_target<T>(tip_updates: &mut mpsc::Receiver<T>) -> Option<T> {
    let mut latest = None;
    loop {
        match tip_updates.try_recv() {
            Ok(update) => latest = Some(update),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                return latest;
            }
        }
    }
}

/// Wraps an unjournaled immutable batch before merkleization.
pub struct ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    batch: CompactUnmerkleizedBatch<F, H, K, V, S>,
    db: ImmutableUnjournaledDbHandle<F, E, K, V, H, C, S>,
    metadata: Option<V::Value>,
    inactivity_floor: Option<Location<F>>,
}

impl<F, E, K, V, H, S, C> Deref for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactUnmerkleizedBatch<F, H, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.batch
    }
}

impl<F, E, K, V, H, S, C> ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
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
pub struct ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C = ()>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    inner: Arc<CompactMerkleizedBatch<F, H::Digest, K, V, S>>,
    db: ImmutableUnjournaledDbHandle<F, E, K, V, H, C, S>,
}

impl<F, E, K, V, H, S, C> Deref for ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Target = CompactMerkleizedBatch<F, H::Digest, K, V, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<F, E, K, V, H, S, C> UnmerkleizedTrait
    for ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>;
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

impl<F, E, K, V, H, S, C> MerkleizedTrait for ImmutableUnjournaledMerkleized<F, E, K, V, H, S, C>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Digest = H::Digest;
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, V, H, S, C>;

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

impl<F, E, K, V, H, S> ManagedDb<E> for fixed::CompactDb<F, E, K, V, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, K, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, FixedEncoding<V>, H, S, ()>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, FixedEncoding<V>, H, S, ()>;
    type Error = Error<F>;
    type Config = fixed::CompactConfig<S>;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

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
        self.current_target()
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Compact storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, K, V, H, C, S> ManagedDb<E> for variable::CompactDb<F, E, K, V, H, C, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Unmerkleized = ImmutableUnjournaledUnmerkleized<F, E, K, VariableEncoding<V>, H, S, C>;
    type Merkleized = ImmutableUnjournaledMerkleized<F, E, K, VariableEncoding<V>, H, S, C>;
    type Error = Error<F>;
    type Config = variable::CompactConfig<C, S>;
    type SyncTarget = sync::compact::Target<F, H::Digest>;

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
        self.current_target()
    }

    async fn rewind_to_target(&mut self, target: Self::SyncTarget) -> Result<(), Error<F>> {
        // Compact storage only retains the previous logical commit range.
        self.rewind().await?;

        let rewound_target = self.sync_target().await;
        assert_eq!(
            rewound_target, target,
            "rewound database target mismatch after one-step rewind",
        );
        Ok(())
    }
}

impl<F, E, K, V, H, R, S> StateSyncDb<E, R> for fixed::CompactDb<F, E, K, V, H, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher + 'static,
    S: Strategy,
    Operation<F, K, FixedEncoding<V>>: EncodeShared + CodecRead<Cfg = ()>,
    R: sync::compact::Resolver<
        Family = F,
        Op = Operation<F, K, FixedEncoding<V>>,
        Digest = H::Digest,
    >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        mut target: Self::SyncTarget,
        mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        let mut attempt = 0u64;
        loop {
            let context = context.child("attempt").with_attribute("attempt", attempt);
            attempt += 1;
            let db = sync::compact::sync(sync::compact::Config::<Self, R> {
                context,
                resolver: resolver.clone(),
                target: target.clone(),
                db_config: config.clone(),
            })
            .await?;

            if let Some(update) = drain_latest_target(&mut tip_updates) {
                target = update;
                continue;
            }

            if let Some(reached_target) = reached_target.as_ref() {
                if reached_target.send(target.clone()).await.is_err() {
                    return Ok(db);
                }
            }

            let Some(finish) = finish.as_mut() else {
                return Ok(db);
            };
            select! {
                _ = finish.recv() => return Ok(db),
                update = tip_updates.recv() => {
                    let Some(update) = update else {
                        return Ok(db);
                    };
                    target = update;
                },
            }
        }
    }
}

impl<F, E, K, V, H, C, R, S> StateSyncDb<E, R> for variable::CompactDb<F, E, K, V, H, C, S>
where
    F: Family,
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher + 'static,
    Operation<F, K, VariableEncoding<V>>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
    R: sync::compact::Resolver<
        Family = F,
        Op = Operation<F, K, VariableEncoding<V>>,
        Digest = H::Digest,
    >,
{
    type SyncError = sync::Error<F, R::Error, H::Digest>;

    async fn sync_db(
        context: E,
        config: Self::Config,
        resolver: R,
        mut target: Self::SyncTarget,
        mut tip_updates: mpsc::Receiver<Self::SyncTarget>,
        mut finish: Option<mpsc::Receiver<()>>,
        reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
        _sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        let mut attempt = 0u64;
        loop {
            let context = context.child("attempt").with_attribute("attempt", attempt);
            attempt += 1;
            let db = sync::compact::sync(sync::compact::Config::<Self, R> {
                context,
                resolver: resolver.clone(),
                target: target.clone(),
                db_config: config.clone(),
            })
            .await?;

            if let Some(update) = drain_latest_target(&mut tip_updates) {
                target = update;
                continue;
            }

            if let Some(reached_target) = reached_target.as_ref() {
                if reached_target.send(target.clone()).await.is_err() {
                    return Ok(db);
                }
            }

            let Some(finish) = finish.as_mut() else {
                return Ok(db);
            };
            select! {
                _ = finish.recv() => return Ok(db),
                update = tip_updates.recv() => {
                    let Some(update) = update else {
                        return Ok(db);
                    };
                    target = update;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_storage::merkle::{compact::Config as MerkleConfig, mmr};
    use commonware_utils::{NZUsize, NZU64};

    type FixedDb = fixed::CompactDb<mmr::Family, deterministic::Context, Digest, Digest, Sha256>;
    type VariableDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        ((), (commonware_codec::RangeCfg<usize>, ())),
    >;

    fn fixed_config(suffix: &str) -> fixed::CompactConfig {
        fixed::CompactConfig {
            merkle: MerkleConfig {
                partition: format!("stateful-immutable-unjournaled-{suffix}"),
                strategy: Sequential,
            },
            commit_codec_config: (),
        }
    }

    const fn sync_config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: 1,
            max_outstanding_requests: 1,
            update_channel_size: NZUsize!(1),
            max_retained_roots: 0,
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
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_finalize_commits_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("managed-db");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
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
            assert_eq!(target.leaf_count, mmr::Location::new(3));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_immutable_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut source = FixedDb::init(context.child("source"), fixed_config("source"))
                .await
                .unwrap();
            let metadata = Sha256::hash(&[3]);
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::hash(&[2]))
                .merkleize(&source, Some(metadata), floor);
            source.apply_batch(batch).unwrap();
            source.sync().await.unwrap();

            let target = source.current_target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.child("target"),
                fixed_config("target"),
                Arc::new(source),
                target.clone(),
                update_rx,
                None,
                None,
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.current_target(), target);
            assert_eq!(synced.get_metadata(), Some(metadata));
        });
    }

    #[test]
    fn managed_db_rewinds_fixed_immutable_unjournaled_one_commit_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("rewind");
            let mut db = FixedDb::init(context.child("db"), config).await.unwrap();

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

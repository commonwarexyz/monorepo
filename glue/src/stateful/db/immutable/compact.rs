//! [`Qmdb`] implementations for compact
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.

use crate::stateful::db::qmdb::{Qmdb, Unmerkleized};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::ValueEncoding,
        immutable::{CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation},
        operation::Key,
        sync,
    },
};
use std::sync::Arc;

impl<F, E, K, V, H, C, S> Unmerkleized<CompactDb<F, E, K, V, H, C, S>>
where
    CompactDb<F, E, K, V, H, C, S>: Qmdb<Batch = CompactUnmerkleizedBatch<F, H, K, V, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

impl<F, E, K, V, H, C, S> Qmdb for CompactDb<F, E, K, V, H, C, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Batch = CompactUnmerkleizedBatch<F, H, K, V, S>;
    type MerkleizedBatch = CompactMerkleizedBatch<F, H::Digest, K, V, S>;
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
        self.prune(target.range.end()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{
        InitError, ManagedDb, Shared, StateSyncDb, Unmerkleized as _,
        tests::configs::{
            immutable::{compact::fixed_config, fixed_config as full_fixed_config},
            sync_config,
        },
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_storage::{
        merkle::mmr,
        qmdb::{immutable::fixed, sync::source},
        translator::TwoCap,
    };
    use commonware_utils::{NZU64, channel::mpsc, non_empty_range};
    use futures::pin_mut;
    use std::time::Duration;

    type FixedDb =
        fixed::CompactDb<mmr::Family, deterministic::Context, Digest, Digest, Sha256, Sequential>;

    type FullFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    #[derive(Clone)]
    struct SupersedingCompactSource {
        source: Arc<FullFixedDb>,
        stale_target: sync::Target<mmr::Family, Digest>,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl sync::Source for SupersedingCompactSource {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = fixed::Operation<mmr::Family, Digest, Digest>;
        type Error = <Arc<FullFixedDb> as sync::Source>::Error;

        async fn serve(&self, request: sync::Request<Self::Family>) -> source::Result<Self> {
            if request.size() == self.stale_target.range.end() {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            self.source.serve(request).await
        }
    }

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[&[1]]);
            let value = Sha256::hash(&[&[2]]);
            let metadata = Sha256::hash(&[&[3]]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .set(key, value)
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(metadata);
            let merkleized = batch.merkleize().await.unwrap();
            let expected_root = merkleized.root();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(metadata));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_apply_retains_each_immutable_bounded_initialization_target() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "apply-checkpoints");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_metadata(Sha256::hash(&[&[11]]));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            let first_target = sync::Target {
                root: first.root(),
                range: non_empty_range!(first.bounds().tip.size - 1, first.bounds().tip.size),
            };
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, first)
                .await
                .unwrap();
            slot.put(database);

            let second = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]))
                .with_metadata(Sha256::hash(&[&[22]]));
            let second = crate::stateful::db::Unmerkleized::merkleize(second)
                .await
                .unwrap();
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, second)
                .await
                .unwrap();
            let (database, sync) = <FixedDb as ManagedDb<_>>::finalize(database).await.unwrap();
            sync.await.expect("database sync failed");
            slot.put(database);
            drop(db);

            let database = <FixedDb as ManagedDb<_>>::init(
                context.child("reopen"),
                fixed_config(&context, "apply-checkpoints"),
                Some(first_target.clone()),
            )
            .await
            .unwrap();
            assert_eq!(
                <FixedDb as ManagedDb<_>>::sync_target(&database),
                first_target,
            );
        });
    }

    #[test]
    fn database_set_bounded_initialization_persists_aligned_immutable_target() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "aligned-bounded-init");
            let db = FixedDb::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_metadata(Sha256::hash(&[&[3]]));
            let batch = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            crate::stateful::db::DatabaseSet::apply(&db, batch).await;
            let target = crate::stateful::db::DatabaseSet::committed_targets(&db).await;
            crate::stateful::db::DatabaseSet::finalize(&db)
                .await
                .durable()
                .await;
            drop(db);
            let db = <Shared<FixedDb> as crate::stateful::db::DatabaseSet<_>>::init(
                context.child("aligned_cap"),
                config,
                Some(target.clone()),
            )
            .await;
            drop(db);

            let database = FixedDb::init(
                context.child("reopen"),
                fixed_config(&context, "aligned-bounded-init"),
                None,
            )
            .await
            .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&database), target,);
        });
    }

    #[test]
    fn state_sync_fetches_fixed_immutable_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = FixedDb::init(
                context.child("source"),
                fixed_config(&context, "source"),
                None,
            )
            .await
            .unwrap();
            let metadata = Sha256::hash(&[&[3]]);
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&source, Some(metadata), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();

            let target = source.target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <FixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.child("target"),
                fixed_config(&context, "target"),
                Arc::new(source),
                target.clone(),
                update_rx,
                None,
                None,
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(metadata));
        });
    }

    #[test]
    fn state_sync_reports_compact_progress() {
        deterministic::Runner::default().start(|context| async move {
            let source_context = context.child("source");
            let source_config = full_fixed_config(&source_context, "source");
            let source = FullFixedDb::init(source_context, source_config, None)
                .await
                .unwrap();
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&source, Some(Sha256::hash(&[&[3]])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let target = sync::Target {
                root: source.root(),
                range: non_empty_range!(source.bounds().end - 1, source.bounds().end),
            };

            // A larger target the source never serves. Its sync attempt
            // hangs so the test can observe the gauges while they diverge.
            let unservable_target = sync::Target {
                root: Sha256::hash(&[&[0xFF]]),
                range: non_empty_range!(target.range.end() + 1 - 1, target.range.end() + 1),
            };
            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let superseding_source = SupersedingCompactSource {
                source: Arc::new(source),
                stale_target: unservable_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let (_finish_tx, finish_rx) = mpsc::channel(1);
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let client_context = context.child("client");
            let client_config = fixed_config(&client_context, "client");
            let sync = <FixedDb as StateSyncDb<_, _>>::sync_db(
                client_context,
                client_config,
                superseding_source,
                target.clone(),
                update_rx,
                Some(finish_rx),
                Some(reached_tx),
                sync_config(),
            );
            pin_mut!(sync);

            select! {
                _ = sync.as_mut() => panic!("sync completed before explicit finish signal"),
                reached = reached_rx.recv() => assert_eq!(reached, Some(target.clone())),
            }

            let synced_size = *target.range.end();
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_sync_target_size {synced_size}")),
                "missing compact sync target gauge: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_sync_size {synced_size}")),
                "missing compact sync progress gauge: {encoded}"
            );

            // Supersede with the unservable target and wait for its fetch to
            // start. The target gauge advances while the synced gauge still
            // reports the previously reached target.
            update_tx.send(unservable_target.clone()).await.unwrap();
            select! {
                _ = sync.as_mut() => panic!("sync completed with an unservable target"),
                request = stale_request_rx.recv() => assert_eq!(request, Some(())),
            }

            let target_size_val = *unservable_target.range.end();
            let encoded = context.encode();
            assert!(
                encoded.contains(&format!("\nclient_sync_target_size {target_size_val}")),
                "target gauge should advance to the superseding target: {encoded}"
            );
            assert!(
                encoded.contains(&format!("\nclient_sync_size {synced_size}")),
                "synced gauge should still report the reached target: {encoded}"
            );
        });
    }

    #[test]
    fn state_sync_supersedes_in_flight_stale_compact_target() {
        deterministic::Runner::default().start(|context| async move {
            let source = FullFixedDb::init(
                context.child("source"),
                full_fixed_config(&context, "source"),
                None,
            )
            .await
            .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&source, Some(Sha256::hash(&[&[9]])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let stale_target = sync::Target {
                root: source.root(),
                range: non_empty_range!(source.bounds().end - 1, source.bounds().end),
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]))
                .merkleize(&source, Some(Sha256::hash(&[&[10]])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let latest_target = sync::Target {
                root: source.root(),
                range: non_empty_range!(source.bounds().end - 1, source.bounds().end),
            };

            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let superseding_source = SupersedingCompactSource {
                source: Arc::new(source),
                stale_target: stale_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let sync_handle = context.child("sync").spawn(move |context| async move {
                <FixedDb as StateSyncDb<_, _>>::sync_db(
                    context.child("target"),
                    fixed_config(&context, "supersede-target"),
                    superseding_source,
                    stale_target,
                    update_rx,
                    None,
                    None,
                    sync_config(),
                )
                .await
            });

            context
                .timeout(Duration::from_secs(1), async move {
                    stale_request_rx.recv().await.unwrap();
                })
                .await
                .expect("sync should request the stale target first");
            update_tx.send(latest_target.clone()).await.unwrap();

            let synced = context
                .timeout(Duration::from_secs(1), sync_handle)
                .await
                .expect("sync should switch to the latest target")
                .expect("spawned sync task should complete")
                .unwrap();

            assert_eq!(synced.target(), latest_target);
            assert_eq!(synced.get_metadata(), Some(Sha256::hash(&[&[10]])));
        });
    }

    #[test]
    fn managed_db_initializes_fixed_immutable_unjournaled_multiple_commit_ranges() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "bounded-init");
            let db = FixedDb::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&db, Some(Sha256::hash(&[&[11]])), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let mut db = db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db);

            // Add two ranges so reopening at the first target spans multiple commits.
            for i in [3u8, 5] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[i]]), Sha256::hash(&[&[i + 1]]))
                    .merkleize(&db, Some(Sha256::hash(&[&[i * 11]])), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            let third_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_ne!(third_target, first_target);

            drop(db);
            let db = <FixedDb as ManagedDb<_>>::init(
                context.child("cap"),
                config.clone(),
                Some(first_target.clone()),
            )
            .await
            .unwrap();

            let recovered_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(recovered_target, first_target);
            assert_eq!(db.get_metadata(), Some(Sha256::hash(&[&[11]])));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_immutable_unjournaled_bounded_initialization_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = FixedDb::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for i in [1u8, 3, 5] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[i]]), Sha256::hash(&[&[i + 1]]))
                    .merkleize(&db, Some(Sha256::hash(&[&[i * 11]])), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<FixedDb as ManagedDb<_>>::sync_target(&db));
            }

            assert_ne!(targets[0], targets[1]);

            // Pruning at the second target retains it but excludes the first.
            let db = <FixedDb as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            drop(db);
            let db = <FixedDb as ManagedDb<_>>::init(
                context.child("cap"),
                config.clone(),
                Some(targets[1].clone()),
            )
            .await
            .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), targets[1]);
            drop(db);
            assert!(matches!(
                <FixedDb as ManagedDb<_>>::init(
                    context.child("pruned_cap"),
                    config,
                    Some(targets[0].clone())
                )
                .await,
                Err(InitError::Database(Error::HistoricalFloorPruned(_)))
            ));
        });
    }
}

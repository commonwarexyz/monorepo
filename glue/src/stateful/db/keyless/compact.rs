//! [`Qmdb`] implementations for compact
//! [`qmdb::keyless`](commonware_storage::qmdb::keyless) databases.

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
        keyless::{CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation},
        sync,
    },
};
use std::sync::Arc;

impl<F, E, V, H, C, S> Unmerkleized<CompactDb<F, E, V, H, C, S>>
where
    CompactDb<F, E, V, H, C, S>: Qmdb<Batch = CompactUnmerkleizedBatch<F, H, V, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    /// Append a value to the speculative batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

impl<F, E, V, H, C, S> Qmdb for CompactDb<F, E, V, H, C, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Batch = CompactUnmerkleizedBatch<F, H, V, S>;
    type MerkleizedBatch = CompactMerkleizedBatch<F, H::Digest, V, S>;
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

    async fn apply(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch).await?;
        Ok(db)
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &sync::Target<F, H::Digest>) -> Result<Self, Error<F>> {
        self.prune(target.range.end()).await
    }

    async fn rewind(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{
        ManagedDb, Shared, StateSyncDb, SyncSession, Unmerkleized as _,
        tests::configs::{
            keyless::{compact_fixed_config, fixed_config},
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
        qmdb::keyless::{self as storage_keyless, fixed},
    };
    use commonware_utils::{NZU64, channel::mpsc, non_empty_range, sequence::U64};
    use futures::pin_mut;
    use std::time::Duration;

    type CompactFixedDb =
        fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type FixedDb =
        storage_keyless::fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;

    #[derive(Clone)]
    struct SupersedingCompactSource {
        source: Arc<CompactFixedDb>,
        stale_target: sync::Target<mmr::Family, Digest>,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl sync::Source for SupersedingCompactSource {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = storage_keyless::fixed::Operation<mmr::Family, U64>;
        type Error = <Arc<CompactFixedDb> as sync::Source>::Error;

        async fn serve(
            &self,
            request: sync::Request<Self::Family>,
        ) -> Result<
            (
                sync::Response<Self::Family, Self::Op, Self::Digest>,
                sync::FeedbackTx,
            ),
            Self::Error,
        > {
            if request.size() == self.stale_target.range.end() {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            self.source.serve(request).await
        }
    }

    async fn populated_fixed_db(context: deterministic::Context, suffix: &str) -> CompactFixedDb {
        let config = compact_fixed_config(&context, suffix);
        let source = CompactFixedDb::init(context.child("db"), config)
            .await
            .unwrap();
        let floor = source.inactivity_floor_loc();
        let batch = source
            .new_batch()
            .append(U64::new(7))
            .merkleize(&source, Some(U64::new(9)), floor)
            .await;
        let (source, _) = source.apply_batch(batch).await.unwrap();
        source.sync().await.unwrap()
    }

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_keyless_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_fixed_config(&context, "managed-db");
            let db = CompactFixedDb::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = batch.merkleize().await.unwrap();
            let expected_root = merkleized.root();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(U64::new(9)));

            let target = <CompactFixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_keyless_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = populated_fixed_db(context.child("source"), "source").await;

            let target = source.target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <CompactFixedDb as StateSyncDb<_, Arc<CompactFixedDb>>>::sync_db(
                context.child("target"),
                compact_fixed_config(&context, "target"),
                Arc::new(source),
                SyncSession {
                    target: target.clone(),
                    tip_updates: update_rx,
                    finish: None,
                    reached_target: None,
                },
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(U64::new(9)));
        });
    }

    #[test]
    fn state_sync_drains_queued_target_before_reporting_reached() {
        deterministic::Runner::default().start(|context| async move {
            let source = FixedDb::init(context.child("source"), fixed_config(&context, "source"))
                .await
                .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let first_target = sync::Target {
                root: source.root(),
                range: non_empty_range!(source.bounds().end - 1, source.bounds().end),
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(8))
                .merkleize(&source, Some(U64::new(10)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let second_target = sync::Target {
                root: source.root(),
                range: non_empty_range!(source.bounds().end - 1, source.bounds().end),
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            update_tx.send(second_target.clone()).await.unwrap();
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let synced = <CompactFixedDb as StateSyncDb<_, Arc<FixedDb>>>::sync_db(
                context.child("target"),
                compact_fixed_config(&context, "target"),
                Arc::new(source),
                SyncSession {
                    target: first_target,
                    tip_updates: update_rx,
                    finish: None,
                    reached_target: Some(reached_tx),
                },
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(reached_rx.recv().await, Some(second_target.clone()));
            assert_eq!(synced.target(), second_target);
            assert_eq!(synced.get_metadata(), Some(U64::new(10)));
        });
    }

    #[test]
    fn state_sync_reports_compact_progress() {
        deterministic::Runner::default().start(|context| async move {
            let source_context = context.child("source");
            let source_config = compact_fixed_config(&source_context, "source");
            let source = CompactFixedDb::init(source_context, source_config)
                .await
                .unwrap();
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let target = source.target();

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
            let client_config = compact_fixed_config(&client_context, "client");
            let sync = <CompactFixedDb as StateSyncDb<_, _>>::sync_db(
                client_context,
                client_config,
                superseding_source,
                SyncSession {
                    target: target.clone(),
                    tip_updates: update_rx,
                    finish: Some(finish_rx),
                    reached_target: Some(reached_tx),
                },
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
            let source = CompactFixedDb::init(
                context.child("source"),
                compact_fixed_config(&context, "supersede-source"),
            )
            .await
            .unwrap();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(7))
                .merkleize(&source, Some(U64::new(9)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let stale_target = source.target();

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .append(U64::new(8))
                .merkleize(&source, Some(U64::new(10)), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let latest_target = source.target();

            let (stale_request_tx, mut stale_request_rx) = mpsc::channel(1);
            let superseding_source = SupersedingCompactSource {
                source: Arc::new(source),
                stale_target: stale_target.clone(),
                stale_request_tx,
            };

            let (update_tx, update_rx) = mpsc::channel(1);
            let sync_handle = context.child("sync").spawn(move |context| async move {
                <CompactFixedDb as StateSyncDb<_, _>>::sync_db(
                    context.child("target"),
                    compact_fixed_config(&context, "supersede-target"),
                    superseding_source,
                    SyncSession {
                        target: stale_target,
                        tip_updates: update_rx,
                        finish: None,
                        reached_target: None,
                    },
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
            assert_eq!(synced.get_metadata(), Some(U64::new(10)));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_keyless_unjournaled_rewind_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = compact_fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = CompactFixedDb::init(context.child("db"), config)
                .await
                .unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for i in [1u64, 2, 3] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .append(U64::new(i))
                    .merkleize(&db, Some(U64::new(i * 11)), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<CompactFixedDb as ManagedDb<_>>::sync_target(&db));
            }

            assert_ne!(targets[0], targets[1]);

            // Prune to the second target: the first is no longer a rewind target, but the
            // second still is.
            let db = <CompactFixedDb as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            let db = <CompactFixedDb as ManagedDb<_>>::rewind_to_target(db, targets[1].clone())
                .await
                .unwrap();
            assert_eq!(
                <CompactFixedDb as ManagedDb<_>>::sync_target(&db),
                targets[1]
            );
            assert_eq!(db.get_metadata(), Some(U64::new(22)));
            assert!(matches!(
                db.rewind(targets[0].range.end()).await,
                Err(Error::Merkle(
                    commonware_storage::merkle::Error::RewindBeyondHistory
                ))
            ));
        });
    }
}

//! Immutable compact adapter: batches set keys.
//!
//! See [`crate::stateful::db::compact`] for the shared
//! [`ManagedDb`](crate::stateful::db::ManagedDb) implementation.

use crate::stateful::db::compact::CompactUnmerkleized;
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::{
    Context,
    merkle::Family,
    qmdb::{any::value::ValueEncoding, immutable::Operation, operation::Key},
};

impl<F, E, K, V, H, S> CompactUnmerkleized<F, E, Operation<F, K, V>, H, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: CodecShared,
{
    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{ManagedDb, Merkleized as _, Shared, StateSyncDb, SyncEngineConfig};
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{full::Config as MerkleConfig, mmr},
        qmdb::{
            Error,
            immutable::{fixed, variable},
            sync,
        },
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc};
    use futures::pin_mut;
    use std::{sync::Arc, time::Duration};

    type FixedDb =
        fixed::CompactDb<mmr::Family, deterministic::Context, Digest, Digest, Sha256, Sequential>;
    type FullFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;
    type VariableDb = variable::CompactDb<
        mmr::Family,
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        Sequential,
    >;

    fn fixed_config(context: &impl BufferPooler, suffix: &str) -> fixed::CompactConfig<Sequential> {
        fixed::CompactConfig {
            strategy: Sequential,
            witness: commonware_storage::journal::contiguous::variable::Config {
                partition: format!("stateful-immutable-unjournaled-{suffix}-witness"),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
                write_buffer: NZUsize!(1024),
            },
        }
    }

    fn full_fixed_config(
        context: &impl BufferPooler,
        suffix: &str,
    ) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        fixed::Config {
            merkle_config: MerkleConfig {
                journal_partition: format!("stateful-immutable-full-journal-{suffix}"),
                metadata_partition: format!("stateful-immutable-full-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-immutable-full-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        }
    }

    const fn sync_config() -> SyncEngineConfig {
        SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: NZU64!(1),
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

    #[derive(Clone)]
    struct SupersedingCompactSource {
        source: Arc<FullFixedDb>,
        stale_target: sync::CompactTarget<mmr::Family, Digest>,
        stale_request_tx: mpsc::Sender<()>,
    }

    impl sync::Source for SupersedingCompactSource {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = fixed::Operation<mmr::Family, Digest, Digest>;
        type Error = <Arc<FullFixedDb> as sync::Source>::Error;

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
            if request.size() == self.stale_target.size {
                let _ = self.stale_request_tx.send(()).await;
                return futures::future::pending().await;
            }

            self.source.serve(request).await
        }
    }

    #[test]
    fn immutable_unjournaled_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
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
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();
            let expected_root = merkleized.root();

            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let (database, sync) = <FixedDb as ManagedDb<_>>::finalize(database).await.unwrap();
                slot.put(database);
                sync.await.expect("database sync failed");
            }

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(metadata));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.size, mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_apply_retains_each_immutable_rewind_target() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "apply-checkpoints");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .with_metadata(Sha256::hash(&[&[11]]));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            let first_target = sync::CompactTarget {
                root: first.root(),
                size: first.bounds().tip.size,
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

            let database = FixedDb::init(
                context.child("reopen"),
                fixed_config(&context, "apply-checkpoints"),
            )
            .await
            .unwrap();
            let database =
                <FixedDb as ManagedDb<_>>::rewind_to_target(database, first_target.clone())
                    .await
                    .unwrap();
            assert_eq!(
                <FixedDb as ManagedDb<_>>::sync_target(&database),
                first_target,
            );
        });
    }

    #[test]
    fn database_set_rewind_persists_aligned_immutable_target() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "aligned-rewind");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
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
            crate::stateful::db::DatabaseSet::rewind_to_targets(&db, target.clone()).await;
            drop(db);

            let database = FixedDb::init(
                context.child("reopen"),
                fixed_config(&context, "aligned-rewind"),
            )
            .await
            .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&database), target,);
        });
    }

    #[test]
    fn state_sync_fetches_fixed_immutable_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = FixedDb::init(context.child("source"), fixed_config(&context, "source"))
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
            let source = FullFixedDb::init(source_context, source_config)
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
            let target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            // A larger target the source never serves. Its sync attempt
            // hangs so the test can observe the gauges while they diverge.
            let unservable_target = sync::CompactTarget {
                root: Sha256::hash(&[&[0xFF]]),
                size: target.size + 1,
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

            let synced_size = *target.size;
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

            let target_size_val = *unservable_target.size;
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
            let stale_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
            };

            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[3]]), Sha256::hash(&[&[4]]))
                .merkleize(&source, Some(Sha256::hash(&[&[10]])), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();
            let latest_target = sync::CompactTarget {
                root: source.root(),
                size: source.bounds().end,
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
    fn managed_db_rewinds_fixed_immutable_unjournaled_multiple_commit_ranges() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "rewind");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();

            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&db, Some(Sha256::hash(&[&[11]])), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let mut db = db.sync().await.unwrap();
            let first_target = <FixedDb as ManagedDb<_>>::sync_target(&db);

            // Commit two more ranges so the rewind below spans multiple commits.
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

            let db = <FixedDb as ManagedDb<_>>::rewind_to_target(db, first_target.clone())
                .await
                .unwrap();

            let rewound_target = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(rewound_target, first_target);
            assert_eq!(db.get_metadata(), Some(Sha256::hash(&[&[11]])));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_immutable_unjournaled_rewind_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = FixedDb::init(context.child("db"), config).await.unwrap();

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

            // Prune to the second target: the first is no longer a rewind target, but the
            // second still is.
            let db = <FixedDb as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            let db = <FixedDb as ManagedDb<_>>::rewind_to_target(db, targets[1].clone())
                .await
                .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), targets[1]);
            assert!(matches!(
                db.rewind(targets[0].size).await,
                Err(Error::Merkle(
                    commonware_storage::merkle::Error::RewindBeyondHistory
                ))
            ));
        });
    }
}

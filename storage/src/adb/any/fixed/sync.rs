use crate::{
    // TODO(https://github.com/commonwarexyz/monorepo/issues/1873): support any::fixed::ordered
    adb::{self, any::fixed::unordered::Any, operation::Fixed},
    index::Unordered as Index,
    journal::fixed,
    mmr::{Location, Position, StandardHasher},
    translator::Translator,
};
use commonware_codec::{CodecFixed, Encode as _};
use commonware_cryptography::Hasher;
use commonware_runtime::{buffer::Append, Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, marker::PhantomData, ops::Range};
use tracing::debug;

impl<E, K, V, H, T> adb::sync::Database for Any<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: CodecFixed<Cfg = ()> + Send + Sync + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = Fixed<K, V>;
    type Journal = fixed::Journal<E, Fixed<K, V>>;
    type Hasher = H;
    type Config = adb::any::fixed::Config<T>;
    type Digest = H::Digest;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, adb::Error> {
        let journal_config = fixed::Config {
            partition: config.log_journal_partition.clone(),
            items_per_blob: config.log_items_per_blob,
            write_buffer: config.log_write_buffer,
            buffer_pool: config.buffer_pool.clone(),
        };

        init_journal(
            context.with_label("log"),
            journal_config,
            *range.start..*range.end,
        )
        .await
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, adb::Error> {
        let mut mmr = crate::mmr::journaled::Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: crate::mmr::journaled::Config {
                    journal_partition: db_config.mmr_journal_partition,
                    metadata_partition: db_config.mmr_metadata_partition,
                    items_per_blob: db_config.mmr_items_per_blob,
                    write_buffer: db_config.mmr_write_buffer,
                    thread_pool: db_config.thread_pool.clone(),
                    buffer_pool: db_config.buffer_pool.clone(),
                },
                // The last node of an MMR with `range.end` leaves is at the position
                // right before where the next leaf (at location `range.end`) goes.
                range: Position::try_from(range.start).unwrap()
                    ..Position::try_from(range.end + 1).unwrap(),
                pinned_nodes,
            },
        )
        .await?;

        // Apply the missing operations from the log to the MMR.
        let mut hasher = StandardHasher::<H>::new();
        let log_size = log.size().await?;
        for i in *mmr.leaves()..log_size {
            let op = log.read(i).await?;
            mmr.add_batched(&mut hasher, &op.encode()).await?;
            if i % apply_batch_size as u64 == 0 {
                // Periodically sync the MMR to avoid memory bloat.
                // Since the first value i takes may not be a multiple of `apply_batch_size`,
                // the first sync may occur before `apply_batch_size` operations are applied.
                // This is fine.
                mmr.sync(&mut hasher).await?;
            }
        }
        mmr.sync(&mut hasher).await?;

        // Build the snapshot from the log.
        let mut snapshot =
            Index::init(context.with_label("snapshot"), db_config.translator.clone());
        Any::<E, K, V, H, T>::build_snapshot_from_log(range.start, &log, &mut snapshot, |_, _| {})
            .await?;

        let mut db = Any {
            mmr,
            log,
            inactivity_floor_loc: range.start,
            snapshot,
            steps: 0,
            hasher: StandardHasher::<H>::new(),
        };
        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        Any::root(self, &mut StandardHasher::<H>::new())
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, adb::Error> {
        let size = journal.size().await?;

        if size <= range.start {
            // Create a new journal with the new bounds
            journal.destroy().await?;
            Self::create_journal(context, config, range).await
        } else {
            // Just prune to the lower bound
            journal.prune(*range.start).await?;
            Ok(journal)
        }
    }
}

/// Initialize a [fixed::Journal] for synchronization, reusing existing data if possible.
///
/// Handles three sync scenarios based on existing journal data vs. the given sync boundaries.
///
/// 1. **Fresh Start**: existing_size ≤ range.start
///    - Deletes existing data (if any)
///    - Creates new [fixed::Journal] pruned to `range.start` and size `range.start`
///
/// 2. **Prune and Reuse**: range.start < existing_size ≤ range.end
///    - Prunes the journal to `range.start`
///    - Reuses existing journal data overlapping with the sync range
///
/// 3. **Unexpected Data**: existing_size > range.end
///    - Returns [adb::Error::UnexpectedData]
///
/// # Invariants
///
/// The returned [fixed::Journal] has size in the given range.
pub(crate) async fn init_journal<E: Storage + Metrics, A: CodecFixed<Cfg = ()>>(
    context: E,
    cfg: fixed::Config,
    range: Range<u64>,
) -> Result<fixed::Journal<E, A>, adb::Error> {
    assert!(!range.is_empty(), "range must not be empty");

    let mut journal =
        fixed::Journal::<E, A>::init(context.with_label("journal"), cfg.clone()).await?;
    let journal_size = journal.size().await?;
    let journal = if journal_size <= range.start {
        debug!(
            journal_size,
            range.start, "Existing journal data is stale, re-initializing in pruned state"
        );
        journal.destroy().await?;
        init_journal_at_size(context, cfg, range.start).await?
    } else if journal_size <= range.end {
        debug!(
            journal_size,
            range.start,
            range.end,
            "Existing journal data within sync range, pruning to lower bound"
        );
        journal.prune(range.start).await?;
        journal
    } else {
        return Err(adb::Error::UnexpectedData(Location::new_unchecked(
            journal_size,
        )));
    };
    let journal_size = journal.size().await?;
    assert!(journal_size <= range.end);
    assert!(journal_size >= range.start);
    Ok(journal)
}

/// Initialize a new [fixed::Journal] instance in a pruned state at a given size.
///
/// # Arguments
/// * `context` - The storage context
/// * `cfg` - Configuration for the journal
/// * `size` - The number of operations that have been pruned.
///
/// # Behavior
/// - Creates only the tail blob at the index that would contain the operation at `size`
/// - Sets the tail blob size to represent the "leftover" operations within that blob.
/// - The [fixed::Journal] is not `sync`ed before being returned.
///
/// # Invariants
/// - The directory given by `cfg.partition` is empty.
///
/// For example, if `items_per_blob = 10` and `size = 25`:
/// - Tail blob index would be 25 / 10 = 2 (third blob, 0-indexed)
/// - Tail blob size would be (25 % 10) * CHUNK_SIZE = 5 * CHUNK_SIZE
/// - Tail blob is filled with dummy data up to its size -- this shouldn't be read.
/// - No blobs are created for indices 0 and 1 (the pruned range)
/// - Reading from positions 0-19 will return `ItemPruned` since those blobs don't exist
/// - This represents a journal that had operations 0-24, with operations 0-19 pruned,
///   leaving operations 20-24 in tail blob 2.
pub(crate) async fn init_journal_at_size<E: Storage + Metrics, A: CodecFixed<Cfg = ()>>(
    context: E,
    cfg: fixed::Config,
    size: u64,
) -> Result<fixed::Journal<E, A>, crate::journal::Error> {
    // Calculate the tail blob index and number of items in the tail
    let tail_index = size / cfg.items_per_blob;
    let tail_items = size % cfg.items_per_blob;
    let tail_size = tail_items * fixed::Journal::<E, A>::CHUNK_SIZE_U64;

    debug!(
        size,
        tail_index, tail_items, tail_size, "Initializing fresh journal at size"
    );

    // Create the tail blob with the correct size to reflect the position
    let (tail_blob, tail_actual_size) = context
        .open(&cfg.partition, &tail_index.to_be_bytes())
        .await?;
    assert_eq!(
        tail_actual_size, 0,
        "Expected empty blob for fresh initialization"
    );

    let tail = Append::new(tail_blob, 0, cfg.write_buffer, cfg.buffer_pool.clone()).await?;
    if tail_items > 0 {
        tail.resize(tail_size).await?;
    }

    // Initialize metrics
    let tracked = Gauge::default();
    tracked.set(tail_index as i64 + 1);
    let synced = Counter::default();
    let pruned = Counter::default();
    context.register("tracked", "Number of blobs", tracked.clone());
    context.register("synced", "Number of syncs", synced.clone());
    context.register("pruned", "Number of blobs pruned", pruned.clone());

    Ok(fixed::Journal::<E, A> {
        context,
        cfg,
        blobs: BTreeMap::new(),
        tail,
        tail_index,
        tracked,
        synced,
        pruned,
        _array: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::{
            self,
            any::fixed::unordered::{
                test::{
                    any_db_config, apply_ops, create_test_config, create_test_db, create_test_ops,
                    AnyTest,
                },
                Any,
            },
            operation::{Fixed, FixedOperation as _},
            sync::{
                self,
                engine::{Config, NextStep},
                resolver::tests::FailResolver,
                Engine, Target,
            },
        },
        journal::{self, fixed},
        mmr::iterator::nodes_to_pin,
        translator::TwoCap,
    };
    use commonware_cryptography::{
        sha256::{self, Digest},
        Digest as _, Hasher, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _, RwLock,
    };
    use commonware_utils::{NZUsize, NZU64};
    use futures::{channel::mpsc, future::join_all, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroU64,
        sync::Arc,
    };
    use test_case::test_case;

    // Janky sizes to test boundary conditions.
    const PAGE_SIZE: usize = 99;
    const PAGE_CACHE_SIZE: usize = 3;

    fn test_hasher() -> StandardHasher<Sha256> {
        StandardHasher::<Sha256>::new()
    }

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(1000, NZU64!(1); "db with batch size 1")]
    #[test_case(1000, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(1000, NZU64!(999); "db size not evenly divided by batch size; different batch size")]
    #[test_case(1000, NZU64!(100); "db size divided by batch size")]
    #[test_case(1000, NZU64!(1000); "db size == batch size")]
    #[test_case(1000, NZU64!(1001); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            target_db
                .prune(target_db.inactivity_floor_loc)
                .await
                .unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound = target_db.inactivity_floor_loc;

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &target_db_ops {
                match op {
                    Fixed::Update(key, _) => {
                        if let Some((value, loc)) = target_db.get_key_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Fixed::Delete(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    Fixed::CommitFloor(_) => {
                        // Ignore
                    }
                }
            }

            let db_config = create_test_config(context.next_u64());

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    range: lower_bound..target_op_count,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let mut got_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify that the synced database matches the target state
            for (key, &(value, loc)) in &expected_kvs {
                let synced_opt = got_db.get_key_loc(key).await.unwrap();
                assert_eq!(synced_opt, Some((value, loc)));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.get_key_loc(key).await.unwrap().is_none(),);
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                new_ops.push(Fixed::Update(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, new_ops.clone()).await;
            apply_ops(&mut *target_db.write().await, new_ops).await;
            got_db.commit().await.unwrap();
            target_db.write().await.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db.write().await.root(&mut hasher);
            assert_eq!(got_db.root(&mut hasher), final_target_root);

            // Capture the database state before closing
            let final_synced_op_count = got_db.op_count();
            let final_synced_log_size = got_db.log.size().await.unwrap();
            let final_synced_inactivity_floor = got_db.inactivity_floor_loc;
            let final_synced_root = got_db.root(&mut hasher);

            // Close the database
            got_db.close().await.unwrap();

            // Reopen the database using the same configuration and verify the state is unchanged
            let reopened_db = AnyTest::init(context, db_config).await.unwrap();

            // Compare state against the database state before closing
            assert_eq!(reopened_db.op_count(), final_synced_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                final_synced_inactivity_floor
            );
            assert_eq!(reopened_db.log.size().await.unwrap(), final_synced_log_size);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                final_synced_inactivity_floor,
            );
            assert_eq!(reopened_db.root(&mut hasher), final_synced_root);

            // Verify that the original key-value pairs are still correct
            for (key, &(value, _loc)) in &expected_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap();
                assert_eq!(reopened_value, Some(value));
            }

            // Verify all new key-value pairs are still correct
            for (key, &value) in &new_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap().unwrap();
                assert_eq!(reopened_value, value);
            }

            // Verify that deleted keys are still absent
            for key in &deleted_keys {
                assert!(reopened_db.get(key).await.unwrap().is_none());
            }

            // Cleanup
            reopened_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that invalid bounds are rejected
    #[test]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let db_config = create_test_config(context.next_u64());
            let config = Config {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: sha256::Digest::from([1u8; 32]),
                    range: Location::new_unchecked(31)..Location::new_unchecked(30), // Invalid range: start > end
                },
                context,
                resolver: Arc::new(commonware_runtime::RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };

            let result: Result<AnyTest, _> = sync::sync(config).await;
            match result {
                Err(sync::Error::Engine(sync::EngineError::InvalidTarget {
                    lower_bound_pos,
                    upper_bound_pos,
                })) => {
                    assert_eq!(lower_bound_pos, Location::new_unchecked(31));
                    assert_eq!(upper_bound_pos, Location::new_unchecked(30));
                }
                _ => panic!("Expected InvalidTarget error"),
            }
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[0..TARGET_DB_OPS - 1].to_vec()).await;
            target_db.commit().await.unwrap();

            let mut hasher = test_hasher();
            let upper_bound = target_db.op_count();
            let root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            apply_ops(&mut target_db, vec![final_op.clone()]).await;
            target_db.commit().await.unwrap();

            // Start of the sync range is after the inactivity floor
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                context,
                resolver: Arc::new(RwLock::new(target_db)),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };

            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the correct range of operations
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound);
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound);
            assert_eq!(synced_db.op_count(), upper_bound);

            // Verify the final root digest matches our target
            assert_eq!(synced_db.root(&mut hasher), root);

            // Verify the synced database doesn't have any operations beyond the sync range.
            assert_eq!(synced_db.get(final_op.key().unwrap()).await.unwrap(), None);

            synced_db.destroy().await.unwrap();
        });
    }

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let original_ops = create_test_ops(ORIGINAL_DB_OPS);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(1337);
            let mut sync_db = AnyTest::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, original_ops.clone()).await;
            apply_ops(&mut sync_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            let original_db_op_count = target_db.op_count();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            apply_ops(&mut target_db, last_op.clone()).await;
            target_db.commit().await.unwrap();
            let mut hasher = test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count();

            // Reopen the sync database and sync it to the target database
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound);
            assert_eq!(
                sync_db.inactivity_floor_loc,
                target_db.read().await.inactivity_floor_loc
            );
            assert_eq!(sync_db.inactivity_floor_loc, lower_bound);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.read().await.log.size().await.unwrap()
            );
            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify that the operations in the overlapping range are present and correct
            for i in *lower_bound..*original_db_op_count {
                let expected_op = target_db.read().await.log.read(i).await.unwrap();
                let synced_op = sync_db.log.read(i).await.unwrap();
                assert_eq!(expected_op, synced_op);
            }

            for target_op in &original_ops {
                if let Some(key) = target_op.key() {
                    let target_value = target_db.read().await.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }
            // Verify the last operation is present
            let last_key = last_op[0].key().unwrap();
            let last_value = *last_op[0].value().unwrap();
            assert_eq!(sync_db.get(last_key).await.unwrap(), Some(last_value));

            sync_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_ops = create_test_ops(NUM_OPS);

            // Create two databases
            let target_config = create_test_config(context.next_u64());
            let mut target_db = AnyTest::init(context.clone(), target_config).await.unwrap();
            let sync_config = create_test_config(context.next_u64());
            let mut sync_db = AnyTest::init(context.clone(), sync_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, target_ops.clone()).await;
            apply_ops(&mut sync_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            target_db
                .prune(target_db.inactivity_floor_loc)
                .await
                .unwrap();
            sync_db.prune(sync_db.inactivity_floor_loc).await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Reopen sync_db
            let mut hasher = test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count();

            // sync_db should never ask the resolver for operations
            // because it is already complete. Use a resolver that always fails
            // to ensure that it's not being used.
            let resolver = FailResolver::<sha256::Digest, sha256::Digest, sha256::Digest>::new();
            let config = Config {
                db_config: sync_config, // Use same config to access same partitions
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                context: context.clone(),
                resolver,
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let sync_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound);
            assert_eq!(sync_db.op_count(), target_db.op_count());
            assert_eq!(sync_db.inactivity_floor_loc, lower_bound);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.log.size().await.unwrap()
            );

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify state matches for sample operations
            for target_op in &target_ops {
                if let Some(key) = target_op.key() {
                    let target_value = target_db.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }

            sync_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that the client fails to sync if the lower bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased lower bound
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_lower_bound.checked_sub(1).unwrap()
                        ..initial_upper_bound.checked_add(1).unwrap(),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync if the upper bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with decreased upper bound
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound.checked_sub(1).unwrap(),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client succeeds when bounds are updated
    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root(&mut hasher);

            // Apply more operations to the target database
            let more_ops = create_test_ops(1);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture final target state
            let mut hasher = test_hasher();
            let final_lower_bound = target_db.inactivity_floor_loc;
            let final_upper_bound = target_db.op_count();
            let final_root = target_db.root(&mut hasher);

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
            };

            // Send target update with increased bounds
            update_sender
                .send(Target {
                    root: final_root,
                    range: final_lower_bound..final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);
            assert_eq!(synced_db.op_count(), final_upper_bound);
            assert_eq!(synced_db.inactivity_floor_loc, final_lower_bound);
            assert_eq!(synced_db.inactivity_floor_loc, final_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync with invalid bounds (lower > upper)
    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: initial_lower_bound..initial_upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };
            let client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();

            // Send target update with invalid range (start > end)
            update_sender
                .send(Target {
                    root: initial_root,
                    range: initial_upper_bound..initial_lower_bound,
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(sync::EngineError::InvalidTarget { .. }))
            ));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that target updates can be sent even after the client is done
    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count();
            let root = target_db.root(&mut hasher);

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(20),
                target: Target {
                    root,
                    range: lower_bound..upper_bound,
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
            };

            // Complete the sync
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Attempt to apply a target update after sync is complete to verify
            // we don't panic
            let _ = update_sender
                .send(Target {
                    // Dummy target update
                    root: sha256::Digest::from([2u8; 32]),
                    range: lower_bound + 1..upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), root);
            assert_eq!(synced_db.op_count(), upper_bound);
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client can handle target updates during sync execution
    #[test_case(1, 1)]
    #[test_case(1, 2)]
    #[test_case(1, 100)]
    #[test_case(2, 1)]
    #[test_case(2, 2)]
    #[test_case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[test_case(20, 10)]
    #[test_case(100, 1)]
    #[test_case(100, 2)]
    #[test_case(100, 100)]
    #[test_case(100, 1000)]
    #[test_traced("WARN")]
    fn test_target_update_during_sync(initial_ops: usize, additional_ops: usize) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database with initial operations
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(initial_ops);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count();
            let initial_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial target and small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            // Step the client to process a batch
            let client = {
                let config = Config {
                    context: context.clone(),
                    db_config: create_test_config(context.next_u64()),
                    target: Target {
                        root: initial_root,
                        range: initial_lower_bound..initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_rx: Some(update_receiver),
                };
                let mut client: Engine<AnyTest, _> = Engine::new(config).await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal().size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Modify the target database by adding more operations
            let additional_ops = create_test_ops(additional_ops);
            let new_root = {
                let mut db = target_db.write().await;
                apply_ops(&mut db, additional_ops).await;
                db.commit().await.unwrap();

                // Capture new target state
                let mut hasher = test_hasher();
                let new_lower_bound = db.inactivity_floor_loc;
                let new_upper_bound = db.op_count();
                let new_root = db.root(&mut hasher);

                // Send target update with new target
                update_sender
                    .send(Target {
                        root: new_root,
                        range: new_lower_bound..new_upper_bound,
                    })
                    .await
                    .unwrap();

                new_root
            };

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), new_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(
                    synced_db.inactivity_floor_loc,
                    target_db.inactivity_floor_loc
                );
                assert_eq!(
                    synced_db.inactivity_floor_loc,
                    target_db.inactivity_floor_loc
                );
                assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));
            }

            // Verify the expected operations are present in the synced database.
            for i in *synced_db.inactivity_floor_loc..*synced_db.op_count() {
                let got = synced_db.log.read(i).await.unwrap();
                let expected = target_db.log.read(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in *synced_db.mmr.oldest_retained_pos().unwrap()..*synced_db.mmr.size() {
                let i = Position::new(i);
                let got = synced_db.mmr.get_node(i).await.unwrap();
                let expected = target_db.mmr.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test demonstrating that a synced database can be reopened and retain its state.
    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count();

            // Perform sync
            let db_config = create_test_config(42);
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    range: lower_bound..upper_bound,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
            };
            let synced_db: AnyTest = sync::sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), target_root);

            // Save state before closing
            let expected_root = synced_db.root(&mut hasher);
            let expected_op_count = synced_db.op_count();
            let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc;

            // Close the database
            synced_db.close().await.unwrap();

            // Re-open the database
            let reopened_db = AnyTest::init(context_clone, db_config).await.unwrap();

            // Verify the state is unchanged
            assert_eq!(reopened_db.root(&mut hasher), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                expected_inactivity_floor_loc
            );
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                expected_inactivity_floor_loc
            );

            // Cleanup
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            reopened_db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_resolver_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let resolver = FailResolver::<sha256::Digest, sha256::Digest, sha256::Digest>::new();
            let target_root = sha256::Digest::from([0; 32]);

            let db_config = create_test_config(context.next_u64());
            let engine_config = Config {
                context,
                target: Target {
                    root: target_root,
                    range: Location::new_unchecked(0)..Location::new_unchecked(5),
                },
                resolver,
                apply_batch_size: 2,
                max_outstanding_requests: 2,
                fetch_batch_size: NZU64!(2),
                db_config,
                update_rx: None,
            };

            // Attempt to sync - should fail due to resolver error
            let result: Result<AnyTest, _> = sync::sync(engine_config).await;
            assert!(result.is_err());
        });
    }

    /// Test `from_sync_result` with an empty source database (nothing persisted) syncing to
    /// an empty target database.
    #[test_traced("WARN")]
    pub fn test_from_sync_result_empty_to_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let log = journal::fixed::Journal::<Context, Fixed<Digest, Digest>>::init(
                context.clone(),
                journal::fixed::Config {
                    partition: "sync_basic_log".into(),
                    items_per_blob: NZU64!(1000),
                    write_buffer: NZUsize!(1024),
                    buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                },
            )
            .await
            .unwrap();

            let mut synced_db: AnyTest = <AnyTest as adb::sync::Database>::from_sync_result(
                context.clone(),
                any_db_config("sync_basic"),
                log,
                None,
                Location::new_unchecked(0)..Location::new_unchecked(1),
                1024,
            )
            .await
            .unwrap();

            // Verify database state
            assert_eq!(synced_db.op_count(), 0);
            assert_eq!(synced_db.inactivity_floor_loc, Location::new_unchecked(0));
            assert_eq!(synced_db.log.size().await.unwrap(), 0);
            assert_eq!(synced_db.mmr.size(), 0);

            // Test that we can perform operations on the synced database
            let key1 = Sha256::hash(&1u64.to_be_bytes());
            let value1 = Sha256::hash(&10u64.to_be_bytes());
            let key2 = Sha256::hash(&2u64.to_be_bytes());
            let value2 = Sha256::hash(&20u64.to_be_bytes());

            synced_db.update(key1, value1).await.unwrap();
            synced_db.update(key2, value2).await.unwrap();
            synced_db.commit().await.unwrap();

            // Verify the operations worked
            assert_eq!(synced_db.get(&key1).await.unwrap(), Some(value1));
            assert_eq!(synced_db.get(&key2).await.unwrap(), Some(value2));
            assert!(synced_db.op_count() > 0);

            synced_db.destroy().await.unwrap();
        });
    }

    /// Test `from_sync_result` with an empty source database (nothing persisted) syncing to
    /// a non-empty target database.
    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        const NUM_OPS: usize = 100;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(NUM_OPS);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit().await.unwrap();
            source_db
                .prune(source_db.inactivity_floor_loc)
                .await
                .unwrap();

            let lower_bound = source_db.inactivity_floor_loc;
            let upper_bound = source_db.op_count();

            // Get pinned nodes and target hash before moving source_db
            let pinned_nodes_pos = nodes_to_pin(Position::try_from(lower_bound).unwrap());
            let pinned_nodes =
                join_all(pinned_nodes_pos.map(|pos| source_db.mmr.get_node(pos))).await;
            let pinned_nodes = pinned_nodes
                .iter()
                .map(|node| node.as_ref().unwrap().unwrap())
                .collect::<Vec<_>>();
            let mut hasher = StandardHasher::<Sha256>::new();
            let target_hash = source_db.root(&mut hasher);

            // Create log with operations
            let mut log = init_journal(
                context.with_label("ops_log"),
                fixed::Config {
                    partition: format!("ops_log_{}", context.next_u64()),
                    items_per_blob: NZU64!(1024),
                    write_buffer: NZUsize!(64),
                    buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                },
                *lower_bound..*upper_bound,
            )
            .await
            .unwrap();

            // Populate log with operations from source db
            for i in *lower_bound..*upper_bound {
                let op = source_db.log.read(i).await.unwrap();
                log.append(op).await.unwrap();
            }

            let db =
                <Any<_, Digest, Digest, Sha256, TwoCap> as adb::sync::Database>::from_sync_result(
                    context.clone(),
                    any_db_config("sync_basic"),
                    log,
                    Some(pinned_nodes),
                    lower_bound..upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(db.op_count(), upper_bound);
            assert_eq!(db.inactivity_floor_loc, lower_bound);
            assert_eq!(db.mmr.size(), source_db.mmr.size());
            assert_eq!(
                db.log.size().await.unwrap(),
                source_db.log.size().await.unwrap()
            );

            // Verify the root digest matches the target
            assert_eq!(db.root(&mut hasher), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &ops {
                if let Fixed::Update(key, value) = op {
                    expected_kvs.insert(*key, *value);
                    deleted_keys.remove(key);
                } else if let Fixed::Delete(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(db.get(&key).await.unwrap().is_none(),);
            }

            db.destroy().await.unwrap();
            source_db.destroy().await.unwrap();
        });
    }

    /// Test `from_sync_result` with an empty source database syncing to a non-empty target database
    /// with different pruning boundaries.
    #[test]
    fn test_from_sync_result_empty_to_nonempty_different_pruning_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(200);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit().await.unwrap();

            let total_ops = source_db.op_count();

            // Test different pruning boundaries
            for lower_bound in [0, 50, 100, 150] {
                let upper_bound = std::cmp::min(lower_bound + 50, *total_ops );

                // Create log with operations
                let mut log = init_journal(
                    context.clone().with_label("boundary_log"),
                    fixed::Config {
                        partition: format!("boundary_log_{}_{}", lower_bound, context.next_u64()),
                        items_per_blob: NZU64!(1024),
                        write_buffer: NZUsize!(64),
                        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
                    },
                    lower_bound..upper_bound,
                )
                .await
                .unwrap();
                log.sync().await.unwrap();

                for i in lower_bound..upper_bound {
                    let op = source_db.log.read(i).await.unwrap();
                    log.append(op).await.unwrap();
                }
                log.sync().await.unwrap();

                let pinned_nodes = nodes_to_pin(
                    Position::try_from(Location::new_unchecked(lower_bound)).unwrap(),
                )
                    .map(|pos| source_db.mmr.get_node(pos));
                let pinned_nodes = join_all(pinned_nodes).await;
                let pinned_nodes = pinned_nodes
                    .iter()
                    .map(|node| node.as_ref().unwrap().unwrap())
                    .collect::<Vec<_>>();

                let db: AnyTest = <Any<_, Digest, Digest, Sha256, TwoCap> as adb::sync::Database>::from_sync_result(
                    context.clone(),
                    create_test_config(context.next_u64()),
                    log,
                    Some(pinned_nodes),
                    Location::new_unchecked(lower_bound)..Location::new_unchecked(upper_bound),
                    1024,
                )
                .await
                .unwrap();

                // Verify database state
                assert_eq!(db.log.size().await.unwrap(), upper_bound);
                assert_eq!(
                    db.mmr.size(),
                    Position::try_from(Location::new_unchecked(upper_bound)).unwrap()
                );
                assert_eq!(db.op_count(), upper_bound);
                assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(lower_bound));

                // Verify state matches the source operations
                let mut expected_kvs = HashMap::new();
                let mut deleted_keys = HashSet::new();
                for op in &ops[lower_bound as usize..upper_bound as usize] {
                    if let Fixed::Update(key, value) = op {
                        expected_kvs.insert(*key, *value);
                        deleted_keys.remove(key);
                    } else if let Fixed::Delete(key) = op {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                }
                for (key, value) in expected_kvs {
                    assert_eq!(db.get(&key).await.unwrap().unwrap(), value,);
                }
                // Verify that deleted keys are absent
                for key in deleted_keys {
                    assert!(db.get(&key).await.unwrap().is_none());
                }

                db.destroy().await.unwrap();
            }
            source_db.destroy().await.unwrap();
        });
    }

    // Test `from_sync_result` where the database has some but not all of the operations in the target
    // database.
    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        const NUM_OPS: usize = 100;
        const NUM_ADDITIONAL_OPS: usize = 5;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate two databases.
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(context.next_u64());
            let mut sync_db: AnyTest = Any::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();
            let original_ops = create_test_ops(NUM_OPS);
            apply_ops(&mut target_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            target_db
                .prune(target_db.inactivity_floor_loc)
                .await
                .unwrap();
            apply_ops(&mut sync_db, original_ops.clone()).await;
            sync_db.commit().await.unwrap();
            sync_db.prune(sync_db.inactivity_floor_loc).await.unwrap();
            let sync_db_original_size = sync_db.op_count();

            // Get pinned nodes before closing the database
            let pinned_nodes_map = sync_db.mmr.get_pinned_nodes();
            let pinned_nodes = nodes_to_pin(Position::try_from(sync_db_original_size).unwrap())
                .map(|pos| *pinned_nodes_map.get(&pos).unwrap())
                .collect::<Vec<_>>();

            // Close the sync db
            sync_db.close().await.unwrap();

            // Add one more operation to the target db
            let more_ops = create_test_ops(NUM_ADDITIONAL_OPS);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target db state for comparison
            let target_db_op_count = target_db.op_count();
            let target_db_inactivity_floor_loc = target_db.inactivity_floor_loc;
            let target_db_log_size = target_db.log.size().await.unwrap();
            let target_db_mmr_size = target_db.mmr.size();

            let sync_lower_bound = target_db.inactivity_floor_loc;
            let sync_upper_bound = target_db.op_count();

            let mut hasher = StandardHasher::<Sha256>::new();
            let target_hash = target_db.root(&mut hasher);

            let AnyTest { mmr, log, .. } = target_db;

            // Re-open `sync_db`
            let sync_db =
                <Any<_, Digest, Digest, Sha256, TwoCap> as adb::sync::Database>::from_sync_result(
                    context.clone(),
                    sync_db_config,
                    log,
                    Some(pinned_nodes),
                    sync_lower_bound..sync_upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(sync_db.inactivity_floor_loc, target_db_inactivity_floor_loc);
            assert_eq!(sync_db.inactivity_floor_loc, sync_lower_bound);
            assert_eq!(sync_db.log.size().await.unwrap(), target_db_log_size);
            assert_eq!(sync_db.mmr.size(), target_db_mmr_size);

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &original_ops {
                if let Fixed::Update(key, value) = op {
                    expected_kvs.insert(*key, *value);
                    deleted_keys.remove(key);
                } else if let Fixed::Delete(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = sync_db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(sync_db.get(&key).await.unwrap().is_none(),);
            }

            sync_db.destroy().await.unwrap();
            mmr.destroy().await.unwrap();
        });
    }

    // Test `from_sync_result` where the database has all of the operations in the target range.
    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db_config = create_test_config(context.next_u64());
            let mut db = Any::init(context.clone(), db_config.clone()).await.unwrap();
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let sync_lower_bound = db.inactivity_floor_loc;
            let sync_upper_bound = db.op_count();
            let target_db_op_count = db.op_count();
            let target_db_inactivity_floor_loc = db.inactivity_floor_loc;
            let target_db_log_size = db.log.size().await.unwrap();
            let target_db_mmr_size = db.mmr.size();

            let pinned_nodes = join_all(
                nodes_to_pin(Position::try_from(db.inactivity_floor_loc).unwrap())
                    .map(|pos| db.mmr.get_node(pos)),
            )
            .await;
            let pinned_nodes = pinned_nodes
                .iter()
                .map(|node| node.as_ref().unwrap().unwrap())
                .collect::<Vec<_>>();
            let AnyTest { mmr, log, .. } = db;

            // When we re-open the database, the MMR is closed and the log is opened.
            let mut hasher = StandardHasher::<Sha256>::new();
            mmr.close(&mut hasher).await.unwrap();

            let sync_db: AnyTest =
                <Any<_, Digest, Digest, Sha256, TwoCap> as adb::sync::Database>::from_sync_result(
                    context.clone(),
                    db_config,
                    log,
                    Some(pinned_nodes),
                    sync_lower_bound..sync_upper_bound,
                    1024,
                )
                .await
                .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(sync_db.inactivity_floor_loc, target_db_inactivity_floor_loc);
            assert_eq!(sync_db.inactivity_floor_loc, sync_lower_bound);
            assert_eq!(sync_db.log.size().await.unwrap(), target_db_log_size);
            assert_eq!(sync_db.mmr.size(), target_db_mmr_size);

            sync_db.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_fresh_start".into(),
                items_per_blob: NZU64!(5),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 26;
            let mut sync_journal =
                init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                    .await
                    .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is initialized at the lower bound
            assert_eq!(sync_journal.size().await.unwrap(), lower_bound);
            assert_eq!(sync_journal.oldest_retained_pos().await.unwrap(), None);

            // Verify the journal structure matches expected state
            // With items_per_blob=5 and lower_bound=10, we expect:
            // - Tail blob at index 2 (10 / 5 = 2)
            // - No historical blobs (all operations are "pruned")
            assert_eq!(sync_journal.blobs.len(), 0);
            assert_eq!(sync_journal.tail_index, 2);

            // Verify that operations can be appended starting from the sync position
            let append_pos = sync_journal.append(test_digest(100)).await.unwrap();
            assert_eq!(append_pos, lower_bound);

            // Verify we can read the appended operation
            let read_value = sync_journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, test_digest(100));

            // Verify that reads before the lower bound return ItemPruned
            for i in 0..lower_bound {
                let result = sync_journal.read(i).await;
                assert!(matches!(result, Err(journal::Error::ItemPruned(_))),);
            }

            sync_journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    /// This tests the "prune and reuse" scenario where existing data partially overlaps with sync boundaries.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_overlap".into(),
                items_per_blob: NZU64!(4),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with 20 operations
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..20 {
                journal.append(test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            let journal_size = journal.size().await.unwrap();
            assert_eq!(journal_size, 20);
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            // Lower bound: 8 (prune operations 0-7)
            // Upper bound: 31 (beyond existing data, so existing data should be kept)
            let lower_bound = 8;
            let upper_bound = 31;
            let mut journal = init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                .await
                .expect("Failed to initialize journal with overlap");

            // Verify the journal size matches the original (no rewind needed)
            assert_eq!(journal.size().await.unwrap(), journal_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(
                journal.oldest_retained_pos().await.unwrap(),
                Some(lower_bound)
            );

            // Verify operations before the lower bound are pruned
            for i in 0..lower_bound {
                let result = journal.read(i).await;
                assert!(matches!(result, Err(journal::Error::ItemPruned(_))),);
            }

            // Verify operations from lower bound to original size are still readable
            for i in lower_bound..journal_size {
                let result = journal.read(i).await;
                assert!(result.is_ok());
                assert_eq!(result.unwrap(), test_digest(i),);
            }

            // Verify that new operations can be appended
            let append_pos = journal.append(test_digest(999)).await.unwrap();
            assert_eq!(append_pos, journal_size);

            // Verify the appended operation is readable
            let read_value = journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, test_digest(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync target range.
    /// This tests the "prune only" scenario where existing data fits within sync boundaries.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_exact_match".into(),
                items_per_blob: NZU64!(3),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with 20 operations (0-19)
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..20 {
                journal.append(test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            let initial_size = journal.size().await.unwrap();
            assert_eq!(initial_size, 20);
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            // Lower bound: 6 (prune operations 0-5, aligns with blob boundary)
            // Upper bound: 20 (last populated location is 19, so no rewinding needed)
            let lower_bound = 6;
            let upper_bound = 20;
            let mut journal = init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                .await
                .expect("Failed to initialize journal with exact match");

            // Verify the journal size remains the same (no rewinding needed)
            assert_eq!(journal.size().await.unwrap(), initial_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(
                journal.oldest_retained_pos().await.unwrap(),
                Some(lower_bound)
            );

            // Verify operations before the lower bound are pruned
            for i in 0..lower_bound {
                let result = journal.read(i).await;
                assert!(matches!(result, Err(journal::Error::ItemPruned(_))),);
            }

            // Verify operations from lower bound to end of existing data are readable
            for i in lower_bound..initial_size {
                let result = journal.read(i).await;
                assert!(result.is_ok(),);
                assert_eq!(result.unwrap(), test_digest(i));
            }

            // Verify that new operations can be appended from the existing size
            let append_pos = journal.append(test_digest(888)).await.unwrap();
            assert_eq!(append_pos, initial_size);

            // Verify the appended operation is readable
            let read_value = journal.read(append_pos).await.unwrap();
            assert_eq!(read_value, test_digest(888));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    /// This tests that UnexpectedData error is returned when existing data goes beyond the upper bound.
    #[test_traced]
    fn test_init_sync_existing_data_exceeds_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_unexpected_data".into(),
                items_per_blob: NZU64!(4),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with 30 operations (0-29)
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..30 {
                journal.append(test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            let initial_size = journal.size().await.unwrap();
            assert_eq!(initial_size, 30);
            journal.close().await.unwrap();

            // Initialize with sync boundaries where existing data exceeds the upper bound
            let lower_bound = 8;
            for upper_bound in 9..30 {
                let result = init_journal::<Context, Digest>(
                    context.clone(),
                    cfg.clone(),
                    lower_bound..upper_bound,
                )
                .await;

                assert!(matches!(result, Err(adb::Error::UnexpectedData(_))));
            }
            context.remove(&cfg.partition, None).await.unwrap();
        });
    }

    #[should_panic]
    #[test_traced]
    fn test_init_sync_invalid_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_invalid_range".into(),
                items_per_blob: NZU64!(4),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            let lower_bound = 6;
            let upper_bound = 6;
            let _result = init_journal::<Context, Digest>(
                context.clone(),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await;
        });
    }

    /// Test `init_at_size` creates a journal in a pruned state at various sizes.
    #[test_traced]
    fn test_init_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed::Config {
                partition: "test_init_at_size".into(),
                items_per_blob: NZU64!(5),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Test 1: Initialize at size 0 (empty journal)
            {
                let mut journal = init_journal_at_size(context.clone(), cfg.clone(), 0)
                    .await
                    .expect("Failed to initialize journal at size 0");

                assert_eq!(journal.size().await.unwrap(), 0);
                assert_eq!(journal.tail_index, 0);
                assert_eq!(journal.blobs.len(), 0);
                assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

                // Should be able to append from position 0
                let append_pos = journal.append(test_digest(100)).await.unwrap();
                assert_eq!(append_pos, 0);
                assert_eq!(journal.read(0).await.unwrap(), test_digest(100));
                journal.destroy().await.unwrap();
            }

            // Test 2: Initialize at size exactly at blob boundary (10 with items_per_blob=5)
            {
                let mut journal = init_journal_at_size(context.clone(), cfg.clone(), 10)
                    .await
                    .expect("Failed to initialize journal at size 10");

                assert_eq!(journal.size().await.unwrap(), 10);
                assert_eq!(journal.tail_index, 2); // 10 / 5 = 2
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                assert_eq!(journal.oldest_retained_pos().await.unwrap(), None); // Tail is empty

                // Operations 0-9 should be pruned
                for i in 0..10 {
                    let result = journal.read(i).await;
                    assert!(matches!(result, Err(journal::Error::ItemPruned(_))));
                }

                // Should be able to append from position 10
                let append_pos = journal.append(test_digest(10)).await.unwrap();
                assert_eq!(append_pos, 10);
                assert_eq!(journal.read(10).await.unwrap(), test_digest(10));

                journal.destroy().await.unwrap();
            }

            // Test 3: Initialize at size in middle of blob (7 with items_per_blob=5)
            {
                let mut journal = init_journal_at_size(context.clone(), cfg.clone(), 7)
                    .await
                    .expect("Failed to initialize journal at size 7");

                assert_eq!(journal.size().await.unwrap(), 7);
                assert_eq!(journal.tail_index, 1); // 7 / 5 = 1
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                                                    // Tail blob should have 2 items worth of space (7 % 5 = 2)
                assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(5)); // First item in tail blob

                // Operations 0-4 should be pruned (blob 0 doesn't exist)
                for i in 0..5 {
                    let result = journal.read(i).await;
                    assert!(matches!(result, Err(journal::Error::ItemPruned(_))));
                }

                // Operations 5-6 should be unreadable (dummy data in tail blob)
                for i in 5..7 {
                    let result = journal.read(i).await;
                    assert!(result.is_err()); // Should fail due to invalid data
                }

                // Should be able to append from position 7
                let append_pos = journal.append(test_digest(7)).await.unwrap();
                assert_eq!(append_pos, 7);
                assert_eq!(journal.read(7).await.unwrap(), test_digest(7));

                journal.destroy().await.unwrap();
            }

            // Test 4: Initialize at larger size spanning multiple pruned blobs
            {
                let mut journal = init_journal_at_size(context.clone(), cfg.clone(), 23)
                    .await
                    .expect("Failed to initialize journal at size 23");

                assert_eq!(journal.size().await.unwrap(), 23);
                assert_eq!(journal.tail_index, 4); // 23 / 5 = 4
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(20)); // First item in tail blob

                // Operations 0-19 should be pruned (blobs 0-3 don't exist)
                for i in 0..20 {
                    let result = journal.read(i).await;
                    assert!(matches!(result, Err(journal::Error::ItemPruned(_))));
                }

                // Operations 20-22 should be unreadable (dummy data in tail blob)
                for i in 20..23 {
                    let result = journal.read(i).await;
                    assert!(result.is_err()); // Should fail due to invalid data
                }

                // Should be able to append from position 23
                let append_pos = journal.append(test_digest(23)).await.unwrap();
                assert_eq!(append_pos, 23);
                assert_eq!(journal.read(23).await.unwrap(), test_digest(23));

                // Continue appending to test normal operation
                let append_pos = journal.append(test_digest(24)).await.unwrap();
                assert_eq!(append_pos, 24);
                assert_eq!(journal.read(24).await.unwrap(), test_digest(24));

                // Should have moved to a new tail blob
                assert_eq!(journal.tail_index, 5);
                assert_eq!(journal.blobs.len(), 1); // Previous tail became historical

                // Fill the tail blob (positions 25-29)
                for i in 25..30 {
                    let append_pos = journal.append(test_digest(i)).await.unwrap();
                    assert_eq!(append_pos, i);
                    assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
                }

                // At this point we should have moved to a new tail blob
                assert_eq!(journal.tail_index, 6);
                assert_eq!(journal.blobs.len(), 2); // Previous tail became historical

                journal.destroy().await.unwrap();
            }
        });
    }
}

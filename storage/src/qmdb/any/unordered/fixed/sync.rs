//! Sync implementation for [Db].

use super::{Db, Operation};
use crate::{
    index::unordered::Index,
    journal::{authenticated, contiguous::fixed},
    mmr::{mem::Clean, Location, Position, StandardHasher},
    // TODO(https://github.com/commonwarexyz/monorepo/issues/1873): support any::fixed::ordered
    qmdb::{self, any::FixedValue, Durable, Merkleized},
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{
    buffer::pool::Append, telemetry::metrics::status::GaugeExt, Blob, Clock, Metrics, Storage,
};
use commonware_utils::Array;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, marker::PhantomData, ops::Range};
use tracing::debug;

impl<E, K, V, H, T> qmdb::sync::Database for Db<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = Operation<K, V>;
    type Journal = fixed::Journal<E, Operation<K, V>>;
    type Hasher = H;
    type Config = qmdb::any::FixedConfig<T>;
    type Digest = H::Digest;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
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
    ) -> Result<Self, qmdb::Error> {
        let mut hasher = StandardHasher::<H>::new();

        let mmr = crate::mmr::journaled::Mmr::init_sync(
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
            &mut hasher,
        )
        .await?;

        let log = authenticated::Journal::<_, _, _, Clean<DigestOf<H>>>::from_components(
            mmr,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;
        // Build the snapshot from the log.
        let snapshot = Index::new(context.with_label("snapshot"), db_config.translator.clone());
        let db = Self::from_components(range.start, log, snapshot).await?;

        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }

    async fn resize_journal(
        mut journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let size = journal.size();

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
///    - Returns [qmdb::Error::UnexpectedData]
///
/// # Invariants
///
/// The returned [fixed::Journal] has size in the given range.
pub(crate) async fn init_journal<E: Storage + Metrics, A: CodecFixed<Cfg = ()>>(
    context: E,
    cfg: fixed::Config,
    range: Range<u64>,
) -> Result<fixed::Journal<E, A>, qmdb::Error> {
    assert!(!range.is_empty(), "range must not be empty");

    let mut journal =
        fixed::Journal::<E, A>::init(context.with_label("journal"), cfg.clone()).await?;
    let journal_size = journal.size();
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
        return Err(qmdb::Error::UnexpectedData(Location::new_unchecked(
            journal_size,
        )));
    };
    let journal_size = journal.size();
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

    let tail = Append::new(
        tail_blob,
        0,
        cfg.write_buffer.into(),
        cfg.buffer_pool.clone(),
    )
    .await?;
    if tail_items > 0 {
        tail.resize(tail_size).await?;
    }
    let pruning_boundary = size - (size % cfg.items_per_blob);

    // Initialize metrics
    let tracked = Gauge::default();
    let _ = tracked.try_set(tail_index + 1);
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
        size,
        pruning_boundary,
        _array: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal,
        qmdb::any::unordered::{
            fixed::test::{
                apply_ops, create_test_config, create_test_db, create_test_ops, AnyTest,
            },
            sync_tests::{self, SyncTestHarness},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rstest::rstest;
    use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

    // Janky sizes to test boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(99);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    /// Harness for sync tests.
    struct FixedHarness;

    impl SyncTestHarness for FixedHarness {
        type Db = AnyTest;

        fn config(suffix: &str) -> super::super::Config<TwoCap> {
            create_test_config(suffix.parse().unwrap_or(0))
        }

        fn clone_config(config: &super::super::Config<TwoCap>) -> super::super::Config<TwoCap> {
            config.clone()
        }

        fn create_ops(n: usize) -> Vec<Operation<Digest, Digest>> {
            create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            create_test_db(ctx).await
        }

        async fn init_db_with_config(
            ctx: Context,
            config: super::super::Config<TwoCap>,
        ) -> Self::Db {
            AnyTest::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(db: Self::Db, ops: Vec<Operation<Digest, Digest>>) -> Self::Db {
            let mut db = db.into_mutable();
            apply_ops(&mut db, ops).await;
            db.commit(None::<Digest>).await.unwrap().0.into_merkleized()
        }
    }

    #[test]
    fn test_sync_invalid_bounds() {
        sync_tests::test_sync_invalid_bounds::<FixedHarness>();
    }

    #[test]
    fn test_sync_subset_of_target_database() {
        sync_tests::test_sync_subset_of_target_database::<FixedHarness>(1000);
    }

    #[rstest]
    #[case::singleton_batch_size_one(1, 1)]
    #[case::singleton_batch_size_gt_db_size(1, 2)]
    #[case::batch_size_one(1000, 1)]
    #[case::floor_div_db_batch_size(1000, 3)]
    #[case::floor_div_db_batch_size_2(1000, 999)]
    #[case::div_db_batch_size(1000, 100)]
    #[case::db_size_eq_batch_size(1000, 1000)]
    #[case::batch_size_gt_db_size(1000, 1001)]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: u64) {
        sync_tests::test_sync::<FixedHarness>(
            target_db_ops,
            NonZeroU64::new(fetch_batch_size).unwrap(),
        );
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        sync_tests::test_sync_use_existing_db_partial_match::<FixedHarness>(1000);
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        sync_tests::test_sync_use_existing_db_exact_match::<FixedHarness>(1000);
    }

    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        sync_tests::test_target_update_lower_bound_decrease::<FixedHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        sync_tests::test_target_update_upper_bound_decrease::<FixedHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        sync_tests::test_target_update_bounds_increase::<FixedHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        sync_tests::test_target_update_invalid_bounds::<FixedHarness>();
    }

    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        sync_tests::test_target_update_on_done_client::<FixedHarness>();
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(1, 100)]
    #[case(2, 1)]
    #[case(2, 2)]
    #[case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[case(20, 10)]
    #[case(100, 1)]
    #[case(100, 2)]
    #[case(100, 100)]
    #[case(100, 1000)]
    fn test_target_update_during_sync(#[case] initial_ops: usize, #[case] additional_ops: usize) {
        sync_tests::test_target_update_during_sync::<FixedHarness>(initial_ops, additional_ops);
    }

    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        sync_tests::test_sync_database_persistence::<FixedHarness>();
    }

    #[test]
    fn test_sync_resolver_fails() {
        sync_tests::test_sync_resolver_fails::<FixedHarness>();
    }

    #[test_traced("WARN")]
    fn test_from_sync_result_empty_to_empty() {
        sync_tests::test_from_sync_result_empty_to_empty::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        sync_tests::test_from_sync_result_empty_to_nonempty::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_partial_match::<FixedHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        sync_tests::test_from_sync_result_nonempty_to_nonempty_exact_match::<FixedHarness>();
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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 26;
            let mut sync_journal =
                init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                    .await
                    .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is initialized at the lower bound
            assert_eq!(sync_journal.size(), lower_bound);
            assert_eq!(sync_journal.oldest_retained_pos(), None);

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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with 20 operations
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..20 {
                journal.append(test_digest(i)).await.unwrap();
            }
            let journal_size = journal.size();
            assert_eq!(journal_size, 20);
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that overlap with existing data
            // Lower bound: 8 (prune operations 0-7)
            // Upper bound: 31 (beyond existing data, so existing data should be kept)
            let lower_bound = 8;
            let upper_bound = 31;
            let mut journal = init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                .await
                .expect("Failed to initialize journal with overlap");

            // Verify the journal size matches the original (no rewind needed)
            assert_eq!(journal.size(), journal_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(journal.oldest_retained_pos(), Some(lower_bound));

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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with 20 operations (0-19)
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..20 {
                journal.append(test_digest(i)).await.unwrap();
            }
            let initial_size = journal.size();
            assert_eq!(initial_size, 20);
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that exactly match existing data
            // Lower bound: 6 (prune operations 0-5, aligns with blob boundary)
            // Upper bound: 20 (last populated location is 19, so no rewinding needed)
            let lower_bound = 6;
            let upper_bound = 20;
            let mut journal = init_journal(context.clone(), cfg.clone(), lower_bound..upper_bound)
                .await
                .expect("Failed to initialize journal with exact match");

            // Verify the journal size remains the same (no rewinding needed)
            assert_eq!(journal.size(), initial_size);

            // Verify the journal has been pruned to the lower bound
            assert_eq!(journal.oldest_retained_pos(), Some(lower_bound));

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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with 30 operations (0-29)
            let mut journal = fixed::Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to create initial journal");

            for i in 0..30 {
                journal.append(test_digest(i)).await.unwrap();
            }
            let initial_size = journal.size();
            assert_eq!(initial_size, 30);
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries where existing data exceeds the upper bound
            let lower_bound = 8;
            for upper_bound in 9..30 {
                let result = init_journal::<Context, Digest>(
                    context.clone(),
                    cfg.clone(),
                    lower_bound..upper_bound,
                )
                .await;

                assert!(matches!(result, Err(qmdb::Error::UnexpectedData(_))));
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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Test 1: Initialize at size 0 (empty journal)
            {
                let mut journal = init_journal_at_size(context.clone(), cfg.clone(), 0)
                    .await
                    .expect("Failed to initialize journal at size 0");

                assert_eq!(journal.size(), 0);
                assert_eq!(journal.tail_index, 0);
                assert_eq!(journal.blobs.len(), 0);
                assert_eq!(journal.oldest_retained_pos(), None);

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

                assert_eq!(journal.size(), 10);
                assert_eq!(journal.tail_index, 2); // 10 / 5 = 2
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                assert_eq!(journal.oldest_retained_pos(), None); // Tail is empty

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

                assert_eq!(journal.size(), 7);
                assert_eq!(journal.tail_index, 1); // 7 / 5 = 1
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                                                    // Tail blob should have 2 items worth of space (7 % 5 = 2)
                assert_eq!(journal.oldest_retained_pos(), Some(5)); // First item in tail blob

                // Operations 0-4 should be pruned (blob 0 doesn't exist)
                for i in 0..5 {
                    let result = journal.read(i).await;
                    assert!(matches!(result, Err(journal::Error::ItemPruned(_))));
                }

                // Operations 5-6 should be unreadable (dummy data in tail blob)
                for i in 5..7 {
                    let result = journal.read(i).await;
                    assert_eq!(result.unwrap(), Sha256::fill(0)); // dummy data is all 0s
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

                assert_eq!(journal.size(), 23);
                assert_eq!(journal.tail_index, 4); // 23 / 5 = 4
                assert_eq!(journal.blobs.len(), 0); // No historical blobs
                assert_eq!(journal.oldest_retained_pos(), Some(20)); // First item in tail blob

                // Operations 0-19 should be pruned (blobs 0-3 don't exist)
                for i in 0..20 {
                    let result = journal.read(i).await;
                    assert!(matches!(result, Err(journal::Error::ItemPruned(_))));
                }

                // Operations 20-22 should be all 0s (dummy data in tail blob)
                for i in 20..23 {
                    let result = journal.read(i).await.unwrap();
                    assert_eq!(result, Sha256::fill(0));
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

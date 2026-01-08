//! Sync implementation for [Db].

use super::{Db, Operation};
use crate::{
    index::unordered::Index,
    journal::{authenticated, contiguous::variable},
    mmr::{mem::Clean, Location, Position, StandardHasher},
    qmdb::{self, any::VariableValue, Durable, Merkleized},
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::ops::Range;

impl<E, K, V, H, T> qmdb::sync::Database for Db<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = Operation<K, V>;
    type Journal = variable::Journal<E, Operation<K, V>>;
    type Hasher = H;
    type Config = qmdb::any::VariableConfig<T, <Operation<K, V> as Read>::Cfg>;
    type Digest = H::Digest;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        range: Range<Location>,
    ) -> Result<Self::Journal, qmdb::Error> {
        let journal_config = variable::Config {
            partition: config.log_partition.clone(),
            items_per_section: config.log_items_per_blob,
            compression: config.log_compression,
            codec_config: config.log_codec_config.clone(),
            buffer_pool: config.buffer_pool.clone(),
            write_buffer: config.log_write_buffer,
        };

        variable::Journal::init_sync(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        qmdb::{
            any::unordered::{sync_tests::SyncTestHarness, Update},
            NonDurable, Unmerkleized,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use rstest::rstest;
    use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(99);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    type VarConfig = qmdb::any::VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())>;

    fn test_config(suffix: &str) -> VarConfig {
        qmdb::any::VariableConfig {
            mmr_journal_partition: format!("mmr_journal_{suffix}"),
            mmr_metadata_partition: format!("mmr_metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(64),
            log_partition: format!("log_{suffix}"),
            log_items_per_blob: NZU64!(11),
            log_write_buffer: NZUsize!(64),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Type alias for tests
    type AnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

    fn test_value(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = test_config(&format!("{seed}"));
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    fn create_test_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = test_value(i as u64);
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    type DirtyAnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Unmerkleized, NonDurable>;

    /// Applies the given operations to the database.
    async fn apply_ops_inner(
        mut db: DirtyAnyTest,
        ops: Vec<Operation<Digest, Vec<u8>>>,
    ) -> DirtyAnyTest {
        for op in ops {
            match op {
                Operation::Update(Update(key, value)) => {
                    db.update(key, value).await.unwrap();
                }
                Operation::Delete(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::CommitFloor(metadata, _) => {
                    db = db.commit(metadata).await.unwrap().0.into_mutable();
                }
            }
        }
        db
    }

    /// Harness for sync tests.
    struct VariableHarness;

    impl SyncTestHarness for VariableHarness {
        type Db = AnyTest;

        fn config(suffix: &str) -> VarConfig {
            test_config(suffix)
        }

        fn clone_config(config: &VarConfig) -> VarConfig {
            config.clone()
        }

        fn create_ops(n: usize) -> Vec<Operation<Digest, Vec<u8>>> {
            create_test_ops(n)
        }

        async fn init_db(ctx: Context) -> Self::Db {
            create_test_db(ctx).await
        }

        async fn init_db_with_config(ctx: Context, config: VarConfig) -> Self::Db {
            AnyTest::init(ctx, config).await.unwrap()
        }

        async fn apply_ops(db: Self::Db, ops: Vec<Operation<Digest, Vec<u8>>>) -> Self::Db {
            apply_ops_inner(db.into_mutable(), ops)
                .await
                .commit(None)
                .await
                .unwrap()
                .0
                .into_merkleized()
        }
    }

    #[test]
    fn test_sync_invalid_bounds() {
        crate::qmdb::any::unordered::sync_tests::test_sync_invalid_bounds::<VariableHarness>();
    }

    #[test]
    fn test_sync_resolver_fails() {
        crate::qmdb::any::unordered::sync_tests::test_sync_resolver_fails::<VariableHarness>();
    }

    #[rstest]
    #[case::small_batch_size_one(10, 1)]
    #[case::small_batch_size_gt_db_size(10, 20)]
    #[case::batch_size_one(1000, 1)]
    #[case::floor_div_db_batch_size(1000, 3)]
    #[case::floor_div_db_batch_size_2(1000, 999)]
    #[case::div_db_batch_size(1000, 100)]
    #[case::db_size_eq_batch_size(1000, 1000)]
    #[case::batch_size_gt_db_size(1000, 1001)]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: u64) {
        crate::qmdb::any::unordered::sync_tests::test_sync::<VariableHarness>(
            target_db_ops,
            NonZeroU64::new(fetch_batch_size).unwrap(),
        );
    }

    #[test]
    fn test_sync_subset_of_target_database() {
        crate::qmdb::any::unordered::sync_tests::test_sync_subset_of_target_database::<
            VariableHarness,
        >(1000);
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        crate::qmdb::any::unordered::sync_tests::test_sync_use_existing_db_partial_match::<
            VariableHarness,
        >(1000);
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        crate::qmdb::any::unordered::sync_tests::test_sync_use_existing_db_exact_match::<
            VariableHarness,
        >(1000);
    }

    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_lower_bound_decrease::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_upper_bound_decrease::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_bounds_increase::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_invalid_bounds::<VariableHarness>(
        );
    }

    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        crate::qmdb::any::unordered::sync_tests::test_target_update_on_done_client::<VariableHarness>(
        );
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
        crate::qmdb::any::unordered::sync_tests::test_target_update_during_sync::<VariableHarness>(
            initial_ops,
            additional_ops,
        );
    }

    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        crate::qmdb::any::unordered::sync_tests::test_sync_database_persistence::<VariableHarness>(
        );
    }

    #[test]
    fn test_from_sync_result_empty_to_nonempty() {
        crate::qmdb::any::unordered::sync_tests::test_from_sync_result_empty_to_nonempty::<
            VariableHarness,
        >();
    }

    #[test_traced("WARN")]
    fn test_from_sync_result_empty_to_empty() {
        crate::qmdb::any::unordered::sync_tests::test_from_sync_result_empty_to_empty::<
            VariableHarness,
        >();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_partial_match() {
        crate::qmdb::any::unordered::sync_tests::test_from_sync_result_nonempty_to_nonempty_partial_match::<VariableHarness>();
    }

    #[test]
    fn test_from_sync_result_nonempty_to_nonempty_exact_match() {
        crate::qmdb::any::unordered::sync_tests::test_from_sync_result_nonempty_to_nonempty_exact_match::<VariableHarness>();
    }
}

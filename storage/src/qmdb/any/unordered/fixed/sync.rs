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
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::ops::Range;

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

        fixed::Journal::init_sync(
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
        qmdb::any::unordered::{
            fixed::test::{
                apply_ops, create_test_config, create_test_db, create_test_ops,
                create_test_ops_seeded, AnyTest,
            },
            sync_tests::{self, SyncTestHarness},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::sha256::Digest;
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic::Context;
    use rstest::rstest;
    use std::num::NonZeroU64;

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

        fn create_ops_seeded(n: usize, seed: u64) -> Vec<Operation<Digest, Digest>> {
            create_test_ops_seeded(n, seed)
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
}

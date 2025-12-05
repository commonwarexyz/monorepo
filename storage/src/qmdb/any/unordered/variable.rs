//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::unordered::fixed]
//! instead for better performance._

use super::operation::VariableOperation as Operation;
use crate::{
    index::unordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, mem::Clean, Location},
    qmdb::{
        any::{unordered::IndexedLog, VariableConfig, VariableValue},
        operation::Committable as _,
        Error,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, H, T, S = Clean<DigestOf<H>>> =
    IndexedLog<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, S>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mmr_config = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_config = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_blob,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.log_write_buffer,
        };

        let log = authenticated::Journal::<_, Journal<_, _>, _, _>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::<K, V>::is_commit,
        )
        .await?;

        let log = Self::init_from_log(
            Index::new(context.with_label("index"), cfg.translator),
            log,
            None,
            |_, _| {},
        )
        .await?;

        Ok(log)
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        qmdb::store::{batch_tests, CleanStore as _},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};
    use rand::RngCore;

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> VariableConfig<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Deterministic byte vector generator for variable-value tests.
    fn to_bytes(i: u64) -> Vec<u8> {
        let len = ((i % 13) + 7) as usize;
        vec![(i % 255) as u8; len]
    }

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_any_variable_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = to_bytes(i);
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_multiple_commits_delete_replayed(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                |i| vec![(i % 255) as u8; ((i % 7) + 3) as usize],
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let root = db.root();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root();

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root();
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(755));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.snapshot.items(), 857);

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(755));
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root();
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            async fn apply_more_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc, inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let db = open_db(context.clone()).await;
            let root = db.root();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            async fn apply_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure.
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure after syncing the log.
            apply_ops(&mut db).await;
            db.simulate_failure(true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let cfg = db_config(&format!("batch_{seed}"));
            AnyTest::init(ctx, cfg).await.unwrap()
        });
    }
}

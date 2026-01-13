//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::unordered::fixed]
//! instead for better performance._

pub mod sync;

use crate::{
    index::unordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, Location},
    qmdb::{
        any::{unordered, value::VariableEncoding, VariableConfig, VariableValue},
        operation::Committable as _,
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

pub type Update<K, V> = unordered::Update<K, VariableEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, VariableEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Db<E, K, V, H, T, Merkleized<H>, Durable>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
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

        let mut log = authenticated::Journal::<_, Journal<_, _>, _, _>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::<K, V>::is_commit,
        )
        .await?;

        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log.sync().await?;
        }

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
        index::Unordered as _, kv::Batchable, qmdb::store::batch_tests, translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::RngCore;
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

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
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete [Db] type used in these unit tests.
    type AnyTest =
        Db<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>, Durable>;

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
            let mut db = open_db(context.clone()).await.into_mutable();

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = to_bytes(i);
                db.update(k, v).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            drop(db);
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
            let db = open_db(context.clone()).await;
            let root = db.root();
            let mut db = db.into_mutable();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // re-apply the updates and commit them this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Update every 3rd key
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-apply updates for every 3rd key and commit them this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            let db = db.commit(None).await.unwrap().0.into_merkleized();
            let root = db.root();

            // Delete every 7th key
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            drop(db);
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());

            // Re-delete every 7th key and commit this time.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            let mut db = db.commit(None).await.unwrap().0.into_merkleized();

            let root = db.root();
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.oldest_retained_loc(), Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

            db.sync().await.unwrap();
            drop(db);

            // Confirm state is preserved after reopen.
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1961);
            assert_eq!(
                Location::try_from(db.log.mmr.size()).ok(),
                Some(Location::new_unchecked(1961))
            );
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(756));
            assert_eq!(db.oldest_retained_loc(), Location::new_unchecked(756));
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_fixed_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_non_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_empty_recovery(
                context,
                db,
                |ctx| Box::pin(open_db(ctx)),
                to_bytes,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_any_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db = open_db(context.clone()).await;
            let mut db = db.into_mutable();

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let mut db = db.into_merkleized();
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_any_unordered_variable_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let cfg = db_config(&format!("batch_{seed}"));
            AnyTest::init(ctx, cfg).await.unwrap().into_mutable()
        });
    }

    // Test that merkleization state changes don't reset `steps`.
    #[test_traced("DEBUG")]
    fn test_any_unordered_variable_db_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = crate::qmdb::any::unordered::test::open_variable_db(context).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
        });
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            mmr::{iterator::nodes_to_pin, journaled::Mmr, mem::Clean, Position},
            qmdb::any::unordered::sync_tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest, Clean<Digest>>;

        impl FromSyncTestable for AnyTest {
            type Mmr = TestMmr;

            fn into_log_components(self) -> (Self::Mmr, Self::Journal) {
                (self.log.mmr, self.log.journal)
            }

            async fn pinned_nodes_at(&self, pos: Position) -> Vec<Digest> {
                join_all(nodes_to_pin(pos).map(|p| self.log.mmr.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }

            fn pinned_nodes_from_map(&self, pos: Position) -> Vec<Digest> {
                let map = self.log.mmr.get_pinned_nodes();
                nodes_to_pin(pos).map(|p| *map.get(&p).unwrap()).collect()
            }
        }
    }

    fn assert_send<T: Send>(_: T) {}

    /// Regression test for https://github.com/commonwarexyz/monorepo/issues/2787
    #[allow(dead_code, clippy::manual_async_fn)]
    fn issue_2787_regression(
        db: &crate::qmdb::immutable::Immutable<
            deterministic::Context,
            Digest,
            Vec<u8>,
            Sha256,
            TwoCap,
        >,
        key: Digest,
    ) -> impl std::future::Future<Output = ()> + Send + use<'_> {
        async move {
            let _ = db.get(&key).await;
        }
    }

    #[test_traced]
    fn test_futures_are_send() {
        use crate::mmr::Location;

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let key = Sha256::hash(&9u64.to_be_bytes());
            let loc = Location::new_unchecked(0);

            assert_send(db.get(&key));
            assert_send(db.get_metadata());
            assert_send(db.sync());
            assert_send(db.prune(loc));
            assert_send(db.proof(loc, NZU64!(1)));

            let mut db = db.into_mutable();
            assert_send(db.get(&key));
            assert_send(db.get_metadata());
            assert_send(db.get_with_loc(&key));
            assert_send(db.write_batch(vec![(key, Some(vec![1u8]))].into_iter()));
            assert_send(db.update(key, vec![]));
            assert_send(db.create(key, vec![]));
            assert_send(db.delete(key));
            assert_send(db.commit(None));
        });
    }
}

//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::qmdb::any] authenticated database combined with an
//! authenticated [crate::bitmap::CleanBitMap] over the activity status of each operation. The two
//! structures are "grafted" together to minimize proof sizes.

use crate::{qmdb::any::FixedConfig as AnyFixedConfig, translator::Translator};
use commonware_parallel::ThreadPool;
use commonware_runtime::buffer::PoolRef;
use std::num::{NonZeroU64, NonZeroUsize};

pub mod db;
pub mod ordered;
pub mod proof;
pub mod unordered;

/// Configuration for a `Current` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

impl<T: Translator> FixedConfig<T> {
    /// Convert this config to an [AnyFixedConfig] used to initialize the authenticated log.
    pub fn to_any_config(self) -> AnyFixedConfig<T> {
        AnyFixedConfig {
            mmr_journal_partition: self.mmr_journal_partition,
            mmr_metadata_partition: self.mmr_metadata_partition,
            mmr_items_per_blob: self.mmr_items_per_blob,
            mmr_write_buffer: self.mmr_write_buffer,
            log_journal_partition: self.log_journal_partition,
            log_items_per_blob: self.log_items_per_blob,
            log_write_buffer: self.log_write_buffer,
            translator: self.translator,
            thread_pool: self.thread_pool,
            buffer_pool: self.buffer_pool,
        }
    }
}

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for Current QMDB variants.

    use crate::{
        kv::{Deletable as _, Updatable as _},
        qmdb::{
            any::states::{CleanAny, MutableAny as _, UnmerkleizedDurableAny as _},
            store::{
                batch_tests::{TestKey, TestValue},
                LogStore,
            },
            Error,
        },
    };
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics as _, Runner as _,
    };
    use core::future::Future;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tracing::warn;

    /// Apply random operations to the given db, committing them (randomly and at the end) only if
    /// `commit_changes` is true. Returns a mutable db; callers should commit if needed.
    pub async fn apply_random_ops<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: C::Mutable,
    ) -> Result<C::Mutable, Error>
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
    {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        for i in 0u64..num_elements {
            let k = TestKey::from_seed(i);
            let v = TestValue::from_seed(rng.next_u64());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = TestKey::from_seed(rng.next_u64() % num_elements);
            if rng.next_u32() % 7 == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = TestValue::from_seed(rng.next_u64());
            db.update(rand_key, v).await.unwrap();
            if commit_changes && rng.next_u32() % 20 == 0 {
                // Commit every ~20 updates.
                let (durable_db, _) = db.commit(None).await?;
                let clean_db: C = durable_db.into_merkleized().await?;
                db = clean_db.into_mutable();
            }
        }
        if commit_changes {
            let (durable_db, _) = db.commit(None).await?;
            let clean_db: C = durable_db.into_merkleized().await?;
            db = clean_db.into_mutable();
        }
        Ok(db)
    }

    /// Run `test_build_random_close_reopen` against a database factory.
    ///
    /// The factory should return a clean (Merkleized, Durable) database when given a context and
    /// partition name. The factory will be called multiple times to test reopening.
    pub fn test_build_random_close_reopen<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        let state1 = executor.start(|mut context| async move {
            let partition = "build_random".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db_clone(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();

            // Drop and reopen the db
            let root = db.root();
            drop(db);
            let db: C = open_db_clone(context.with_label("second"), partition).await;

            // Ensure the root matches
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        // Run again to verify determinism
        let executor = deterministic::Runner::default();
        let state2 = executor.start(|mut context| async move {
            let partition = "build_random".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();

            let root = db.root();
            drop(db);
            let db: C = open_db(context.with_label("second"), partition).await;
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        assert_eq!(state1, state2);
    }

    /// Run `test_simulate_write_failures` against a database factory.
    ///
    /// This test builds a random database and simulates recovery from different types of
    /// failure scenarios.
    pub fn test_simulate_write_failures<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random_fail_commit".to_string();
            let rng_seed = context.next_u64();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            let committed_root = db.root();
            let committed_op_count = db.op_count();
            let committed_inactivity_floor = db.inactivity_floor_loc();
            db.prune(committed_inactivity_floor).await.unwrap();

            // Perform more random operations without committing any of them.
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
            // state of the DB should be as of the last commit.
            drop(db);
            let db: C = open_db(context.with_label("scenario1"), partition.clone()).await;
            assert_eq!(db.root(), committed_root);
            assert_eq!(db.op_count(), committed_op_count);

            // Re-apply the exact same uncommitted operations.
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
            // before the state of the pruned bitmap can be written to disk (i.e., before
            // into_merkleized is called). We do this by committing and then dropping the durable
            // db without calling close or into_merkleized.
            let (durable_db, _) = db.commit(None).await.unwrap();
            let committed_op_count = durable_db.op_count();
            drop(durable_db);

            // We should be able to recover, so the root should differ from the previous commit, and
            // the op count should be greater than before.
            let db: C = open_db(context.with_label("scenario2"), partition.clone()).await;
            let scenario_2_root = db.root();

            // To confirm the second committed hash is correct we'll re-build the DB in a new
            // partition, but without any failures. They should have the exact same state.
            let fresh_partition = "build_random_fail_commit_fresh".to_string();
            let db: C = open_db(context.with_label("fresh"), fresh_partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            // State from scenario #2 should match that of a successful commit.
            assert_eq!(db.op_count(), committed_op_count);
            assert_eq!(db.root(), scenario_2_root);

            db.destroy().await.unwrap();
        });
    }
}

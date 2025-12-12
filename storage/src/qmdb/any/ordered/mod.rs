use commonware_codec::Codec;
use commonware_utils::Array;

pub mod fixed;
pub mod variable;

/// Data about a key in an ordered database or an ordered database operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyData<K: Array + Ord, V: Codec> {
    /// The key that exists in the database or in the database operation.
    pub key: K,
    /// The value of `key` in the database or operation.
    pub value: V,
    /// The next-key of `key` in the database or operation.
    ///
    /// The next-key is the next active key that lexicographically follows it in the key space. If
    /// the key is the lexicographically-last active key, then next-key is the
    /// lexicographically-first of all active keys (in a DB with only one key, this means its
    /// next-key is itself)
    pub next_key: K,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        mmr::{
            mem::{Clean, Mmr as MemMmr},
            Location, StandardHasher as Standard,
        },
        qmdb::{
            any::{
                test::{fixed_db_config, variable_db_config},
                CleanAny, DirtyAny as _,
            },
            store::{Batchable as _, DirtyStore as _, LogStore as _},
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use commonware_utils::sequence::FixedBytes;
    use core::{future::Future, pin::Pin};

    /// A type alias for the concrete [Any] type used in these unit tests.
    type FixedDb = fixed::Any<Context, FixedBytes<4>, Digest, Sha256, TwoCap>;

    /// A type alias for the concrete [Any] type used in these unit tests.
    type VariableDb = variable::Any<Context, FixedBytes<4>, Digest, Sha256, TwoCap, Clean<Digest>>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_fixed_db(context: Context) -> FixedDb {
        FixedDb::init(context, fixed_db_config("partition"))
            .await
            .unwrap()
    }

    /// Return an `Any` database initialized with a variable config.
    async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    async fn test_ordered_any_db_empty<D>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        let mut hasher = Standard::<Sha256>::new();
        assert_eq!(db.op_count(), 0);
        assert!(db.get_metadata().await.unwrap().is_none());
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
        assert_eq!(
            &db.root(),
            MemMmr::default().merkleize(&mut hasher, None).root()
        );

        // Make sure closing/reopening gets us back to the same state, even after adding an
        // uncommitted op, and even without a clean shutdown.
        let d1 = FixedBytes::from([1u8; 4]);
        let d2 = Sha256::fill(2u8);
        let root = db.root();
        let mut db = db.into_dirty();
        db.update(d1, d2).await.unwrap();
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), 0);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        let metadata = Sha256::fill(3u8);
        let range = db.commit(Some(metadata)).await.unwrap();
        assert_eq!(range.start, Location::new_unchecked(0));
        assert_eq!(range.end, Location::new_unchecked(1));
        assert_eq!(db.op_count(), 1); // floor op added
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        let root = db.root();
        assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

        // Re-opening the DB without a clean shutdown should still recover the correct state.
        let mut db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), 1);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));
        assert_eq!(db.root(), root);

        // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
        for _ in 1..100 {
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count() - 1, db.inactivity_floor_loc());
        }

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    async fn test_ordered_any_db_basic<D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
    ) where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        // Build a db with 2 keys and make sure updates and deletions of those keys work as
        // expected.
        let key1 = FixedBytes::from([1u8; 4]);
        let key2 = FixedBytes::from([2u8; 4]);
        let val1 = Sha256::fill(3u8);
        let val2 = Sha256::fill(4u8);

        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.into_dirty();
        assert!(db.create(key1.clone(), val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert!(db.get(&key2).await.unwrap().is_none());

        assert!(db.create(key2.clone(), val2).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val1);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        db.delete(key1.clone()).await.unwrap();
        assert!(db.get(&key1).await.unwrap().is_none());
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val2);

        let new_val = Sha256::fill(5u8);
        db.update(key1.clone(), new_val).await.unwrap();
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        db.update(key2.clone(), new_val).await.unwrap();
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), new_val);

        // 2 new keys (4 ops), 2 updates (2 ops), 1 deletion (2 ops) = 8 ops
        assert_eq!(db.op_count(), 8);
        assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let mut db = db.into_dirty();

        // Make sure create won't modify active keys.
        assert!(!db.create(key1.clone(), val1).await.unwrap());
        assert_eq!(db.get(&key1).await.unwrap().unwrap(), new_val);

        // Delete all keys.
        assert!(db.delete(key1.clone()).await.unwrap());
        assert!(db.delete(key2.clone()).await.unwrap());
        assert!(db.get(&key1).await.unwrap().is_none());
        assert!(db.get(&key2).await.unwrap().is_none());

        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let root = db.root();

        // Multiple deletions of the same key should be a no-op.
        let prev_op_count = db.op_count();
        let mut db = db.into_dirty();
        assert!(!db.delete(key1.clone()).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);
        let db = db.merkleize().await.unwrap();
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Deletions of non-existent keys should be a no-op.
        let key3 = FixedBytes::from([6u8; 4]);
        assert!(!db.delete(key3).await.unwrap());
        assert_eq!(db.op_count(), prev_op_count);

        // Make sure closing/reopening gets us back to the same state.
        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();
        let op_count = db.op_count();
        let root = db.root();
        let db = reopen_db(context.clone()).await;
        assert_eq!(db.op_count(), op_count);
        assert_eq!(db.root(), root);
        let mut db = db.into_dirty();

        // Re-activate the keys by updating them.
        db.update(key1.clone(), val1).await.unwrap();
        db.update(key2.clone(), val2).await.unwrap();
        db.delete(key1.clone()).await.unwrap();
        db.update(key2.clone(), val1).await.unwrap();
        db.update(key1.clone(), val2).await.unwrap();

        let mut db = db.merkleize().await.unwrap();
        db.commit(None).await.unwrap();

        // Confirm close/reopen gets us back to the same state.
        let op_count = db.op_count();
        let root = db.root();
        let mut db = reopen_db(context.clone()).await;

        assert_eq!(db.root(), root);
        assert_eq!(db.op_count(), op_count);

        // Commit will raise the inactivity floor, which won't affect state but will affect the
        // root.
        db.commit(None).await.unwrap();

        assert!(db.root() != root);

        // Pruning inactive ops should not affect current state or root.
        let root = db.root();
        db.prune(db.inactivity_floor_loc()).await.unwrap();
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_fixed_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_fixed_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    /// Builds a db with colliding keys to make sure the "cycle around when there are translated
    /// key collisions" edge case is exercised.
    async fn test_ordered_any_update_collision_edge_case<D>(db: D)
    where
        D: CleanAny<Key = FixedBytes<4>, Value = Digest, Digest = Digest>,
    {
        // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
        // collisions.
        let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
        let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
        // Our last must precede the others to trigger previous-key cycle around.
        let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 0u8, 0u8]);
        let val = Sha256::fill(1u8);

        let mut db = db.into_dirty();
        db.update(key1.clone(), val).await.unwrap();
        db.update(key2.clone(), val).await.unwrap();
        db.update(key3.clone(), val).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
        assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

        let db = db.merkleize().await.unwrap();
        db.destroy().await.unwrap();
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_fixed() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_fixed_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_update_collision_edge_case_variable() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_update_collision_edge_case(db).await;
        });
    }

    /// Builds a db with two colliding keys, and creates a new one between them using a batch
    /// update.
    #[test_traced("WARN")]
    fn test_ordered_any_update_batch_create_between_collisions() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_variable_db(context.clone()).await;

            // This DB uses a TwoCap so we use equivalent two byte prefixes for each key to ensure
            // collisions.
            let key1 = FixedBytes::from([0xFFu8, 0xFFu8, 5u8, 5u8]);
            let key2 = FixedBytes::from([0xFFu8, 0xFFu8, 6u8, 6u8]);
            let key3 = FixedBytes::from([0xFFu8, 0xFFu8, 7u8, 0u8]);
            let val = Sha256::fill(1u8);

            db.update(key1.clone(), val).await.unwrap();
            db.update(key3.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert!(db.get(&key2).await.unwrap().is_none());
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            // Batch-insert the middle key.
            let mut batch = db.start_batch();
            batch.update(key2.clone(), val).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key2).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&key3).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key1);

            db.destroy().await.unwrap();
        });
    }

    /// Builds a db with one key, and then creates another non-colliding key preceeding it in a
    /// batch. The prev_key search will have to "cycle around" in order to find the correct next_key
    /// value.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_with_cycling_next_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let mid_key = FixedBytes::from([0xAAu8; 4]);
            let val = Sha256::fill(1u8);

            db.create(mid_key.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Batch-insert a preceeding non-translated-colliding key.
            let preceeding_key = FixedBytes::from([0x55u8; 4]);
            let mut batch = db.start_batch();
            assert!(batch.create(preceeding_key.clone(), val).await.unwrap());
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            assert_eq!(db.get(&preceeding_key).await.unwrap().unwrap(), val);
            assert_eq!(db.get(&mid_key).await.unwrap().unwrap(), val);

            let span1 = db.get_span(&preceeding_key).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, mid_key);
            let span2 = db.get_span(&mid_key).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, preceeding_key);

            db.destroy().await.unwrap();
        });
    }

    /// Builds a db with three keys A < B < C, then batch-deletes B. Verifies that A's next_key is
    /// correctly updated to C (skipping the deleted B).
    #[test_traced("WARN")]
    fn test_ordered_any_batch_delete_middle_key() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut db = open_fixed_db(context.clone()).await;

            let key_a = FixedBytes::from([0x11u8; 4]);
            let key_b = FixedBytes::from([0x22u8; 4]);
            let key_c = FixedBytes::from([0x33u8; 4]);
            let val = Sha256::fill(1u8);

            // Create three keys in order: A -> B -> C -> A (circular)
            db.create(key_a.clone(), val).await.unwrap();
            db.create(key_b.clone(), val).await.unwrap();
            db.create(key_c.clone(), val).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify initial spans
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_b);
            let span_b = db.get_span(&key_b).await.unwrap().unwrap();
            assert_eq!(span_b.1.next_key, key_c);
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            // Batch-delete the middle key B
            let mut batch = db.start_batch();
            batch.delete(key_b.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();
            db.commit(None).await.unwrap();

            // Verify B is deleted
            assert!(db.get(&key_b).await.unwrap().is_none());

            // Verify A's next_key is now C (not B)
            let span_a = db.get_span(&key_a).await.unwrap().unwrap();
            assert_eq!(span_a.1.next_key, key_c);

            // Verify C's next_key is still A
            let span_c = db.get_span(&key_c).await.unwrap().unwrap();
            assert_eq!(span_c.1.next_key, key_a);

            db.destroy().await.unwrap();
        });
    }

    /// Batch create/delete cases where the deleted key is the previous key of a newly created key,
    /// and vice-versa.
    #[test_traced("WARN")]
    fn test_ordered_any_batch_create_delete_prev_links() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let key1 = FixedBytes::from([0x10u8, 0x00, 0x00, 0x00]);
            let key2 = FixedBytes::from([0x20u8, 0x00, 0x00, 0x00]);
            let key3 = FixedBytes::from([0x30u8, 0x00, 0x00, 0x00]);
            let val1 = Sha256::fill(1u8);
            let val2 = Sha256::fill(2u8);
            let val3 = Sha256::fill(3u8);

            // Delete the previous key of a newly created key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.delete(key1.clone()).await.unwrap();
            batch.create(key2.clone(), val2).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert!(db.get(&key1).await.unwrap().is_none());
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert_eq!(db.get(&key3).await.unwrap(), Some(val3));
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key3);
            let span3 = db.get_span(&key3).await.unwrap().unwrap();
            assert_eq!(span3.1.next_key, key2);
            db.destroy().await.unwrap();

            // Create a key that becomes the previous key of a concurrently deleted key.
            let mut db = open_variable_db(context.clone()).await;
            db.update(key1.clone(), val1).await.unwrap();
            db.update(key3.clone(), val3).await.unwrap();
            db.commit(None).await.unwrap();

            let mut batch = db.start_batch();
            batch.create(key2.clone(), val2).await.unwrap();
            batch.delete(key3.clone()).await.unwrap();
            db.write_batch(batch.into_iter()).await.unwrap();

            assert_eq!(db.get(&key1).await.unwrap(), Some(val1));
            assert_eq!(db.get(&key2).await.unwrap(), Some(val2));
            assert!(db.get(&key3).await.unwrap().is_none());
            let span1 = db.get_span(&key1).await.unwrap().unwrap();
            assert_eq!(span1.1.next_key, key2);
            let span2 = db.get_span(&key2).await.unwrap().unwrap();
            assert_eq!(span2.1.next_key, key1);
            db.destroy().await.unwrap();
        });
    }
}

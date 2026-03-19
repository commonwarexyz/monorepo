//! _Unordered_ variants of a [crate::qmdb::current] authenticated database.
//!
//! These variants do not maintain key ordering, so they cannot generate exclusion proofs. Use
//! the [super::ordered] variants if exclusion proofs are required.
//!
//! Variants:
//! - [fixed]: Variant optimized for values of fixed size.
//! - [variable]: Variant for values of variable size.

pub mod db;
pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;
pub mod variable;

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for unordered Current QMDB variants.

    use crate::{
        mmr::Location,
        qmdb::{
            any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            current::BitmapPrunedBits,
            store::tests::{TestKey, TestValue},
        },
    };
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics as _, Runner as _,
    };
    use core::future::Future;

    /// Run `test_current_db_build_small_close_reopen` against an unordered database factory.
    ///
    /// This test builds a small database, performs basic operations (create, delete, commit),
    /// and verifies state is preserved across close/reopen cycles.
    pub fn test_build_small_close_reopen<C, F, Fut>(mut open_db: F)
    where
        C: DbAny + BitmapPrunedBits,
        C::Key: TestKey,
        <C as DbAny>::Value: TestValue,
        F: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build-small".to_string();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            assert_eq!(db.inactivity_floor_loc().await, Location::new(0));
            assert_eq!(db.oldest_retained().await, 0);
            let root0 = db.root();
            drop(db);
            let mut db: C = open_db(context.with_label("second"), partition.clone()).await;
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let k1: C::Key = TestKey::from_seed(0);
            let v1: <C as DbAny>::Value = TestValue::from_seed(10);
            assert!(db.get(&k1).await.unwrap().is_none());
            let finalized = db
                .new_batch()
                .write(k1, Some(v1.clone()))
                .merkleize(None)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get_metadata().await.unwrap().is_none());
            let root1 = db.root();
            assert_ne!(root1, root0);
            drop(db);
            let mut db: C = open_db(context.with_label("third"), partition.clone()).await;
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root1);

            // Create of same key should fail (key already exists).
            assert!(db.get(&k1).await.unwrap().is_some());

            // Delete that one key.
            assert!(db.get(&k1).await.unwrap().is_some());
            let metadata: <C as DbAny>::Value = TestValue::from_seed(1);
            let finalized = db
                .new_batch()
                .write(k1, None)
                .merkleize(Some(metadata.clone()))
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            let root2 = db.root();

            // Repeated delete of same key should fail (key already deleted).
            assert!(db.get(&k1).await.unwrap().is_none());
            let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();
            db.sync().await.unwrap();
            let root3 = db.root();
            assert_ne!(root3, root2);

            // Confirm re-open preserves state.
            drop(db);
            let mut db: C = open_db(context.with_label("fourth"), partition.clone()).await;
            // Last commit had no metadata (passed None to merkleize).
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root3);

            // Confirm all activity bits are false except for the last commit.
            let bounds = db.bounds().await;
            for i in 0..*bounds.end - 1 {
                assert!(!db.get_bit(i));
            }
            assert!(db.get_bit(*bounds.end - 1));

            // Test that we can get a non-durable root.
            let finalized = db
                .new_batch()
                .write(k1, Some(v1))
                .merkleize(None)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_ne!(db.root(), root3);

            db.destroy().await.unwrap();
        });
    }
}

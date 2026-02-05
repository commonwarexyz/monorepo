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
        kv::{Deletable as _, Gettable as _, Updatable as _},
        mmr::Location,
        qmdb::{
            any::states::{CleanAny, MutableAny as _, UnmerkleizedDurableAny as _},
            current::BitmapPrunedBits,
            store::{
                batch_tests::{TestKey, TestValue},
                LogStore,
            },
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
        C: CleanAny + BitmapPrunedBits,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build_small".to_string();
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            assert_eq!(db.bounds().end, Location::new_unchecked(1));
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.oldest_retained(), 0);
            let root0 = db.root();
            drop(db);
            let db: C = open_db(context.with_label("second"), partition.clone()).await;
            assert_eq!(db.bounds().end, Location::new_unchecked(1));
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let mut db = db.into_mutable();
            let k1: C::Key = TestKey::from_seed(0);
            let v1: <C as LogStore>::Value = TestValue::from_seed(10);
            assert!(db.create(k1, v1.clone()).await.unwrap());
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            let (db, range) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 1);
            assert_eq!(*range.end, 4);
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.bounds().end, Location::new_unchecked(4)); // 1 update, 1 commit, 1 move + 1 initial commit.
            let root1 = db.root();
            assert_ne!(root1, root0);
            drop(db);
            let db: C = open_db(context.with_label("third"), partition.clone()).await;
            assert_eq!(db.bounds().end, Location::new_unchecked(4)); // 1 update, 1 commit, 1 moves + 1 initial commit.
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root1);

            // Create of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.create(k1, v1.clone()).await.unwrap());

            // Delete that one key.
            assert!(db.delete(k1).await.unwrap());
            let metadata: <C as LogStore>::Value = TestValue::from_seed(1);
            let (db, range) = db.commit(Some(metadata.clone())).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 4);
            assert_eq!(*range.end, 6);
            assert_eq!(db.bounds().end, Location::new_unchecked(6)); // 1 update, 2 commits, 1 move, 1 delete.
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            let root2 = db.root();

            // Repeated delete of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.delete(k1).await.unwrap());
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            // Commit adds a commit even for no-op, so op_count increases and root changes.
            assert_eq!(db.bounds().end, Location::new_unchecked(7));
            let root3 = db.root();
            assert_ne!(root3, root2);

            // Confirm re-open preserves state.
            drop(db);
            let db: C = open_db(context.with_label("fourth"), partition.clone()).await;
            assert_eq!(db.bounds().end, Location::new_unchecked(7));
            // Last commit had no metadata (passed None to commit).
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root3);

            // Confirm all activity bits are false except for the last commit.
            for i in 0..*db.bounds().end - 1 {
                assert!(!db.get_bit(i));
            }
            assert!(db.get_bit(*db.bounds().end - 1));

            // Test that we can get a non-durable root.
            let mut db = db.into_mutable();
            db.update(k1, v1).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            assert_ne!(db.root(), root3);

            db.destroy().await.unwrap();
        });
    }
}

//! _Ordered_ variants of a [crate::qmdb::current] authenticated database.
//!
//! These variants maintain the lexicographic-next active key for each active key, enabling
//! exclusion proofs via [ExclusionProof]. This adds overhead compared to [super::unordered]
//! variants.
//!
//! Variants:
//! - [fixed]: Variant optimized for values of fixed size.
//! - [variable]: Variant for values of variable size.

use crate::qmdb::{
    any::{ordered::Update, ValueEncoding},
    current::proof::OperationProof,
};
use commonware_cryptography::Digest;
use commonware_utils::Array;

pub mod db;
pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;
pub mod variable;

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for ordered Current QMDB variants.

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

    /// Run `test_current_db_build_small_close_reopen` against an ordered database factory.
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
            assert_eq!(db.op_count(), Location::new_unchecked(1));
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.oldest_retained(), 0);
            let root0 = db.root();
            drop(db);
            let db: C = open_db(context.with_label("second"), partition.clone()).await;
            assert_eq!(db.op_count(), Location::new_unchecked(1));
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let k1: C::Key = TestKey::from_seed(0);
            let v1: <C as LogStore>::Value = TestValue::from_seed(10);
            let mut db = db.into_mutable();
            assert!(db.create(k1, v1.clone()).await.unwrap());
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            assert_eq!(db.op_count(), Location::new_unchecked(4)); // 1 update, 1 commit, 1 move + 1 initial commit.
            assert!(db.get_metadata().await.unwrap().is_none());
            let root1 = db.root();
            assert_ne!(root1, root0);

            drop(db);
            let db: C = open_db(context.with_label("third"), partition.clone()).await;
            assert_eq!(db.op_count(), Location::new_unchecked(4));
            assert_eq!(db.root(), root1);

            // Create of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.create(k1, v1.clone()).await.unwrap());

            // Delete that one key.
            assert!(db.delete(k1).await.unwrap());

            let metadata: <C as LogStore>::Value = TestValue::from_seed(1);
            let (db, _) = db.commit(Some(metadata.clone())).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            assert_eq!(db.op_count(), Location::new_unchecked(6)); // 1 update, 2 commits, 1 move, 1 delete.
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(5));
            let root2 = db.root();

            drop(db);
            let db: C = open_db(context.with_label("fourth"), partition.clone()).await;
            assert_eq!(db.op_count(), Location::new_unchecked(6));
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(5));
            assert_eq!(db.root(), root2);

            // Repeated delete of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.delete(k1).await.unwrap());
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
            let root3 = db.root();
            assert_ne!(root3, root2);

            // Confirm all activity bits except the last are false.
            for i in 0..*db.op_count() - 1 {
                assert!(!db.get_bit(i));
            }
            assert!(db.get_bit(*db.op_count() - 1));

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

/// Proof that a key has no assigned value in the database.
///
/// When the database has active keys, exclusion is proven by showing the key falls within a span
/// between two adjacent active keys. Otherwise exclusion is proven by showing the database contains
/// no active keys through the most recent commit operation.
///
/// Verify using [Db::verify_exclusion_proof](fixed::Db::verify_exclusion_proof).
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProof<K: Array, V: ValueEncoding, D: Digest, const N: usize> {
    /// Proves that two keys are active in the database and adjacent to each other in the key
    /// ordering. Any key falling between them (non-inclusively) can be proven excluded.
    KeyValue(OperationProof<D, N>, Update<K, V>),

    /// Proves that the database has no active keys, allowing any key to be proven excluded.
    /// Specifically, the proof establishes the most recent Commit operation has an activity floor
    /// equal to its own location, which is a necessary and sufficient condition for an empty
    /// database.
    Commit(OperationProof<D, N>, Option<V::Value>),
}

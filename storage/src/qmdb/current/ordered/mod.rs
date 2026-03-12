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
    operation::Key,
};
use commonware_cryptography::Digest;

pub mod db;
pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;
pub mod variable;

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for ordered Current QMDB variants.

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

    /// Run `test_current_db_build_small_close_reopen` against an ordered database factory.
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

            drop(db);
            let mut db: C = open_db(context.with_label("fourth"), partition.clone()).await;
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            assert_eq!(db.root(), root2);

            // Repeated delete of same key should fail (key already deleted).
            assert!(db.get(&k1).await.unwrap().is_none());
            let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();
            db.commit().await.unwrap();
            let root3 = db.root();
            assert_ne!(root3, root2);

            // Confirm all activity bits except the last are false.
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

/// Proof that a key has no assigned value in the database.
///
/// When the database has active keys, exclusion is proven by showing the key falls within a span
/// between two adjacent active keys. Otherwise exclusion is proven by showing the database contains
/// no active keys through the most recent commit operation.
///
/// Verify using [Db::verify_exclusion_proof](fixed::Db::verify_exclusion_proof).
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProof<K: Key, V: ValueEncoding, D: Digest, const N: usize> {
    /// Proves that two keys are active in the database and adjacent to each other in the key
    /// ordering. Any key falling between them (non-inclusively) can be proven excluded.
    KeyValue(OperationProof<D, N>, Update<K, V>),

    /// Proves that the database has no active keys, allowing any key to be proven excluded.
    /// Specifically, the proof establishes the most recent Commit operation has an activity floor
    /// equal to its own location, which is a necessary and sufficient condition for an empty
    /// database.
    Commit(OperationProof<D, N>, Option<V::Value>),
}

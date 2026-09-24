//! Immutable [`compact::Db`] db.
//!
//! See [`crate::qmdb::compact`] for the shared implementation.

use super::operation::Operation;
pub use crate::qmdb::compact::Config;
use crate::{
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, compact, operation::Key},
};
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::collections::BTreeMap;

impl<F: Family, K: Key, V: ValueEncoding> compact::sealed::Sealed for Operation<F, K, V> {}

impl<F: Family, K: Key, V: ValueEncoding> compact::Operation<F> for Operation<F, K, V>
where
    Self: CodecShared,
{
    type Metadata = V::Value;
    type Mutations = BTreeMap<K, V::Value>;
    const NAME: &'static str = "immutable";

    fn commit(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Self {
        Self::Commit(metadata, inactivity_floor_loc)
    }

    fn mutation((key, value): (K, V::Value)) -> Self {
        Self::Set(key, value)
    }

    fn metadata(&self) -> Option<&V::Value> {
        match self {
            Self::Commit(metadata, _) => metadata.as_ref(),
            Self::Set(..) => None,
        }
    }
}

/// An immutable compact db.
pub type Db<F, E, K, V, H, S> = compact::Db<F, E, Operation<F, K, V>, H, S>;

/// A speculative batch for an immutable compact db.
pub type UnmerkleizedBatch<F, H, K, V, S> = compact::UnmerkleizedBatch<F, H, Operation<F, K, V>, S>;

/// A speculative batch for an immutable compact db whose root digest has been computed.
pub type MerkleizedBatch<F, D, K, V, S> = compact::MerkleizedBatch<F, D, Operation<F, K, V>, S>;

impl<F, H, K, V, S> UnmerkleizedBatch<F, H, K, V, S>
where
    F: Family,
    H: Hasher,
    K: Key,
    V: ValueEncoding,
    S: Strategy,
    Operation<F, K, V>: CodecShared,
{
    /// Set `key` to `value`. A later `set` of the same key in this batch replaces it.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.mutations.insert(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{Location, mmr},
        qmdb::{
            any::value::FixedEncoding,
            compact::db::tests::{TestBatch, TestOperation, compact_db_tests, open_db},
        },
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    type TestOp = Operation<mmr::Family, Digest, FixedEncoding<Digest>>;

    impl TestOperation for TestOp {
        fn value(seed: u64) -> Digest {
            Sha256::hash(&[&seed.to_le_bytes()])
        }

        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self> {
            batch.set(Sha256::hash(&[&seed.to_be_bytes()]), Self::value(seed))
        }
    }

    compact_db_tests!(TestOp);

    /// Setting a key twice in one batch keeps the later value and emits one operation.
    #[test_traced("INFO")]
    fn test_compact_set_same_key_twice_keeps_last() {
        deterministic::Runner::default().start(|context| async move {
            let key = Sha256::hash(&[b"key"]);
            let (first, last) = (Sha256::fill(1), Sha256::fill(2));

            let twice = open_db::<TestOp>(context.child("twice"), "compact-set-twice").await;
            let floor = twice.inactivity_floor_loc();
            let batch = twice
                .new_batch()
                .set(key, first)
                .set(key, last)
                .merkleize(&twice, None, floor)
                .await;
            let (twice, range) = twice.apply_batch(batch).await.unwrap();
            assert_eq!(range, Location::new(1)..Location::new(3));

            let once = open_db::<TestOp>(context.child("once"), "compact-set-once").await;
            let batch = once
                .new_batch()
                .set(key, last)
                .merkleize(&once, None, floor)
                .await;
            let (once, _) = once.apply_batch(batch).await.unwrap();
            assert_eq!(twice.root(), once.root());
        });
    }

    /// Sets are applied in key order: insertion order does not affect the root.
    #[test_traced("INFO")]
    fn test_compact_set_order_is_insignificant() {
        deterministic::Runner::default().start(|context| async move {
            let (k1, k2) = (Sha256::hash(&[b"k1"]), Sha256::hash(&[b"k2"]));
            let (v1, v2) = (Sha256::fill(1), Sha256::fill(2));

            let forward = open_db::<TestOp>(context.child("forward"), "compact-set-forward").await;
            let floor = forward.inactivity_floor_loc();
            let batch = forward
                .new_batch()
                .set(k1, v1)
                .set(k2, v2)
                .merkleize(&forward, None, floor)
                .await;
            let (forward, _) = forward.apply_batch(batch).await.unwrap();

            let reverse = open_db::<TestOp>(context.child("reverse"), "compact-set-reverse").await;
            let batch = reverse
                .new_batch()
                .set(k2, v2)
                .set(k1, v1)
                .merkleize(&reverse, None, floor)
                .await;
            let (reverse, _) = reverse.apply_batch(batch).await.unwrap();
            assert_eq!(forward.size(), reverse.size());
            assert_eq!(forward.root(), reverse.root());
        });
    }
}

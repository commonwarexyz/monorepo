//! The keyless compact db: a [`db::Db`] whose batches append values.
//!
//! See [`crate::qmdb::compact::db`] for the shared implementation. Commits carry an inactivity
//! floor for wire-format compatibility with [`crate::qmdb::keyless::Keyless`].

use super::operation::Operation;
pub use crate::qmdb::compact::Config;
use crate::{
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, compact::db},
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

impl<F: Family, V: ValueEncoding> db::sealed::Sealed for Operation<F, V> {}

impl<F: Family, V: ValueEncoding> db::Variant<F> for Operation<F, V> {
    type Metadata = V::Value;
    type Mutations = Vec<V::Value>;
    const NAME: &'static str = "keyless";

    fn commit_op(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Self {
        Self::Commit(metadata, inactivity_floor_loc)
    }

    fn into_commit(self) -> Option<(Option<V::Value>, Location<F>)> {
        match self {
            Self::Commit(metadata, inactivity_floor_loc) => Some((metadata, inactivity_floor_loc)),
            Self::Append(_) => None,
        }
    }

    fn into_ops(mutations: Self::Mutations) -> impl ExactSizeIterator<Item = Self> {
        mutations.into_iter().map(Self::Append)
    }
}

/// A keyless compact db.
pub type Db<F, E, V, H, C, S> = db::Db<F, E, Operation<F, V>, H, C, S>;

/// A speculative batch for a keyless compact db.
pub type UnmerkleizedBatch<F, H, V, S> = db::UnmerkleizedBatch<F, H, Operation<F, V>, S>;

/// A speculative batch for a keyless compact db whose root digest has been computed.
pub type MerkleizedBatch<F, D, V, S> = db::MerkleizedBatch<F, D, Operation<F, V>, S>;

impl<F, H, V, S> UnmerkleizedBatch<F, H, V, S>
where
    F: Family,
    H: Hasher,
    V: ValueEncoding,
    S: Strategy,
{
    /// Append `value`.
    pub fn append(mut self, value: V::Value) -> Self {
        self.mutations.push(value);
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
            compact::db::tests::{TestBatch, TestVariant, compact_db_tests, open_db},
        },
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::sequence::U64;

    type TestVariantMarker = Operation<mmr::Family, FixedEncoding<U64>>;

    impl TestVariant for TestVariantMarker {
        fn value(seed: u64) -> U64 {
            U64::new(seed)
        }

        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self> {
            batch.append(U64::new(seed))
        }
    }

    compact_db_tests!(TestVariantMarker);

    /// Appends are ordered: the same values in a different order give a different root.
    #[test_traced("INFO")]
    fn test_compact_append_order_is_significant() {
        deterministic::Runner::default().start(|context| async move {
            let forward =
                open_db::<TestVariantMarker>(context.child("forward"), "compact-append-forward")
                    .await;
            let floor = forward.inactivity_floor_loc();
            let batch = forward
                .new_batch()
                .append(U64::new(1))
                .append(U64::new(2))
                .merkleize(&forward, None, floor)
                .await;
            let (forward, range) = forward.apply_batch(batch).await.unwrap();
            assert_eq!(range, Location::new(1)..Location::new(4));

            let reverse =
                open_db::<TestVariantMarker>(context.child("reverse"), "compact-append-reverse")
                    .await;
            let batch = reverse
                .new_batch()
                .append(U64::new(2))
                .append(U64::new(1))
                .merkleize(&reverse, None, floor)
                .await;
            let (reverse, _) = reverse.apply_batch(batch).await.unwrap();
            assert_eq!(forward.size(), reverse.size());
            assert_ne!(forward.root(), reverse.root());
        });
    }
}

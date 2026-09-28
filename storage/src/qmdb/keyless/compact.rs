//! Keyless [`compact::Db`] db.
//!
//! See [`crate::qmdb::compact`] for the shared implementation.

use super::operation::Operation;
pub use crate::qmdb::compact::Config;
use crate::{
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, compact},
};
use commonware_codec::CodecShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;

impl<F: Family, V: ValueEncoding> compact::sealed::Sealed for Operation<F, V> {}

impl<F: Family, V: ValueEncoding> compact::Operation<F> for Operation<F, V>
where
    Self: CodecShared,
{
    type Metadata = V::Value;
    type Mutations = Vec<V::Value>;
    const NAME: &'static str = "keyless";

    fn commit(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Self {
        Self::Commit(metadata, inactivity_floor_loc)
    }

    fn mutation(value: V::Value) -> Self {
        Self::Append(value)
    }

    fn metadata(&self) -> Option<&V::Value> {
        match self {
            Self::Commit(metadata, _) => metadata.as_ref(),
            Self::Append(_) => None,
        }
    }
}

/// A keyless compact db.
pub type Db<F, E, V, H, S> = compact::Db<F, E, Operation<F, V>, H, S>;

/// A speculative batch for a keyless compact db.
pub type UnmerkleizedBatch<F, H, V, S> = compact::UnmerkleizedBatch<F, H, Operation<F, V>, S>;

/// A speculative batch for a keyless compact db whose root digest has been computed.
pub type MerkleizedBatch<F, D, V, S> = compact::MerkleizedBatch<F, D, Operation<F, V>, S>;

impl<F, H, V, S> UnmerkleizedBatch<F, H, V, S>
where
    F: Family,
    H: Hasher,
    V: ValueEncoding,
    S: Strategy,
    Operation<F, V>: CodecShared,
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
        merkle::{Location, mmb, mmr},
        qmdb::{
            any::value::{FixedEncoding, VariableEncoding},
            compact::db::tests::{TestBatch, TestOperation, compact_db_tests, open_db},
        },
    };
    use commonware_codec::RangeCfg;
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::sequence::U64;

    type TestOp<F = mmr::Family> = Operation<F, FixedEncoding<U64>>;

    impl<F: Family> TestOperation for TestOp<F> {
        type Family = F;

        fn codec_config() {}

        fn value(seed: u64) -> U64 {
            U64::new(seed)
        }

        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self> {
            batch.append(U64::new(seed))
        }

        fn op(seed: u64) -> Self {
            Self::Append(U64::new(seed))
        }
    }

    type VariableTestOp<F = mmr::Family> = Operation<F, VariableEncoding<Vec<u8>>>;

    impl<F: Family> TestOperation for VariableTestOp<F> {
        type Family = F;

        fn codec_config() -> (RangeCfg<usize>, ()) {
            ((..=64).into(), ())
        }

        fn value(seed: u64) -> Vec<u8> {
            seed.to_be_bytes().to_vec()
        }

        fn mutate(batch: TestBatch<Self>, seed: u64) -> TestBatch<Self> {
            batch.append(Self::value(seed))
        }

        fn op(seed: u64) -> Self {
            Self::Append(Self::value(seed))
        }
    }

    compact_db_tests!(TestOp);

    mod mmb_tests {
        use super::*;

        compact_db_tests!(TestOp<mmb::Family>);
    }

    mod variable_tests {
        use super::*;

        compact_db_tests!(VariableTestOp);
    }

    /// Appends are ordered: the same values in a different order give a different root.
    #[test_traced("INFO")]
    fn test_compact_append_order_is_significant() {
        deterministic::Runner::default().start(|context| async move {
            let forward =
                open_db::<TestOp>(context.child("forward"), "compact-append-forward").await;
            let floor = forward.inactivity_floor_loc();
            let batch = forward
                .new_batch()
                .append(U64::new(1))
                .append(U64::new(2))
                .merkleize(&forward, None, floor)
                .await
                .unwrap();
            let (forward, range) = forward.apply_batch(batch).await.unwrap();
            assert_eq!(range, Location::new(1)..Location::new(4));

            let reverse =
                open_db::<TestOp>(context.child("reverse"), "compact-append-reverse").await;
            let batch = reverse
                .new_batch()
                .append(U64::new(2))
                .append(U64::new(1))
                .merkleize(&reverse, None, floor)
                .await
                .unwrap();
            let (reverse, _) = reverse.apply_batch(batch).await.unwrap();
            assert_eq!(forward.size(), reverse.size());
            assert_ne!(forward.root(), reverse.root());
        });
    }
}

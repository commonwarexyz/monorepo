//! _Ordered_ variants of a [crate::qmdb::current] authenticated database.
//!
//! These variants maintain the lexicographic-next active key for each active key, enabling
//! exclusion proofs via [ExclusionProof]. This adds overhead compared to [super::unordered]
//! variants.
//!
//! Variants:
//! - [fixed]: Variant optimized for values of fixed size.

use crate::qmdb::{
    any::{ordered::fixed::Update, FixedValue},
    current::proof::OperationProof,
};
use commonware_cryptography::Digest;
use commonware_utils::Array;

pub mod fixed;
#[cfg(any(test, feature = "test-traits"))]
mod test_trait_impls;

/// Proof that a key has no assigned value in the database.
///
/// When the database has active keys, exclusion is proven by showing the key falls within a span
/// between two adjacent active keys. Otherwise exclusion is proven by showing the database contains
/// no active keys through the most recent commit operation.
///
/// Verify using [Db::verify_exclusion_proof](fixed::Db::verify_exclusion_proof).
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProof<K: Array, V: FixedValue, D: Digest, const N: usize> {
    /// Proves that two keys are active in the database and adjacent to each other in the key
    /// ordering. Any key falling between them (non-inclusively) can be proven excluded.
    KeyValue(OperationProof<D, N>, Update<K, V>),

    /// Proves that the database has no active keys, allowing any key to be proven excluded.
    /// Specifically, the proof establishes the most recent Commit operation has an activity floor
    /// equal to its own location, which is a necessary and sufficient condition for an empty
    /// database.
    Commit(OperationProof<D, N>, Option<V>),
}

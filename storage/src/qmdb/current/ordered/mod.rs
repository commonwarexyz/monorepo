//! _Ordered_ variants of a [crate::qmdb::current] authenticated database. These variants maintain
//! the lexicographic-next active key of each active key, allowing for exclusion proofs.

use crate::qmdb::{
    any::{ordered::fixed::Update, FixedValue},
    current::proof::OperationProof,
};
use commonware_cryptography::Digest;
use commonware_utils::Array;

pub mod fixed;

/// Proof information for verifying a key is not currently active in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExclusionProof<K: Array, V: FixedValue, D: Digest, const N: usize> {
    /// For the KeyValue variant, we're proving that a span over the keyspace exists in the
    /// database, allowing one to prove any key falling within that span (but not at the beginning)
    /// is excluded.
    KeyValue(OperationProof<D, N>, Update<K, V>),

    /// For the Commit variant, we're proving that there exists a Commit operation in the database
    /// that establishes an inactivity floor equal to its own location. This implies there are no
    /// active keys, and therefore any key can be proven excluded against it. The wrapped values
    /// consist of the location of the commit operation and its digest.
    Commit(OperationProof<D, N>, Option<V>),
}

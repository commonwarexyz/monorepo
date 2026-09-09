//! Unordered current proofs with fixed-size or runtime-sized bitmap chunks.

/// Proofs with fixed-size bitmap chunks.
pub mod constant {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, D, const N: usize> =
        crate::qmdb::current::proof::constant::OperationProof<F, D, N>;
}

/// Proofs with runtime-sized bitmap chunks.
pub mod dynamic {
    /// Proof information for verifying a key has a particular value in the database.
    pub type KeyValueProof<F, D> = crate::qmdb::current::proof::dynamic::OperationProof<F, D>;
}

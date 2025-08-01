use crate::mmr::verification::Proof;
use commonware_cryptography::Digest;

/// Verifies proofs over operation batches
pub trait Verifier<Op, D: Digest> {
    type Error: std::error::Error + Send + 'static;

    /// Verify that a proof is valid for the given operations and target root
    fn verify_proof(
        &mut self,
        proof: &Proof<D>,
        start_loc: u64,
        operations: &[Op],
        target_root: &D,
    ) -> bool;

    /// Extract pinned nodes from a proof if needed for future verifications
    fn extract_pinned_nodes(
        &mut self,
        proof: &Proof<D>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<Option<Vec<D>>, Self::Error>;
}

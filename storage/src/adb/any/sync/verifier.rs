use crate::{
    adb::{any::verify_proof, sync},
    mmr::{hasher::Standard, iterator::leaf_num_to_pos, verification::Proof},
    store::operation::Fixed,
};
use commonware_cryptography::Hasher;
use commonware_utils::Array;

/// Verifier for Any database operations using the database's built-in proof verification
pub struct Verifier<H>
where
    H: Hasher,
{
    hasher: Standard<H>,
}

impl<H> Verifier<H>
where
    H: Hasher,
{
    /// Create a new verifier with the given hasher
    pub fn new(hasher: Standard<H>) -> Self {
        Self { hasher }
    }
}

impl<K, V, H> sync::Verifier<Fixed<K, V>, H::Digest> for Verifier<H>
where
    K: Array,
    V: Array,
    H: Hasher,
{
    type Error = crate::mmr::Error;

    fn verify_proof(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations: &[Fixed<K, V>],
        target_root: &H::Digest,
    ) -> bool {
        verify_proof(&mut self.hasher, proof, start_loc, operations, target_root)
    }

    fn extract_pinned_nodes(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<Option<Vec<H::Digest>>, Self::Error> {
        // Always try to extract pinned nodes - the engine will decide when to use them
        let start_pos_mmr = leaf_num_to_pos(start_loc);
        let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
        proof
            .extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
            .map(Some)
    }
}

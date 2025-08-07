use crate::{
    adb::{operation::Variable, sync},
    mmr::{hasher::Standard, verification::Proof},
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_utils::Array;

/// Verifier for Immutable database operations
pub struct Verifier<H: Hasher> {
    hasher: Standard<H>,
}

impl<H: Hasher> Verifier<H> {
    pub fn new(hasher: Standard<H>) -> Self {
        Self { hasher }
    }
}

impl<K, V, H> sync::Verifier<Variable<K, V>, H::Digest> for Verifier<H>
where
    K: Array,
    V: Codec,
    H: Hasher,
{
    type Error = crate::mmr::Error;

    fn verify_proof(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations: &[Variable<K, V>],
        target_root: &H::Digest,
    ) -> bool {
        // Use the free function verify_proof from immutable module
        crate::adb::immutable::verify_proof(
            &mut self.hasher,
            proof,
            start_loc,
            operations,
            target_root,
        )
    }

    fn extract_pinned_nodes(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<Option<Vec<H::Digest>>, Self::Error> {
        // Always try to extract pinned nodes - the engine will decide when to use them
        use crate::mmr::iterator::leaf_num_to_pos;
        let start_pos_mmr = leaf_num_to_pos(start_loc);
        let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
        proof
            .extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
            .map(Some)
    }
}

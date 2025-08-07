use crate::{
    adb::{any::Any, operation::Fixed, sync},
    mmr::{hasher::Standard, iterator::leaf_num_to_pos, verification::Proof},
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_utils::Array;

/// Verifier for Any database operations using the database's built-in proof verification
pub struct Verifier<E, K, V, H, T>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    hasher: Standard<H>,
    _phantom: std::marker::PhantomData<(E, K, V, T)>,
}

impl<E, K, V, H, T> Verifier<E, K, V, H, T>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    /// Create a new verifier with the given hasher
    pub fn new(hasher: Standard<H>) -> Self {
        Self {
            hasher,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E, K, V, H, T> sync::Verifier<Fixed<K, V>, H::Digest> for Verifier<E, K, V, H, T>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    type Error = crate::mmr::Error;

    fn verify_proof(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations: &[Fixed<K, V>],
        target_root: &H::Digest,
    ) -> bool {
        Any::<E, K, V, H, T>::verify_proof(
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
        let start_pos_mmr = leaf_num_to_pos(start_loc);
        let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
        proof
            .extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
            .map(Some)
    }
}

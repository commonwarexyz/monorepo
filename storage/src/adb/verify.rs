use crate::mmr::{hasher::Standard, iterator::leaf_num_to_pos, verification::Proof};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};

/// Verify that a proof is valid for a range of operations and a target root
pub fn verify_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let start_pos = leaf_num_to_pos(start_loc);
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion(hasher, &elements, start_pos, target_root)
}

/// Extract pinned nodes from the proof starting at `start_loc`.
pub fn extract_pinned_nodes<D: Digest>(
    proof: &Proof<D>,
    start_loc: u64,
    operations_len: u64,
) -> Result<Vec<D>, crate::mmr::Error> {
    let start_pos_mmr = leaf_num_to_pos(start_loc);
    let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
    proof.extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
}

/// Verify that a proof is valid for a range of operations and extract all digests (and their positions)
/// in the range of the proof.
pub fn verify_proof_and_extract_digests<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    target_root: &D,
) -> Result<Vec<(u64, D)>, crate::mmr::Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    let start_pos = leaf_num_to_pos(start_loc);
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    proof.verify_range_inclusion_and_extract_digests(hasher, &elements, start_pos, target_root)
}

/// Calculate the digests required to construct a proof for a range of operations.
pub fn digests_required_for_proof<D: Digest>(size: u64, start_loc: u64, end_loc: u64) -> Vec<u64> {
    let size = leaf_num_to_pos(size);
    let start_pos = leaf_num_to_pos(start_loc);
    let end_pos = leaf_num_to_pos(end_loc);
    Proof::<D>::nodes_required_for_range_proof(size, start_pos, end_pos)
}

/// Construct a proof from a size and a list of digests.
///
/// To compute the digests required for a proof, use [digests_required_for_proof].
pub fn construct_proof<D: Digest>(size: u64, digests: Vec<D>) -> Proof<D> {
    let size = leaf_num_to_pos(size);
    Proof::<D> { size, digests }
}

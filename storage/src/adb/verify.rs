use crate::mmr::{
    hasher::Standard,
    iterator::leaf_num_to_pos,
    verification::{Proof, ProofStore},
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};

/// Verify that a [Proof] is valid for a range of operations and a target root
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

/// Extract pinned nodes from the [Proof] starting at `start_loc`.
pub fn extract_pinned_nodes<D: Digest>(
    proof: &Proof<D>,
    start_loc: u64,
    operations_len: u64,
) -> Result<Vec<D>, crate::mmr::Error> {
    let start_pos_mmr = leaf_num_to_pos(start_loc);
    let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
    proof.extract_pinned_nodes(start_pos_mmr, end_pos_mmr)
}

/// Verify that a [Proof] is valid for a range of operations and extract all digests (and their positions)
/// in the range of the [Proof].
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

/// Calculate the digests required to construct a [Proof] for a range of operations.
pub fn digests_required_for_proof<D: Digest>(size: u64, start_loc: u64, end_loc: u64) -> Vec<u64> {
    let size = leaf_num_to_pos(size);
    let start_pos = leaf_num_to_pos(start_loc);
    let end_pos = leaf_num_to_pos(end_loc);
    Proof::<D>::nodes_required_for_range_proof(size, start_pos, end_pos)
}

/// Construct a [Proof] from a size and a list of digests.
///
/// To compute the digests required for a [Proof], use [digests_required_for_proof].
pub fn construct_proof<D: Digest>(size: u64, digests: Vec<D>) -> Proof<D> {
    let size = leaf_num_to_pos(size);
    Proof::<D> { size, digests }
}

/// Verify a [Proof] and convert it into a [ProofStore].
pub fn create_proof_store<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    root: &D,
) -> Result<ProofStore<D>, crate::mmr::Error>
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // Convert operation location to MMR position
    let start_pos = leaf_num_to_pos(start_loc);

    // Encode operations for verification
    let elements: Vec<Vec<u8>> = operations.iter().map(|op| op.encode().to_vec()).collect();

    // Create ProofStore by verifying the proof and extracting all digests
    ProofStore::new(hasher, proof, &elements, start_pos, root)
}

/// Create a [ProofStore] from a list of digests (output by [verify_proof_and_extract_digests]).
///
/// If you have not yet verified the proof, use [create_proof_store] instead.
pub fn create_proof_store_from_digests<D: Digest>(
    proof: &Proof<D>,
    digests: Vec<(u64, D)>,
) -> ProofStore<D> {
    ProofStore::new_from_digests(proof.size, digests)
}

/// Generate a Multi-Proof for specific operations (identified by location) from a [ProofStore].
pub async fn generate_multi_proof<D: Digest>(
    proof_store: &ProofStore<D>,
    locations: &[u64],
) -> Result<Proof<D>, crate::mmr::Error> {
    // Convert locations to MMR positions
    let positions: Vec<u64> = locations.iter().map(|&loc| leaf_num_to_pos(loc)).collect();

    // Generate the proof
    Proof::multi_proof(proof_store, &positions).await
}

/// Verify a Multi-Proof for operations at specific locations.
pub fn verify_multi_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    operations: &[(u64, Op)],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // Encode operations and convert locations to positions
    let elements = operations
        .iter()
        .map(|(loc, op)| (op.encode(), leaf_num_to_pos(*loc)))
        .collect::<Vec<_>>();

    // Verify the proof
    proof.verify_multi_inclusion(hasher, &elements, target_root)
}

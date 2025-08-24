use crate::mmr::{hasher::{Hasher as MmrHasher, Standard}, iterator::leaf_num_to_pos, verification::Proof};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
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

/// Verify that a proof is valid for a range of mixed operations and pre-computed digests
pub fn verify_proof_mixed<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[FilteredOperation<Op, D>],
    target_root: &D,
) -> bool
where
    Op: Encode,
    H: Hasher<Digest = D>,
    D: Digest,
{
    use crate::mmr::verification::MixedLeaf;
    
    let start_pos = leaf_num_to_pos(start_loc);
    
    // First encode all included operations
    let encoded_ops: Vec<Vec<u8>> = operations
        .iter()
        .map(|op| match op {
            FilteredOperation::Included(op) => op.encode().to_vec(),
            FilteredOperation::Digest(_) => Vec::new(), // Won't be used
        })
        .collect();
    
    // Convert FilteredOperation to MixedLeaf for the MMR verification
    let mixed_leaves: Vec<MixedLeaf<Vec<u8>, D>> = operations
        .iter()
        .zip(encoded_ops.iter())
        .map(|(op, encoded)| match op {
            FilteredOperation::Included(_) => MixedLeaf::Element(encoded),
            FilteredOperation::Digest(digest) => MixedLeaf::Digest(digest.clone()),
        })
        .collect();
    
    // Use the new mixed verification method
    proof.verify_range_inclusion_mixed(hasher, &mixed_leaves, start_pos, target_root)
}

/// Create a filtered proof that includes only specified operations while maintaining
/// proof validity by replacing filtered operations with their digests.
///
/// This is useful for creating proofs that only reveal certain operations while
/// still allowing verification against the root.
///
/// # Arguments
/// * `hasher` - The hasher to use for computing digests
/// * `proof` - The original proof containing all operations
/// * `start_loc` - The starting location of operations in the tree
/// * `operations` - All operations in the range
/// * `indices_to_include` - Indices of operations to include (0-based from start of operations slice)
/// * `target_root` - The root to verify against
///
/// # Returns
/// A tuple of (filtered_proof, filtered_operations) where:
/// - `filtered_proof` - A proof that can verify the filtered operations
/// - `filtered_operations` - Operations with filtered ones replaced by digest placeholders
pub fn create_filtered_proof<Op, H, D>(
    hasher: &mut Standard<H>,
    proof: &Proof<D>,
    start_loc: u64,
    operations: &[Op],
    indices_to_include: &[usize],
    target_root: &D,
) -> Result<(Proof<D>, Vec<FilteredOperation<Op, D>>), crate::mmr::Error>
where
    Op: Encode + Clone,
    H: Hasher<Digest = D>,
    D: Digest,
{
    // First, verify the original proof and extract all digests
    let start_pos = leaf_num_to_pos(start_loc);
    let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
    let node_digests = proof.verify_range_inclusion_and_extract_digests(hasher, &elements, start_pos, target_root)?;
    
    // Create a map of position to digest for quick lookup
    let digest_map: std::collections::HashMap<u64, D> = node_digests.into_iter().collect();
    
    // Create filtered operations list
    let mut filtered_ops = Vec::with_capacity(operations.len());
    for (i, op) in operations.iter().enumerate() {
        if indices_to_include.contains(&i) {
            filtered_ops.push(FilteredOperation::Included(op.clone()));
        } else {
            // Get the digest for this operation's position
            let op_pos = leaf_num_to_pos(start_loc + i as u64);
            let op_digest = digest_map.get(&op_pos)
                .cloned()
                .unwrap_or_else(|| {
                    let h = MmrHasher::<H>::inner(hasher);
                    h.update(&op.encode());
                    h.finalize()
                });
            filtered_ops.push(FilteredOperation::Digest(op_digest));
        }
    }
    
    // The proof remains the same since it contains all necessary digests
    // for verifying any subset of operations
    Ok((proof.clone(), filtered_ops))
}

/// Represents an operation that may be filtered out and replaced with its digest
#[derive(Clone, Debug)]
pub enum FilteredOperation<Op, D> {
    /// The full operation is included
    Included(Op),
    /// The operation was filtered and replaced with its digest
    Digest(D),
}

impl<Op: Encode, D: Digest> FilteredOperation<Op, D> {
    /// Get the encoded bytes for proof verification
    /// For Included operations, encode them
    /// For Digest operations, encode the digest (which is what the proof expects for that leaf)
    pub fn encode_for_proof(&self) -> Vec<u8> {
        match self {
            FilteredOperation::Included(op) => op.encode().to_vec(),
            FilteredOperation::Digest(digest) => digest.encode().to_vec(),
        }
    }
}

impl<Op: Write, D: Write> Write for FilteredOperation<Op, D> {
    fn write(&self, writer: &mut impl bytes::BufMut) {
        match self {
            FilteredOperation::Included(op) => {
                0u8.write(writer);
                op.write(writer);
            }
            FilteredOperation::Digest(digest) => {
                1u8.write(writer);
                digest.write(writer);
            }
        }
    }
}

impl<Op: Read, D: Read> Read for FilteredOperation<Op, D> {
    type Cfg = (Op::Cfg, D::Cfg);

    fn read_cfg(reader: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let discriminator = u8::read(reader)?;
        match discriminator {
            0 => Ok(FilteredOperation::Included(Op::read_cfg(reader, &cfg.0)?)),
            1 => Ok(FilteredOperation::Digest(D::read_cfg(reader, &cfg.1)?)),
            _ => Err(commonware_codec::Error::InvalidEnum(discriminator)),
        }
    }
}

impl<Op: EncodeSize, D: EncodeSize> EncodeSize for FilteredOperation<Op, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            FilteredOperation::Included(op) => op.encode_size(),
            FilteredOperation::Digest(digest) => digest.encode_size(),
        }
    }
}

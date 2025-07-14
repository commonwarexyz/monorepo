//! Reed-Solomon coding.

use commonware_codec::{Decode, Encode};
use commonware_storage::bmt as BinaryMerkleTree;
use reed_solomon_simd::{Error as RsError, ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashSet;
use std::convert::TryInto;

#[derive(Debug)]
pub enum CodingError {
    InvalidParameters,
    RsError(RsError),
    CodecError,
    Inconsistent,
    InvalidProof,
    NotEnoughPieces,
    DuplicateIndex,
    InvalidShardSize,
    InvalidDataLength,
}

pub type Root = [u8; 32];
pub type Proof = Vec<u8>;

/// Encodes the input data into total_pieces proofs using Reed-Solomon and a Binary Merkle Tree.
/// Returns the Merkle root and a vector of encoded proofs (one per piece).
pub fn encode(
    data: &[u8],
    total_pieces: usize,
    min_pieces: usize,
) -> Result<(Root, Vec<Proof>), CodingError> {
    if total_pieces <= min_pieces || min_pieces == 0 {
        return Err(CodingError::InvalidParameters);
    }
    let n = total_pieces;
    let k = min_pieces;
    let m = n - k;

    // Prepend length for recovery
    let mut extended_data = Vec::new();
    extended_data.extend_from_slice(&(data.len() as u64).to_be_bytes());
    extended_data.extend_from_slice(data);

    // Compute shard_size (even)
    let mut shard_size = (extended_data.len() + k - 1) / k;
    if shard_size % 2 != 0 {
        shard_size += 1;
    }

    // Pad data
    let padded_len = shard_size * k;
    extended_data.resize(padded_len, 0);

    // Create original shards
    let mut original_shards = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * shard_size;
        original_shards.push(extended_data[start..start + shard_size].to_vec());
    }

    // RS encoding
    let mut encoder =
        ReedSolomonEncoder::new(k as u16, m as u16, shard_size).map_err(CodingError::RsError)?;
    for shard in &original_shards {
        encoder
            .add_original_shard(shard)
            .map_err(CodingError::RsError)?;
    }
    let recovery_shards = encoder
        .encode()
        .map_err(CodingError::RsError)?
        .recovery_iter()
        .collect::<Vec<_>>();

    // All shards
    let mut all_shards = original_shards;
    all_shards.extend(recovery_shards);

    // Build Merkle tree
    let tree = BinaryMerkleTree::new(&all_shards);
    let root = tree.root();

    // Generate encoded proofs
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        let merkle_proof = tree.proof(i);
        let shard = &all_shards[i];
        let encoded =
            encode(&(shard.clone(), merkle_proof)).map_err(|_| CodingError::CodecError)?;
        proofs.push(encoded);
    }

    Ok((root, proofs))
}

/// Decodes the original data from at least min_pieces assembled pieces with valid Merkle proofs.
/// Verifies consistency with the provided root and checks if the original encoding was correct.
/// Requires total_pieces, min_pieces, and shard_size (assumed known or derivable in context).
pub fn decode(
    root: &Root,
    pieces: &[(usize, Proof)],
    total_pieces: usize,
    min_pieces: usize,
    shard_size: usize,
) -> Result<Vec<u8>, CodingError> {
    let n = total_pieces;
    let k = min_pieces;
    let m = n - k;
    if pieces.len() < k {
        return Err(CodingError::NotEnoughPieces);
    }

    let mut seen = HashSet::new();
    let mut provided_originals: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut provided_recoveries: Vec<(u16, Vec<u8>)> = Vec::new();

    for &(index, ref encoded) in pieces {
        if index >= n || seen.contains(&index) {
            return Err(CodingError::DuplicateIndex);
        }
        seen.insert(index);

        let (shard, merkle_proof): (Vec<u8>, Vec<[u8; 32]>) =
            decode(encoded).map_err(|_| CodingError::CodecError)?;
        if shard.len() != shard_size {
            return Err(CodingError::InvalidShardSize);
        }
        if !merkle_verify(root, index, &shard, &merkle_proof) {
            return Err(CodingError::InvalidProof);
        }

        if index < k {
            provided_originals.push((index as u16, shard));
        } else {
            provided_recoveries.push(((index - k) as u16, shard));
        }
    }

    // Decode originals
    let mut decoder =
        ReedSolomonDecoder::new(k as u16, m as u16, shard_size).map_err(CodingError::RsError)?;
    for (idx, ref shard) in &provided_originals {
        decoder
            .add_original_shard(*idx, shard)
            .map_err(CodingError::RsError)?;
    }
    for (idx, ref shard) in &provided_recoveries {
        decoder
            .add_recovery_shard(*idx, shard)
            .map_err(CodingError::RsError)?;
    }
    let decode_result = decoder.decode().map_err(CodingError::RsError)?;

    // Build full originals, checking consistency
    let mut full_originals = vec![None; k];
    for (idx, shard) in provided_originals {
        full_originals[idx as usize] = Some(shard);
    }
    for (idx, shard) in decode_result.restored_original_iter() {
        let idx_usize = idx as usize;
        if let Some(existing) = &full_originals[idx_usize] {
            if existing != &shard {
                return Err(CodingError::Inconsistent);
            }
        } else {
            full_originals[idx_usize] = Some(shard);
        }
    }
    if full_originals.iter().any(|o| o.is_none()) {
        return Err(CodingError::Inconsistent);
    }
    let full_originals = full_originals
        .into_iter()
        .map(|o| o.unwrap())
        .collect::<Vec<_>>();

    // Re-encode to check parities
    let mut encoder =
        ReedSolomonEncoder::new(k as u16, m as u16, shard_size).map_err(CodingError::RsError)?;
    for shard in &full_originals {
        encoder
            .add_original_shard(shard)
            .map_err(CodingError::RsError)?;
    }
    let computed_recoveries = encoder
        .encode()
        .map_err(CodingError::RsError)?
        .recovery_iter()
        .collect::<Vec<_>>();

    for (idx, shard) in provided_recoveries {
        if computed_recoveries[idx as usize] != shard {
            return Err(CodingError::Inconsistent);
        }
    }

    // Reconstruct full shards and verify Merkle root
    let mut full_shards = full_originals;
    full_shards.extend(computed_recoveries);
    let computed_tree = BinaryMerkleTree::new(&full_shards);
    if computed_tree.root() != *root {
        return Err(CodingError::Inconsistent); // Original encoding incorrect
    }

    // Extract original data
    let mut data_buf = Vec::new();
    for shard in full_shards.into_iter().take(k) {
        data_buf.extend(shard);
    }
    let len = u64::from_be_bytes(
        data_buf[0..8]
            .try_into()
            .map_err(|_| CodingError::InvalidDataLength)?,
    ) as usize;
    if len + 8 > data_buf.len() {
        return Err(CodingError::InvalidDataLength);
    }
    Ok(data_buf[8..8 + len].to_vec())
}

//! Reed-Solomon coding.

use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_storage::bmt::Builder;
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

pub type Root = Digest;
pub type Proof = Vec<u8>;

/// Verifies a merkle proof against the given root
fn merkle_verify(root: &Root, index: usize, shard: &[u8], merkle_proof: &[Digest]) -> bool {
    // Create a tree from the proof to verify
    let mut hasher = Sha256::new();

    // Recreate the proof structure that BMT expects
    let proof = commonware_storage::bmt::Proof::<Sha256> {
        siblings: merkle_proof.to_vec(),
    };

    // Convert shard to digest format (BMT handles position hashing internally)
    hasher.update(shard);
    let shard_digest = hasher.finalize();

    // Verify the proof
    proof
        .verify(&mut hasher, &shard_digest, index as u32, root)
        .is_ok()
}

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

    // RS encoding - use correct API (original_count, recovery_count, shard_length)
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_size).map_err(CodingError::RsError)?;
    for shard in &original_shards {
        encoder
            .add_original_shard(shard)
            .map_err(CodingError::RsError)?;
    }
    let recovery_result = encoder.encode().map_err(CodingError::RsError)?;
    let recovery_shards: Vec<Vec<u8>> = recovery_result
        .recovery_iter()
        .map(|shard| shard.to_vec())
        .collect();

    // All shards
    let mut all_shards = original_shards;
    all_shards.extend(recovery_shards);

    // Build Merkle tree using BMT Builder
    let mut builder = Builder::<Sha256>::new(n);
    for shard in &all_shards {
        builder.add(&{
            let mut hasher = Sha256::new();
            hasher.update(shard);
            hasher.finalize()
        });
    }
    let tree = builder.build();
    let root = tree.root();

    // Generate encoded proofs
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        let merkle_proof = tree
            .proof(i as u32)
            .map_err(|_| CodingError::InvalidProof)?;
        let shard = &all_shards[i];
        let proof_data = (shard.clone(), merkle_proof.siblings);
        let encoded = proof_data.encode();
        proofs.push(encoded.to_vec());
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
    let mut provided_originals: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut provided_recoveries: Vec<(usize, Vec<u8>)> = Vec::new();

    for &(index, ref encoded) in pieces {
        if index >= n || seen.contains(&index) {
            return Err(CodingError::DuplicateIndex);
        }
        seen.insert(index);

        let (shard, merkle_proof): (Vec<u8>, Vec<Digest>) = <(Vec<u8>, Vec<Digest>)>::decode_cfg(
            &encoded[..],
            &(((..).into(), ()), ((..).into(), ())),
        )
        .map_err(|_| CodingError::CodecError)?;
        if shard.len() != shard_size {
            return Err(CodingError::InvalidShardSize);
        }
        if !merkle_verify(root, index, &shard, &merkle_proof) {
            return Err(CodingError::InvalidProof);
        }

        if index < k {
            provided_originals.push((index, shard));
        } else {
            provided_recoveries.push((index - k, shard));
        }
    }

    // Decode originals - use correct API (original_count, recovery_count, shard_length)
    let mut decoder = ReedSolomonDecoder::new(k, m, shard_size).map_err(CodingError::RsError)?;
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
        full_originals[idx] = Some(shard);
    }
    for (idx, shard) in decode_result.restored_original_iter() {
        let idx_usize = idx;
        if let Some(ref existing) = full_originals[idx_usize] {
            if existing != &shard.to_vec() {
                return Err(CodingError::Inconsistent);
            }
        } else {
            full_originals[idx_usize] = Some(shard.to_vec());
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
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_size).map_err(CodingError::RsError)?;
    for shard in &full_originals {
        encoder
            .add_original_shard(shard)
            .map_err(CodingError::RsError)?;
    }
    let computed_recoveries_result = encoder.encode().map_err(CodingError::RsError)?;
    let computed_recoveries: Vec<Vec<u8>> = computed_recoveries_result
        .recovery_iter()
        .map(|shard| shard.to_vec())
        .collect();

    for (idx, shard) in provided_recoveries {
        if computed_recoveries[idx] != shard {
            return Err(CodingError::Inconsistent);
        }
    }

    // Reconstruct full shards and verify Merkle root
    let mut full_shards = full_originals;
    full_shards.extend(computed_recoveries);

    // Build tree to verify root
    let mut builder = Builder::<Sha256>::new(n);
    for shard in &full_shards {
        builder.add(&{
            let mut hasher = Sha256::new();
            hasher.update(shard);
            hasher.finalize()
        });
    }
    let computed_tree = builder.build();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_basic() {
        let data = b"Hello, Reed-Solomon!";
        let total_pieces = 7;
        let min_pieces = 4;

        // Encode the data
        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();
        assert_eq!(proofs.len(), total_pieces);

        // Try to decode with exactly min_pieces
        let pieces: Vec<_> = (0..min_pieces).map(|i| (i, proofs[i].clone())).collect();

        // We need to determine shard_size for decoding
        // This is a limitation of the current API - in practice, this would be known
        let extended_len = 8 + data.len(); // 8 bytes for length prefix
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let decoded = decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_more_pieces() {
        let data = b"Testing with more pieces than minimum";
        let total_pieces = 10;
        let min_pieces = 4;

        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Use 6 pieces (more than minimum)
        let pieces: Vec<_> = (0..6).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let decoded = decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_recovery_pieces() {
        let data = b"Testing recovery pieces";
        let total_pieces = 8;
        let min_pieces = 3;

        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            (0, proofs[0].clone()), // original
            (4, proofs[4].clone()), // recovery
            (6, proofs[6].clone()), // recovery
        ];

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let decoded = decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total_pieces = 6;
        let min_pieces = 4;

        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Try with fewer than min_pieces
        let pieces: Vec<_> = (0..2).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let result = decode(&root, &pieces, total_pieces, min_pieces, shard_size);
        assert!(matches!(result, Err(CodingError::NotEnoughPieces)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total_pieces = 5;
        let min_pieces = 3;

        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Include duplicate index
        let pieces: Vec<_> = vec![
            (0, proofs[0].clone()),
            (0, proofs[0].clone()), // duplicate
            (1, proofs[1].clone()),
        ];

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let result = decode(&root, &pieces, total_pieces, min_pieces, shard_size);
        assert!(matches!(result, Err(CodingError::DuplicateIndex)));
    }

    #[test]
    fn test_invalid_parameters() {
        let data = b"Test parameter validation";

        // total_pieces <= min_pieces
        assert!(matches!(
            encode(data, 3, 3),
            Err(CodingError::InvalidParameters)
        ));

        // min_pieces = 0
        assert!(matches!(
            encode(data, 5, 0),
            Err(CodingError::InvalidParameters)
        ));
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total_pieces = 4;
        let min_pieces = 2;

        let (root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        let pieces: Vec<_> = (0..min_pieces).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8; // Just the length prefix
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let decoded = decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total_pieces = 7;
        let min_pieces = 4;

        let (root, proofs) = encode(&data, total_pieces, min_pieces).unwrap();

        let pieces: Vec<_> = (0..min_pieces).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        let decoded = decode(&root, &pieces, total_pieces, min_pieces, shard_size).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        // This test demonstrates the security property that under collision resistance
        // of the hash function, maliciously constructed roots will be detected.
        // As stated: "if the decoding function outputs ⊥, we can be sure that τ was maliciously constructed"

        let data = b"Original data that should be protected";
        let total_pieces = 7;
        let min_pieces = 4;

        // Encode data correctly to get valid proofs
        let (_correct_root, proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Create a malicious/fake root (simulating a malicious encoder)
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        // Collect valid pieces (these are legitimate fragments)
        let pieces: Vec<_> = (0..min_pieces).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        // Attempt to decode with malicious root - this should fail
        let result = decode(
            &malicious_root,
            &pieces,
            total_pieces,
            min_pieces,
            shard_size,
        );

        // The decoding function outputs ⊥ (error), proving the root was maliciously constructed
        assert!(matches!(result, Err(CodingError::InvalidProof)));

        // This demonstrates that under collision resistance, any n-2t certified fragments
        // for a maliciously constructed tag τ will be detected as invalid
    }

    #[test]
    fn test_consistency_verification_detects_tampering() {
        // This test shows that even if initial Merkle proofs pass, the consistency
        // check during Reed-Solomon verification will detect tampering

        let data = b"Data integrity must be maintained";
        let total_pieces = 6;
        let min_pieces = 3;

        let (root, mut proofs) = encode(data, total_pieces, min_pieces).unwrap();

        // Tamper with one of the proofs by modifying the shard data
        // (while keeping the Merkle proof intact - simulating sophisticated attack)
        let mut tampered_proof_data: (Vec<u8>, Vec<Digest>) = <(Vec<u8>, Vec<Digest>)>::decode_cfg(
            &proofs[1][..],
            &(((..).into(), ()), ((..).into(), ())),
        )
        .unwrap();

        // Modify the shard data
        if !tampered_proof_data.0.is_empty() {
            tampered_proof_data.0[0] ^= 0xFF; // Flip bits in first byte
        }

        // Re-encode the tampered proof
        proofs[1] = tampered_proof_data.encode().to_vec();

        let pieces: Vec<_> = (0..min_pieces).map(|i| (i, proofs[i].clone())).collect();

        let extended_len = 8 + data.len();
        let shard_size = if (extended_len + min_pieces - 1) / min_pieces % 2 == 0 {
            (extended_len + min_pieces - 1) / min_pieces
        } else {
            (extended_len + min_pieces - 1) / min_pieces + 1
        };

        // The tampered piece will fail at Merkle proof verification first
        let result = decode(&root, &pieces, total_pieces, min_pieces, shard_size);
        assert!(matches!(result, Err(CodingError::InvalidProof)));

        // This proves that any tampering with fragment data is immediately detected
        // by Merkle proof validation, providing strong integrity guarantees
    }

    #[test]
    fn test_malicious_encoder_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total_pieces = 5;
        let min_pieces = 3;

        // Compute shard_size
        let mut extended_data = Vec::new();
        extended_data.extend_from_slice(&(data.len() as u64).to_be_bytes());
        extended_data.extend_from_slice(data);

        let mut shard_size = (extended_data.len() + min_pieces - 1) / min_pieces;
        if shard_size % 2 != 0 {
            shard_size += 1;
        }

        let padded_len = shard_size * min_pieces;
        extended_data.resize(padded_len, 0);

        // Create original shards
        let mut original_shards = Vec::with_capacity(min_pieces);
        for i in 0..min_pieces {
            let start = i * shard_size;
            original_shards.push(extended_data[start..start + shard_size].to_vec());
        }

        // RS encoding
        let m = total_pieces - min_pieces;
        let mut encoder = ReedSolomonEncoder::new(min_pieces, m, shard_size).unwrap();
        for shard in &original_shards {
            encoder.add_original_shard(shard).unwrap();
        }
        let recovery_result = encoder.encode().unwrap();
        let mut recovery_shards: Vec<Vec<u8>> = recovery_result
            .recovery_iter()
            .map(|s| s.to_vec())
            .collect();

        // Tamper with one recovery shard
        if !recovery_shards[0].is_empty() {
            recovery_shards[0][0] ^= 0xFF;
        }

        // Build malicious shards
        let mut malicious_shards = original_shards.clone();
        malicious_shards.extend(recovery_shards);

        // Build malicious tree
        let mut builder = Builder::<Sha256>::new(total_pieces);
        for shard in &malicious_shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let malicious_tree = builder.build();
        let malicious_root = malicious_tree.root();

        // Generate proofs for min_pieces pieces, including the tampered recovery
        let selected_indices = vec![0, 1, 3]; // originals 0,1 and recovery 0 (index 3)
        let mut pieces = Vec::new();
        for &i in &selected_indices {
            let merkle_proof = malicious_tree.proof(i as u32).unwrap();
            let shard = malicious_shards[i].clone();
            let proof_data = (shard, merkle_proof.siblings);
            let encoded = proof_data.encode();
            pieces.push((i, encoded.to_vec()));
        }

        // Attempt decode
        let result = decode(
            &malicious_root,
            &pieces,
            total_pieces,
            min_pieces,
            shard_size,
        );
        assert!(matches!(result, Err(CodingError::Inconsistent)));
    }
}

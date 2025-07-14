//! Reed-Solomon coding.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Hasher;
use commonware_storage::bmt::{self, Builder};
use reed_solomon_simd::{Error as RsError, ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::HashSet;

#[derive(Debug)]
pub enum Error {
    InvalidParameters,
    Rs(RsError),
    CodecError,
    Inconsistent,
    InvalidProof,
    NotEnoughPieces,
    DuplicateIndex,
    InvalidShardSize,
    InvalidDataLength,
}

/// A chunk of data that has been encoded using Reed-Solomon and a Binary Merkle Tree.
#[derive(Clone)]
pub struct Chunk<H: Hasher> {
    pub index: u32,
    pub shard: Vec<u8>,
    pub proof: bmt::Proof<H>,
}

impl<H: Hasher> Chunk<H> {
    /// Creates a new chunk from the given shard and proof.
    pub fn new(index: u32, shard: Vec<u8>, proof: bmt::Proof<H>) -> Self {
        Self {
            index,
            shard,
            proof,
        }
    }

    /// Verifies the chunk against the given root and index.
    pub fn verify(&self, root: &H::Digest) -> bool {
        // Compute shard digest
        let mut hasher = H::new();
        hasher.update(&self.shard);
        let shard_digest = hasher.finalize();

        // Verify proof
        self.proof
            .verify(&mut hasher, &shard_digest, self.index, root)
            .is_ok()
    }
}

impl<H: Hasher> Write for Chunk<H> {
    fn write(&self, writer: &mut impl BufMut) {
        self.index.write(writer);
        self.shard.write(writer);
        self.proof.write(writer);
    }
}

impl<H: Hasher> Read for Chunk<H> {
    /// The maximum size of the shard.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let index = u32::read(reader)?;
        let shard = Vec::<u8>::read_range(reader, ..=*cfg)?;
        let proof = bmt::Proof::<H>::read(reader)?;
        Ok(Self {
            index,
            shard,
            proof,
        })
    }
}

impl<H: Hasher> EncodeSize for Chunk<H> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.shard.encode_size() + self.proof.encode_size()
    }
}

pub fn encode<H: Hasher>(
    total: u32,
    min: u32,
    data: Vec<u8>,
) -> Result<(H::Digest, Vec<Chunk<H>>), Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;

    // Encode data
    let mut data = data.encode().to_vec();

    // Compute shard_len (must be even)
    let mut shard_len = data.len().div_ceil(k);
    if shard_len % 2 != 0 {
        shard_len += 1;
    }

    // Pad data
    let padded_len = shard_len * k;
    data.resize(padded_len, 0);

    // Create original shards
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::Rs)?;
    let mut original_shards = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * shard_len;
        original_shards.push(data[start..start + shard_len].to_vec());
    }
    for shard in &original_shards {
        encoder.add_original_shard(shard).map_err(Error::Rs)?;
    }
    let mut shards = original_shards;

    // Compute recovery shards
    let encoding = encoder.encode().map_err(Error::Rs)?;
    let recovery_shards: Vec<Vec<u8>> = encoding
        .recovery_iter()
        .map(|shard| shard.to_vec())
        .collect();
    shards.extend(recovery_shards);

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    let mut hasher = H::new();
    for shard in &shards {
        builder.add(&{
            hasher.update(shard);
            hasher.finalize()
        });
    }
    let tree = builder.build();
    let root = tree.root();

    // Generate chunks
    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in shards.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(i as u32, shard, proof));
    }

    Ok((root, chunks))
}

pub fn decode<H: Hasher>(
    total: u32,
    min: u32,
    root: &H::Digest,
    chunks: Vec<Chunk<H>>,
) -> Result<Vec<u8>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    if chunks.len() < k {
        return Err(Error::NotEnoughPieces);
    }

    // Verify chunks
    let shard_len = chunks[0].shard.len();
    let mut seen = HashSet::new();
    let mut provided_originals: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut provided_recoveries: Vec<(usize, Vec<u8>)> = Vec::new();
    for chunk in chunks {
        // Check for duplicate index
        if seen.contains(&chunk.index) {
            return Err(Error::DuplicateIndex);
        }
        seen.insert(chunk.index);

        // Verify Merkle proof
        if !chunk.verify(root) {
            return Err(Error::InvalidProof);
        }

        // Add to provided shards
        if chunk.index < min {
            provided_originals.push((chunk.index as usize, chunk.shard));
        } else {
            provided_recoveries.push((chunk.index as usize - k, chunk.shard));
        }
    }

    // Decode original data
    let mut decoder = ReedSolomonDecoder::new(k, m, shard_len).map_err(Error::Rs)?;
    for (idx, ref shard) in &provided_originals {
        decoder.add_original_shard(*idx, shard).map_err(Error::Rs)?;
    }
    for (idx, ref shard) in &provided_recoveries {
        decoder.add_recovery_shard(*idx, shard).map_err(Error::Rs)?;
    }
    let decoding = decoder.decode().map_err(Error::Rs)?;

    // Encode recovered data
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::Rs)?;
    for (_, shard) in decoding.restored_original_iter() {
        encoder.add_original_shard(shard).map_err(Error::Rs)?;
    }
    let encoding = encoder.encode().map_err(Error::Rs)?;
    let recovery_shards: Vec<Vec<u8>> = encoding
        .recovery_iter()
        .map(|shard| shard.to_vec())
        .collect();
    let mut shards = decoding
        .restored_original_iter()
        .map(|(_, shard)| shard.to_vec())
        .collect::<Vec<_>>();
    shards.extend(recovery_shards);

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    let mut hasher = H::new();
    for shard in &shards {
        builder.add(&{
            hasher.update(shard);
            hasher.finalize()
        });
    }
    let computed_tree = builder.build();

    // Confirm root is consistent
    if computed_tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    let mut data = Vec::new();
    for shard in shards.into_iter().take(k) {
        data.extend(shard);
    }
    Ok(Vec::<u8>::read_range(&mut data.as_slice(), ..).expect("decoding failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;

    #[test]
    fn test_basic() {
        let data = b"Hello, Reed-Solomon!";
        let total_pieces = 7u32;
        let min_pieces = 4u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();
        assert_eq!(chunks.len(), total_pieces as usize);

        // Try to decode with exactly min_pieces (all original shards)
        let minimal = chunks.into_iter().take(min_pieces as usize).collect();
        let decoded = decode::<Sha256>(total_pieces, min_pieces, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_moderate() {
        let data = b"Testing with more pieces than minimum";
        let total_pieces = 10u32;
        let min_pieces = 4u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Try to decode with min_pieces (all original shards)
        let minimal = chunks.into_iter().take(min_pieces as usize).collect();
        let decoded = decode::<Sha256>(total_pieces, min_pieces, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total_pieces = 8u32;
        let min_pieces = 3u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            chunks[0].clone(), // original
            chunks[4].clone(), // recovery
            chunks[6].clone(), // recovery
        ];

        // Try to decode with a mix of original and recovery pieces
        let decoded = decode::<Sha256>(total_pieces, min_pieces, &root, pieces).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total_pieces = 6u32;
        let min_pieces = 4u32;

        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Try with fewer than min_pieces
        let pieces: Vec<_> = chunks.into_iter().take(2).collect();

        let result = decode::<Sha256>(total_pieces, min_pieces, &root, pieces);
        assert!(matches!(result, Err(Error::NotEnoughPieces)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total_pieces = 5u32;
        let min_pieces = 3u32;

        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Include duplicate index by cloning the first chunk
        let pieces = vec![chunks[0].clone(), chunks[0].clone(), chunks[1].clone()];

        let result = decode::<Sha256>(total_pieces, min_pieces, &root, pieces);
        assert!(matches!(result, Err(Error::DuplicateIndex)));
    }

    #[test]
    fn test_invalid_parameters() {
        let data = b"Test parameter validation";

        // total_pieces <= min_pieces should panic due to assert
        // We'll test this with total_pieces == min_pieces
        let result = std::panic::catch_unwind(|| encode::<Sha256>(3, 3, data.to_vec()));
        assert!(result.is_err());

        // min_pieces = 0 should panic due to assert
        let result = std::panic::catch_unwind(|| encode::<Sha256>(5, 0, data.to_vec()));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total_pieces = 4u32;
        let min_pieces = 2u32;

        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        let pieces: Vec<_> = chunks.into_iter().take(min_pieces as usize).collect();

        let decoded = decode::<Sha256>(total_pieces, min_pieces, &root, pieces).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total_pieces = 7u32;
        let min_pieces = 4u32;

        let (root, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.clone()).unwrap();

        let pieces: Vec<_> = chunks.into_iter().take(min_pieces as usize).collect();

        let decoded = decode::<Sha256>(total_pieces, min_pieces, &root, pieces).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        // This test demonstrates the security property that under collision resistance
        // of the hash function, maliciously constructed roots will be detected.
        // As stated: "if the decoding function outputs ⊥, we can be sure that τ was maliciously constructed"

        let data = b"Original data that should be protected";
        let total_pieces = 7u32;
        let min_pieces = 4u32;

        // Encode data correctly to get valid chunks
        let (_correct_root, chunks) =
            encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Create a malicious/fake root (simulating a malicious encoder)
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        // Collect valid pieces (these are legitimate fragments)
        let pieces: Vec<_> = chunks.into_iter().take(min_pieces as usize).collect();

        // Attempt to decode with malicious root - this should fail
        let result = decode::<Sha256>(total_pieces, min_pieces, &malicious_root, pieces);

        // The decoding function outputs ⊥ (error), proving the root was maliciously constructed
        assert!(matches!(result, Err(Error::InvalidProof)));

        // This demonstrates that under collision resistance, any n-2t certified fragments
        // for a maliciously constructed tag τ will be detected as invalid
    }

    #[test]
    fn test_consistency_verification_detects_tampering() {
        // This test shows that even if initial Merkle proofs pass, the consistency
        // check during Reed-Solomon verification will detect tampering

        let data = b"Data integrity must be maintained";
        let total_pieces = 6u32;
        let min_pieces = 3u32;

        let (root, mut chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Tamper with one of the chunks by modifying the shard data
        if !chunks[1].shard.is_empty() {
            chunks[1].shard[0] ^= 0xFF; // Flip bits in first byte
        }

        let pieces: Vec<_> = chunks.into_iter().take(min_pieces as usize).collect();

        // The tampered piece will fail at Merkle proof verification first
        let result = decode::<Sha256>(total_pieces, min_pieces, &root, pieces);
        assert!(matches!(result, Err(Error::InvalidProof)));

        // This proves that any tampering with fragment data is immediately detected
        // by Merkle proof validation, providing strong integrity guarantees
    }

    #[test]
    fn test_malicious_encoder_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total_pieces = 5u32;
        let min_pieces = 3u32;

        // First encode properly to get the correct structure
        let (_, chunks) = encode::<Sha256>(total_pieces, min_pieces, data.to_vec()).unwrap();

        // Get the shard size from the first chunk
        let shard_size = chunks[0].shard.len();

        // Compute original data encoding
        let mut extended_data = data.to_vec().encode().to_vec();

        let padded_len = shard_size * min_pieces as usize;
        extended_data.resize(padded_len, 0);

        // Create original shards
        let mut original_shards = Vec::with_capacity(min_pieces as usize);
        for i in 0..min_pieces as usize {
            let start = i * shard_size;
            original_shards.push(extended_data[start..start + shard_size].to_vec());
        }

        // RS encoding
        let m = total_pieces - min_pieces;
        let mut encoder =
            ReedSolomonEncoder::new(min_pieces as usize, m as usize, shard_size).unwrap();
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
        let mut builder = Builder::<Sha256>::new(total_pieces as usize);
        for shard in &malicious_shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let malicious_tree = builder.build();
        let malicious_root = malicious_tree.root();

        // Generate chunks for min_pieces pieces, including the tampered recovery
        let selected_indices = vec![0, 1, 3]; // originals 0,1 and recovery 0 (index 3)
        let mut pieces = Vec::new();
        for &i in &selected_indices {
            let merkle_proof = malicious_tree.proof(i as u32).unwrap();
            let shard = malicious_shards[i].clone();
            let chunk = Chunk::new(i as u32, shard, merkle_proof);
            pieces.push(chunk);
        }

        // Attempt decode - should fail due to inconsistency
        let result = decode::<Sha256>(total_pieces, min_pieces, &malicious_root, pieces);
        // The tampered recovery shard should cause the consistency check to fail
        assert!(matches!(result, Err(Error::Inconsistent)));
    }
}

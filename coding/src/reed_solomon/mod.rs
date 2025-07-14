//! Reed-Solomon coding.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, FixedSize, Read, ReadExt, ReadRangeExt, Write};
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

fn prepare_data(data: Vec<u8>, k: usize, m: usize) -> Vec<Vec<u8>> {
    // Compute shard_len (must be even)
    let prefixed_len = u64::SIZE + data.len();
    let mut shard_len = prefixed_len.div_ceil(k);
    if shard_len % 2 != 0 {
        shard_len += 1;
    }

    // Create shards
    let mut shards = Vec::with_capacity(k + m); // prepare for recovery shards
    let length_bytes = (data.len() as u64).to_be_bytes();
    let mut length_offset = 0;
    let mut data_offset = 0;
    for _ in 0..k {
        // Fill shard with length prefix first (if any remaining)
        let mut shard = Vec::with_capacity(shard_len);
        while length_offset < u64::SIZE && shard.len() < shard_len {
            shard.push(length_bytes[length_offset]);
            length_offset += 1;
        }

        // Fill remaining space with data
        while data_offset < data.len() && shard.len() < shard_len {
            shard.push(data[data_offset]);
            data_offset += 1;
        }

        // Pad with zeros if needed
        shard.resize(shard_len, 0);
        shards.push(shard);
    }

    shards
}

fn extract_data(shards: Vec<Vec<u8>>) -> Vec<u8> {
    // Concatenate shards
    let mut data = Vec::with_capacity(shards.len() * shards[0].len());
    for shard in shards {
        data.extend_from_slice(&shard);
    }

    // Read length prefix
    let data_len = u64::from_be_bytes(data[..u64::SIZE].try_into().unwrap()) as usize;

    // Return data
    data[u64::SIZE..data_len + u64::SIZE].to_vec()
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

    // Prepare data
    let mut shards = prepare_data(data, k, m);
    let shard_len = shards[0].len();

    // Create encoder
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::Rs)?;
    for shard in &shards {
        encoder.add_original_shard(shard).map_err(Error::Rs)?;
    }

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

    // Reconstruct all original shards
    let mut shards = Vec::with_capacity(n);
    shards.resize(k, Vec::new());
    for (idx, shard) in provided_originals {
        shards[idx] = shard;
    }
    for (idx, shard) in decoding.restored_original_iter() {
        shards[idx] = shard.to_vec();
    }

    // Encode recovered data to get recovery shards
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::Rs)?;
    for shard in shards.iter().take(k) {
        encoder.add_original_shard(shard).map_err(Error::Rs)?;
    }
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
    let computed_tree = builder.build();

    // Confirm root is consistent
    if computed_tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    Ok(extract_data(shards))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;

    #[test]
    fn test_basic() {
        let data = b"Hello, Reed-Solomon!";
        let total = 7u32;
        let min = 4u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();
        assert_eq!(chunks.len(), total as usize);

        // Try to decode with exactly min (all original shards)
        let minimal = chunks.into_iter().take(min as usize).collect();
        let decoded = decode::<Sha256>(total, min, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_moderate() {
        let data = b"Testing with more pieces than minimum";
        let total = 10u32;
        let min = 4u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Try to decode with min (all original shards)
        let minimal = chunks.into_iter().take(min as usize).collect();
        let decoded = decode::<Sha256>(total, min, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total = 8u32;
        let min = 3u32;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            chunks[0].clone(), // original
            chunks[4].clone(), // recovery
            chunks[6].clone(), // recovery
        ];

        // Try to decode with a mix of original and recovery pieces
        let decoded = decode::<Sha256>(total, min, &root, pieces).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 6u32;
        let min = 4u32;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Try with fewer than min
        let pieces: Vec<_> = chunks.into_iter().take(2).collect();

        // Fail to decode
        let result = decode::<Sha256>(total, min, &root, pieces);
        assert!(matches!(result, Err(Error::NotEnoughPieces)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 5u32;
        let min = 3u32;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Include duplicate index by cloning the first chunk
        let pieces = vec![chunks[0].clone(), chunks[0].clone(), chunks[1].clone()];

        // Fail to decode
        let result = decode::<Sha256>(total, min, &root, pieces);
        assert!(matches!(result, Err(Error::DuplicateIndex)));
    }

    #[test]
    #[should_panic(expected = "assertion failed: total > min")]
    fn test_invalid_total() {
        let data = b"Test parameter validation";

        // total <= min should panic
        encode::<Sha256>(3, 3, data.to_vec()).unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: min > 0")]
    fn test_invalid_min() {
        let data = b"Test parameter validation";

        // min = 0 should panic
        encode::<Sha256>(5, 0, data.to_vec()).unwrap();
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 100u32;
        let min = 30u32;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Try to decode with min
        let minimal = chunks.into_iter().take(min as usize).collect();
        let decoded = decode::<Sha256>(total, min, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = 7u32;
        let min = 4u32;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.clone()).unwrap();

        // Try to decode with min
        let minimal = chunks.into_iter().take(min as usize).collect();
        let decoded = decode::<Sha256>(total, min, &root, minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u32;
        let min = 4u32;

        // Encode data correctly to get valid chunks
        let (_correct_root, chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Create a malicious/fake root (simulating a malicious encoder)
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        // Collect valid pieces (these are legitimate fragments)
        let minimal = chunks.into_iter().take(min as usize).collect();

        // Attempt to decode with malicious root
        let result = decode::<Sha256>(total, min, &malicious_root, minimal);
        assert!(matches!(result, Err(Error::InvalidProof)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 6u32;
        let min = 3u32;

        // Encode data
        let (root, mut chunks) = encode::<Sha256>(total, min, data.to_vec()).unwrap();

        // Tamper with one of the chunks by modifying the shard data
        if !chunks[1].shard.is_empty() {
            chunks[1].shard[0] ^= 0xFF; // Flip bits in first byte
        }

        // Try to decode with the tampered chunk
        let result = decode::<Sha256>(total, min, &root, chunks);
        assert!(matches!(result, Err(Error::InvalidProof)));
    }

    #[test]
    fn test_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total = 5u32;
        let min = 3u32;
        let m = total - min;

        // Compute original data encoding
        let shards = prepare_data(data.to_vec(), min as usize, total as usize - min as usize);
        let shard_size = shards[0].len();

        // Re-encode the data
        let mut encoder = ReedSolomonEncoder::new(min as usize, m as usize, shard_size).unwrap();
        for shard in &shards {
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
        let mut malicious_shards = shards.clone();
        malicious_shards.extend(recovery_shards);

        // Build malicious tree
        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &malicious_shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let malicious_tree = builder.build();
        let malicious_root = malicious_tree.root();

        // Generate chunks for min pieces, including the tampered recovery
        let selected_indices = vec![0, 1, 3]; // originals 0,1 and recovery 0 (index 3)
        let mut pieces = Vec::new();
        for &i in &selected_indices {
            let merkle_proof = malicious_tree.proof(i as u32).unwrap();
            let shard = malicious_shards[i].clone();
            let chunk = Chunk::new(i as u32, shard, merkle_proof);
            pieces.push(chunk);
        }

        // Fail to decode
        let result = decode::<Sha256>(total, min, &malicious_root, pieces);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }
}

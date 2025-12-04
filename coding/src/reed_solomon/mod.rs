use crate::{Config, Scheme};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Hasher;
use commonware_storage::bmt::{self, Builder};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use reed_solomon_simd::{Error as RsError, ReedSolomonDecoder, ReedSolomonEncoder};
use std::{collections::HashSet, marker::PhantomData};
use thiserror::Error;

/// Errors that can occur when interacting with the Reed-Solomon coder.
#[derive(Error, Debug)]
pub enum Error {
    #[error("reed-solomon error: {0}")]
    ReedSolomon(#[from] RsError),
    #[error("inconsistent")]
    Inconsistent,
    #[error("invalid proof")]
    InvalidProof,
    #[error("not enough chunks")]
    NotEnoughChunks,
    #[error("duplicate chunk index: {0}")]
    DuplicateIndex(u16),
    #[error("invalid data length: {0}")]
    InvalidDataLength(usize),
    #[error("invalid index: {0}")]
    InvalidIndex(u16),
    #[error("wrong index: {0}")]
    WrongIndex(u16),
    #[error("too many total shards: {0}")]
    TooManyTotalShards(u32),
}

fn total_shards(config: &Config) -> Result<u16, Error> {
    let total = config.total_shards();
    total
        .try_into()
        .map_err(|_| Error::TooManyTotalShards(total))
}

/// A piece of data from a Reed-Solomon encoded object.
#[derive(Debug, Clone)]
pub struct Chunk<H: Hasher> {
    /// The shard of encoded data.
    shard: Vec<u8>,

    /// The index of [Chunk] in the original data.
    index: u16,

    /// The proof of the shard in the [bmt] at the given index.
    proof: bmt::Proof<H>,
}

impl<H: Hasher> Chunk<H> {
    /// Create a new [Chunk] from the given shard, index, and proof.
    const fn new(shard: Vec<u8>, index: u16, proof: bmt::Proof<H>) -> Self {
        Self {
            shard,
            index,
            proof,
        }
    }

    /// Verify a [Chunk] against the given root.
    fn verify(&self, index: u16, root: &H::Digest) -> bool {
        // Ensure the index matches
        if index != self.index {
            return false;
        }

        // Compute shard digest
        let mut hasher = H::new();
        hasher.update(&self.shard);
        let shard_digest = hasher.finalize();

        // Verify proof
        self.proof
            .verify(&mut hasher, &shard_digest, self.index as u32, root)
            .is_ok()
    }
}

impl<H: Hasher> Write for Chunk<H> {
    fn write(&self, writer: &mut impl BufMut) {
        self.shard.write(writer);
        self.index.write(writer);
        self.proof.write(writer);
    }
}

impl<H: Hasher> Read for Chunk<H> {
    /// The maximum size of the shard.
    type Cfg = crate::CodecConfig;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let shard = Vec::<u8>::read_range(reader, ..=cfg.maximum_shard_size)?;
        let index = u16::read(reader)?;
        let proof = bmt::Proof::<H>::read(reader)?;
        Ok(Self {
            shard,
            index,
            proof,
        })
    }
}

impl<H: Hasher> EncodeSize for Chunk<H> {
    fn encode_size(&self) -> usize {
        self.shard.encode_size() + self.index.encode_size() + self.proof.encode_size()
    }
}

impl<H: Hasher> PartialEq for Chunk<H> {
    fn eq(&self, other: &Self) -> bool {
        self.shard == other.shard && self.index == other.index && self.proof == other.proof
    }
}

impl<H: Hasher> Eq for Chunk<H> {}

/// Prepare data for encoding.
fn prepare_data(data: Vec<u8>, k: usize, m: usize) -> Vec<Vec<u8>> {
    // Compute shard length
    let data_len = data.len();
    let prefixed_len = u32::SIZE + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);

    // Ensure shard length is even (required for optimizations in `reed-solomon-simd`)
    if !shard_len.is_multiple_of(2) {
        shard_len += 1;
    }

    // Prepare data
    let length_bytes = (data_len as u32).to_be_bytes();
    let mut padded = vec![0u8; k * shard_len];
    padded[..u32::SIZE].copy_from_slice(&length_bytes);
    padded[u32::SIZE..u32::SIZE + data_len].copy_from_slice(&data);

    let mut shards = Vec::with_capacity(k + m); // assume recovery shards will be added later
    for chunk in padded.chunks(shard_len) {
        shards.push(chunk.to_vec());
    }
    shards
}

/// Extract data from encoded shards.
fn extract_data(shards: Vec<&[u8]>, k: usize) -> Vec<u8> {
    // Concatenate shards
    let mut data = shards.into_iter().take(k).flatten();

    // Extract length prefix
    let data_len = (&mut data)
        .take(u32::SIZE)
        .copied()
        .collect::<Vec<_>>()
        .try_into()
        .expect("insufficient data");
    let data_len = u32::from_be_bytes(data_len) as usize;

    // Extract data
    data.take(data_len).copied().collect()
}

/// Type alias for the internal encoding result.
type Encoding<H> = (bmt::Tree<H>, Vec<Vec<u8>>);

/// Inner logic for [encode()]
fn encode_inner<H: Hasher>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    concurrency: usize,
) -> Result<Encoding<H>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidDataLength(data.len()));
    }

    // Prepare data
    let mut shards = prepare_data(data, k, m);
    let shard_len = shards[0].len();

    // Create encoder
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::ReedSolomon)?;
    for shard in &shards {
        encoder
            .add_original_shard(shard)
            .map_err(Error::ReedSolomon)?;
    }

    // Compute recovery shards
    let encoding = encoder.encode().map_err(Error::ReedSolomon)?;
    let recovery_shards: Vec<Vec<u8>> = encoding
        .recovery_iter()
        .map(|shard| shard.to_vec())
        .collect();
    shards.extend(recovery_shards);

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    if concurrency > 1 {
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("unable to build thread pool");
        let shard_hashes = pool.install(|| {
            shards
                .par_iter()
                .map_init(H::new, |hasher, shard| {
                    hasher.update(shard);
                    hasher.finalize()
                })
                .collect::<Vec<_>>()
        });
        for hash in &shard_hashes {
            builder.add(hash);
        }
    } else {
        let mut hasher = H::new();
        for shard in &shards {
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
    }
    let tree = builder.build();

    Ok((tree, shards))
}

/// Encode data using a Reed-Solomon coder and insert it into a [bmt].
///
/// # Parameters
///
/// - `total`: The total number of chunks to generate.
/// - `min`: The minimum number of chunks required to decode the data.
/// - `data`: The data to encode.
/// - `concurrency`: The level of concurrency to use.
///
/// # Returns
///
/// - `root`: The root of the [bmt].
/// - `chunks`: [Chunk]s of encoded data (that can be proven against `root`).
fn encode<H: Hasher>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    concurrency: usize,
) -> Result<(H::Digest, Vec<Chunk<H>>), Error> {
    // Encode data
    let (tree, shards) = encode_inner::<H>(total, min, data, concurrency)?;
    let root = tree.root();
    let n = total as usize;

    // Generate chunks
    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in shards.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(shard, i as u16, proof));
    }

    Ok((root, chunks))
}

/// Decode data from a set of [Chunk]s.
///
/// It is assumed that all [Chunk]s have already been verified against the given root using [Chunk::verify].
///
/// # Parameters
///
/// - `total`: The total number of chunks to generate.
/// - `min`: The minimum number of chunks required to decode the data.
/// - `root`: The root of the [bmt].
/// - `chunks`: [Chunk]s of encoded data (that can be proven against `root`).
/// - `concurrency`: The level of concurrency to use.
///
/// # Returns
///
/// - `data`: The decoded data.
fn decode<H: Hasher>(
    total: u16,
    min: u16,
    root: &H::Digest,
    chunks: &[Chunk<H>],
    concurrency: usize,
) -> Result<Vec<u8>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    if chunks.len() < k {
        return Err(Error::NotEnoughChunks);
    }

    // Verify chunks
    let shard_len = chunks[0].shard.len();
    let mut seen = HashSet::new();
    let mut provided_originals: Vec<(usize, &[u8])> = Vec::new();
    let mut provided_recoveries: Vec<(usize, &[u8])> = Vec::new();
    for chunk in chunks {
        // Check for duplicate index
        let index = chunk.index;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        if seen.contains(&index) {
            return Err(Error::DuplicateIndex(index));
        }
        seen.insert(index);

        // Add to provided shards
        if index < min {
            provided_originals.push((index as usize, chunk.shard.as_slice()));
        } else {
            provided_recoveries.push((index as usize - k, chunk.shard.as_slice()));
        }
    }

    // Decode original data
    let mut decoder = ReedSolomonDecoder::new(k, m, shard_len).map_err(Error::ReedSolomon)?;
    for (idx, ref shard) in &provided_originals {
        decoder
            .add_original_shard(*idx, shard)
            .map_err(Error::ReedSolomon)?;
    }
    for (idx, ref shard) in &provided_recoveries {
        decoder
            .add_recovery_shard(*idx, shard)
            .map_err(Error::ReedSolomon)?;
    }
    let decoding = decoder.decode().map_err(Error::ReedSolomon)?;

    // Reconstruct all original shards
    let mut shards = Vec::with_capacity(n);
    shards.resize(k, Default::default());
    for (idx, shard) in provided_originals {
        shards[idx] = shard;
    }
    for (idx, shard) in decoding.restored_original_iter() {
        shards[idx] = shard;
    }

    // Encode recovered data to get recovery shards
    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).map_err(Error::ReedSolomon)?;
    for shard in shards.iter().take(k) {
        encoder
            .add_original_shard(shard)
            .map_err(Error::ReedSolomon)?;
    }
    let encoding = encoder.encode().map_err(Error::ReedSolomon)?;
    let recovery_shards: Vec<&[u8]> = encoding.recovery_iter().collect();
    shards.extend(recovery_shards);

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    if concurrency > 1 {
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("unable to build thread pool");
        let shard_hashes = pool.install(|| {
            shards
                .par_iter()
                .map_init(H::new, |hasher, shard| {
                    hasher.update(shard);
                    hasher.finalize()
                })
                .collect::<Vec<_>>()
        });

        for hash in &shard_hashes {
            builder.add(hash);
        }
    } else {
        let mut hasher = H::new();
        for shard in &shards {
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
    }
    let tree = builder.build();

    // Confirm root is consistent
    if tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    Ok(extract_data(shards, k))
}

/// A SIMD-optimized Reed-Solomon coder that emits chunks that can be proven against a [bmt].
///
/// # Behavior
///
/// The encoder takes input data, splits it into `k` data shards, and generates `m` recovery
/// shards using [Reed-Solomon encoding](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction).
/// All `n = k + m` shards are then used to build a [bmt], producing a single root hash. Each shard
/// is packaged as a chunk containing the shard data, its index, and a Merkle proof against the [bmt] root.
///
/// ## Encoding
///
/// ```text
///               +--------------------------------------+
///               |         Original Data (Bytes)        |
///               +--------------------------------------+
///                                  |
///                                  v
///               +--------------------------------------+
///               | [Length Prefix | Original Data...]   |
///               +--------------------------------------+
///                                  |
///                                  v
///              +----------+ +----------+    +-----------+
///              |  Shard 0 | |  Shard 1 | .. | Shard k-1 |  (Data Shards)
///              +----------+ +----------+    +-----------+
///                     |            |             |
///                     |            |             |
///                     +------------+-------------+
///                                  |
///                                  v
///                        +------------------+
///                        | Reed-Solomon     |
///                        | Encoder (k, m)   |
///                        +------------------+
///                                  |
///                                  v
///              +----------+ +----------+    +-----------+
///              |  Shard k | | Shard k+1| .. | Shard n-1 |  (Recovery Shards)
///              +----------+ +----------+    +-----------+
/// ```
///
/// ## Merkle Tree Construction
///
/// All `n` shards (data and recovery) are hashed and used as leaves to build a [bmt].
///
/// ```text
/// Shards:    [Shard 0, Shard 1, ..., Shard n-1]
///             |        |              |
///             v        v              v
/// Hashes:    [H(S_0), H(S_1), ..., H(S_n-1)]
///             \       / \       /
///              \     /   \     /
///               +---+     +---+
///                 |         |
///                 \         /
///                  \       /
///                   +-----+
///                      |
///                      v
///                +----------+
///                |   Root   |
///                +----------+
/// ```
///
/// The final output is the [bmt] root and a set of `n` chunks.
///
/// `(Root, [Chunk 0, Chunk 1, ..., Chunk n-1])`
///
/// Each chunk contains:
/// - `shard`: The shard data (original or recovery).
/// - `index`: The shard's original index (0 to n-1).
/// - `proof`: A Merkle proof of the shard's inclusion in the [bmt].
///
/// ## Decoding and Verification
///
/// The decoder requires any `k` chunks to reconstruct the original data.
/// 1. Each chunk's Merkle proof is verified against the [bmt] root.
/// 2. The shards from the valid chunks are used to reconstruct the original `k` data shards.
/// 3. To ensure consistency, the recovered data shards are re-encoded, and a new [bmt] root is
///    generated. This new root MUST match the original [bmt] root. This prevents attacks where
///    an adversary provides a valid set of chunks that decode to different data.
/// 4. If the roots match, the original data is extracted from the reconstructed data shards.
#[derive(Clone, Copy)]
pub struct ReedSolomon<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for ReedSolomon<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReedSolomon").finish()
    }
}

impl<H: Hasher> Scheme for ReedSolomon<H> {
    type Commitment = H::Digest;

    type Shard = Chunk<H>;
    type ReShard = Chunk<H>;
    type CheckedShard = Chunk<H>;
    type CheckingData = ();

    type Error = Error;

    fn encode(
        config: &Config,
        mut data: impl Buf,
        concurrency: usize,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        encode(
            total_shards(config)?,
            config.minimum_shards,
            data,
            concurrency,
        )
    }

    fn reshard(
        _config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        if shard.index != index {
            return Err(Error::WrongIndex(index));
        }
        if shard.verify(shard.index, commitment) {
            Ok(((), shard.clone(), shard))
        } else {
            Err(Error::InvalidProof)
        }
    }

    fn check(
        _config: &Config,
        commitment: &Self::Commitment,
        _checking_data: &Self::CheckingData,
        index: u16,
        reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        if reshard.index != index {
            return Err(Error::WrongIndex(reshard.index));
        }
        if !reshard.verify(reshard.index, commitment) {
            return Err(Error::InvalidProof);
        }
        Ok(reshard)
    }

    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        _checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
        concurrency: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        decode(
            total_shards(config)?,
            config.minimum_shards,
            commitment,
            shards,
            concurrency,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;

    const CONCURRENCY: usize = 1;

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            chunks[0].clone(), // original
            chunks[4].clone(), // recovery
            chunks[6].clone(), // recovery
        ];

        // Try to decode with a mix of original and recovery pieces
        let decoded = decode::<Sha256>(total, min, &root, &pieces, CONCURRENCY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 6u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Try with fewer than min
        let pieces: Vec<_> = chunks.into_iter().take(2).collect();

        // Fail to decode
        let result = decode::<Sha256>(total, min, &root, &pieces, CONCURRENCY);
        assert!(matches!(result, Err(Error::NotEnoughChunks)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Include duplicate index by cloning the first chunk
        let pieces = vec![chunks[0].clone(), chunks[0].clone(), chunks[1].clone()];

        // Fail to decode
        let result = decode::<Sha256>(total, min, &root, &pieces, CONCURRENCY);
        assert!(matches!(result, Err(Error::DuplicateIndex(0))));
    }

    #[test]
    fn test_invalid_index() {
        let data = b"Test invalid index";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Verify all proofs at invalid index
        for i in 0..total {
            assert!(!chunks[i as usize].verify(i + 1, &root));
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed: total > min")]
    fn test_invalid_total() {
        let data = b"Test parameter validation";

        // total <= min should panic
        encode::<Sha256>(3, 3, data.to_vec(), CONCURRENCY).unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: min > 0")]
    fn test_invalid_min() {
        let data = b"Test parameter validation";

        // min = 0 should panic
        encode::<Sha256>(5, 0, data.to_vec(), CONCURRENCY).unwrap();
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 100u16;
        let min = 30u16;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Try to decode with min
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded = decode::<Sha256>(total, min, &root, &minimal, CONCURRENCY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = 7u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.clone(), CONCURRENCY).unwrap();

        // Try to decode with min
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded = decode::<Sha256>(total, min, &root, &minimal, CONCURRENCY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u16;
        let min = 4u16;

        // Encode data correctly to get valid chunks
        let (_correct_root, chunks) =
            encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Create a malicious/fake root (simulating a malicious encoder)
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        // Verify all proofs at incorrect root
        for i in 0..total {
            assert!(!chunks[i as usize].verify(i, &malicious_root));
        }

        // Collect valid pieces (these are legitimate fragments)
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();

        // Attempt to decode with malicious root
        let result = decode::<Sha256>(total, min, &malicious_root, &minimal, CONCURRENCY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 6u16;
        let min = 3u16;

        // Encode data
        let (root, mut chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Tamper with one of the chunks by modifying the shard data
        if !chunks[1].shard.is_empty() {
            chunks[1].shard[0] ^= 0xFF; // Flip bits in first byte
        }

        // Try to decode with the tampered chunk
        let result = decode::<Sha256>(total, min, &root, &chunks, CONCURRENCY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total = 5u16;
        let min = 3u16;
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
            let chunk = Chunk::new(shard, i as u16, merkle_proof);
            pieces.push(chunk);
        }

        // Fail to decode
        let result = decode::<Sha256>(total, min, &malicious_root, &pieces, CONCURRENCY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_decode_invalid_index() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, mut chunks) = encode::<Sha256>(total, min, data.to_vec(), CONCURRENCY).unwrap();

        // Use a mix of original and recovery pieces
        chunks[1].index = 8;
        let pieces: Vec<_> = vec![
            chunks[0].clone(), // original
            chunks[1].clone(), // recovery with invalid index
            chunks[6].clone(), // recovery
        ];

        // Fail to decode
        let result = decode::<Sha256>(total, min, &root, &pieces, CONCURRENCY);
        assert!(matches!(result, Err(Error::InvalidIndex(8))));
    }

    #[test]
    fn test_max_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2;

        // Encode data
        let (root, chunks) = encode::<Sha256>(total, min, data.clone(), CONCURRENCY).unwrap();

        // Try to decode with min
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded = decode::<Sha256>(total, min, &root, &minimal, CONCURRENCY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2 - 1;

        // Encode data
        let result = encode::<Sha256>(total, min, data, CONCURRENCY);
        assert!(matches!(
            result,
            Err(Error::ReedSolomon(
                reed_solomon_simd::Error::UnsupportedShardCount {
                    original_count: _,
                    recovery_count: _,
                }
            ))
        ));
    }

    #[test]
    fn test_too_many_total_shards() {
        assert!(ReedSolomon::<Sha256>::encode(
            &Config {
                minimum_shards: u16::MAX / 2 + 1,
                extra_shards: u16::MAX,
            },
            [].as_slice(),
            CONCURRENCY,
        )
        .is_err())
    }
}

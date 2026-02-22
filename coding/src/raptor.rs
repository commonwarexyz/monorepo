use crate::reed_solomon::Chunk;
use crate::{Config, Scheme};
use bytes::Buf;
use commonware_codec::FixedSize;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::bmt::Builder;
use raptor_code::SourceBlockDecoder;
use std::{collections::HashSet, marker::PhantomData};
use thiserror::Error;

/// Maximum number of source symbols supported by RFC 5053.
///
/// This limit comes from the SYSTEMATIC_INDEX table in the RFC specification,
/// which has 8193 entries (indices 0 through 8192).
const MAX_SOURCE_SYMBOLS: u16 = 8192;

/// Minimum number of source symbols required by RFC 5053.
///
/// The Raptor code's pre-coding matrix is not fully specified with fewer
/// than 4 source symbols.
const MIN_SOURCE_SYMBOLS: u16 = 4;

/// Errors that can occur when interacting with the Raptor coder.
#[derive(Error, Debug)]
pub enum Error {
    #[error("raptor encoding failed: {0}")]
    Encoding(&'static str),
    #[error("raptor decoding failed")]
    DecodingFailed,
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
    #[error("too few source symbols: {0} (minimum {MIN_SOURCE_SYMBOLS})")]
    TooFewSourceSymbols(u16),
    #[error("too many source symbols: {0} (maximum {MAX_SOURCE_SYMBOLS})")]
    TooManySourceSymbols(u16),
}

/// Validate config and return (total, k) as u16 values.
fn validate_config(config: &Config) -> Result<(u16, u16), Error> {
    let k = config.minimum_shards.get();
    if k < MIN_SOURCE_SYMBOLS {
        return Err(Error::TooFewSourceSymbols(k));
    }
    if k > MAX_SOURCE_SYMBOLS {
        return Err(Error::TooManySourceSymbols(k));
    }
    let total = config.total_shards();
    let total: u16 = total
        .try_into()
        .map_err(|_| Error::TooManyTotalShards(total))?;
    Ok((total, k))
}

/// Prepend a u32 length prefix and pad so the data divides evenly into `k` symbols.
fn prepare_data(data: Vec<u8>, k: usize) -> Vec<u8> {
    let data_len = data.len();
    let prefixed_len = u32::SIZE + data_len;
    let symbol_len = prefixed_len.div_ceil(k);
    let padded_len = k * symbol_len;

    let mut padded = vec![0u8; padded_len];
    padded[..u32::SIZE].copy_from_slice(&(data_len as u32).to_be_bytes());
    padded[u32::SIZE..u32::SIZE + data_len].copy_from_slice(&data);
    padded
}

/// Extract original data from decoded bytes (strip u32 length prefix).
fn extract_data(decoded: &[u8]) -> Vec<u8> {
    let data_len =
        u32::from_be_bytes(decoded[..u32::SIZE].try_into().expect("insufficient data")) as usize;
    decoded[u32::SIZE..u32::SIZE + data_len].to_vec()
}

/// Encode data using Raptor codes and insert into a [bmt].
#[allow(clippy::type_complexity)]
fn encode<H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    strategy: &S,
) -> Result<(H::Digest, Vec<Chunk<H::Digest>>), Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min >= MIN_SOURCE_SYMBOLS);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidDataLength(data.len()));
    }

    // Prepare data with length prefix and padding
    let padded = prepare_data(data, k);

    // Encode using Raptor codes
    let (symbols, actual_k) =
        raptor_code::encode_source_block(&padded, k, m).map_err(Error::Encoding)?;
    assert_eq!(
        actual_k as usize, k,
        "raptor partitioned into {actual_k} symbols, expected {k}"
    );

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    let shard_hashes = strategy.map_init_collect_vec(&symbols, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();
    let root = tree.root();

    // Generate chunks
    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in symbols.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(shard.into(), i as u16, proof));
    }

    Ok((root, chunks))
}

/// Decode data from a set of [Chunk]s using Raptor codes.
fn decode<H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    root: &H::Digest,
    chunks: &[Chunk<H::Digest>],
    strategy: &S,
) -> Result<Vec<u8>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min >= MIN_SOURCE_SYMBOLS);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    if chunks.len() < k {
        return Err(Error::NotEnoughChunks);
    }

    // Validate chunks and feed to decoder
    let shard_len = chunks[0].shard.len();
    let mut seen = HashSet::new();
    let mut decoder = SourceBlockDecoder::new(k);
    for chunk in chunks {
        let index = chunk.index;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        if seen.contains(&index) {
            return Err(Error::DuplicateIndex(index));
        }
        seen.insert(index);
        decoder.push_encoding_symbol(&chunk.shard, u32::from(index));
    }

    // Decode
    let padded_len = k * shard_len;
    let decoded = decoder.decode(padded_len).ok_or(Error::DecodingFailed)?;

    // Re-encode for consistency verification
    let (re_encoded, re_k) =
        raptor_code::encode_source_block(&decoded, k, m).map_err(Error::Encoding)?;
    assert_eq!(re_k as usize, k);

    // Build Merkle tree from re-encoded symbols and verify root
    let mut builder = Builder::<H>::new(n);
    let shard_hashes = strategy.map_init_collect_vec(&re_encoded, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();
    if tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    Ok(extract_data(&decoded))
}

/// A Raptor code ([RFC 5053](https://datatracker.ietf.org/doc/html/rfc5053))
/// encoder that emits chunks provable against a [bmt](commonware_storage::bmt).
///
/// # Behavior
///
/// Raptor codes are a class of fountain codes that enable efficient forward error
/// correction. The encoder takes input data, splits it into `k` source symbols, and
/// generates `m` repair symbols using LDPC pre-coding and LT (Luby Transform) encoding.
/// All `n = k + m` symbols are then used to build a
/// [bmt](commonware_storage::bmt), producing a single root hash.
/// Each symbol is packaged as a chunk containing the symbol data, its index,
/// and a Merkle proof against the root.
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
///               | [Length Prefix | Original Data | Pad] |
///               +--------------------------------------+
///                                  |
///                                  v
///              +----------+ +----------+    +-----------+
///              | Symbol 0 | | Symbol 1 | .. | Symbol k-1|  (Source Symbols)
///              +----------+ +----------+    +-----------+
///                     |            |             |
///                     +------------+-------------+
///                                  |
///                                  v
///                        +------------------+
///                        | Raptor Encoder   |
///                        | (RFC 5053)       |
///                        +------------------+
///                                  |
///                                  v
///              +----------+ +----------+    +-----------+
///              | Symbol k | | Symbol k+1| ..| Symbol n-1|  (Repair Symbols)
///              +----------+ +----------+    +-----------+
/// ```
///
/// ## Merkle Tree Construction
///
/// All `n` symbols (source and repair) are hashed and used as leaves to build a
/// [bmt](commonware_storage::bmt).
///
/// The final output is the root and a set of `n` chunks.
///
/// ## Decoding and Verification
///
/// The decoder requires any `k` chunks to reconstruct the original data.
/// 1. Each chunk's Merkle proof is verified against the root.
/// 2. The symbols from valid chunks are fed to the Raptor decoder.
/// 3. To ensure consistency, the recovered data is re-encoded, and a new root is
///    generated. This new root MUST match the original root.
/// 4. If the roots match, the original data is extracted.
///
/// ## Constraints
///
/// - Minimum source symbols (k): 4
/// - Maximum source symbols (k): 8192
/// - This is a systematic code: source symbols contain the original data.
#[derive(Clone, Copy)]
pub struct Raptor<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for Raptor<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Raptor").finish()
    }
}

impl<H: Hasher> Scheme for Raptor<H> {
    type Commitment = H::Digest;

    type StrongShard = Chunk<H::Digest>;
    type WeakShard = Chunk<H::Digest>;
    type CheckedShard = Chunk<H::Digest>;
    type CheckingData = ();

    type Error = Error;

    fn encode(
        config: &Config,
        mut data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error> {
        let (total, k) = validate_config(config)?;
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        encode::<H, _>(total, k, data, strategy)
    }

    fn weaken(
        _config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::StrongShard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error> {
        if shard.index != index {
            return Err(Error::WrongIndex(index));
        }
        if shard.verify::<H>(shard.index, commitment) {
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
        weak_shard: Self::WeakShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        if weak_shard.index != index {
            return Err(Error::WrongIndex(weak_shard.index));
        }
        if !weak_shard.verify::<H>(weak_shard.index, commitment) {
            return Err(Error::InvalidProof);
        }
        Ok(weak_shard)
    }

    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        _checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        let (total, k) = validate_config(config)?;
        decode::<H, _>(total, k, commitment, shards, strategy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;

    const STRATEGY: Sequential = Sequential;

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery with Raptor codes";
        let total = 10u16;
        let min = 5u16;

        // Encode the data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Use a mix of source and repair symbols
        let pieces: Vec<_> = vec![
            chunks[0].clone(), // source
            chunks[2].clone(), // source
            chunks[4].clone(), // source
            chunks[6].clone(), // repair
            chunks[8].clone(), // repair
        ];

        // Decode
        let decoded = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 10u16;
        let min = 6u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Try with fewer than min
        let pieces: Vec<_> = chunks.into_iter().take(3).collect();

        // Fail to decode
        let result = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::NotEnoughChunks)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 10u16;
        let min = 5u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Include duplicate index
        let pieces = vec![
            chunks[0].clone(),
            chunks[0].clone(),
            chunks[1].clone(),
            chunks[2].clone(),
            chunks[3].clone(),
        ];

        // Fail to decode
        let result = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::DuplicateIndex(0))));
    }

    #[test]
    fn test_invalid_index() {
        let data = b"Test invalid index";
        let total = 10u16;
        let min = 5u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Verify all proofs at invalid index
        for i in 0..total {
            assert!(!chunks[i as usize].verify::<Sha256>(i + 1, &root));
        }
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 12u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Decode with min
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000];
        let total = 12u16;
        let min = 6u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        // Decode with min
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 12u16;
        let min = 6u16;

        // Encode data
        let (_correct_root, chunks) =
            encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Create a malicious root
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data");
        let malicious_root = hasher.finalize();

        // Verify all proofs fail against malicious root
        for i in 0..total {
            assert!(!chunks[i as usize].verify::<Sha256>(i, &malicious_root));
        }

        // Attempt decode with malicious root
        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let result = decode::<Sha256, _>(total, min, &malicious_root, &minimal, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 10u16;
        let min = 5u16;

        // Encode data
        let (root, mut chunks) =
            encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Tamper with one chunk
        if !chunks[1].shard.is_empty() {
            let mut shard = chunks[1].shard.to_vec();
            shard[0] ^= 0xFF;
            chunks[1] = Chunk::new(shard.into(), chunks[1].index, chunks[1].proof.clone());
        }

        // Decode with tampered chunk should fail consistency check
        let pieces: Vec<_> = chunks.into_iter().take(min as usize).collect();
        let result = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_too_few_source_symbols() {
        let config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(2),
        };
        let result = Raptor::<Sha256>::encode(&config, [0u8].as_slice(), &STRATEGY);
        assert!(matches!(result, Err(Error::TooFewSourceSymbols(3))));
    }

    #[test]
    fn test_decode_invalid_index() {
        let data = b"Testing Raptor codes";
        let total = 10u16;
        let min = 5u16;

        // Encode
        let (root, mut chunks) =
            encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Set invalid index
        chunks[1] = Chunk::new(chunks[1].shard.clone(), 10, chunks[1].proof.clone());
        let pieces: Vec<_> = vec![
            chunks[0].clone(),
            chunks[1].clone(),
            chunks[2].clone(),
            chunks[3].clone(),
            chunks[4].clone(),
        ];

        let result = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::InvalidIndex(10))));
    }

    #[test]
    fn test_extra_shards() {
        // Decode using more than minimum number of shards
        let data = b"Decode with extra shards";
        let total = 12u16;
        let min = 4u16;

        // Encode
        let (root, chunks) = encode::<Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Use min+2 shards (a mix of source and repair)
        let pieces: Vec<_> = vec![
            chunks[0].clone(),
            chunks[1].clone(),
            chunks[2].clone(),
            chunks[3].clone(),
            chunks[5].clone(),
            chunks[7].clone(),
        ];

        let decoded = decode::<Sha256, _>(total, min, &root, &pieces, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_total_shards() {
        // k = 8192 is valid, but total = 8192 + 65535 overflows u16
        let result = Raptor::<Sha256>::encode(
            &Config {
                minimum_shards: NZU16!(MAX_SOURCE_SYMBOLS),
                extra_shards: NZU16!(u16::MAX),
            },
            [].as_slice(),
            &STRATEGY,
        );
        assert!(matches!(result, Err(Error::TooManyTotalShards(_))));
    }

    #[test]
    fn test_too_many_source_symbols() {
        let result = Raptor::<Sha256>::encode(
            &Config {
                minimum_shards: NZU16!(MAX_SOURCE_SYMBOLS + 1),
                extra_shards: NZU16!(1),
            },
            [].as_slice(),
            &STRATEGY,
        );
        assert!(matches!(result, Err(Error::TooManySourceSymbols(_))));
    }
}

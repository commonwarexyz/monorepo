use crate::{Config, Scheme};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{self, Builder};
use std::{collections::HashSet, fmt::Debug, marker::PhantomData};
use thiserror::Error;

pub(crate) mod gf8_arithmetic;
pub(crate) mod gf8_simd;

mod gf16;
mod gf8;

pub use gf16::Gf16;
pub use gf8::Gf8;

/// A Reed-Solomon encoding/decoding engine over a specific Galois field.
///
/// Implementations provide the core field arithmetic and matrix operations
/// for encoding original data shards into recovery shards, and decoding
/// a mix of original and recovery shards back to the full set of originals.
pub trait Engine: Clone + Debug + Send + Sync + 'static {
    /// Error type for encode/decode operations.
    type Error: Debug + std::fmt::Display + std::error::Error + Send + 'static;

    /// Required shard length alignment in bytes (1 = no requirement).
    const SHARD_ALIGNMENT: usize;

    /// Maximum total shards (k + m) supported by this engine.
    fn max_shards() -> usize;

    /// Encode `k` original shards into `m` recovery shards.
    ///
    /// All shards in `original` must have the same length.
    fn encode(k: usize, m: usize, original: &[&[u8]]) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Decode from a mix of original and recovery shards.
    ///
    /// `original`: (index, data) pairs for available originals (index in `0..k`).
    /// `recovery`: (index, data) pairs for available recovery (index in `0..m`).
    ///
    /// Returns all `k` original shards.
    fn decode(
        k: usize,
        m: usize,
        shard_len: usize,
        original: &[(usize, &[u8])],
        recovery: &[(usize, &[u8])],
    ) -> Result<Vec<Vec<u8>>, Self::Error>;
}

/// Errors that can occur when interacting with the Reed-Solomon coder.
#[derive(Error, Debug)]
pub enum Error {
    #[error("engine error: {0}")]
    Engine(String),
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

fn validate_total_shards<V: Engine>(config: &Config) -> Result<u16, Error> {
    let total = config.total_shards();
    let n: u16 = total
        .try_into()
        .map_err(|_| Error::TooManyTotalShards(total))?;
    if (n as usize) > V::max_shards() {
        return Err(Error::TooManyTotalShards(total));
    }
    Ok(n)
}

/// A piece of data from a Reed-Solomon encoded object.
#[derive(Debug, Clone)]
pub struct Chunk<D: Digest> {
    /// The shard of encoded data.
    shard: Bytes,

    /// The index of [Chunk] in the original data.
    index: u16,

    /// The multi-proof of the shard in the [bmt] at the given index.
    proof: bmt::Proof<D>,
}

impl<D: Digest> Chunk<D> {
    /// Create a new [Chunk] from the given shard, index, and proof.
    const fn new(shard: Bytes, index: u16, proof: bmt::Proof<D>) -> Self {
        Self {
            shard,
            index,
            proof,
        }
    }

    /// Verify a [Chunk] against the given root.
    fn verify<H: Hasher<Digest = D>>(&self, index: u16, root: &D) -> bool {
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
            .verify_element_inclusion(&mut hasher, &shard_digest, self.index as u32, root)
            .is_ok()
    }
}

impl<D: Digest> Write for Chunk<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.shard.write(writer);
        self.index.write(writer);
        self.proof.write(writer);
    }
}

impl<D: Digest> Read for Chunk<D> {
    /// The maximum size of the shard.
    type Cfg = crate::CodecConfig;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let shard = Bytes::read_cfg(reader, &RangeCfg::new(..=cfg.maximum_shard_size))?;
        let index = u16::read(reader)?;
        let proof = bmt::Proof::<D>::read_cfg(reader, &1)?;
        Ok(Self {
            shard,
            index,
            proof,
        })
    }
}

impl<D: Digest> EncodeSize for Chunk<D> {
    fn encode_size(&self) -> usize {
        self.shard.encode_size() + self.index.encode_size() + self.proof.encode_size()
    }
}

impl<D: Digest> PartialEq for Chunk<D> {
    fn eq(&self, other: &Self) -> bool {
        self.shard == other.shard && self.index == other.index && self.proof == other.proof
    }
}

impl<D: Digest> Eq for Chunk<D> {}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Chunk<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            shard: u.arbitrary::<Vec<u8>>()?.into(),
            index: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// Prepare data for encoding, splitting it into `k` equal-length shards
/// with a 4-byte length prefix.
fn prepare_data<V: Engine>(data: Vec<u8>, k: usize, m: usize) -> Vec<Vec<u8>> {
    // Compute shard length
    let data_len = data.len();
    let prefixed_len = u32::SIZE + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);

    // Align shard length to the engine's requirement
    let align = V::SHARD_ALIGNMENT;
    if align > 1 && !shard_len.is_multiple_of(align) {
        shard_len = shard_len.div_ceil(align) * align;
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
type Encoding<D> = (bmt::Tree<D>, Vec<Vec<u8>>);

/// Inner logic for encoding with a specific engine.
fn encode_inner<V: Engine, H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    strategy: &S,
) -> Result<Encoding<H::Digest>, Error> {
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
    let mut shards = prepare_data::<V>(data, k, m);
    // Use engine to encode
    let original_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();
    let recovery_shards = V::encode(k, m, &original_refs).map_err(|e| Error::Engine(e.to_string()))?;
    shards.extend(recovery_shards);

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    let shard_hashes = strategy.map_init_collect_vec(&shards, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();

    Ok((tree, shards))
}

/// Encode data using a Reed-Solomon coder and insert it into a [bmt].
#[allow(clippy::type_complexity)]
fn rs_encode<V: Engine, H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    strategy: &S,
) -> Result<(H::Digest, Vec<Chunk<H::Digest>>), Error> {
    // Encode data
    let (tree, shards) = encode_inner::<V, H, _>(total, min, data, strategy)?;
    let root = tree.root();
    let n = total as usize;

    // Generate chunks
    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in shards.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(shard.into(), i as u16, proof));
    }

    Ok((root, chunks))
}

/// Decode data from a set of [Chunk]s using a specific engine.
fn rs_decode<V: Engine, H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    root: &H::Digest,
    chunks: &[Chunk<H::Digest>],
    strategy: &S,
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

    // Collect and validate chunks
    let shard_len = chunks[0].shard.len();
    let mut seen = HashSet::new();
    let mut provided_originals: Vec<(usize, &[u8])> = Vec::new();
    let mut provided_recoveries: Vec<(usize, &[u8])> = Vec::new();
    for chunk in chunks {
        let index = chunk.index;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        if seen.contains(&index) {
            return Err(Error::DuplicateIndex(index));
        }
        seen.insert(index);

        if index < min {
            provided_originals.push((index as usize, chunk.shard.as_ref()));
        } else {
            provided_recoveries.push((index as usize - k, chunk.shard.as_ref()));
        }
    }

    // Use engine to decode
    let decoded_originals = V::decode(k, m, shard_len, &provided_originals, &provided_recoveries)
        .map_err(|e| Error::Engine(e.to_string()))?;

    // Reconstruct all shards (originals from decode + re-encode for recovery)
    let original_refs: Vec<&[u8]> = decoded_originals.iter().map(|s| s.as_slice()).collect();
    let recovery_shards =
        V::encode(k, m, &original_refs).map_err(|e| Error::Engine(e.to_string()))?;

    let mut all_shards: Vec<&[u8]> = Vec::with_capacity(n);
    for s in &decoded_originals {
        all_shards.push(s.as_slice());
    }
    for s in &recovery_shards {
        all_shards.push(s.as_slice());
    }

    // Build Merkle tree to verify consistency
    let mut builder = Builder::<H>::new(n);
    let shard_hashes = strategy.map_init_collect_vec(&all_shards, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();

    // Confirm root is consistent
    if tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    Ok(extract_data(all_shards, k))
}

/// A Reed-Solomon coder parameterized by a hasher `H` and an engine `V`.
///
/// The engine determines the Galois field used for encoding/decoding. Use
/// [`Gf16`] for GF(2^16) (up to 65535 shards) or [`Gf8`] for GF(2^8)
/// (up to 255 shards with SIMD-accelerated arithmetic).
///
/// See [`ReedSolomon`] and [`ReedSolomon8`] for convenient type aliases.
#[derive(Clone, Copy)]
pub struct ReedSolomonInner<H, V: Engine> {
    _marker: PhantomData<(H, V)>,
}

impl<H, V: Engine> std::fmt::Debug for ReedSolomonInner<H, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReedSolomon").finish()
    }
}

impl<H: Hasher, V: Engine> Scheme for ReedSolomonInner<H, V> {
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
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        rs_encode::<V, H, _>(
            validate_total_shards::<V>(config)?,
            config.minimum_shards.get(),
            data,
            strategy,
        )
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
        rs_decode::<V, H, _>(
            validate_total_shards::<V>(config)?,
            config.minimum_shards.get(),
            commitment,
            shards,
            strategy,
        )
    }
}

/// Backward-compatible type alias: Reed-Solomon over GF(2^16).
///
/// Supports up to 65535 total shards. Uses `reed-solomon-simd` internally.
pub type ReedSolomon<H> = ReedSolomonInner<H, Gf16>;

/// Reed-Solomon over GF(2^8) with SIMD-accelerated arithmetic.
///
/// Supports up to 255 total shards. Uses native Rust with runtime SIMD
/// dispatch (GFNI, AVX2, SSSE3, NEON) for ISA-L-class performance.
pub type ReedSolomon8<H> = ReedSolomonInner<H, Gf8>;

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;
    use reed_solomon_simd::ReedSolomonEncoder;

    const STRATEGY: Sequential = Sequential;

    // ======================================================================
    // Tests using the Gf16 engine (backward compat verification)
    // ======================================================================

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let pieces: Vec<_> = vec![
            chunks[0].clone(),
            chunks[4].clone(),
            chunks[6].clone(),
        ];

        let decoded =
            rs_decode::<Gf16, Sha256, _>(total, min, &root, &pieces, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 6u16;
        let min = 4u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let pieces: Vec<_> = chunks.into_iter().take(2).collect();

        let result = rs_decode::<Gf16, Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::NotEnoughChunks)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 5u16;
        let min = 3u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let pieces = vec![chunks[0].clone(), chunks[0].clone(), chunks[1].clone()];

        let result = rs_decode::<Gf16, Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::DuplicateIndex(0))));
    }

    #[test]
    fn test_invalid_index() {
        let data = b"Test invalid index";
        let total = 5u16;
        let min = 3u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        for i in 0..total {
            assert!(!chunks[i as usize].verify::<Sha256>(i + 1, &root));
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed: total > min")]
    fn test_invalid_total() {
        let data = b"Test parameter validation";
        rs_encode::<Gf16, Sha256, _>(3, 3, data.to_vec(), &STRATEGY).unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: min > 0")]
    fn test_invalid_min() {
        let data = b"Test parameter validation";
        rs_encode::<Gf16, Sha256, _>(5, 0, data.to_vec(), &STRATEGY).unwrap();
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 100u16;
        let min = 30u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf16, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000];
        let total = 7u16;
        let min = 4u16;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf16, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u16;
        let min = 4u16;

        let (_correct_root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        for i in 0..total {
            assert!(!chunks[i as usize].verify::<Sha256>(i, &malicious_root));
        }

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();

        let result =
            rs_decode::<Gf16, Sha256, _>(total, min, &malicious_root, &minimal, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 6u16;
        let min = 3u16;

        let (root, mut chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        if !chunks[1].shard.is_empty() {
            let mut shard = chunks[1].shard.to_vec();
            shard[0] ^= 0xFF;
            chunks[1].shard = shard.into();
        }

        let result = rs_decode::<Gf16, Sha256, _>(total, min, &root, &chunks, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total = 5u16;
        let min = 3u16;
        let m = total - min;

        let shards = prepare_data::<Gf16>(data.to_vec(), min as usize, m as usize);
        let shard_size = shards[0].len();

        let mut encoder =
            ReedSolomonEncoder::new(min as usize, m as usize, shard_size).unwrap();
        for shard in &shards {
            encoder.add_original_shard(shard).unwrap();
        }
        let recovery_result = encoder.encode().unwrap();
        let mut recovery_shards: Vec<Vec<u8>> = recovery_result
            .recovery_iter()
            .map(|s| s.to_vec())
            .collect();

        if !recovery_shards[0].is_empty() {
            recovery_shards[0][0] ^= 0xFF;
        }

        let mut malicious_shards = shards.clone();
        malicious_shards.extend(recovery_shards);

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &malicious_shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let malicious_tree = builder.build();
        let malicious_root = malicious_tree.root();

        let selected_indices = vec![0, 1, 3];
        let mut pieces = Vec::new();
        for &i in &selected_indices {
            let merkle_proof = malicious_tree.proof(i as u32).unwrap();
            let shard = malicious_shards[i].clone();
            let chunk = Chunk::new(shard.into(), i as u16, merkle_proof);
            pieces.push(chunk);
        }

        let result =
            rs_decode::<Gf16, Sha256, _>(total, min, &malicious_root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_decode_invalid_index() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        let (root, mut chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        chunks[1].index = 8;
        let pieces: Vec<_> = vec![
            chunks[0].clone(),
            chunks[1].clone(),
            chunks[6].clone(),
        ];

        let result = rs_decode::<Gf16, Sha256, _>(total, min, &root, &pieces, &STRATEGY);
        assert!(matches!(result, Err(Error::InvalidIndex(8))));
    }

    #[test]
    fn test_max_chunks() {
        let data = vec![42u8; 1000];
        let total = u16::MAX;
        let min = u16::MAX / 2;

        let (root, chunks) =
            rs_encode::<Gf16, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf16, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_chunks() {
        let data = vec![42u8; 1000];
        let total = u16::MAX;
        let min = u16::MAX / 2 - 1;

        let result = rs_encode::<Gf16, Sha256, _>(total, min, data, &STRATEGY);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_many_total_shards() {
        assert!(ReedSolomon::<Sha256>::encode(
            &Config {
                minimum_shards: NZU16!(u16::MAX / 2 + 1),
                extra_shards: NZU16!(u16::MAX),
            },
            [].as_slice(),
            &STRATEGY,
        )
        .is_err())
    }

    // ======================================================================
    // Tests using the Gf8 engine
    // ======================================================================

    #[test]
    fn test_gf8_recovery() {
        let data = b"Testing GF8 recovery pieces";
        let total = 8u16;
        let min = 3u16;

        let (root, chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let pieces: Vec<_> = vec![
            chunks[0].clone(),
            chunks[4].clone(),
            chunks[6].clone(),
        ];

        let decoded =
            rs_decode::<Gf8, Sha256, _>(total, min, &root, &pieces, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_gf8_empty_data() {
        let data = b"";
        let total = 100u16;
        let min = 30u16;

        let (root, chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf8, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_gf8_large_data() {
        let data = vec![42u8; 1000];
        let total = 7u16;
        let min = 4u16;

        let (root, chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf8, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_gf8_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u16;
        let min = 4u16;

        let (_correct_root, chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"malicious");
        let malicious_root = hasher.finalize();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let result =
            rs_decode::<Gf8, Sha256, _>(total, min, &malicious_root, &minimal, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_gf8_max_shards() {
        let data = vec![42u8; 100];
        let total = 255u16;
        let min = 85u16;

        let (root, chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        let minimal = chunks.into_iter().take(min as usize).collect::<Vec<_>>();
        let decoded =
            rs_decode::<Gf8, Sha256, _>(total, min, &root, &minimal, &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_gf8_too_many_shards() {
        assert!(ReedSolomon8::<Sha256>::encode(
            &Config {
                minimum_shards: NZU16!(128),
                extra_shards: NZU16!(128),
            },
            [0u8; 100].as_slice(),
            &STRATEGY,
        )
        .is_err());
    }

    #[test]
    fn test_gf8_manipulated_chunk() {
        let data = b"Data integrity must be maintained";
        let total = 6u16;
        let min = 3u16;

        let (root, mut chunks) =
            rs_encode::<Gf8, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        if !chunks[1].shard.is_empty() {
            let mut shard = chunks[1].shard.to_vec();
            shard[0] ^= 0xFF;
            chunks[1].shard = shard.into();
        }

        let result = rs_decode::<Gf8, Sha256, _>(total, min, &root, &chunks, &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Chunk<Sha256Digest>>,
        }
    }
}

use crate::{Config, Scheme};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{self, Builder};
use std::{fmt::Debug, marker::PhantomData};
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
    /// All shards in `original` must have the same length.
    fn encode(k: usize, m: usize, original: &[&[u8]]) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Decode from a mix of original and recovery shards.
    /// `original`: (index, data) pairs for available originals (index in `0..k`).
    /// `recovery`: (index, data) pairs for available recovery (index in `0..m`).
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
    #[error("too many total shards: {0}")]
    TooManyTotalShards(u32),
    #[error("checked shard commitment does not match decode commitment")]
    CommitmentMismatch,
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

    /// The index of [`Chunk`] in the original data.
    index: u16,

    /// The multi-proof of the shard in the [`bmt`] at the given index.
    proof: bmt::Proof<D>,
}

impl<D: Digest> Chunk<D> {
    /// Create a new [`Chunk`] from the given shard, index, and proof.
    const fn new(shard: Bytes, index: u16, proof: bmt::Proof<D>) -> Self {
        Self {
            shard,
            index,
            proof,
        }
    }

    /// Verify a [`Chunk`] against the given root.
    fn verify<H: Hasher<Digest = D>>(&self, index: u16, root: &D) -> Option<CheckedChunk<D>> {
        // Ensure the index matches
        if index != self.index {
            return None;
        }

        // Compute shard digest
        let mut hasher = H::new();
        hasher.update(&self.shard);
        let shard_digest = hasher.finalize();

        // Verify proof
        self.proof
            .verify_element_inclusion(&mut hasher, &shard_digest, self.index as u32, root)
            .ok()?;

        Some(CheckedChunk::new(
            *root,
            self.shard.clone(),
            self.index,
            shard_digest,
        ))
    }
}

/// A shard that has been checked against a commitment.
///
/// This stores the shard digest computed during [`Chunk::verify`] and the
/// commitment root it was verified against. The root is checked at decode
/// time to prevent cross-commitment shard mixing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedChunk<D: Digest> {
    root: D,
    shard: Bytes,
    index: u16,
    digest: D,
}

impl<D: Digest> CheckedChunk<D> {
    const fn new(root: D, shard: Bytes, index: u16, digest: D) -> Self {
        Self {
            root,
            shard,
            index,
            digest,
        }
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

/// Prepare data for encoding.
///
/// Returns a contiguous buffer of `k` padded shards and the shard length.
/// The buffer layout is `[length_prefix | data | zero_padding]` split into
/// `k` equal-sized shards of `shard_len` bytes each.
fn prepare_data<V: Engine>(data: &[u8], k: usize) -> (Vec<u8>, usize) {
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
    padded[u32::SIZE..u32::SIZE + data_len].copy_from_slice(data);

    (padded, shard_len)
}

/// Extract data from encoded shards.
///
/// The first `k` shards, when concatenated, form `[length_prefix | data | padding]`.
/// This function bulk-copies shard slices while skipping the 4-byte prefix.
fn extract_data(shards: &[&[u8]], k: usize) -> Result<Vec<u8>, Error> {
    let shards = shards.get(..k).ok_or(Error::NotEnoughChunks)?;
    let (data_len, payload_len) = read_prefix_and_payload_len(shards)?;
    let mut payload = copy_payload_after_prefix(shards, payload_len);
    validate_zero_padding(&payload, data_len)?;
    payload.truncate(data_len);
    Ok(payload)
}

/// Read the 4-byte big-endian length prefix from `shards` and validate that
/// the decoded length fits in the post-prefix payload region.
fn read_prefix_and_payload_len(shards: &[&[u8]]) -> Result<(usize, usize), Error> {
    let total_len: usize = shards.iter().map(|s| s.len()).sum();
    if total_len < u32::SIZE {
        return Err(Error::Inconsistent);
    }

    // Read the length prefix, which may span multiple shards.
    let mut prefix = [0u8; u32::SIZE];
    let mut prefix_len = 0usize;
    for shard in shards {
        if prefix_len == u32::SIZE {
            break;
        }
        let read = (u32::SIZE - prefix_len).min(shard.len());
        prefix[prefix_len..prefix_len + read].copy_from_slice(&shard[..read]);
        prefix_len += read;
    }

    let data_len = u32::from_be_bytes(prefix) as usize;
    let payload_len = total_len - u32::SIZE;
    if data_len > payload_len {
        return Err(Error::Inconsistent);
    }
    Ok((data_len, payload_len))
}

/// Bulk-copy bytes after the 4-byte prefix from `shards` into a contiguous
/// payload buffer.
fn copy_payload_after_prefix(shards: &[&[u8]], payload_len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(payload_len);
    let mut prefix_bytes_left = u32::SIZE;
    for shard in shards {
        if prefix_bytes_left >= shard.len() {
            prefix_bytes_left -= shard.len();
            continue;
        }
        payload.extend_from_slice(&shard[prefix_bytes_left..]);
        prefix_bytes_left = 0;
    }
    payload
}

/// Validate canonical encoding by requiring trailing bytes after `data_len`
/// to be zero.
fn validate_zero_padding(payload: &[u8], data_len: usize) -> Result<(), Error> {
    // Canonical encoding requires all trailing bytes to be zero.
    if !payload[data_len..].iter().all(|byte| *byte == 0) {
        return Err(Error::Inconsistent);
    }
    Ok(())
}

/// Type alias for the internal encoding result.
type Encoding<D> = (D, Vec<Chunk<D>>);

/// Encode data using a Reed-Solomon coder and insert it into a [`bmt`].
///
/// # Parameters
///
/// - `total`: The total number of chunks to generate.
/// - `min`: The minimum number of chunks required to decode the data.
/// - `data`: The data to encode.
/// - `strategy`: The parallelism strategy to use.
///
/// # Returns
///
/// - `root`: The root of the [`bmt`].
/// - `chunks`: [`Chunk`]s of encoded data (that can be proven against `root`).
fn encode<V: Engine, H: Hasher, S: Strategy>(
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

    // Prepare data as a contiguous buffer of k shards
    let (padded, shard_len) = prepare_data::<V>(&data, k);

    // Use engine to encode
    let original_refs: Vec<&[u8]> = padded.chunks(shard_len).collect();
    let recovery_shards =
        V::encode(k, m, &original_refs).map_err(|e| Error::Engine(e.to_string()))?;

    // Collect recovery into a contiguous buffer
    let mut recovery_buf = Vec::with_capacity(m * shard_len);
    for shard in &recovery_shards {
        recovery_buf.extend_from_slice(shard);
    }

    // Create zero-copy Bytes views into the original and recovery buffers
    let originals: Bytes = padded.into();
    let recoveries: Bytes = recovery_buf.into();

    // Build Merkle tree
    let mut builder = Builder::<H>::new(n);
    let shard_slices: Vec<Bytes> = (0..k)
        .map(|i| originals.slice(i * shard_len..(i + 1) * shard_len))
        .chain((0..m).map(|i| recoveries.slice(i * shard_len..(i + 1) * shard_len)))
        .collect();
    let shard_hashes = strategy.map_init_collect_vec(&shard_slices, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();
    let root = tree.root();

    // Generate chunks with zero-copy shard views
    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in shard_slices.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(shard, i as u16, proof));
    }

    Ok((root, chunks))
}

/// Decode data from a set of [`CheckedChunk`]s.
///
/// It is assumed that all chunks have already been verified against the given root using [`Chunk::verify`].
///
/// # Parameters
///
/// - `total`: The total number of chunks to generate.
/// - `min`: The minimum number of chunks required to decode the data.
/// - `root`: The root of the [`bmt`].
/// - `chunks`: [`CheckedChunk`]s of encoded data (that can be proven against `root`)
///
/// # Returns
///
/// - `data`: The decoded data.
fn decode<'a, V: Engine, H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    root: &H::Digest,
    chunks: impl Iterator<Item = &'a CheckedChunk<H::Digest>>,
    strategy: &S,
) -> Result<Vec<u8>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    let mut chunks = chunks.peekable();
    let Some(first) = chunks.peek() else {
        return Err(Error::NotEnoughChunks);
    };

    // Process checked chunks
    let shard_len = first.shard.len();
    let mut shard_digests: Vec<Option<H::Digest>> = vec![None; n];
    let mut provided_originals: Vec<(usize, &[u8])> = Vec::new();
    let mut provided_recoveries: Vec<(usize, &[u8])> = Vec::new();
    let mut provided = 0usize;
    for chunk in chunks {
        provided += 1;
        if &chunk.root != root {
            return Err(Error::CommitmentMismatch);
        }
        // Check for duplicate index
        let index = chunk.index;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        let digest_slot = &mut shard_digests[index as usize];
        if digest_slot.is_some() {
            return Err(Error::DuplicateIndex(index));
        }

        // Add to provided shards and retain the checked digest for this index.
        *digest_slot = Some(chunk.digest);
        if index < min {
            provided_originals.push((index as usize, chunk.shard.as_ref()));
        } else {
            provided_recoveries.push((index as usize - k, chunk.shard.as_ref()));
        }
    }
    if provided < k {
        return Err(Error::NotEnoughChunks);
    }

    // Use engine to decode
    let decoded_originals =
        V::decode(k, m, shard_len, &provided_originals, &provided_recoveries)
            .map_err(|e| Error::Engine(e.to_string()))?;

    // Reconstruct all shards (originals from decode + re-encode for recovery)
    let original_refs: Vec<&[u8]> = decoded_originals.iter().map(|s| s.as_slice()).collect();
    let recovery_shards =
        V::encode(k, m, &original_refs).map_err(|e| Error::Engine(e.to_string()))?;

    let mut shards: Vec<&[u8]> = Vec::with_capacity(n);
    for s in &decoded_originals {
        shards.push(s.as_slice());
    }
    for s in &recovery_shards {
        shards.push(s.as_slice());
    }

    // Build Merkle tree, reusing digests we already have from checked chunks
    for (i, digest) in strategy.map_init_collect_vec(
        shard_digests
            .iter()
            .enumerate()
            .filter_map(|(i, digest)| digest.is_none().then_some(i)),
        H::new,
        |hasher, i| {
            hasher.update(shards[i]);
            (i, hasher.finalize())
        },
    ) {
        shard_digests[i] = Some(digest);
    }

    let mut builder = Builder::<H>::new(n);
    shard_digests
        .into_iter()
        .map(|digest| digest.expect("digest must be present for every shard"))
        .for_each(|digest| {
            builder.add(&digest);
        });
    let tree = builder.build();

    // Confirm root is consistent
    if tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    // Extract original data
    extract_data(&shards, k)
}

/// A SIMD-optimized Reed-Solomon coder that emits chunks that can be proven against a [`bmt`].
///
/// # Behavior
///
/// The encoder takes input data, splits it into `k` data shards, and generates `m` recovery
/// shards using [Reed-Solomon encoding](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction).
/// All `n = k + m` shards are then used to build a [`bmt`], producing a single root hash. Each shard
/// is packaged as a chunk containing the shard data, its index, and a Merkle multi-proof against the [`bmt`] root.
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
/// All `n` shards (data and recovery) are hashed and used as leaves to build a [`bmt`].
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
/// The final output is the [`bmt`] root and a set of `n` chunks.
///
/// `(Root, [Chunk 0, Chunk 1, ..., Chunk n-1])`
///
/// Each chunk contains:
/// - `shard`: The shard data (original or recovery).
/// - `index`: The shard's original index (0 to n-1).
/// - `proof`: A Merkle multi-proof of the shard's inclusion in the [`bmt`].
///
/// ## Decoding and Verification
///
/// The decoder requires any `k` chunks to reconstruct the original data.
/// 1. Each chunk's Merkle multi-proof is verified against the [`bmt`] root.
/// 2. The shards from the valid chunks are used to reconstruct the original `k` data shards.
/// 3. To ensure consistency, the recovered data shards are re-encoded, and a new [`bmt`] root is
///    generated. This new root MUST match the original [`bmt`] root. This prevents attacks where
///    an adversary provides a valid set of chunks that decode to different data.
/// 4. If the roots match, the original data is extracted from the reconstructed data shards.
///
/// The engine `V` determines the Galois field used for encoding/decoding. Use
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
    type Shard = Chunk<H::Digest>;
    type CheckedShard = CheckedChunk<H::Digest>;
    type Error = Error;

    fn encode(
        config: &Config,
        mut data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        encode::<V, H, _>(
            validate_total_shards::<V>(config)?,
            config.minimum_shards.get(),
            data,
            strategy,
        )
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: &Self::Shard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        let total = validate_total_shards::<V>(config)?;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        if shard.proof.leaf_count != u32::from(total) {
            return Err(Error::InvalidProof);
        }
        if shard.index != index {
            return Err(Error::InvalidIndex(shard.index));
        }
        shard
            .verify::<H>(shard.index, commitment)
            .ok_or(Error::InvalidProof)
    }

    fn decode<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        shards: impl Iterator<Item = &'a Self::CheckedShard>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        decode::<V, H, _>(
            validate_total_shards::<V>(config)?,
            config.minimum_shards.get(),
            commitment,
            shards,
            strategy,
        )
    }
}

/// Reed-Solomon over GF(2^16).
///
/// Supports up to 65535 total shards. Uses `reed-solomon-simd` internally.
pub type ReedSolomon16<H> = ReedSolomonInner<H, Gf16>;

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

    type RS = ReedSolomon16<Sha256>;
    const STRATEGY: Sequential = Sequential;

    fn checked(
        root: <Sha256 as Hasher>::Digest,
        chunk: Chunk<<Sha256 as Hasher>::Digest>,
    ) -> CheckedChunk<<Sha256 as Hasher>::Digest> {
        let Chunk { shard, index, .. } = chunk;
        let digest = Sha256::hash(&shard);
        CheckedChunk::new(root, shard, index, digest)
    }

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, chunks) =
            encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            checked(root, chunks[0].clone()), // original
            checked(root, chunks[4].clone()), // recovery
            checked(root, chunks[6].clone()), // recovery
        ];

        // Try to decode with a mix of original and recovery pieces
        let decoded = decode::<Gf16, Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 6u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Try with fewer than min
        let pieces: Vec<_> = chunks
            .into_iter()
            .take(2)
            .map(|c| checked(root, c))
            .collect();

        // Fail to decode
        let result = decode::<Gf16, Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::NotEnoughChunks)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Include duplicate index by cloning the first chunk
        let pieces = [
            checked(root, chunks[0].clone()),
            checked(root, chunks[0].clone()),
            checked(root, chunks[1].clone()),
        ];

        // Fail to decode
        let result = decode::<Gf16, Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::DuplicateIndex(0))));
    }

    #[test]
    fn test_invalid_index() {
        let data = b"Test invalid index";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Verify all proofs at invalid index
        for i in 0..total {
            assert!(chunks[i as usize].verify::<Sha256>(i + 1, &root).is_none());
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed: total > min")]
    fn test_invalid_total() {
        let data = b"Test parameter validation";

        // total <= min should panic
        encode::<Gf16, Sha256, _>(3, 3, data.to_vec(), &STRATEGY).unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: min > 0")]
    fn test_invalid_min() {
        let data = b"Test parameter validation";

        // min = 0 should panic
        encode::<Gf16, Sha256, _>(5, 0, data.to_vec(), &STRATEGY).unwrap();
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 100u16;
        let min = 30u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Gf16, Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = 7u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Gf16, Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u16;
        let min = 4u16;

        // Encode data correctly to get valid chunks
        let (_correct_root, chunks) =
            encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Create a malicious/fake root (simulating a malicious encoder)
        let mut hasher = Sha256::new();
        hasher.update(b"malicious_data_that_wasnt_actually_encoded");
        let malicious_root = hasher.finalize();

        // Verify all proofs at incorrect root
        for i in 0..total {
            assert!(chunks[i as usize]
                .clone()
                .verify::<Sha256>(i, &malicious_root)
                .is_none());
        }

        // Collect valid pieces (these are legitimate fragments checked against
        // the correct root).
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(_correct_root, c))
            .collect::<Vec<_>>();

        // Attempt to decode with malicious root - rejected because checked
        // chunks are bound to a different commitment.
        let result = decode::<Gf16, Sha256, _>(total, min, &malicious_root, minimal.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::CommitmentMismatch)));
    }

    #[test]
    fn test_mismatched_config_rejected_during_check() {
        let config_expected = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };
        let config_actual = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(3),
        };

        let data = b"leaf_count mismatch proof";
        let (commitment, shards) = RS::encode(&config_actual, data.as_slice(), &STRATEGY).unwrap();

        // Previously this passed because check() ignored config and only verified
        // against commitment root. It must now fail immediately.
        let check_result = RS::check(&config_expected, &commitment, 0, &shards[0]);
        assert!(matches!(check_result, Err(Error::InvalidProof)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 6u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();
        let mut pieces: Vec<_> = chunks.into_iter().map(|c| checked(root, c)).collect();

        // Tamper with one of the checked chunks by modifying the shard data.
        if !pieces[1].shard.is_empty() {
            let mut shard = pieces[1].shard.to_vec();
            shard[0] ^= 0xFF; // Flip bits in first byte
            pieces[1].shard = shard.into();
            pieces[1].digest = Sha256::hash(&pieces[1].shard);
        }

        // Try to decode with the tampered chunk
        let result = decode::<Gf16, Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total = 5u16;
        let min = 3u16;
        let m = total - min;

        // Compute original data encoding
        let (padded, shard_size) = prepare_data::<Gf16>(data, min as usize);

        // Re-encode the data
        let mut encoder = ReedSolomonEncoder::new(min as usize, m as usize, shard_size).unwrap();
        for shard in padded.chunks(shard_size) {
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
        let mut malicious_shards: Vec<Vec<u8>> =
            padded.chunks(shard_size).map(|s| s.to_vec()).collect();
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
            let chunk = Chunk::new(shard.into(), i as u16, merkle_proof);
            pieces.push(chunk);
        }
        let pieces: Vec<_> = pieces
            .into_iter()
            .map(|c| checked(malicious_root, c))
            .collect();

        // Fail to decode
        let result = decode::<Gf16, Sha256, _>(total, min, &malicious_root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    // Regression: a commitment built from shards with non-zero trailing padding
    // used to pass decode(), even though canonical re-encoding (zero padding)
    // produces a different root. decode() must reject such non-canonical shards.
    #[test]
    fn test_non_canonical_padding_rejected() {
        let data = b"X";
        let total = 6u16;
        let min = 3u16;
        let k = min as usize;
        let m = total as usize - k;

        let (mut padded, shard_len) = prepare_data::<Gf16>(data, k);
        let payload_end = u32::SIZE + data.len();
        let total_original_len = k * shard_len;
        assert!(payload_end < total_original_len, "test requires padding");

        // Corrupt one canonical padding byte while keeping payload unchanged.
        let pad_shard = payload_end / shard_len;
        let pad_offset = payload_end % shard_len;
        padded[pad_shard * shard_len + pad_offset] = 0xAA;

        let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).unwrap();
        for shard in padded.chunks(shard_len) {
            encoder.add_original_shard(shard).unwrap();
        }
        let recovery = encoder.encode().unwrap();
        let mut shards: Vec<Vec<u8>> = padded.chunks(shard_len).map(|s| s.to_vec()).collect();
        shards.extend(recovery.recovery_iter().map(|s| s.to_vec()));

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let tree = builder.build();
        let non_canonical_root = tree.root();

        let mut pieces = Vec::with_capacity(k);
        for (i, shard) in shards.iter().take(k).enumerate() {
            let proof = tree.proof(i as u32).unwrap();
            pieces.push(checked(
                non_canonical_root,
                Chunk::new(shard.clone().into(), i as u16, proof),
            ));
        }

        let result = decode::<Gf16, Sha256, _>(total, min, &non_canonical_root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_decode_invalid_index() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.to_vec(), &STRATEGY).unwrap();

        // Use a mix of original and recovery pieces
        let mut invalid = checked(root, chunks[1].clone());
        invalid.index = 8;
        let pieces: Vec<_> = vec![
            checked(root, chunks[0].clone()), // original
            invalid,                          // recovery with invalid index
            checked(root, chunks[6].clone()), // recovery
        ];

        // Fail to decode
        let result = decode::<Gf16, Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::InvalidIndex(8))));
    }

    #[test]
    fn test_max_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2;

        // Encode data
        let (root, chunks) = encode::<Gf16, Sha256, _>(total, min, data.clone(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Gf16, Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2 - 1;

        // Encode data
        let result = encode::<Gf16, Sha256, _>(total, min, data, &STRATEGY);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_many_total_shards() {
        assert!(RS::encode(
            &Config {
                minimum_shards: NZU16!(u16::MAX / 2 + 1),
                extra_shards: NZU16!(u16::MAX),
            },
            [].as_slice(),
            &STRATEGY,
        )
        .is_err())
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

use crate::{Config, Scheme};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{BufsMut, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    reed_solomon::{Decoder, Encoder, Error as RsError, SHARD_CHUNK_BYTES},
    Digest, Hasher,
};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{self, Builder};
use commonware_utils::Cached;
use std::{marker::PhantomData, ops::Range};
use thiserror::Error;

// Thread-local caches for reusing `Encoder` and `Decoder`
// instances across calls. Constructing these objects is expensive because
// the underlying engine initializes GF lookup tables. The `reset()` method
// reconfigures the work buffers without rebuilding those tables.
commonware_utils::thread_local_cache!(static CACHED_ENCODER: Encoder);
commonware_utils::thread_local_cache!(static CACHED_DECODER: Decoder);

// Keep each stripe large enough to amortize extra encoder/decoder setup
const MIN_STRIPE_BYTES: usize = 8 * 1024;

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
    #[error("too many total shards: {0}")]
    TooManyTotalShards(u32),
    #[error("checked shard commitment does not match decode commitment")]
    CommitmentMismatch,
}

fn total_shards(config: &Config) -> Result<u16, Error> {
    let total = config.total_shards();
    total
        .try_into()
        .map_err(|_| Error::TooManyTotalShards(total))
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

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.shard.write_bufs(buf);
        self.index.write(buf);
        self.proof.write(buf);
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

    fn encode_inline_size(&self) -> usize {
        self.shard.encode_inline_size() + self.index.encode_size() + self.proof.encode_size()
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
fn prepare_data(mut data: impl Buf, k: usize) -> (Vec<u8>, usize) {
    // Compute shard length
    let data_len = data.remaining();
    let shard_len = canonical_shard_len(data_len, k);

    // Prepare data
    let length_bytes = (data_len as u32).to_be_bytes();
    let mut padded = vec![0u8; k * shard_len];
    padded[..u32::SIZE].copy_from_slice(&length_bytes);
    data.copy_to_slice(&mut padded[u32::SIZE..u32::SIZE + data_len]);

    (padded, shard_len)
}

/// Return the canonical shard width for a payload and shard count.
///
/// Encoding prefixes the payload with its length, splits the result across
/// `k` original shards, and rounds up to an even width required by the
/// Reed-Solomon implementation. Decode uses the same calculation to reject
/// commitments that decode to the same payload with a non-canonical shard width.
const fn canonical_shard_len(data_len: usize, k: usize) -> usize {
    let prefixed_len = u32::SIZE + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);

    // Ensure shard length is even, as required by the Reed-Solomon implementation.
    if !shard_len.is_multiple_of(2) {
        shard_len += 1;
    }

    shard_len
}

/// Extract data from encoded shards and verify that original shards use the canonical width.
///
/// The first `k` shards, when concatenated, form `[length_prefix | data | padding]`.
/// This function copies only the data bytes while validating trailing zero
/// padding directly from the shard slices.
fn extract_data(shards: &[&[u8]], k: usize, expected_shard_len: usize) -> Result<Vec<u8>, Error> {
    let shards = shards.get(..k).ok_or(Error::NotEnoughChunks)?;
    let data_len = read_data_len(shards)?;
    let mut data = Vec::with_capacity(data_len);
    let mut prefix_bytes_left = u32::SIZE;
    let mut data_bytes_left = data_len;
    for shard in shards {
        // The length prefix may straddle shard boundaries, so ignore bytes until
        // we reach the first payload byte.
        if prefix_bytes_left >= shard.len() {
            prefix_bytes_left -= shard.len();
            continue;
        }

        // Copy only the live payload bytes from this shard.
        let payload = &shard[prefix_bytes_left..];
        let copy_len = data_bytes_left.min(payload.len());
        data.extend_from_slice(&payload[..copy_len]);
        data_bytes_left -= copy_len;

        // Any remaining bytes in this shard must be canonical zero padding.
        if !payload[copy_len..].iter().all(|byte| *byte == 0) {
            return Err(Error::Inconsistent);
        }
        prefix_bytes_left = 0;
    }

    // The prefix advertised more payload bytes than were present in the first
    // `k` shards.
    if data_bytes_left != 0 {
        return Err(Error::Inconsistent);
    }

    // Validate that the original shards use the canonical shard width.
    if canonical_shard_len(data.len(), k) != expected_shard_len {
        return Err(Error::Inconsistent);
    }
    Ok(data)
}

/// Read the 4-byte big-endian length prefix from `shards` and validate that
/// the decoded length fits in the post-prefix payload region.
fn read_data_len(shards: &[&[u8]]) -> Result<usize, Error> {
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
    Ok(data_len)
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
fn encode<H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    data: impl Buf,
    strategy: &S,
) -> Result<Encoding<H::Digest>, Error> {
    // Validate parameters
    assert!(total > min);
    assert!(min > 0);
    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    let data_len = data.remaining();
    if data_len > u32::MAX as usize {
        return Err(Error::InvalidDataLength(data_len));
    }

    // Prepare data as a contiguous buffer of k shards
    let (padded, shard_len) = prepare_data(data, k);

    // Compute recovery shards, striping large shard widths across the strategy
    let recovery_buf = match striped::ranges(shard_len, strategy.parallelism_hint()) {
        Some(ranges) => {
            let original_shards = padded.chunks(shard_len).collect::<Vec<_>>();
            let mut buf = vec![0u8; m * shard_len];
            let dst = striped::Dst::new(&mut buf, shard_len);
            strategy.try_map_collect_vec(ranges, |range| {
                striped::encode_recovery_into(k, m, range, &original_shards, dst)
            })?;
            buf
        }
        None => {
            let mut encoder = Cached::take(
                &CACHED_ENCODER,
                || Encoder::new(k, m, shard_len),
                |enc| enc.reset(k, m, shard_len),
            )
            .map_err(Error::ReedSolomon)?;
            for shard in padded.chunks(shard_len) {
                encoder
                    .add_original_shard(shard)
                    .map_err(Error::ReedSolomon)?;
            }

            // Compute recovery shards and collect into a contiguous buffer
            let encoding = encoder.encode().map_err(Error::ReedSolomon)?;
            let mut buf = Vec::with_capacity(m * shard_len);
            for shard in encoding.recovery_iter() {
                buf.extend_from_slice(shard);
            }
            buf
        }
    };

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

/// Read-only parameters shared across the decode helpers.
///
/// Bundling these keeps the decode functions below the argument-count threshold and
/// ensures the same `n`/`k`/`m`/`shard_len`/`root`/`strategy` are threaded consistently
/// between the striped and sequential paths.
struct DecodeCtx<'a, H: Hasher, S: Strategy> {
    /// Total number of shards (`k + m`).
    n: usize,
    /// Minimum shards required to decode (the number of original shards).
    k: usize,
    /// Number of recovery shards (`n - k`).
    m: usize,
    /// Width of every shard, in bytes.
    shard_len: usize,
    /// Commitment that the reconstructed codeword must reproduce.
    root: &'a H::Digest,
    /// Parallelism strategy.
    strategy: &'a S,
}

/// Striped Reed-Solomon: split every shard by byte range and run independent
/// Reed-Solomon operations over those ranges.
///
/// ```text
///   originals:
///     O0: [ stripe 0 ][ stripe 1 ][ tail ]
///     O1: [ stripe 0 ][ stripe 1 ][ tail ]
///     O(k-1): [ stripe 0 ][ stripe 1 ][ tail ]
///
///   encode stripe 0 -> R0[0], R1[0], more recoveries
///   encode stripe 1 -> R0[1], R1[1], more recoveries
///   encode tail     -> R0[t], R1[t], more recoveries
///
///   recovery Ri = concat(Ri[0], Ri[1], Ri[t])
/// ```
///
/// [`decode`](striped::decode) uses the same layout in reverse: recover only missing
/// original stripes, re-encode recovery stripes from the reconstructed originals, compare
/// provided recoveries against those stripes, and hash missing recoveries without first
/// materializing full recovery shards.
mod striped {
    use super::*;

    /// Target for writing stripes into a shared, strided output buffer in parallel.
    ///
    /// Holds the buffer's base address as a `usize` so disjoint stripe tasks can write the
    /// same allocation concurrently (a `&mut` would not be `Send` across tasks). Shard `i`
    /// occupies `[i * shard_len, (i + 1) * shard_len)`, and each task writes only its own
    /// stripe `range` within each shard.
    #[derive(Clone, Copy)]
    pub(super) struct Dst {
        ptr: usize,
        shard_len: usize,
    }

    impl Dst {
        pub(super) fn new(buf: &mut [u8], shard_len: usize) -> Self {
            Self {
                ptr: buf.as_mut_ptr() as usize,
                shard_len,
            }
        }

        /// Copies `src` into stripe `range` of shard `index`.
        ///
        /// # Safety
        ///
        /// Callers must ensure no two concurrent writes overlap. Stripe `range`s are disjoint
        /// and shard slots are disjoint, so concurrent tasks never alias. `index` and `range`
        /// must stay within the buffer the [`Dst`] was built from, and `src.len()` must
        /// equal `range.len()`.
        unsafe fn write(&self, index: usize, range: &Range<usize>, src: &[u8]) {
            let start = index * self.shard_len + range.start;
            let out = std::slice::from_raw_parts_mut((self.ptr as *mut u8).add(start), range.len());
            out.copy_from_slice(src);
        }
    }

    /// Split a shard of `shard_len` bytes into disjoint stripe ranges, or return `None`
    /// when striping would not help (too little parallelism or data).
    ///
    /// Every non-final stripe ends on a [`SHARD_CHUNK_BYTES`] boundary: the engine lays
    /// shards out in symbol blocks of that width (a partial final block is padded
    /// internally), so a boundary in the middle of a block would change the bytes each
    /// sub-instance encodes.
    pub(super) fn ranges(shard_len: usize, parallelism: usize) -> Option<Vec<Range<usize>>> {
        let full_blocks = shard_len / SHARD_CHUNK_BYTES;

        // Bound the stripe count by available parallelism, the number of MIN_STRIPE_BYTES
        // chunks (so each stripe stays large enough to amortize encoder/decoder setup), and
        // the number of `SHARD_CHUNK_BYTES` blocks (each non-final stripe needs at least one
        // whole block). The block bound is implied by the MIN_STRIPE_BYTES bound today
        // (MIN_STRIPE_BYTES is a multiple of SHARD_CHUNK_BYTES), but is kept to state the
        // invariant explicitly.
        let stripe_count = parallelism
            .min(shard_len / MIN_STRIPE_BYTES)
            .min(full_blocks)
            .max(1);
        if stripe_count <= 1 {
            return None;
        }

        let mut ranges = Vec::with_capacity(stripe_count);
        let mut start = 0usize;
        for stripe in 0..stripe_count {
            let remaining_stripes = stripe_count - stripe;
            let remaining = shard_len - start;
            let len = if remaining_stripes == 1 {
                remaining
            } else {
                let remaining_full_blocks = remaining / SHARD_CHUNK_BYTES;
                (remaining_full_blocks / remaining_stripes).max(1) * SHARD_CHUNK_BYTES
            };
            let end = start + len;
            ranges.push(start..end);
            start = end;
        }
        Some(ranges)
    }

    /// Recover the missing original shards for a single stripe, writing each restored
    /// shard's stripe into `dst` (one slot per entry of `missing_originals`).
    fn decode_missing_original_into(
        k: usize,
        m: usize,
        range: Range<usize>,
        provided_originals: &[(usize, &[u8])],
        provided_recoveries: &[(usize, &[u8])],
        missing_originals: &[usize],
        dst: Dst,
    ) -> Result<(), Error> {
        let shard_len = range.len();
        let mut decoder = Cached::take(
            &CACHED_DECODER,
            || Decoder::new(k, m, shard_len),
            |dec| dec.reset(k, m, shard_len),
        )
        .map_err(Error::ReedSolomon)?;

        for (idx, shard) in provided_originals {
            decoder
                .add_original_shard(*idx, &shard[range.clone()])
                .map_err(Error::ReedSolomon)?;
        }
        for (idx, shard) in provided_recoveries {
            decoder
                .add_recovery_shard(*idx, &shard[range.clone()])
                .map_err(Error::ReedSolomon)?;
        }

        let decoding = decoder.decode().map_err(Error::ReedSolomon)?;
        for (pos, idx) in missing_originals.iter().enumerate() {
            let shard = decoding
                .restored_original(*idx)
                .ok_or(Error::Inconsistent)?;
            // SAFETY: stripe `range`s and missing-original slots are disjoint, so concurrent
            // tasks never alias; see [`Dst::write`].
            unsafe { dst.write(pos, &range, shard) };
        }

        Ok(())
    }

    /// Encode the recovery shards for a single stripe, returning the stripe's range and
    /// the `m` recovery stripes concatenated into one buffer.
    fn encode_recovery(
        k: usize,
        m: usize,
        range: Range<usize>,
        originals: &[impl AsRef<[u8]>],
    ) -> Result<(Range<usize>, Vec<u8>), Error> {
        let shard_len = range.len();
        let mut encoder = Cached::take(
            &CACHED_ENCODER,
            || Encoder::new(k, m, shard_len),
            |enc| enc.reset(k, m, shard_len),
        )
        .map_err(Error::ReedSolomon)?;

        for shard in originals.iter().take(k) {
            let shard = shard.as_ref();
            encoder
                .add_original_shard(&shard[range.clone()])
                .map_err(Error::ReedSolomon)?;
        }
        let encoding = encoder.encode().map_err(Error::ReedSolomon)?;
        let mut recoveries = Vec::with_capacity(m * shard_len);
        for shard in encoding.recovery_iter() {
            recoveries.extend_from_slice(shard);
        }

        Ok((range, recoveries))
    }

    /// Encode the recovery shards for a single stripe, writing each recovery shard's
    /// stripe into `dst` (one slot per recovery shard).
    pub(super) fn encode_recovery_into(
        k: usize,
        m: usize,
        range: Range<usize>,
        originals: &[impl AsRef<[u8]>],
        dst: Dst,
    ) -> Result<(), Error> {
        let shard_len = range.len();
        let mut encoder = Cached::take(
            &CACHED_ENCODER,
            || Encoder::new(k, m, shard_len),
            |enc| enc.reset(k, m, shard_len),
        )
        .map_err(Error::ReedSolomon)?;

        for shard in originals.iter().take(k) {
            let shard = shard.as_ref();
            encoder
                .add_original_shard(&shard[range.clone()])
                .map_err(Error::ReedSolomon)?;
        }
        let encoding = encoder.encode().map_err(Error::ReedSolomon)?;
        for (i, shard) in encoding.recovery_iter().enumerate() {
            // SAFETY: stripe `range`s and recovery shard slots are disjoint, so concurrent
            // tasks never alias; see [`Dst::write`].
            unsafe { dst.write(i, &range, shard) };
        }

        Ok(())
    }

    /// Decode the codeword stripe by stripe, reconstructing the original data and
    /// verifying the rebuilt commitment against `ctx.root`.
    pub(super) fn decode<'a, H: Hasher, S: Strategy>(
        ctx: &DecodeCtx<'_, H, S>,
        ranges: Vec<Range<usize>>,
        mut shard_digests: Vec<Option<H::Digest>>,
        provided_originals: Vec<(usize, &'a [u8])>,
        provided_recoveries: Vec<(usize, &'a [u8])>,
    ) -> Result<Vec<u8>, Error> {
        let &DecodeCtx {
            k,
            m,
            shard_len,
            strategy,
            ..
        } = ctx;
        assert!(ranges.len() > 1);

        // Recover any missing original shards, one stripe per task.
        let missing_originals = shard_digests
            .iter()
            .take(k)
            .enumerate()
            .filter_map(|(i, digest)| digest.is_none().then_some(i))
            .collect::<Vec<_>>();

        let mut restored_originals = vec![0u8; missing_originals.len() * shard_len];
        if !missing_originals.is_empty() {
            let dst = Dst::new(&mut restored_originals, shard_len);
            strategy.try_map_collect_vec(ranges.clone(), |range| {
                decode_missing_original_into(
                    k,
                    m,
                    range,
                    &provided_originals,
                    &provided_recoveries,
                    &missing_originals,
                    dst,
                )
            })?;
        }

        // Gather references to every original shard, provided or restored.
        let mut original_refs: Vec<&[u8]> = vec![&[]; k];
        for &(idx, shard) in &provided_originals {
            original_refs[idx] = shard;
        }
        for (pos, idx) in missing_originals.iter().enumerate() {
            let start = pos * shard_len;
            original_refs[*idx] = &restored_originals[start..start + shard_len];
        }

        let data = extract_data(&original_refs, k, shard_len)?;

        // Re-encode the recovery stripes from the reconstructed originals.
        let recovery_stripes =
            strategy.try_map_collect_vec(ranges, |range| encode_recovery(k, m, range, &original_refs))?;

        let mut provided_recovery_by_idx = vec![None; m];
        for (idx, shard) in provided_recoveries {
            provided_recovery_by_idx[idx] = Some(shard);
        }

        // Provided originals are already bound to the commitment by their checked
        // digests. Provided recoveries must match the canonical re-encode before
        // reusing their checked digests.
        for (range, recovery_stripe) in &recovery_stripes {
            let stripe_len = range.len();
            for i in 0..m {
                let stripe = &recovery_stripe[i * stripe_len..(i + 1) * stripe_len];
                if let Some(provided) = provided_recovery_by_idx[i] {
                    if &provided[range.clone()] != stripe {
                        return Err(Error::Inconsistent);
                    }
                }
            }
        }

        // Hash missing recoveries directly from stripes instead of materializing
        // full shard buffers that would only be used as Merkle leaves.
        let missing_recovery_indices = provided_recovery_by_idx
            .iter()
            .enumerate()
            .filter_map(|(i, shard)| shard.is_none().then_some(i));
        for (i, digest) in
            strategy.map_init_collect_vec(missing_recovery_indices, H::new, |hasher, i| {
                for (range, recovery_stripe) in &recovery_stripes {
                    let stripe_len = range.len();
                    hasher.update(&recovery_stripe[i * stripe_len..(i + 1) * stripe_len]);
                }
                (k + i, hasher.finalize())
            })
        {
            shard_digests[i] = Some(digest);
        }
        drop(recovery_stripes);

        verify_codeword::<H, S>(ctx, &mut shard_digests, &original_refs, data)
    }

    /// Hash any remaining missing shards, rebuild the Merkle tree, and confirm its root
    /// matches the commitment.
    fn verify_codeword<H: Hasher, S: Strategy>(
        ctx: &DecodeCtx<'_, H, S>,
        shard_digests: &mut [Option<H::Digest>],
        originals: &[&[u8]],
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let &DecodeCtx {
            n, root, strategy, ..
        } = ctx;
        let missing_shards = originals
            .iter()
            .enumerate()
            .filter_map(|(i, shard)| shard_digests[i].is_none().then_some((i, *shard)))
            .collect::<Vec<_>>();

        for (i, digest) in
            strategy.map_init_collect_vec(missing_shards, H::new, |hasher, (i, shard)| {
                hasher.update(shard);
                (i, hasher.finalize())
            })
        {
            shard_digests[i] = Some(digest);
        }

        let mut builder = Builder::<H>::new(n);
        shard_digests
            .iter()
            .map(|digest| digest.expect("digest must be present for every shard"))
            .for_each(|digest| {
                builder.add(&digest);
            });
        let tree = builder.build();
        if tree.root() != *root {
            return Err(Error::Inconsistent);
        }

        Ok(data)
    }
}

/// Sequential Reed-Solomon: recover and re-encode the codeword as a single
/// Reed-Solomon instance, used when striping would not help.
mod sequential {
    use super::*;

    /// Decode the codeword as a single Reed-Solomon instance, reconstructing the
    /// original data and verifying the rebuilt commitment against `ctx.root`.
    pub(super) fn decode<'a, H: Hasher, S: Strategy>(
        ctx: &DecodeCtx<'_, H, S>,
        shard_digests: Vec<Option<H::Digest>>,
        provided_originals: Vec<(usize, &'a [u8])>,
        provided_recoveries: Vec<(usize, &'a [u8])>,
    ) -> Result<Vec<u8>, Error> {
        let &DecodeCtx {
            k, m, shard_len, ..
        } = ctx;
        if provided_originals.len() == k {
            // All originals are present, so skip Reed-Solomon decode and still run
            // canonical re-encode/root verification below.
            let mut shards: Vec<&[u8]> = vec![&[]; k];
            for &(idx, shard) in &provided_originals {
                shards[idx] = shard;
            }
            return verify_codeword::<H, S>(ctx, shard_digests, &provided_recoveries, &shards);
        }

        // Decode original data.
        let mut decoder = Cached::take(
            &CACHED_DECODER,
            || Decoder::new(k, m, shard_len),
            |dec| dec.reset(k, m, shard_len),
        )
        .map_err(Error::ReedSolomon)?;
        for (idx, shard) in &provided_originals {
            decoder
                .add_original_shard(*idx, shard)
                .map_err(Error::ReedSolomon)?;
        }
        for (idx, shard) in &provided_recoveries {
            decoder
                .add_recovery_shard(*idx, shard)
                .map_err(Error::ReedSolomon)?;
        }
        let decoding = decoder.decode().map_err(Error::ReedSolomon)?;

        let mut shards: Vec<&[u8]> = vec![&[]; k];
        for &(idx, shard) in &provided_originals {
            shards[idx] = shard;
        }
        for (idx, shard) in decoding.restored_original_iter() {
            shards[idx] = shard;
        }
        verify_codeword::<H, S>(ctx, shard_digests, &provided_recoveries, &shards)
    }

    /// Re-encode the recovery shards, confirm any provided recoveries match, hash the
    /// remaining missing shards, rebuild the Merkle tree, and confirm its root matches
    /// the commitment.
    fn verify_codeword<H: Hasher, S: Strategy>(
        ctx: &DecodeCtx<'_, H, S>,
        mut shard_digests: Vec<Option<H::Digest>>,
        provided_recoveries: &[(usize, &[u8])],
        originals: &[&[u8]],
    ) -> Result<Vec<u8>, Error> {
        let &DecodeCtx {
            n,
            k,
            m,
            shard_len,
            root,
            strategy,
        } = ctx;
        let data = extract_data(originals, k, shard_len)?;

        let mut encoder = Cached::take(
            &CACHED_ENCODER,
            || Encoder::new(k, m, shard_len),
            |enc| enc.reset(k, m, shard_len),
        )
        .map_err(Error::ReedSolomon)?;
        for shard in originals.iter().take(k) {
            encoder
                .add_original_shard(shard)
                .map_err(Error::ReedSolomon)?;
        }
        let encoding = encoder.encode().map_err(Error::ReedSolomon)?;

        // Provided original bytes are already bound to the commitment by their verified
        // inclusion proofs (their checked digests are reused when the root is rebuilt
        // below), so they need no separate comparison here. Provided recovery shards must
        // match the canonical re-encode before their checked digests are trusted.
        for (idx, shard) in provided_recoveries {
            let canonical = encoding.recovery(*idx).ok_or(Error::Inconsistent)?;
            if *shard != canonical {
                return Err(Error::Inconsistent);
            }
        }

        let missing_shards = shard_digests
            .iter()
            .enumerate()
            .filter(|(_, digest)| digest.is_none())
            .map(|(i, _)| {
                let shard = if i < k {
                    originals[i]
                } else {
                    encoding
                        .recovery(i - k)
                        .expect("missing recovery index must be in range")
                };
                (i, shard)
            })
            .collect::<Vec<_>>();

        for (i, digest) in
            strategy.map_init_collect_vec(missing_shards, H::new, |hasher, (i, shard)| {
                hasher.update(shard);
                (i, hasher.finalize())
            })
        {
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
        if tree.root() != *root {
            return Err(Error::Inconsistent);
        }

        Ok(data)
    }
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
fn decode<'a, H: Hasher, S: Strategy>(
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
    let stripes = striped::ranges(shard_len, strategy.parallelism_hint());
    let mut shard_digests: Vec<Option<H::Digest>> = vec![None; n];
    let mut provided_originals: Vec<(usize, &[u8])> = Vec::new();
    let mut provided_recoveries: Vec<(usize, &[u8])> = Vec::new();
    let mut provided = 0usize;
    for chunk in chunks {
        provided += 1;
        if &chunk.root != root {
            return Err(Error::CommitmentMismatch);
        }

        // Every shard must share the first shard's width. The striped decode path slices
        // each shard by stripe range, so a wrong-width shard would otherwise panic.
        if chunk.shard.len() != shard_len {
            return Err(Error::Inconsistent);
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

        // Retain the checked digest and split provided bytes by shard type
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

    let ctx = DecodeCtx {
        n,
        k,
        m,
        shard_len,
        root,
        strategy,
    };
    if let Some(ranges) = stripes {
        return striped::decode::<H, S>(
            &ctx,
            ranges,
            shard_digests,
            provided_originals,
            provided_recoveries,
        );
    }
    sequential::decode::<H, S>(&ctx, shard_digests, provided_originals, provided_recoveries)
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
    type Shard = Chunk<H::Digest>;
    type CheckedShard = CheckedChunk<H::Digest>;
    type Error = Error;

    fn encode(
        config: &Config,
        data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        encode::<H, _>(
            total_shards(config)?,
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
        let total = total_shards(config)?;
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
        decode::<H, _>(
            total_shards(config)?,
            config.minimum_shards.get(),
            commitment,
            shards,
            strategy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_invariants::minifuzz;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{deterministic, iobuf::EncodeExt, BufferPooler, Runner};
    use commonware_utils::{NZUsize, NZU16};

    type RS = ReedSolomon<Sha256>;
    const STRATEGY: Sequential = Sequential;
    const FUZZ_MAX_MIN_SHARDS: u16 = 8;
    const FUZZ_MAX_EXTRA_SHARDS: u16 = 8;
    const FUZZ_MAX_DATA_LEN: usize = 256;
    const FUZZ_MAX_EXTRA_SHARD_WIDTH: usize = 16;

    fn checked(
        root: <Sha256 as Hasher>::Digest,
        chunk: Chunk<<Sha256 as Hasher>::Digest>,
    ) -> CheckedChunk<<Sha256 as Hasher>::Digest> {
        let Chunk { shard, index, .. } = chunk;
        let digest = Sha256::hash(&shard);
        CheckedChunk::new(root, shard, index, digest)
    }

    fn build_chunks(
        shards: &[Vec<u8>],
    ) -> (
        <Sha256 as Hasher>::Digest,
        Vec<Chunk<<Sha256 as Hasher>::Digest>>,
    ) {
        let mut builder = Builder::<Sha256>::new(shards.len());
        for shard in shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let tree = builder.build();
        let root = tree.root();
        let chunks = shards
            .iter()
            .enumerate()
            .map(|(i, shard)| {
                let proof = tree.proof(i as u32).unwrap();
                Chunk::new(shard.clone().into(), i as u16, proof)
            })
            .collect();

        (root, chunks)
    }

    fn selected_indices(
        u: &mut arbitrary::Unstructured<'_>,
        total: u16,
        minimum: u16,
    ) -> arbitrary::Result<Vec<u16>> {
        let to_use = u.int_in_range(minimum..=total)?;
        let mut selected = (0..total).collect::<Vec<_>>();
        for i in 0..usize::from(to_use) {
            let remaining = usize::from(total) - i;
            let j = i + u.choose_index(remaining)?;
            selected.swap(i, j);
        }
        selected.truncate(usize::from(to_use));
        Ok(selected)
    }

    fn assert_decode_unique_commitment(
        total: u16,
        min: u16,
        root: <Sha256 as Hasher>::Digest,
        chunks: &[Chunk<<Sha256 as Hasher>::Digest>],
        selected: &[u16],
    ) {
        let pieces = selected
            .iter()
            .map(|&i| chunks[usize::from(i)].verify::<Sha256>(i, &root).unwrap())
            .collect::<Vec<_>>();

        let Ok(decoded) = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY) else {
            return;
        };
        let (canonical_root, _) =
            encode::<Sha256, _>(total, min, decoded.as_slice(), &STRATEGY).unwrap();
        assert_eq!(
            root, canonical_root,
            "decode accepted a root not produced by canonical encode"
        );
    }

    fn fuzz_arbitrary_codeword(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<()> {
        let min = u.int_in_range(1..=FUZZ_MAX_MIN_SHARDS)?;
        let extra = u.int_in_range(1..=FUZZ_MAX_EXTRA_SHARDS)?;
        let total = min + extra;
        let k = usize::from(min);
        let m = usize::from(extra);

        let data_len = u.int_in_range(0..=FUZZ_MAX_DATA_LEN)?;
        let data = u.bytes(data_len)?.to_vec();
        let canonical = canonical_shard_len(data.len(), k);
        let extra_width = u.int_in_range(0..=FUZZ_MAX_EXTRA_SHARD_WIDTH / 2)? * 2;
        let shard_len = canonical + extra_width;

        let mut padded = vec![0u8; k * shard_len];
        padded[..u32::SIZE].copy_from_slice(&(data.len() as u32).to_be_bytes());
        padded[u32::SIZE..u32::SIZE + data.len()].copy_from_slice(&data);

        let payload_end = u32::SIZE + data.len();
        if payload_end < padded.len() && u.int_in_range(0..=3)? == 0 {
            let offset = payload_end + u.choose_index(padded.len() - payload_end)?;
            padded[offset] ^= u.arbitrary::<u8>()? | 1;
        }

        let mut encoder = Encoder::new(k, m, shard_len).unwrap();
        for shard in padded.chunks(shard_len) {
            encoder.add_original_shard(shard).unwrap();
        }
        let recovery = encoder.encode().unwrap();

        let mut shards = padded
            .chunks(shard_len)
            .map(|shard| shard.to_vec())
            .collect::<Vec<_>>();
        shards.extend(recovery.recovery_iter().map(|shard| shard.to_vec()));

        let (root, chunks) = build_chunks(&shards);
        let selected = selected_indices(u, total, min)?;
        assert_decode_unique_commitment(total, min, root, &chunks, &selected);

        Ok(())
    }

    fn fuzz_mixed_codeword(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<()> {
        let min = u.int_in_range(1..=FUZZ_MAX_MIN_SHARDS)?;
        let extra = u.int_in_range(1..=FUZZ_MAX_EXTRA_SHARDS)?;
        let total = min + extra;

        let data_len = u.int_in_range(0..=FUZZ_MAX_DATA_LEN)?;
        let data = u.bytes(data_len)?.to_vec();
        let (_canonical_root, chunks) =
            encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        let mut shards = chunks
            .iter()
            .map(|chunk| chunk.shard.to_vec())
            .collect::<Vec<_>>();

        let mutated = usize::from(min + u.int_in_range(0..=extra - 1)?);
        let offset = u.choose_index(shards[mutated].len())?;
        shards[mutated][offset] ^= u.arbitrary::<u8>()? | 1;

        let (root, chunks) = build_chunks(&shards);
        let mut selected = (0..min).collect::<Vec<_>>();
        selected.push(mutated as u16);
        assert_decode_unique_commitment(total, min, root, &chunks, &selected);

        Ok(())
    }

    #[test]
    fn test_recovery() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Use a mix of original and recovery pieces
        let pieces: Vec<_> = vec![
            checked(root, chunks[0].clone()), // original
            checked(root, chunks[4].clone()), // recovery
            checked(root, chunks[6].clone()), // recovery
        ];

        // Try to decode with a mix of original and recovery pieces
        let decoded = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_not_enough_pieces() {
        let data = b"Test insufficient pieces";
        let total = 6u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Try with fewer than min
        let pieces: Vec<_> = chunks
            .into_iter()
            .take(2)
            .map(|c| checked(root, c))
            .collect();

        // Fail to decode
        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::NotEnoughChunks)));
    }

    #[test]
    fn test_duplicate_index() {
        let data = b"Test duplicate detection";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Include duplicate index by cloning the first chunk
        let pieces = [
            checked(root, chunks[0].clone()),
            checked(root, chunks[0].clone()),
            checked(root, chunks[1].clone()),
        ];

        // Fail to decode
        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::DuplicateIndex(0))));
    }

    #[test]
    fn test_invalid_index() {
        let data = b"Test invalid index";
        let total = 5u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Verify all proofs at invalid index
        for i in 0..total {
            assert!(chunks[i as usize].verify::<Sha256>(i + 1, &root).is_none());
        }
    }

    #[test]
    #[should_panic(expected = "assertion failed: total > min")]
    fn test_invalid_total() {
        let data = b"Test parameter validation";

        // The total shard count must exceed the recovery threshold.
        encode::<Sha256, _>(3, 3, data.as_slice(), &STRATEGY).unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: min > 0")]
    fn test_invalid_min() {
        let data = b"Test parameter validation";

        // The recovery threshold must be non-zero.
        encode::<Sha256, _>(5, 0, data.as_slice(), &STRATEGY).unwrap();
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let total = 100u16;
        let min = 30u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = 7u16;
        let min = 4u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_parallel_encode_matches_sequential() {
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        let data = vec![42u8; 256 * 1024];
        let total = 24u16;
        let min = 8u16;

        let (sequential_root, sequential_chunks) =
            encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        let (parallel_root, parallel_chunks) =
            encode::<Sha256, _>(total, min, data.as_slice(), &strategy).unwrap();

        assert_eq!(sequential_root, parallel_root);
        assert_eq!(sequential_chunks, parallel_chunks);
    }

    #[test]
    fn test_parallel_recovery_decode() {
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        let data = vec![42u8; 256 * 1024];
        let total = 24u16;
        let min = 8u16;

        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &strategy).unwrap();

        let minimal = chunks
            .into_iter()
            .skip(min as usize)
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, minimal.iter(), &strategy).unwrap();
        assert_eq!(decoded, data);
    }

    /// Striped recovery decode must be byte-identical to the sequential (full-shard)
    /// path. The striped path only activates for shards of at least
    /// `MIN_STRIPE_BYTES`, so this sweeps payload sizes and shard counts that land on
    /// several stripe-count boundaries under a parallel `Strategy`, decoding from a
    /// recovery-only set (which forces Reed-Solomon recovery) and checking the result
    /// against the original data on both the sequential and parallel paths.
    #[test]
    fn test_striped_recovery_matches_sequential() {
        for &data_len in &[128 * 1024usize, 257 * 1024, 512 * 1024, 1024 * 1024] {
            for &(total, min) in &[(12u16, 4u16), (24, 8), (33, 11)] {
                let data: Vec<u8> = (0..data_len)
                    .map(|i| (i as u8) ^ ((i >> 7) as u8))
                    .collect();
                let (root, chunks) =
                    encode::<Sha256, _>(total, min, data.as_slice(), &Sequential).unwrap();
                let recovery_only = chunks
                    .into_iter()
                    .skip(min as usize)
                    .take(min as usize)
                    .map(|c| checked(root, c))
                    .collect::<Vec<_>>();
                let sequential =
                    decode::<Sha256, _>(total, min, &root, recovery_only.iter(), &Sequential)
                        .unwrap();
                assert_eq!(sequential, data);
                for &parallelism in &[2usize, 8] {
                    let strategy = Rayon::new(NZUsize!(parallelism)).unwrap();
                    let striped =
                        decode::<Sha256, _>(total, min, &root, recovery_only.iter(), &strategy)
                            .unwrap();
                    assert_eq!(
                        striped, data,
                        "striped decode mismatch (len={data_len} total={total} min={min} parallelism={parallelism})"
                    );
                }
            }
        }
    }

    /// Single-threaded exercise of the striped encode helper and its [`striped::Dst`]
    /// raw-pointer writes, independent of any [`Strategy`]. The rayon-driven striped tests
    /// cannot run under miri (crossbeam's work-stealing deque relies on integer-to-pointer
    /// casts that abort miri during threadpool setup), so this drives the same `unsafe`
    /// writes sequentially to keep them miri-checkable: splitting a shard into stripes and
    /// encoding each must reproduce the single full-width encode byte-for-byte.
    #[test]
    fn test_striped_encode_into_matches_full_width() {
        let k = 2usize;
        let m = 2usize;
        let shard_len = 2 * MIN_STRIPE_BYTES;
        let ranges = striped::ranges(shard_len, 4).expect("must split into stripes");
        assert!(ranges.len() >= 2);

        let mut originals_buf = vec![0u8; k * shard_len];
        for (i, byte) in originals_buf.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let originals: Vec<&[u8]> = originals_buf.chunks(shard_len).collect();

        // Encode each stripe into its slot via Dst (the `unsafe` path).
        let mut striped_recovery = vec![0u8; m * shard_len];
        let dst = striped::Dst::new(&mut striped_recovery, shard_len);
        for range in &ranges {
            striped::encode_recovery_into(k, m, range.clone(), &originals, dst).unwrap();
        }

        // A single full-width encode must produce the identical recovery buffer.
        let mut full_recovery = vec![0u8; m * shard_len];
        let dst_full = striped::Dst::new(&mut full_recovery, shard_len);
        striped::encode_recovery_into(k, m, 0..shard_len, &originals, dst_full).unwrap();

        assert_eq!(striped_recovery, full_recovery);
    }

    // Each tamper mutates a canonical codeword in place before a (malicious) commitment is
    // rebuilt over the tampered shards. `k` is the original-shard count, `shard_len` the
    // per-shard width.
    fn tamper_flip_recovery(shards: &mut [Vec<u8>], k: usize, _shard_len: usize) {
        shards[k][0] ^= 0xFF;
    }

    fn tamper_flip_original_data(shards: &mut [Vec<u8>], _k: usize, shard_len: usize) {
        // First payload byte sits right after the 4-byte length prefix.
        let offset = u32::SIZE;
        shards[offset / shard_len][offset % shard_len] ^= 0xFF;
    }

    fn tamper_corrupt_padding(shards: &mut [Vec<u8>], k: usize, shard_len: usize) {
        // Final byte of the last original shard is canonical zero padding for the data
        // sizes used by the adversarial tests below.
        shards[k - 1][shard_len - 1] = 0xAA;
    }

    /// Encode `data` canonically, apply `tamper`, rebuild a (malicious) commitment over the
    /// tampered shards, and decode the `selected` shard indices with `strategy`. Generic over
    /// [`Strategy`] so the same attack drives both the sequential and striped decode paths.
    fn decode_tampered_codeword<S: Strategy>(
        total: u16,
        min: u16,
        data: &[u8],
        selected: &[u16],
        tamper: fn(&mut [Vec<u8>], usize, usize),
        strategy: &S,
    ) -> Result<Vec<u8>, Error> {
        let (_root, chunks) = encode::<Sha256, _>(total, min, data, &Sequential).unwrap();
        let mut shards = chunks.iter().map(|c| c.shard.to_vec()).collect::<Vec<_>>();
        let shard_len = shards[0].len();
        tamper(&mut shards, min as usize, shard_len);
        let (root, chunks) = build_chunks(&shards);
        let pieces = selected
            .iter()
            .map(|&i| checked(root, chunks[i as usize].clone()))
            .collect::<Vec<_>>();
        decode::<Sha256, _>(total, min, &root, pieces.iter(), strategy)
    }

    // (name, selected shard indices, tamper). With total=12/min=4, indices 0..4 are
    // originals and 4..12 are recoveries.
    #[allow(clippy::type_complexity)]
    const ADVERSARIAL_SCENARIOS: &[(&str, &[u16], fn(&mut [Vec<u8>], usize, usize))] = &[
        // Tampered recovery that is NOT provided: caught when the root is rebuilt from the
        // re-encoded recoveries.
        (
            "tampered_recovery_unprovided",
            &[0, 1, 2, 3],
            tamper_flip_recovery,
        ),
        // Tampered recovery that IS provided and forces RS reconstruction of a missing
        // original (exercises striped::decode_missing_original_into on the striped path).
        (
            "tampered_recovery_provided",
            &[0, 1, 2, 4],
            tamper_flip_recovery,
        ),
        // Non-canonical (non-zero) trailing padding in an original shard (extract_data).
        (
            "non_canonical_padding",
            &[0, 1, 2, 3],
            tamper_corrupt_padding,
        ),
        // Tampered original payload byte: detected by the rebuilt commitment.
        (
            "tampered_original_data",
            &[0, 1, 2, 3],
            tamper_flip_original_data,
        ),
        // Recovery-only decode where one provided recovery is tampered.
        (
            "recovery_only_tampered",
            &[4, 5, 6, 7],
            tamper_flip_recovery,
        ),
    ];

    /// Every adversarial scenario must be rejected as [`Error::Inconsistent`] on whichever
    /// decode path `strategy` + `data` selects.
    fn assert_adversarial_rejected<S: Strategy>(total: u16, min: u16, data: &[u8], strategy: &S) {
        for &(name, selected, tamper) in ADVERSARIAL_SCENARIOS {
            let result = decode_tampered_codeword(total, min, data, selected, tamper, strategy);
            assert!(
                matches!(result, Err(Error::Inconsistent)),
                "scenario {name} not rejected as Inconsistent: {result:?}"
            );
        }
    }

    #[test]
    fn test_adversarial_rejection_sequential_small() {
        // Small payload: striping never engages, so this exercises the sequential path
        // (matching the rest of the small-data adversarial tests).
        assert_adversarial_rejected(12, 4, &[0xCDu8; 30], &Sequential);
    }

    /// The striped decode path re-implements every consensus-critical rejection check in a
    /// separate code path from the sequential one. Drive each malicious scenario through both
    /// paths on the same large payload and require identical (Inconsistent) verdicts.
    #[test]
    fn test_adversarial_rejection_striped_matches_sequential() {
        let total = 12u16;
        let min = 4u16;

        // Large payload so the parallel strategy takes the striped path. Assert it actually
        // splits into >= 2 stripes; otherwise this would silently degrade to the sequential
        // path and give false confidence.
        let data = vec![0xABu8; 64 * 1024];
        let shard_len = canonical_shard_len(data.len(), min as usize);
        let rayon = Rayon::new(NZUsize!(4)).unwrap();
        assert!(
            striped::ranges(shard_len, rayon.parallelism_hint()).map_or(0, |r| r.len()) >= 2,
            "test must exercise >= 2 stripes (shard_len={shard_len})"
        );

        // Same attacks, same data: the striped path must reject identically to sequential.
        assert_adversarial_rejected(total, min, &data, &Sequential);
        assert_adversarial_rejected(total, min, &data, &rayon);

        // Sanity: an untampered mixed (some originals + a recovery) set still decodes via the
        // striped path, forcing striped::decode_missing_original_into to reconstruct an original.
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &Sequential).unwrap();
        let mixed = [0u16, 1, 2, 4]
            .into_iter()
            .map(|i| checked(root, chunks[i as usize].clone()))
            .collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, mixed.iter(), &rayon).unwrap();
        assert_eq!(decoded, data);
    }

    /// Pin the exact vendored Reed-Solomon recovery output for a fixed `(k, m, shard_len)` with a
    /// partial final block (`shard_len % SHARD_CHUNK_BYTES != 0`). The striped coder assumes this
    /// crate's internal block layout and tail packing (see [`SHARD_CHUNK_BYTES`]); if the
    /// implementation changes its produced bytes this fixture trips, signalling that the striping
    /// assumption must be re-verified before the new output is accepted.
    #[test]
    fn test_recovery_output_format_pinned() {
        let k = 5usize;
        let m = 3usize;
        // Two full blocks plus a 2-byte partial tail.
        let shard_len = 2 * SHARD_CHUNK_BYTES + 2;

        let mut encoder = Encoder::new(k, m, shard_len).unwrap();
        for i in 0..k {
            let shard: Vec<u8> = (0..shard_len)
                .map(|j| ((i * 31 + j * 7) & 0xFF) as u8)
                .collect();
            encoder.add_original_shard(&shard).unwrap();
        }
        let encoding = encoder.encode().unwrap();

        let mut hasher = Sha256::new();
        for shard in encoding.recovery_iter() {
            hasher.update(shard);
        }
        let digest = hasher.finalize();
        assert_eq!(
            format!("{digest}"),
            "e38bb9dbba4a102c4bd8447e212957742dab0af0c4148d4660c671f2f33d3df2",
            "vendored Reed-Solomon recovery output changed; re-verify the striping \
             assumption before updating this fixture"
        );
    }

    #[test]
    fn test_parallel_decode_rejects_mismatched_shard_lengths() {
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        let data = vec![42u8; 256 * 1024];
        let total = 24u16;
        let min = 8u16;

        let (_root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &strategy).unwrap();
        let mut shards = chunks
            .iter()
            .map(|chunk| chunk.shard.to_vec())
            .collect::<Vec<_>>();
        shards[min as usize].pop();

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let tree = builder.build();
        let root = tree.root();

        let pieces = [9u16, 8, 10, 11, 12, 13, 14, 15]
            .into_iter()
            .map(|i| {
                let proof = tree.proof(i as u32).unwrap();
                checked(
                    root,
                    Chunk::new(shards[i as usize].clone().into(), i, proof),
                )
            })
            .collect::<Vec<_>>();

        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &strategy);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_malicious_root_detection() {
        let data = b"Original data that should be protected";
        let total = 7u16;
        let min = 4u16;

        // Encode data correctly to get valid chunks
        let (_correct_root, chunks) =
            encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

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
        let result = decode::<Sha256, _>(total, min, &malicious_root, minimal.iter(), &STRATEGY);
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

        // A proof generated under a different shard configuration is invalid
        // for this commitment.
        let check_result = RS::check(&config_expected, &commitment, 0, &shards[0]);
        assert!(matches!(check_result, Err(Error::InvalidProof)));
    }

    #[test]
    fn test_manipulated_chunk_detection() {
        let data = b"Data integrity must be maintained";
        let total = 6u16;
        let min = 3u16;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        let mut pieces: Vec<_> = chunks.into_iter().map(|c| checked(root, c)).collect();

        // Tamper with one of the checked chunks by modifying the shard data.
        if !pieces[1].shard.is_empty() {
            let mut shard = pieces[1].shard.to_vec();
            shard[0] ^= 0xFF; // Flip bits in first byte
            pieces[1].shard = shard.into();
        }

        // Try to decode with the tampered chunk
        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_inconsistent_shards() {
        let data = b"Test data for malicious encoding";
        let total = 5u16;
        let min = 3u16;
        let m = total - min;

        // Compute original data encoding
        let (padded, shard_size) = prepare_data(data.as_slice(), min as usize);

        // Re-encode the data
        let mut encoder = Encoder::new(min as usize, m as usize, shard_size).unwrap();
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
        let result = decode::<Sha256, _>(total, min, &malicious_root, pieces.iter(), &STRATEGY);
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

        let (mut padded, shard_len) = prepare_data(data.as_slice(), k);
        let payload_end = u32::SIZE + data.len();
        let total_original_len = k * shard_len;
        assert!(payload_end < total_original_len, "test requires padding");

        // Corrupt one canonical padding byte while keeping payload unchanged.
        let pad_shard = payload_end / shard_len;
        let pad_offset = payload_end % shard_len;
        padded[pad_shard * shard_len + pad_offset] = 0xAA;

        let mut encoder = Encoder::new(k, m, shard_len).unwrap();
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

        let result = decode::<Sha256, _>(total, min, &non_canonical_root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn minifuzz_decode_unique_commitment() {
        minifuzz::Builder::default()
            .with_search_limit(2048)
            .test(|u| {
                fuzz_arbitrary_codeword(u)?;
                fuzz_mixed_codeword(u)?;
                Ok(())
            });
    }

    #[test]
    fn test_oversized_zero_padded_shards_rejected() {
        let data = b"X";
        let total = 6u16;
        let min = 3u16;
        let k = min as usize;
        let m = total as usize - k;

        let oversized_shard_len = 4usize;
        let mut padded = vec![0u8; k * oversized_shard_len];
        padded[..u32::SIZE].copy_from_slice(&(data.len() as u32).to_be_bytes());
        padded[u32::SIZE..u32::SIZE + data.len()].copy_from_slice(data);

        let mut encoder = Encoder::new(k, m, oversized_shard_len).unwrap();
        for shard in padded.chunks(oversized_shard_len) {
            encoder.add_original_shard(shard).unwrap();
        }
        let recovery = encoder.encode().unwrap();

        let mut oversized_shards: Vec<Vec<u8>> = padded
            .chunks(oversized_shard_len)
            .map(|shard| shard.to_vec())
            .collect();
        oversized_shards.extend(recovery.recovery_iter().map(|shard| shard.to_vec()));

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &oversized_shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let oversized_tree = builder.build();
        let oversized_root = oversized_tree.root();

        let (canonical_root, _) =
            encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        assert_ne!(oversized_root, canonical_root);

        let pieces = [0u16, 1u16, 4u16]
            .into_iter()
            .map(|i| {
                let proof = oversized_tree.proof(i as u32).unwrap();
                checked(
                    oversized_root,
                    Chunk::new(oversized_shards[i as usize].clone().into(), i, proof),
                )
            })
            .collect::<Vec<_>>();

        let result = decode::<Sha256, _>(total, min, &oversized_root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_extra_non_canonical_recovery_rejected() {
        let data = b"canonical originals with bad recovery";
        let total = 6u16;
        let min = 3u16;

        let (_root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        let mut shards = chunks
            .iter()
            .map(|chunk| chunk.shard.to_vec())
            .collect::<Vec<_>>();
        shards[min as usize][0] ^= 0xFF;

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let tree = builder.build();
        let root = tree.root();

        let pieces = (0u16..=3u16)
            .map(|i| {
                let proof = tree.proof(i as u32).unwrap();
                checked(
                    root,
                    Chunk::new(shards[i as usize].clone().into(), i, proof),
                )
            })
            .collect::<Vec<_>>();

        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_reconstructed_original_with_extra_non_canonical_recovery_rejected() {
        let data = b"canonical reconstructed originals with bad extra recovery";
        let total = 6u16;
        let min = 3u16;

        let (_root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();
        let mut shards = chunks
            .iter()
            .map(|chunk| chunk.shard.to_vec())
            .collect::<Vec<_>>();
        shards[4][0] ^= 0xFF;

        let mut builder = Builder::<Sha256>::new(total as usize);
        for shard in &shards {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            builder.add(&hasher.finalize());
        }
        let tree = builder.build();
        let root = tree.root();

        let pieces = [0u16, 1u16, 3u16, 4u16]
            .into_iter()
            .map(|i| {
                let proof = tree.proof(i as u32).unwrap();
                checked(
                    root,
                    Chunk::new(shards[i as usize].clone().into(), i, proof),
                )
            })
            .collect::<Vec<_>>();

        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::Inconsistent)));
    }

    #[test]
    fn test_decode_invalid_index() {
        let data = b"Testing recovery pieces";
        let total = 8u16;
        let min = 3u16;

        // Encode the data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Use a mix of original and recovery pieces
        let mut invalid = checked(root, chunks[1].clone());
        invalid.index = 8;
        let pieces: Vec<_> = vec![
            checked(root, chunks[0].clone()), // original
            invalid,                          // recovery with invalid index
            checked(root, chunks[6].clone()), // recovery
        ];

        // Fail to decode
        let result = decode::<Sha256, _>(total, min, &root, pieces.iter(), &STRATEGY);
        assert!(matches!(result, Err(Error::InvalidIndex(8))));
    }

    #[test]
    fn test_max_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2;

        // Encode data
        let (root, chunks) = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY).unwrap();

        // Try to decode with min
        let minimal = chunks
            .into_iter()
            .take(min as usize)
            .map(|c| checked(root, c))
            .collect::<Vec<_>>();
        let decoded = decode::<Sha256, _>(total, min, &root, minimal.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_chunks() {
        let data = vec![42u8; 1000]; // 1KB of data
        let total = u16::MAX;
        let min = u16::MAX / 2 - 1;

        // Encode data
        let result = encode::<Sha256, _>(total, min, data.as_slice(), &STRATEGY);
        assert!(matches!(
            result,
            Err(Error::ReedSolomon(RsError::UnsupportedShardCount {
                original_count: _,
                recovery_count: _,
            }))
        ));
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

    #[test]
    fn test_chunk_encode_with_pool_matches_encode() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pool = context.network_buffer_pool();

            let data = b"pool encoding test";
            let (_root, chunks) = encode::<Sha256, _>(5, 3, data.as_slice(), &STRATEGY).unwrap();
            let chunk = &chunks[0];

            let encoded = chunk.encode();
            let mut encoded_pool = chunk.encode_with_pool(pool);
            let mut encoded_pool_bytes = vec![0u8; encoded_pool.remaining()];
            encoded_pool.copy_to_slice(&mut encoded_pool_bytes);
            assert_eq!(encoded_pool_bytes, encoded.as_ref());
        });
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

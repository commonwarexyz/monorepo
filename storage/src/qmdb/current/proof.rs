//! Proof types for [crate::qmdb::current] authenticated databases.
//!
//! This module provides:
//! - [OpsRootWitness]: Authenticates an ops root against a canonical `current` root.
//! - [RangeProof]: Proves a range of operations exist in the database.
//! - [OperationProof]: Proves a specific operation is active in the database.

use crate::{
    journal::contiguous::{Contiguous, Reader as _},
    merkle::{
        self,
        hasher::{Hasher, Standard as StandardHasher},
        storage::Storage,
        Family, Graftable, Location, Position, Proof,
    },
    qmdb::{
        self,
        current::{db::combine_roots, grafting},
        Error,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use core::ops::Range;
use futures::future::try_join_all;
use std::{collections::BTreeMap, num::NonZeroU64};
use tracing::debug;

/// Witness that a particular `ops_root` is committed by a `current` canonical root.
///
/// `canonical_root = hash(ops_root || grafted_root [|| next_bit || partial_chunk_digest])`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OpsRootWitness<D: Digest> {
    /// The grafted-tree root committed by the canonical root.
    pub grafted_root: D,

    /// The trailing partial chunk contribution, if the bitmap length is not chunk-aligned:
    /// `(next_bit, partial_chunk_digest)`.
    pub partial_chunk: Option<(u64, D)>,
}

impl<D: Digest> OpsRootWitness<D> {
    /// Return true if this witness proves that `canonical_root` commits to `ops_root`.
    pub fn verify<H: CHasher<Digest = D>>(
        &self,
        hasher: &mut StandardHasher<H>,
        ops_root: &D,
        canonical_root: &D,
    ) -> bool {
        let partial = self.partial_chunk.as_ref().map(|(nb, d)| (*nb, d));
        combine_roots(hasher, ops_root, &self.grafted_root, partial) == *canonical_root
    }
}

impl<D: Digest> Write for OpsRootWitness<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.grafted_root.write(buf);
        self.partial_chunk.is_some().write(buf);
        if let Some((next_bit, digest)) = &self.partial_chunk {
            UInt(*next_bit).write(buf);
            digest.write(buf);
        }
    }
}

impl<D: Digest> EncodeSize for OpsRootWitness<D> {
    fn encode_size(&self) -> usize {
        self.grafted_root.encode_size()
            + self
                .partial_chunk
                .as_ref()
                .map_or(1, |(nb, d)| 1 + UInt(*nb).encode_size() + d.encode_size())
    }
}

impl<D: Digest> Read for OpsRootWitness<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let grafted_root = D::read(buf)?;
        let partial_chunk = if bool::read(buf)? {
            let next_bit = UInt::<u64>::read(buf)?.into();
            let digest = D::read(buf)?;
            Some((next_bit, digest))
        } else {
            None
        };
        Ok(Self {
            grafted_root,
            partial_chunk,
        })
    }
}

/// An inventory of all structural peaks for a Merkle-family tree, mapped linearly top-to-bottom
/// relative to the bounds of a verified range proof.
///
/// Because the database operations log acts dynamically like an append-only structure (MMR or MMB),
/// the elements verified in a range proof intersect with zero or more contiguous root peaks.
/// This struct mechanically buckets every peak into exactly one of three sequential layout regions:
/// those appearing structurally before the range, those structurally overlapping the range, and
/// those physically placed after the range bounds.
struct PeakLayout<F: Family> {
    /// Peaks whose leaves are entirely preceding the operation range's starting location.
    prefix: Vec<(Position<F>, u32)>,
    /// Peaks that physically intersect with the operations proven within the range.
    range: Vec<(Position<F>, u32)>,
    /// Peaks whose leaves entirely succeed the operation range's ending location.
    after: Vec<(Position<F>, u32)>,
}

/// Helper to bucket a tree's current peaks into prefix, range, and after sub-vectors.
///
/// Traverses all structural peaks left-to-right (from largest/leftmost to smallest/rightmost)
/// and divides them into the three regions described by [`PeakLayout`].
fn peak_layout<F: Family>(
    leaves: Location<F>,
    range: Range<Location<F>>,
) -> Result<PeakLayout<F>, merkle::Error<F>> {
    if range.is_empty() {
        return Err(merkle::Error::Empty);
    }
    let end_minus_one = range.end.checked_sub(1).expect("range is non-empty");
    if end_minus_one >= leaves {
        return Err(merkle::Error::RangeOutOfBounds(range.end));
    }

    let size = Position::<F>::try_from(leaves)?;
    let mut prefix = Vec::new();
    let mut range_peaks = Vec::new();
    let mut after = Vec::new();
    let mut leaf_cursor = 0u64;

    for (peak_pos, height) in F::peaks(size) {
        let leaf_end = leaf_cursor + (1u64 << height);
        if leaf_end <= *range.start {
            prefix.push((peak_pos, height));
        } else if leaf_cursor >= *range.end {
            after.push((peak_pos, height));
        } else {
            range_peaks.push((peak_pos, height));
        }
        leaf_cursor = leaf_end;
    }

    Ok(PeakLayout {
        prefix,
        range: range_peaks,
        after,
    })
}

/// Determines if a specific chunk index spans multiple peaks and has been fully sealed.
///
/// If `chunk_idx` is less than `complete_chunks` and structurally covers more than
/// one peak, it implies those discrete ops peaks must be explicitly folded together (via the
/// "grafted fold" interception mechanics) during proof verification.
fn chunk_needs_grafted_fold<F: Graftable>(
    size: Position<F>,
    chunk_idx: u64,
    grafting_height: u32,
    complete_chunks: u64,
) -> bool {
    chunk_idx < complete_chunks
        && F::chunk_peaks(size, chunk_idx, grafting_height)
            .nth(1)
            .is_some()
}

/// Checks if the provided proof interacts with ANY multi-peak complete chunks.
///
/// It scans all peaks dynamically bucketed by `layout` (prefix, active range, and suffix after).
/// If any peak's height is sub-grafting-height and falls within a completely sealed chunk
/// that spans multiple peaks, the standard contiguous root verification MUST be intercepted and
/// rebuilt completely using the `reconstruct_grafted_root` algorithm.
fn proof_needs_grafted_peak_fold<F: Graftable>(
    layout: &PeakLayout<F>,
    size: Position<F>,
    grafting_height: u32,
    complete_chunks: u64,
) -> bool {
    layout
        .prefix
        .iter()
        .chain(layout.range.iter())
        .chain(layout.after.iter())
        .any(|(pos, height)| {
            if *height < grafting_height {
                let chunk_idx = *F::leftmost_leaf(*pos, *height) >> grafting_height;
                chunk_needs_grafted_fold(size, chunk_idx, grafting_height, complete_chunks)
            } else {
                false
            }
        })
}

/// Return the number of leaves covered by `peaks`.
fn peaks_leaf_len<F: Family>(peaks: &[(Position<F>, u32)]) -> u64 {
    peaks
        .iter()
        .fold(0u64, |acc, (_pos, height)| acc + (1u64 << *height))
}

/// Return the prefix index where peaks may need to regroup with caller-provided chunks.
fn prefix_raw_start_idx<F: Family>(
    peaks: &[(Position<F>, u32)],
    start_chunk: u64,
    grafting_height: u32,
) -> usize {
    let chunk_start = start_chunk << grafting_height;
    let mut leaf_cursor = 0u64;
    for (idx, (_pos, height)) in peaks.iter().enumerate() {
        leaf_cursor += 1u64 << *height;
        if leaf_cursor > chunk_start {
            return idx;
        }
    }
    peaks.len()
}

/// Return the after-region index up to which peaks may need caller-provided chunks.
fn after_raw_end_idx<F: Family>(
    peaks: &[(Position<F>, u32)],
    start_leaf: u64,
    end_chunk: u64,
    grafting_height: u32,
) -> usize {
    let chunk_end = (end_chunk + 1) << grafting_height;
    let mut leaf_cursor = start_leaf;
    for (idx, (_pos, height)) in peaks.iter().enumerate() {
        if leaf_cursor >= chunk_end {
            return idx;
        }
        leaf_cursor += 1u64 << *height;
    }
    peaks.len()
}

/// Return the transformed grafted witness shape for a peak slice.
fn transformed_peak_counts<F: Graftable>(
    peaks: &[(Position<F>, u32)],
    start_leaf: u64,
    grafting_height: u32,
    has_chunk: impl Fn(u64) -> bool,
) -> Vec<usize> {
    let chunk_size = 1u64 << grafting_height;
    let mut leaf_cursor = start_leaf;
    let mut out = Vec::new();
    let mut pending_chunk: Option<(u64, usize)> = None;

    let flush = |out: &mut Vec<usize>, pending: &mut Option<(u64, usize)>| {
        if let Some((_idx, count)) = pending.take() {
            out.push(count);
        }
    };

    for (_pos, height) in peaks {
        let peak_start = leaf_cursor;
        leaf_cursor += 1u64 << *height;

        if *height >= grafting_height {
            flush(&mut out, &mut pending_chunk);
            out.push(1);
            continue;
        }

        let chunk_idx = peak_start / chunk_size;
        match pending_chunk.take() {
            Some((idx, count)) if idx == chunk_idx => {
                pending_chunk = Some((idx, count + 1));
            }
            old_chunk => {
                pending_chunk = old_chunk;
                flush(&mut out, &mut pending_chunk);
                if has_chunk(chunk_idx) {
                    pending_chunk = Some((chunk_idx, 1));
                } else {
                    out.push(1);
                }
            }
        }
    }
    flush(&mut out, &mut pending_chunk);

    out
}

// Reconstructs the canonical grafted root from the combination of generic proof boundaries,
// operation elements, and grafted prefix/suffix witnesses provided by the prover.
#[allow(clippy::too_many_arguments)]
fn reconstruct_grafted_root<F: Graftable, H: CHasher, C: AsRef<[u8]>>(
    verifier: &grafting::Verifier<'_, F, H>,
    proof: &RangeProof<F, H::Digest>,
    layout: &PeakLayout<F>,
    leaves: Location<F>,
    range: Range<Location<F>>,
    collected: &BTreeMap<Position<F>, H::Digest>,
    grafting_height: u32,
    get_chunk: impl Fn(u64) -> Option<C>,
) -> Option<H::Digest> {
    let prefix_start = 0;
    let range_start = peaks_leaf_len(&layout.prefix);
    let after_start = range_start + peaks_leaf_len(&layout.range);
    let chunk_available = |idx| idx < (*leaves >> grafting_height);
    let start_chunk = *range.start >> grafting_height;
    let end_chunk = *range.end.checked_sub(1)? >> grafting_height;
    let prefix_raw_start = prefix_raw_start_idx(&layout.prefix, start_chunk, grafting_height);
    let after_raw_end = after_raw_end_idx(&layout.after, after_start, end_chunk, grafting_height);

    let prefix_counts = transformed_peak_counts(
        &layout.prefix[..prefix_raw_start],
        prefix_start,
        grafting_height,
        chunk_available,
    );
    let suffix_counts = transformed_peak_counts(
        &layout.after[after_raw_end..],
        after_start + peaks_leaf_len(&layout.after[..after_raw_end]),
        grafting_height,
        chunk_available,
    );
    let prefix_witness_len = prefix_counts.len() + layout.prefix[prefix_raw_start..].len();
    let suffix_witness_len = layout.after[..after_raw_end].len() + suffix_counts.len();
    if proof.unfolded_prefix_peaks.len() != prefix_witness_len
        || proof.unfolded_suffix_peaks.len() != suffix_witness_len
    {
        return None;
    }

    let mut transformed = Vec::with_capacity(
        proof.unfolded_prefix_peaks.len() + layout.range.len() + proof.unfolded_suffix_peaks.len(),
    );
    let (prefix_transformed, prefix_raw) =
        proof.unfolded_prefix_peaks.split_at(prefix_counts.len());
    transformed.extend(prefix_transformed.iter().copied().zip(prefix_counts));
    let mut range_digests = Vec::with_capacity(layout.range.len());
    for (pos, _) in &layout.range {
        range_digests.push(*collected.get(pos)?);
    }
    let (suffix_raw, suffix_transformed) = proof
        .unfolded_suffix_peaks
        .split_at(layout.after[..after_raw_end].len());

    // The transformed list has three regions: entries before the range-adjacent chunks, the
    // middle chunks that may combine raw prefix/range/suffix peaks, and entries after that middle
    // region. `middle_peaks` covers exactly the chunk span from the first raw prefix peak through
    // the last raw suffix peak that can share a grafted chunk with the proven range.
    let middle_iter = layout.prefix[prefix_raw_start..]
        .iter()
        .map(|(_, h)| *h)
        .zip(prefix_raw.iter().copied())
        .chain(
            layout
                .range
                .iter()
                .map(|(_, h)| *h)
                .zip(range_digests.iter().copied()),
        )
        .chain(
            layout.after[..after_raw_end]
                .iter()
                .map(|(_, h)| *h)
                .zip(suffix_raw.iter().copied()),
        );
    transformed.extend(grafting::transform_peak_digests::<F, _, _, _>(
        verifier,
        middle_iter,
        range_start - peaks_leaf_len(&layout.prefix[prefix_raw_start..]),
        grafting_height,
        get_chunk,
    ));
    transformed.extend(suffix_transformed.iter().copied().zip(suffix_counts));

    let inactive_peaks = proof.proof.inactive_peaks;
    let inactive_to_fold = grafting::transformed_inactive_peaks::<F, _>(
        &transformed,
        inactive_peaks,
        layout.prefix.len() + layout.range.len() + layout.after.len(),
    )
    .ok()?;
    let digests = transformed.iter().map(|(digest, _count)| digest);
    verifier.root_with_folded_peaks(leaves, inactive_to_fold, inactive_peaks, digests)
}

struct GraftedProofParts<F: Family, D: Digest> {
    proof: Proof<F, D>,
    unfolded_prefix_peaks: Vec<D>,
    unfolded_suffix_peaks: Vec<D>,
}

fn grafted_chunk<const N: usize>(
    status: &impl BitmapReadable<N>,
    complete_chunks: u64,
    pruned_chunks: u64,
    idx: u64,
) -> Option<[u8; N]> {
    if idx >= complete_chunks {
        None
    } else if idx < pruned_chunks {
        Some([0u8; N])
    } else {
        Some(status.get_chunk(idx as usize))
    }
}

fn peak_digests<F: Family, D: Digest>(
    peaks: &[(Position<F>, u32)],
    fetched: &BTreeMap<Position<F>, D>,
) -> Result<Vec<D>, Error<F>> {
    peaks
        .iter()
        .map(|&(pos, _)| {
            fetched
                .get(&pos)
                .copied()
                .ok_or_else(|| Error::from(merkle::Error::<F>::MissingNode(pos)))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn prefix_witness<F: Graftable, D: Digest, H: CHasher<Digest = D>, const N: usize>(
    hasher: &StandardHasher<H>,
    status: &impl BitmapReadable<N>,
    peaks: &[(Position<F>, u32)],
    raw_digests: &[D],
    raw_start: usize,
    grafting_height: u32,
    complete_chunks: u64,
    pruned_chunks: u64,
) -> Vec<D> {
    let mut witness = grafting::transform_peak_digests::<F, _, _, _>(
        hasher,
        peaks[..raw_start]
            .iter()
            .map(|(_, h)| *h)
            .zip(raw_digests[..raw_start].iter().copied()),
        0,
        grafting_height,
        |idx| grafted_chunk(status, complete_chunks, pruned_chunks, idx),
    )
    .into_iter()
    .map(|(digest, _count)| digest)
    .collect::<Vec<_>>();
    witness.extend_from_slice(&raw_digests[raw_start..]);
    witness
}

#[allow(clippy::too_many_arguments)]
fn suffix_witness<F: Graftable, D: Digest, H: CHasher<Digest = D>, const N: usize>(
    hasher: &StandardHasher<H>,
    status: &impl BitmapReadable<N>,
    peaks: &[(Position<F>, u32)],
    raw_digests: &[D],
    suffix_start: u64,
    raw_end: usize,
    grafting_height: u32,
    complete_chunks: u64,
    pruned_chunks: u64,
) -> Vec<D> {
    let mut witness = raw_digests[..raw_end].to_vec();
    witness.extend(
        grafting::transform_peak_digests::<F, _, _, _>(
            hasher,
            peaks[raw_end..]
                .iter()
                .map(|(_, h)| *h)
                .zip(raw_digests[raw_end..].iter().copied()),
            suffix_start + peaks_leaf_len(&peaks[..raw_end]),
            grafting_height,
            |idx| grafted_chunk(status, complete_chunks, pruned_chunks, idx),
        )
        .into_iter()
        .map(|(digest, _count)| digest),
    );
    witness
}

#[allow(clippy::too_many_arguments)]
async fn build_grafted_range_proof<
    F: Graftable,
    D: Digest,
    H: CHasher<Digest = D>,
    S: Storage<F, Digest = D>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    status: &impl BitmapReadable<N>,
    storage: &S,
    layout: &PeakLayout<F>,
    leaves: Location<F>,
    inactive_peaks: usize,
    range: Range<Location<F>>,
    grafting_height: u32,
    complete_chunks: u64,
    pruned_chunks: u64,
) -> Result<GraftedProofParts<F, D>, Error<F>> {
    let proof_start_chunk = *range.start >> grafting_height;
    let proof_end_chunk = *range.end.checked_sub(1).ok_or(merkle::Error::Empty)? >> grafting_height;

    let proof_positions = merkle::range_collection_nodes(leaves, inactive_peaks, range)?;
    let mut fetch_positions = proof_positions.clone();
    fetch_positions.extend(layout.prefix.iter().map(|&(pos, _)| pos));
    fetch_positions.extend(layout.after.iter().map(|&(pos, _)| pos));
    fetch_positions.sort_unstable();
    debug_assert!(
        fetch_positions
            .windows(2)
            .all(|window| window[0] != window[1]),
        "grafted proof fetch positions should be unique"
    );

    let node_futures = fetch_positions
        .into_iter()
        .map(|pos| async move { storage.get_node(pos).await.map(|digest| (pos, digest)) })
        .collect::<Vec<_>>();
    let fetched: BTreeMap<Position<F>, D> = try_join_all(node_futures)
        .await?
        .into_iter()
        .map(|(pos, digest)| {
            digest
                .ok_or_else(|| Error::from(merkle::Error::<F>::MissingNode(pos)))
                .map(|d| (pos, d))
        })
        .collect::<Result<_, Error<F>>>()?;

    let proof = merkle::build_range_collection_proof::<F, D, Error<F>>(
        leaves,
        inactive_peaks,
        &proof_positions,
        |pos| fetched.get(&pos).copied(),
        |pos| Error::from(merkle::Error::<F>::MissingNode(pos)),
    )?;

    let prefix_raw = peak_digests(&layout.prefix, &fetched)?;
    let prefix_raw_start = prefix_raw_start_idx(&layout.prefix, proof_start_chunk, grafting_height);
    let unfolded_prefix_peaks = prefix_witness::<F, D, H, N>(
        hasher,
        status,
        &layout.prefix,
        &prefix_raw,
        prefix_raw_start,
        grafting_height,
        complete_chunks,
        pruned_chunks,
    );

    let suffix_raw = peak_digests(&layout.after, &fetched)?;
    let suffix_start = peaks_leaf_len(&layout.prefix) + peaks_leaf_len(&layout.range);
    let suffix_raw_end = after_raw_end_idx(
        &layout.after,
        suffix_start,
        proof_end_chunk,
        grafting_height,
    );
    let unfolded_suffix_peaks = suffix_witness::<F, D, H, N>(
        hasher,
        status,
        &layout.after,
        &suffix_raw,
        suffix_start,
        suffix_raw_end,
        grafting_height,
        complete_chunks,
        pruned_chunks,
    );

    Ok(GraftedProofParts {
        proof,
        unfolded_prefix_peaks,
        unfolded_suffix_peaks,
    })
}

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<F: Family, D: Digest> {
    /// The Merkle digest material required to verify the proof.
    pub proof: Proof<F, D>,

    /// Extra prefix witnesses needed when generic proof collection would hide peaks behind a
    /// prefix accumulator that grafted reconstruction must inspect.
    ///
    /// This vector is intentionally split by convention. It starts with already-transformed
    /// grafted digests for the prefix region before the range-adjacent chunk span, then contains
    /// raw peak digests that can regroup with the proven range. The verifier reconstructs the split
    /// point from the peak layout.
    pub unfolded_prefix_peaks: Vec<D>,

    /// Extra suffix witnesses needed when generic backward-bagged proofs hide peaks behind a
    /// suffix accumulator that grafted reconstruction must inspect.
    ///
    /// This vector is intentionally split by convention. It starts with raw peak digests adjacent
    /// to the proven range, because those peaks may share grafted chunks with in-range peaks. It
    /// then contains already-transformed grafted digests for the remaining suffix region. The
    /// verifier reconstructs the split point from the peak layout.
    pub unfolded_suffix_peaks: Vec<D>,

    /// The partial chunk digest from the status bitmap at the time of proof generation, if any.
    pub partial_chunk_digest: Option<D>,

    /// The ops-tree root at the time of proof generation.
    /// Needed by the verifier to reconstruct the canonical root.
    pub ops_root: D,
}

impl<F: Graftable, D: Digest> RangeProof<F, D> {
    /// Create a new range proof for the provided `range` of operations.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>, const N: usize>(
        hasher: &mut H,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        range: Range<Location<F>>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        let std_hasher = qmdb::hasher::<H>();
        let range_for_layout = range.clone();
        let complete_chunks = status.complete_chunks() as u64;
        let pruned_chunks = status.pruned_chunks() as u64;
        let leaves = Location::try_from(storage.size().await)?;
        let layout = peak_layout(leaves, range_for_layout)?;
        let grafting_height = grafting::height::<N>();
        let inactive_peaks =
            grafting::chunk_aligned_inactive_peaks::<F>(leaves, inactivity_floor, grafting_height)?;

        let size = Position::<F>::try_from(leaves)?;
        let needs_grafted_peak_fold =
            proof_needs_grafted_peak_fold(&layout, size, grafting_height, complete_chunks);
        let GraftedProofParts {
            proof,
            unfolded_prefix_peaks,
            unfolded_suffix_peaks,
        } = if needs_grafted_peak_fold {
            build_grafted_range_proof(
                &std_hasher,
                status,
                storage,
                &layout,
                leaves,
                inactive_peaks,
                range.clone(),
                grafting_height,
                complete_chunks,
                pruned_chunks,
            )
            .await?
        } else {
            GraftedProofParts {
                proof: merkle::verification::historical_range_proof(
                    &std_hasher,
                    storage,
                    leaves,
                    range.clone(),
                    inactive_peaks,
                )
                .await?,
                unfolded_prefix_peaks: Vec::new(),
                unfolded_suffix_peaks: Vec::new(),
            }
        };

        let (last_chunk, next_bit) = status.last_chunk();
        let partial_chunk_digest = if next_bit != BitMap::<N>::CHUNK_SIZE_BITS {
            // Last chunk is incomplete, meaning it's not yet in the MMR and needs to be included
            // in the proof.
            hasher.update(&last_chunk);
            Some(hasher.finalize())
        } else {
            None
        };

        Ok(Self {
            proof,
            unfolded_prefix_peaks,
            unfolded_suffix_peaks,
            partial_chunk_digest,
            ops_root,
        })
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range and their activity status chunks. A truncated range (from
    /// hitting the max) can be detected by looking at the length of the returned operations vector.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `start_loc` falls in a pruned bitmap chunk.
    /// Returns [`merkle::Error::LocationOverflow`] if `start_loc` > [merkle::Family::MAX_LEAVES].
    /// Returns [`merkle::Error::RangeOutOfBounds`] if `start_loc` >= number of leaves in the MMR.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_ops<
        H: CHasher<Digest = D>,
        C: Contiguous,
        S: Storage<F, Digest = D>,
        const N: usize,
    >(
        hasher: &mut H,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        log: &C,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
        ops_root: D,
    ) -> Result<(Self, Vec<C::Item>, Vec<[u8; N]>), Error<F>> {
        // Compute the start and end locations & positions of the range.
        let leaves = Location::new(status.len());
        if start_loc >= leaves {
            return Err(merkle::Error::RangeOutOfBounds(start_loc).into());
        }

        // Reject ranges that start in pruned bitmap chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start = *start_loc / chunk_bits;
        if (start as usize) < status.pruned_chunks() {
            return Err(Error::OperationPruned(start_loc));
        }

        let max_loc = start_loc.saturating_add(max_ops.get());
        let end_loc = core::cmp::min(max_loc, leaves);

        // Generate the proof from the grafted storage.
        let proof = Self::new(
            hasher,
            status,
            storage,
            inactivity_floor,
            start_loc..end_loc,
            ops_root,
        )
        .await?;

        // Collect the operations necessary to verify the proof.
        let reader = log.reader().await;
        let futures = (*start_loc..*end_loc)
            .map(|i| reader.read(i))
            .collect::<Vec<_>>();
        let ops = try_join_all(futures).await?;

        // Gather the chunks necessary to verify the proof.
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the last bit
        let chunks = (start..=end)
            .map(|i| status.get_chunk(i as usize))
            .collect::<Vec<_>>();

        Ok((proof, ops, chunks))
    }
}

impl<F: Graftable, D: Digest> RangeProof<F, D> {
    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the db with the provided root, and having the activity status described by `chunks`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec, const N: usize>(
        &self,
        hasher: &mut H,
        start_loc: Location<F>,
        ops: &[O],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        if ops.is_empty() || chunks.is_empty() {
            debug!("verification failed, empty input");
            return false;
        }
        // Compute the (non-inclusive) end location of the range.
        let Some(end_loc) = start_loc.checked_add(ops.len() as u64) else {
            debug!("verification failed, end_loc overflow");
            return false;
        };

        let leaves = self.proof.leaves;
        if end_loc > leaves {
            debug!(
                loc = ?end_loc,
                ?leaves, "verification failed, invalid range"
            );
            return false;
        }

        // Validate the number of input chunks.
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let start_chunk = *start_loc / chunk_bits;
        let end_chunk = (*end_loc - 1) / chunk_bits;
        let complete_chunks = *leaves / chunk_bits;

        if (end_chunk - start_chunk + 1) != chunks.len() as u64 {
            debug!("verification failed, chunk metadata length mismatch");
            return false;
        }

        let next_bit = *leaves % chunk_bits;
        let has_partial_chunk = next_bit != 0;

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();
        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let grafting_height = grafting::height::<N>();
        let verifier = grafting::Verifier::<F, H>::new(
            grafting_height,
            start_chunk,
            chunk_vec,
            qmdb::ROOT_BAGGING,
        );

        // For partial chunks, validate the last chunk digest from the proof.
        if has_partial_chunk {
            let Some(last_chunk_digest) = self.partial_chunk_digest else {
                debug!("proof has no partial chunk digest");
                return false;
            };

            // If the proof covers an operation in the partial chunk, verify that the
            // chunk provided by the caller matches the digest embedded in the proof.
            if end_chunk == complete_chunks {
                let last_chunk = chunks.last().expect("chunks non-empty");
                if last_chunk_digest != verifier.digest(last_chunk) {
                    debug!("last chunk digest does not match expected value");
                    return false;
                }
            }
        } else if self.partial_chunk_digest.is_some() {
            debug!("proof has unexpected partial chunk digest");
            return false;
        }

        let layout = match peak_layout(leaves, start_loc..end_loc) {
            Ok(layout) => layout,
            Err(error) => {
                debug!(?error, "verification failed, invalid peak layout");
                return false;
            }
        };
        let size = match Position::<F>::try_from(leaves) {
            Ok(size) => size,
            Err(error) => {
                debug!(?error, "verification failed, invalid size");
                return false;
            }
        };
        let needs_grafted_peak_fold =
            proof_needs_grafted_peak_fold(&layout, size, grafting_height, complete_chunks);
        let merkle_root = if !needs_grafted_peak_fold {
            if !self.unfolded_prefix_peaks.is_empty() || !self.unfolded_suffix_peaks.is_empty() {
                debug!("verification failed, unexpected grafted metadata");
                return false;
            }
            match self.proof.reconstruct_root(&verifier, &elements, start_loc) {
                Ok(root) => root,
                Err(error) => {
                    debug!(?error, "invalid proof input");
                    return false;
                }
            }
        } else {
            let mut collected = Vec::new();
            if let Err(error) = self.proof.reconstruct_range_collecting(
                &verifier,
                &elements,
                start_loc,
                &mut collected,
            ) {
                debug!(?error, "invalid proof input");
                return false;
            };

            let collected: BTreeMap<Position<F>, D> = collected.into_iter().collect();
            let get_chunk = |chunk_idx: u64| -> Option<&[u8]> {
                if chunk_idx >= complete_chunks {
                    return None;
                }
                chunk_idx
                    .checked_sub(start_chunk)
                    .filter(|&idx| idx < chunks.len() as u64)
                    .map(|idx| chunks[idx as usize].as_ref())
            };
            let Some(root) = reconstruct_grafted_root(
                &verifier,
                self,
                &layout,
                leaves,
                start_loc..end_loc,
                &collected,
                grafting_height,
                get_chunk,
            ) else {
                debug!("verification failed, could not reconstruct grafted root");
                return false;
            };
            root
        };

        // Compute the canonical root and compare.
        hasher.update(&self.ops_root);
        hasher.update(&merkle_root);
        if has_partial_chunk {
            // partial_chunk_digest is guaranteed Some by the check above.
            hasher.update(&next_bit.to_be_bytes());
            hasher.update(self.partial_chunk_digest.as_ref().unwrap());
        }
        let reconstructed_root = hasher.finalize();
        reconstructed_root == *root
    }
}

/// A proof that a specific operation is currently active in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct OperationProof<F: Family, D: Digest, const N: usize> {
    /// The location of the operation in the db.
    pub loc: Location<F>,

    /// The status bitmap chunk that contains the bit corresponding the operation's location.
    pub chunk: [u8; N],

    /// The range proof that incorporates activity status for the operation designated by `loc`.
    pub range_proof: RangeProof<F, D>,
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Return an inclusion proof that incorporates activity status for the operation designated by
    /// `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `loc` falls in a pruned bitmap chunk.
    pub async fn new<H: CHasher<Digest = D>, S: Storage<F, Digest = D>>(
        hasher: &mut H,
        status: &impl BitmapReadable<N>,
        storage: &S,
        inactivity_floor: Location<F>,
        loc: Location<F>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Reject locations in pruned bitmap chunks.
        if BitMap::<N>::to_chunk_index(*loc) < status.pruned_chunks() {
            return Err(Error::OperationPruned(loc));
        }
        let range_proof = RangeProof::new(
            hasher,
            status,
            storage,
            inactivity_floor,
            loc..loc + 1,
            ops_root,
        )
        .await?;
        let chunk = status.get_chunk(BitMap::<N>::to_chunk_index(*loc));
        Ok(Self {
            loc,
            chunk,
            range_proof,
        })
    }
}

impl<F: Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
    /// Verify that the proof proves that `operation` is active in the database with the given
    /// `root`.
    pub fn verify<H: CHasher<Digest = D>, O: Codec>(
        &self,
        hasher: &mut H,
        operation: O,
        root: &D,
    ) -> bool {
        // Make sure that the bit for the operation in the bitmap chunk is actually a 1 (indicating
        // the operation is indeed active).
        if !BitMap::<N>::get_bit_from_chunk(&self.chunk, *self.loc) {
            debug!(
                ?self.loc,
                "proof verification failed, operation is inactive"
            );
            return false;
        }

        self.range_proof
            .verify(hasher, self.loc, &[operation], &[self.chunk], root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mem, mem::Mem},
        mmb,
        qmdb::current::{db, grafting},
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};

    #[test]
    fn test_ops_root_witness_codec_roundtrip() {
        for partial_chunk in [
            None,
            Some((0u64, Sha256::hash(b"partial-zero"))),
            Some((123u64, Sha256::hash(b"partial-nonzero"))),
        ] {
            let witness = OpsRootWitness {
                grafted_root: Sha256::hash(b"grafted"),
                partial_chunk,
            };
            let encoded = witness.encode();
            assert_eq!(encoded.len(), witness.encode_size());
            let decoded = OpsRootWitness::<sha256::Digest>::decode(encoded).unwrap();
            assert_eq!(decoded, witness);
        }
    }

    #[test_traced]
    fn test_range_proof_verifies_for_mmb_multi_peak_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();

            let leaf_count = (16..=64u64)
                .find(|&leaves| {
                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1).is_some()
                })
                .expect("expected an MMB size whose second chunk spans multiple peaks");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(BitMap::<N>::CHUNK_SIZE_BITS + 4);
            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let mut verify_hasher = Sha256::new();
            assert!(proof.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 1)],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_with_partial_suffix_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();

            let (leaf_count, loc) = (17..=64u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / BitMap::<N>::CHUNK_SIZE_BITS;
                    if complete_chunks < 2 || leaves % BitMap::<N>::CHUNK_SIZE_BITS == 0 {
                        return None;
                    }

                    let size = F::location_to_position(mmb::Location::new(leaves));
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;

                    for offset in 0..BitMap::<N>::CHUNK_SIZE_BITS {
                        let loc = mmb::Location::new(BitMap::<N>::CHUNK_SIZE_BITS + offset);
                        if *loc >= leaves {
                            break;
                        }
                        let after_peaks = peak_layout(mmb::Location::new(leaves), loc..loc + 1)
                            .ok()?
                            .after;
                        let has_partial_suffix_peak = after_peaks.iter().any(|(pos, height)| {
                            *height < grafting_height
                                && (*F::leftmost_leaf(*pos, *height) >> grafting_height)
                                    == complete_chunks
                        });
                        if has_partial_suffix_peak {
                            return Some((leaves, loc));
                        }
                    }
                    None
                })
                .expect("expected an MMB proof with a partial trailing suffix chunk");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / BitMap::<N>::CHUNK_SIZE_BITS) as usize;
            let mut verify_hasher = Sha256::new();
            assert!(proof.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_verifies_when_range_reaches_partial_chunk_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, start_loc, complete_chunks) = (17..=128u64)
                .find_map(|leaves| {
                    let complete_chunks = leaves / chunk_bits;
                    if complete_chunks < 2 || leaves % chunk_bits == 0 {
                        return None;
                    }

                    let leaves_loc = mmb::Location::new(leaves);
                    let size = F::location_to_position(leaves_loc);
                    F::chunk_peaks(size, 1, grafting_height).nth(1)?;

                    (0..chunk_bits).find_map(|offset| {
                        let start_loc = mmb::Location::new(chunk_bits + offset);
                        if *start_loc >= complete_chunks * chunk_bits {
                            return None;
                        }
                        let layout = peak_layout(leaves_loc, start_loc..leaves_loc).ok()?;
                        proof_needs_grafted_peak_fold(
                            &layout,
                            size,
                            grafting_height,
                            complete_chunks,
                        )
                        .then_some((leaves, start_loc, complete_chunks))
                    })
                })
                .expect("expected an MMB proof into the trailing partial chunk");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                partial,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let leaves_loc = mmb::Location::new(leaf_count);
            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                Location::new(0),
                start_loc..leaves_loc,
                ops_root,
            )
            .await
            .unwrap();

            let elements = (*start_loc..leaf_count)
                .map(|idx| hasher.digest(&idx.to_be_bytes()))
                .collect::<Vec<_>>();
            let start_chunk_idx = (*start_loc / chunk_bits) as usize;
            let end_chunk_idx = complete_chunks as usize;
            let chunks = (start_chunk_idx..=end_chunk_idx)
                .map(|chunk_idx| <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx))
                .collect::<Vec<_>>();

            let mut verify_hasher = Sha256::new();
            assert!(proof.verify(&mut verify_hasher, start_loc, &elements, &chunks, &root,));
        });
    }
    #[test_traced]
    fn test_range_proof_rejects_unexpected_partial_chunk_digest() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let leaf_count = chunk_bits * 2; // Perfect chunks, NO partial trailing bits
            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(0);
            let mut proof_hasher = Sha256::new();
            let mut proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);

            let mut tampered = proof.clone();
            tampered
                .unfolded_prefix_peaks
                .push(hasher.digest(b"fake unfolded prefix"));
            let mut verify_hasher = Sha256::new();
            assert!(!tampered.verify(&mut verify_hasher, loc, &[element], &[chunk], &root,));

            // Tamper with the proof by injecting a fake partial chunk digest
            proof.partial_chunk_digest = Some(hasher.digest(b"fake partial chunk"));

            let mut verify_hasher = Sha256::new();
            assert!(!proof.verify(&mut verify_hasher, loc, &[element], &[chunk], &root,));
        });
    }

    #[test_traced]
    fn test_range_proof_unfolds_mmb_peaks_for_grafted_reconstruction() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc, layout) = (chunk_bits * 3..=128u64)
                .filter(|leaves| leaves % chunk_bits == 0)
                .find_map(|leaves| {
                    let leaves_loc = mmb::Location::new(leaves);
                    let complete_chunks = leaves / chunk_bits;
                    (0..leaves).find_map(|idx| {
                        let loc = mmb::Location::new(idx);
                        let layout = peak_layout(leaves_loc, loc..loc + 1).ok()?;
                        let size = F::location_to_position(leaves_loc);
                        proof_needs_grafted_peak_fold(
                            &layout,
                            size,
                            grafting_height,
                            complete_chunks,
                        )
                        .then_some((leaves, loc, layout))
                    })
                })
                .expect("expected an MMB proof requiring grafted peak folding");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);
            let ops_root = ops.root(&hasher, 0).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                Location::new(0),
                &ops_root,
            )
            .await
            .unwrap();

            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                Location::new(0),
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();

            // Grafted reconstruction needs the individual prefix/suffix peaks that generic
            // backward proofs may otherwise hide behind fold accumulators. These witnesses are
            // already grouped by grafted chunk, so their counts can be smaller than raw peak
            // counts.
            let prefix_counts =
                transformed_peak_counts(&layout.prefix, 0, grafting_height, |idx| {
                    idx < leaf_count / chunk_bits
                });
            let suffix_start = peaks_leaf_len(&layout.prefix) + peaks_leaf_len(&layout.range);
            let suffix_counts =
                transformed_peak_counts(&layout.after, suffix_start, grafting_height, |idx| {
                    idx < leaf_count / chunk_bits
                });
            assert_eq!(proof.unfolded_prefix_peaks.len(), prefix_counts.len());
            assert_eq!(proof.unfolded_suffix_peaks.len(), suffix_counts.len());

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk_idx = (*loc / chunk_bits) as usize;
            let mut verify_hasher = Sha256::new();
            assert!(proof.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = 1;
            let mut verify_hasher = Sha256::new();
            assert!(!tampered.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            tampered.proof.inactive_peaks = usize::MAX;
            let mut verify_hasher = Sha256::new();
            assert!(!tampered.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));

            let mut tampered = proof.clone();
            assert!(!tampered.proof.digests.is_empty());
            tampered.proof.digests[0] = hasher.digest(b"fake generic sibling");
            let mut verify_hasher = Sha256::new();
            assert!(!tampered.verify(
                &mut verify_hasher,
                loc,
                &[element],
                &[<BitMap<N> as BitmapReadable<N>>::get_chunk(
                    &status, chunk_idx
                )],
                &root,
            ));
        });
    }

    #[test_traced]
    fn test_range_proof_allows_ops_and_grafted_inactive_counts_to_differ() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher = qmdb::hasher::<Sha256>();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
            let leaf_count = chunk_bits;
            let leaves = mmb::Location::new(leaf_count);
            let inactivity_floor = mmb::Location::new(chunk_bits - 2);

            let raw_inactive = F::inactive_peaks(F::location_to_position(leaves), inactivity_floor);
            let aligned_inactive = grafting::chunk_aligned_inactive_peaks::<F>(
                leaves,
                inactivity_floor,
                grafting_height,
            )
            .unwrap();
            assert_ne!(raw_inactive, aligned_inactive);

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(), leaf_count);

            // The ops root is the inner QMDB log root and commits the raw inactive peak count.
            // The grafted bitmap root commits the chunk-aligned count, since grafted chunks are
            // the atomic inactive-prefix boundary for the current root.
            let ops_root = ops.root(&hasher, raw_inactive).unwrap();

            let chunk_inputs: Vec<_> =
                (0..<BitMap<N> as BitmapReadable<N>>::complete_chunks(&status))
                    .map(|chunk_idx| {
                        (
                            chunk_idx,
                            <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, chunk_idx),
                        )
                    })
                    .collect();
            let mut leaf_digests = db::compute_grafted_leaves::<F, Sha256, Sequential, N>(
                &hasher,
                &ops,
                chunk_inputs,
                &Sequential,
            )
            .await
            .unwrap();
            leaf_digests.sort_by_key(|(chunk_idx, _)| *chunk_idx);

            let grafted_hasher =
                grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
            let mut grafted = Mem::<F, sha256::Digest>::new();
            let merkleized = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted, &grafted_hasher)
            };
            grafted.apply_batch(&merkleized).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops, hasher.clone());
            let root = db::compute_db_root::<F, Sha256, _, _, N>(
                &hasher,
                &status,
                &storage,
                None,
                inactivity_floor,
                &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(chunk_bits - 1);
            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
                inactivity_floor,
                loc..loc + 1,
                ops_root,
            )
            .await
            .unwrap();
            assert_eq!(proof.proof.inactive_peaks, aligned_inactive);

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);
            let mut verify_hasher = Sha256::new();
            assert!(proof.verify(&mut verify_hasher, loc, &[element], &[chunk], &root));
        });
    }
}

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

/// Finds the index in `prefix_peaks` where the standard prefix accumulation must stop.
///
/// During proof generation, prefix peaks are typically accumulated into a single digest
/// (`pre_prefix_acc`). However, if a complete chunk spans some of these prefix peaks AND
/// extends into the proven range, we must NOT fold those overlapping prefix peaks into the generic
/// accumulator. Instead, we must expose them individually (`unfolded_prefix_peaks`) so the
/// Verifier can correctly regroup them with the in-range peaks for grafted root reconstruction.
/// Returns the slice index where unfolding must begin, or `None` if zero unfolding is needed.
fn unfolding_start_idx<F: Graftable>(
    prefix_peaks: &[(Position<F>, u32)],
    grafting_height: u32,
    start_chunk: u64,
    complete_chunks: u64,
) -> Option<usize> {
    let mut leaf_cursor = 0;
    prefix_peaks.iter().position(|&(_pos, height)| {
        let chunk_idx = leaf_cursor / (1u64 << grafting_height);
        leaf_cursor += 1u64 << height;
        chunk_idx == start_chunk && chunk_idx < complete_chunks
    })
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

/// Accumulates the absolute physical leaf count spanned by the slice of given prefix peaks.
fn prefix_leaf_end<F: Family>(prefix_peaks: &[(Position<F>, u32)]) -> u64 {
    prefix_peaks
        .iter()
        .fold(0u64, |acc, (_, height)| acc + (1u64 << *height))
}

/// Safely extracts the computed digests for all active-range and after-range peaks.
///
/// Since standard verification sequentially computes and caches these intermediate node digests
/// into the `collected` map, this function plucks them out linearly to pass into the grafted root
/// reconstruction engine. Returns `None` if any structurally required peak is missing.
fn collect_peak_digests<F: Family, D: Digest>(
    layout: &PeakLayout<F>,
    collected: &BTreeMap<Position<F>, D>,
) -> Option<Vec<D>> {
    let mut peak_digests = Vec::with_capacity(layout.range.len() + layout.after.len());
    for (pos, _) in layout.range.iter().chain(layout.after.iter()) {
        peak_digests.push(*collected.get(pos)?);
    }
    Some(peak_digests)
}

// Reconstructs the canonical grafted root from the combination of generic proof boundaries,
// the operation elements, and the prefix hashes provided by the prover.
fn reconstruct_grafted_root<F: Graftable, H: CHasher, C: AsRef<[u8]>>(
    verifier: &grafting::Verifier<'_, F, H>,
    proof: &RangeProof<F, H::Digest>,
    layout: &PeakLayout<F>,
    leaves: Location<F>,
    collected: &BTreeMap<Position<F>, H::Digest>,
    grafting_height: u32,
    get_chunk: impl Fn(u64) -> Option<C>,
) -> Option<H::Digest> {
    let suffix_peaks = collect_peak_digests(layout, collected)?;

    let (initial_acc, start_leaf, prefix_peaks) =
        if proof.pre_prefix_acc.is_some() || !proof.unfolded_prefix_peaks.is_empty() {
            let split_idx = layout
                .prefix
                .len()
                .checked_sub(proof.unfolded_prefix_peaks.len())?;
            (
                proof.pre_prefix_acc,
                prefix_leaf_end(&layout.prefix[..split_idx]),
                layout.prefix[split_idx..]
                    .iter()
                    .zip(proof.unfolded_prefix_peaks.iter())
                    .map(|((_, height), &digest)| (*height, digest))
                    .collect::<Vec<_>>(),
            )
        } else {
            (None, prefix_leaf_end(&layout.prefix), vec![])
        };

    let peaks = prefix_peaks.into_iter().chain(
        layout
            .range
            .iter()
            .chain(layout.after.iter())
            .zip(suffix_peaks)
            .map(|((_, height), digest)| (*height, digest)),
    );

    let acc = grafting::fold_grafted_peaks::<F, H::Digest, _, _>(
        verifier,
        initial_acc,
        start_leaf,
        peaks,
        grafting_height,
        get_chunk,
    );
    Some(acc.map_or_else(
        || verifier.digest(&(*leaves).to_be_bytes()),
        |acc| verifier.hash([(*leaves).to_be_bytes().as_slice(), acc.as_ref()]),
    ))
}

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<F: Family, D: Digest> {
    /// The Merkle digest material required to verify the proof.
    pub proof: Proof<F, D>,

    /// The single folded accumulator of all aligned prefix peaks that do not require unfolding.
    pub pre_prefix_acc: Option<D>,

    /// Individual fold-prefix peak digests, in peak order, when the generic proof's single
    /// folded prefix accumulator would otherwise hide multi-peak chunk structure needed for
    /// grafted-root reconstruction.
    pub unfolded_prefix_peaks: Vec<D>,

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
        range: Range<Location<F>>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        let std_hasher = merkle::hasher::Standard::<H>::new();
        let range_for_layout = range.clone();
        let start_chunk = *range.start / BitMap::<N>::CHUNK_SIZE_BITS;
        let complete_chunks = status.complete_chunks() as u64;
        let pruned_chunks = status.pruned_chunks() as u64;
        let leaves = Location::try_from(storage.size().await)?;
        let layout = peak_layout(leaves, range_for_layout)?;
        let grafting_height = grafting::height::<N>();

        let size = Position::<F>::try_from(leaves)?;
        let needs_grafted_peak_fold =
            proof_needs_grafted_peak_fold(&layout, size, grafting_height, complete_chunks);
        let proof =
            merkle::verification::historical_range_proof(&std_hasher, storage, leaves, range, 0)
                .await?;
        let mut pre_prefix_acc: Option<D> = None;
        let mut unfolded_prefix_peaks = Vec::new();
        if needs_grafted_peak_fold {
            let split_idx_opt = unfolding_start_idx(
                &layout.prefix,
                grafting_height,
                start_chunk,
                complete_chunks,
            );
            let split_idx = split_idx_opt.unwrap_or(layout.prefix.len());

            let prefix_futures = layout.prefix.iter().map(|&(pos, _)| storage.get_node(pos));
            let prefix_digests = try_join_all(prefix_futures)
                .await?
                .into_iter()
                .zip(layout.prefix.iter())
                .map(|(result, &(pos, height))| {
                    result
                        .ok_or(merkle::Error::<F>::MissingNode(pos))
                        .map(|d| (height, d))
                })
                .collect::<Result<Vec<_>, _>>()?;

            if split_idx > 0 {
                let prefix_peaks = prefix_digests[..split_idx].to_vec();
                pre_prefix_acc = grafting::fold_grafted_peaks::<F, D, _, _>(
                    &std_hasher,
                    None,
                    0,
                    prefix_peaks,
                    grafting_height,
                    |idx| {
                        if idx < complete_chunks {
                            // Pruned chunks are guaranteed all-zero (only chunks with no active
                            // operations are prunable), so a synthetic zero chunk produces the
                            // correct grafted digest via the zero-chunk identity shortcut.
                            if idx < pruned_chunks {
                                Some([0u8; N])
                            } else {
                                Some(status.get_chunk(idx as usize))
                            }
                        } else {
                            None
                        }
                    },
                );
            }
            if split_idx < layout.prefix.len() {
                unfolded_prefix_peaks.reserve(layout.prefix.len() - split_idx);
                for (_, digest) in &prefix_digests[split_idx..] {
                    unfolded_prefix_peaks.push(*digest);
                }
            }
        }

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
            pre_prefix_acc,
            unfolded_prefix_peaks,
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
        let proof = Self::new(hasher, status, storage, start_loc..end_loc, ops_root).await?;

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
        if self.proof.inactive_peaks != 0 {
            debug!("verification failed, current proofs must use full-forward ops roots");
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
        let verifier = grafting::Verifier::<F, H>::new(grafting_height, start_chunk, chunk_vec);

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
            if self.pre_prefix_acc.is_some() || !self.unfolded_prefix_peaks.is_empty() {
                debug!("verification failed, unexpected grafted prefix metadata");
                return false;
            }
            match self
                .proof
                .reconstruct_root(&verifier, &elements, start_loc, 0)
            {
                Ok(root) => root,
                Err(error) => {
                    debug!(?error, "invalid proof input");
                    return false;
                }
            }
        } else {
            let mut collected = Vec::new();
            if let Err(error) = self.proof.reconstruct_root_inner(
                &verifier,
                &elements,
                start_loc,
                Some(&mut collected),
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
        loc: Location<F>,
        ops_root: D,
    ) -> Result<Self, Error<F>> {
        // Reject locations in pruned bitmap chunks.
        if BitMap::<N>::to_chunk_index(*loc) < status.pruned_chunks() {
            return Err(Error::OperationPruned(loc));
        }
        let range_proof = RangeProof::new(hasher, status, storage, loc..loc + 1, ops_root).await?;
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
        mmr::StandardHasher,
        qmdb::current::{db, grafting},
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
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

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
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
            let mut leaf_digests =
                db::compute_grafted_leaves::<F, Sha256, N>(&hasher, &ops, chunk_inputs, None)
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
                &hasher, &status, &storage, None, &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(BitMap::<N>::CHUNK_SIZE_BITS + 4);
            let mut proof_hasher = Sha256::new();
            let proof =
                RangeProof::new(&mut proof_hasher, &status, &storage, loc..loc + 1, ops_root)
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

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
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
            let mut leaf_digests =
                db::compute_grafted_leaves::<F, Sha256, N>(&hasher, &ops, chunk_inputs, None)
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
                &hasher, &status, &storage, partial, &ops_root,
            )
            .await
            .unwrap();

            let mut proof_hasher = Sha256::new();
            let proof =
                RangeProof::new(&mut proof_hasher, &status, &storage, loc..loc + 1, ops_root)
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

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
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
            let mut leaf_digests =
                db::compute_grafted_leaves::<F, Sha256, N>(&hasher, &ops, chunk_inputs, None)
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
                &hasher, &status, &storage, partial, &ops_root,
            )
            .await
            .unwrap();

            let leaves_loc = mmb::Location::new(leaf_count);
            let mut proof_hasher = Sha256::new();
            let proof = RangeProof::new(
                &mut proof_hasher,
                &status,
                &storage,
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

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
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
            let mut leaf_digests =
                db::compute_grafted_leaves::<F, Sha256, N>(&hasher, &ops, chunk_inputs, None)
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
                &hasher, &status, &storage, None, &ops_root,
            )
            .await
            .unwrap();

            let loc = mmb::Location::new(0);
            let mut proof_hasher = Sha256::new();
            let mut proof =
                RangeProof::new(&mut proof_hasher, &status, &storage, loc..loc + 1, ops_root)
                    .await
                    .unwrap();

            let element = hasher.digest(&(*loc).to_be_bytes());
            let chunk = <BitMap<N> as BitmapReadable<N>>::get_chunk(&status, 0);

            let mut tampered = proof.clone();
            tampered.pre_prefix_acc = Some(hasher.digest(b"fake prefix"));
            let mut verify_hasher = Sha256::new();
            assert!(!tampered.verify(&mut verify_hasher, loc, &[element], &[chunk], &root,));

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
    fn test_range_proof_uses_canonical_mmb_prefix_unfolding() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc, layout, split_idx, _complete_chunks) = (chunk_bits * 3..=128u64)
                .filter(|leaves| leaves % chunk_bits == 0)
                .find_map(|leaves| {
                    let leaves_loc = mmb::Location::new(leaves);
                    let complete_chunks = leaves / chunk_bits;
                    (0..leaves).find_map(|idx| {
                        let loc = mmb::Location::new(idx);
                        let start_chunk = *loc / chunk_bits;
                        let layout = peak_layout(leaves_loc, loc..loc + 1).ok()?;
                        let split_idx = unfolding_start_idx(
                            &layout.prefix,
                            grafting_height,
                            start_chunk,
                            complete_chunks,
                        )?;
                        (split_idx > 0 && split_idx < layout.prefix.len()).then_some((
                            leaves,
                            loc,
                            layout,
                            split_idx,
                            complete_chunks,
                        ))
                    })
                })
                .expect("expected an MMB proof with a partially unfolded prefix");

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
            let mut leaf_digests =
                db::compute_grafted_leaves::<F, Sha256, N>(&hasher, &ops, chunk_inputs, None)
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
                &hasher, &status, &storage, None, &ops_root,
            )
            .await
            .unwrap();

            let mut proof_hasher = Sha256::new();
            let proof =
                RangeProof::new(&mut proof_hasher, &status, &storage, loc..loc + 1, ops_root)
                    .await
                    .unwrap();

            // Under the family's ForwardFold bagging, the prefix peaks before the multi-peak
            // chunk that straddles the range are folded into `pre_prefix_acc`. Only the
            // straddling chunk's prefix peaks ship individually as `unfolded_prefix_peaks` so the
            // verifier can re-graft.
            let expected_unfolded_len = layout.prefix[split_idx..].len();
            assert_eq!(proof.unfolded_prefix_peaks.len(), expected_unfolded_len);
            assert!(!proof.unfolded_prefix_peaks.is_empty());
            assert!(proof.pre_prefix_acc.is_some());

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
        });
    }
}

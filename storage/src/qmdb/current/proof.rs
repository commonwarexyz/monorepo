//! Proof types for [crate::qmdb::current] authenticated databases.
//!
//! This module provides:
//! - [RangeProof]: Proves a range of operations exist in the database.
//! - [OperationProof]: Proves a specific operation is active in the database.

use crate::{
    journal::contiguous::{Contiguous, Reader as _},
    merkle::{self, hasher::Hasher as _, storage::Storage, Family, Location, Position, Proof},
    qmdb::{current::grafting, Error},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use core::ops::Range;
use futures::future::try_join_all;
use std::{collections::BTreeMap, num::NonZeroU64};
use tracing::debug;

struct PeakLayout<F: Family> {
    prefix: Vec<(Position<F>, u32)>,
    range: Vec<(Position<F>, u32)>,
    after: Vec<(Position<F>, u32)>,
}

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

fn chunk_needs_grafted_fold<F: merkle::Graftable>(
    size: Position<F>,
    chunk_idx: u64,
    grafting_height: u32,
    complete_chunks: u64,
) -> bool {
    chunk_idx < complete_chunks && F::chunk_peaks(size, chunk_idx, grafting_height).count() > 1
}

fn unfolding_start_idx<F: merkle::Graftable>(
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

fn proof_needs_grafted_peak_fold<F: merkle::Graftable>(
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

fn prefix_leaf_end<F: Family>(prefix_peaks: &[(Position<F>, u32)]) -> u64 {
    prefix_peaks
        .iter()
        .fold(0u64, |acc, (_, height)| acc + (1u64 << *height))
}

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
//
// Security Note on Trust Boundaries:
// The `pre_prefix_acc` and `unfolded_prefix_peaks` supplied by the Prover are natively untrusted.
// However, they are NOT authenticated against `_proof.digests` (e.g. `_proof.digests[0]`) because:
//
// 1. In the grafted path, the generic root returned by `reconstruct_root_collecting` is discarded
//    and NEVER authenticated against the canonical `expected_root`. Therefore, `_proof.digests[0]`
//    is equally untrusted.
// 2. The *only* trust anchor in verification is the final equivalence mathematical check:
//    `reconstructed_grafted_root == expected_root`.
//
// If a malicious prover attempts to tamper with `pre_prefix_acc` or `unfolded_prefix_peaks`
// independently of the elements/proof, they are fundamentally forced to find a pre-image/collision
// for `expected_root` (the canonical DB root) in order for the forged prefix to be accepted by
// the Verifier. Since SHA-256 collision resistance holds, no intermediate sequential validation is
// required to safely guarantee the rigorous integrity of the prefix materials.
fn reconstruct_grafted_root<F: merkle::Graftable, H: CHasher, C: AsRef<[u8]>>(
    std_hasher: &merkle::hasher::Standard<H>,
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
        std_hasher,
        initial_acc,
        start_leaf,
        peaks,
        grafting_height,
        get_chunk,
    );
    Some(acc.map_or_else(
        || std_hasher.digest(&(*leaves).to_be_bytes()),
        |acc| std_hasher.hash([(*leaves).to_be_bytes().as_slice(), acc.as_ref()]),
    ))
}

/// A proof that a range of operations exist in the database.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RangeProof<F: Family, D: Digest> {
    /// The MMR digest material required to verify the proof.
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

impl<F: merkle::Graftable, D: Digest> RangeProof<F, D> {
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
        let proof = merkle::verification::range_proof(&std_hasher, storage, range).await?;
        let layout = peak_layout(proof.leaves, range_for_layout)?;
        let grafting_height = grafting::height::<N>();

        let split_idx_opt = unfolding_start_idx(
            &layout.prefix,
            grafting_height,
            start_chunk,
            complete_chunks,
        );
        let split_idx = split_idx_opt.unwrap_or(layout.prefix.len());
        let mut pre_prefix_acc: Option<D> = None;
        let mut unfolded_prefix_peaks = Vec::new();
        if split_idx > 0 {
            let mut prefix_peaks = Vec::with_capacity(split_idx);
            for (pos, height) in &layout.prefix[..split_idx] {
                let digest = storage
                    .get_node(*pos)
                    .await?
                    .ok_or(merkle::Error::<F>::MissingNode(*pos))?;
                prefix_peaks.push((*height, digest));
            }
            pre_prefix_acc = grafting::fold_grafted_peaks::<F, D, _, _>(
                &std_hasher,
                None,
                0,
                prefix_peaks,
                grafting_height,
                |idx| {
                    if idx < complete_chunks {
                        Some(status.get_chunk(idx as usize))
                    } else {
                        None
                    }
                },
            );
        }
        if split_idx < layout.prefix.len() {
            unfolded_prefix_peaks.reserve(layout.prefix.len() - split_idx);
            for (pos, _) in &layout.prefix[split_idx..] {
                let digest = storage
                    .get_node(*pos)
                    .await?
                    .ok_or(merkle::Error::<F>::MissingNode(*pos))?;
                unfolded_prefix_peaks.push(digest);
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
    /// Returns [`crate::merkle::Error::LocationOverflow`] if `start_loc` > [crate::merkle::Family::MAX_LEAVES].
    /// Returns [`crate::merkle::Error::RangeOutOfBounds`] if `start_loc` >= number of leaves in the MMR.
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
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let reader = log.reader().await;
        let futures = (*start_loc..*end_loc)
            .map(|i| reader.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        // Gather the chunks necessary to verify the proof.
        let end = (*end_loc - 1) / chunk_bits; // chunk that contains the last bit
        let mut chunks = Vec::with_capacity((end - start + 1) as usize);
        for i in start..=end {
            chunks.push(status.get_chunk(i as usize));
        }

        Ok((proof, ops, chunks))
    }
}

impl<F: merkle::Graftable, D: Digest> RangeProof<F, D> {
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
        let start = *start_loc / chunk_bits; // chunk that contains first bit
        let end = (*end_loc.saturating_sub(1)) / chunk_bits; // chunk that contains the last bit
        let expected = end - start + 1;
        let actual = chunks.len() as u64;
        if expected != actual {
            debug!(expected, actual, "verification failed, chunk mismatch");
            return false;
        }

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        let chunk_vec = chunks.iter().map(|c| c.as_ref()).collect::<Vec<_>>();
        let start_chunk_idx = *start_loc / BitMap::<N>::CHUNK_SIZE_BITS;
        let verifier =
            grafting::Verifier::<F, H>::new(grafting::height::<N>(), start_chunk_idx, chunk_vec);
        let grafting_height = grafting::height::<N>();
        let next_bit = *leaves % BitMap::<N>::CHUNK_SIZE_BITS;
        let has_partial_chunk = next_bit != 0;

        // For partial chunks, validate the last chunk digest from the proof.
        if has_partial_chunk {
            let Some(last_chunk_digest) = self.partial_chunk_digest else {
                debug!("proof has no partial chunk digest");
                return false;
            };

            // If the proof covers an operation in the partial chunk, verify that the
            // chunk provided by the caller matches the digest embedded in the proof.
            if *(end_loc - 1) / BitMap::<N>::CHUNK_SIZE_BITS
                == *leaves / BitMap::<N>::CHUNK_SIZE_BITS
            {
                let Some(last_chunk) = chunks.last() else {
                    debug!("chunks is empty");
                    return false;
                };
                let expected_last_chunk_digest = verifier.digest(last_chunk);
                if last_chunk_digest != expected_last_chunk_digest {
                    debug!("last chunk digest does not match expected value");
                    return false;
                }
            }
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
        let complete_chunks = *leaves / BitMap::<N>::CHUNK_SIZE_BITS;
        let needs_grafted_peak_fold =
            proof_needs_grafted_peak_fold(&layout, size, grafting_height, complete_chunks);

        let mmr_root = if !needs_grafted_peak_fold {
            match self.proof.reconstruct_root(&verifier, &elements, start_loc) {
                Ok(root) => root,
                Err(error) => {
                    debug!(?error, "invalid proof input");
                    return false;
                }
            }
        } else {
            let mut collected = Vec::new();
            if let Err(error) = self.proof.reconstruct_root_collecting(
                &verifier,
                &elements,
                start_loc,
                Some(&mut collected),
            ) {
                debug!(?error, "invalid proof input");
                return false;
            }

            let collected: BTreeMap<Position<F>, D> = collected.into_iter().collect();
            let std_hasher = merkle::hasher::Standard::<H>::new();
            let get_chunk = |chunk_idx: u64| -> Option<&[u8]> {
                if chunk_idx >= complete_chunks {
                    return None;
                }
                chunk_idx
                    .checked_sub(start_chunk_idx)
                    .filter(|&idx| idx < chunks.len() as u64)
                    .map(|idx| chunks[idx as usize].as_ref())
            };
            let Some(root) = reconstruct_grafted_root(
                &std_hasher,
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
        hasher.update(&mmr_root);
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

impl<F: merkle::Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
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

impl<F: merkle::Graftable, D: Digest, const N: usize> OperationProof<F, D, N> {
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
        merkle::{conformance::build_test_mem, Graftable as _},
        mmb,
        mmr::StandardHasher,
        qmdb::current::{db, grafting},
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};

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
                    F::chunk_peaks(size, 1, grafting_height).count() > 1
                })
                .expect("expected an MMB size whose second chunk spans multiple peaks");

            let mut status = BitMap::<N>::new();
            for _ in 0..leaf_count {
                status.push(true);
            }
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
            let ops_root = *ops.root();

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
            let mut grafted = merkle::mem::Mem::<F, sha256::Digest>::new(&grafted_hasher);
            let changeset = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted_hasher).finalize()
            };
            grafted.apply(changeset).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops);
            let root = db::compute_db_root::<F, Sha256, _, _, _, N>(
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
                    if F::chunk_peaks(size, 1, grafting_height).count() <= 1 {
                        return None;
                    }

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
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
            let ops_root = *ops.root();

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
            let mut grafted = merkle::mem::Mem::<F, sha256::Digest>::new(&grafted_hasher);
            let changeset = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted_hasher).finalize()
            };
            grafted.apply(changeset).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops);
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, _, N>(
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
                    if F::chunk_peaks(size, 1, grafting_height).count() <= 1 {
                        return None;
                    }

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
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
            let ops_root = *ops.root();

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
            let mut grafted = merkle::mem::Mem::<F, sha256::Digest>::new(&grafted_hasher);
            let changeset = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted_hasher).finalize()
            };
            grafted.apply(changeset).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops);
            let partial = {
                let (chunk, next_bit) = status.last_chunk();
                Some((*chunk, next_bit))
            };
            let root = db::compute_db_root::<F, Sha256, _, _, _, N>(
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
    fn test_range_proof_uses_compact_mmb_prefix_unfolding() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;
            const N: usize = 1;

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
            let grafting_height = grafting::height::<N>();
            let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;

            let (leaf_count, loc, layout, split_idx, complete_chunks) = (chunk_bits * 3..=128u64)
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
            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
            let ops_root = *ops.root();

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
            let mut grafted = merkle::mem::Mem::<F, sha256::Digest>::new(&grafted_hasher);
            let changeset = {
                let mut batch = grafted.new_batch();
                for (_, digest) in leaf_digests {
                    batch = batch.add_leaf_digest(digest);
                }
                batch.merkleize(&grafted_hasher).finalize()
            };
            grafted.apply(changeset).unwrap();

            let storage = grafting::Storage::new(&grafted, grafting_height, &ops);
            let root = db::compute_db_root::<F, Sha256, _, _, _, N>(
                &hasher, &status, &storage, None, &ops_root,
            )
            .await
            .unwrap();

            let mut proof_hasher = Sha256::new();
            let proof =
                RangeProof::new(&mut proof_hasher, &status, &storage, loc..loc + 1, ops_root)
                    .await
                    .unwrap();

            assert_eq!(
                proof.unfolded_prefix_peaks.len(),
                layout.prefix.len() - split_idx
            );
            assert!(!proof.unfolded_prefix_peaks.is_empty());
            assert!(proof.unfolded_prefix_peaks.len() < layout.prefix.len());
            assert!(proof.pre_prefix_acc.is_some());

            let mut prefix_peaks = Vec::with_capacity(split_idx);
            for (pos, height) in &layout.prefix[..split_idx] {
                let digest = storage
                    .get_node(*pos)
                    .await
                    .unwrap()
                    .expect("prefix peak must exist");
                prefix_peaks.push((*height, digest));
            }
            let expected_pre_prefix_acc = grafting::fold_grafted_peaks::<F, sha256::Digest, _, _>(
                &hasher,
                None,
                0,
                prefix_peaks,
                grafting_height,
                |idx| {
                    if idx < complete_chunks {
                        Some(<BitMap<N> as BitmapReadable<N>>::get_chunk(
                            &status,
                            idx as usize,
                        ))
                    } else {
                        None
                    }
                },
            );
            assert_eq!(proof.pre_prefix_acc, expected_pre_prefix_acc);

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
        });
    }
}

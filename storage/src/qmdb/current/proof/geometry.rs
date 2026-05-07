//! Geometry helpers for range proofs over grafted current trees.
//!
//! The proof format starts from ops-tree peaks, but the current root commits to bitmap chunks
//! grafted onto those ops-tree digests. This module keeps track of where the proven operation range
//! falls among the ops-tree peaks and which boundary peaks must stay unfolded so verification can
//! regroup them by complete grafted chunk.

use crate::merkle::{self, Family, Graftable, Location, Position};
use core::ops::Range;

/// An inventory of current ops-tree peaks, paired with their heights, from oldest to youngest
/// relative to the bounds of a range proof. Every peak is assigned to exactly one of three
/// sequential layout regions: before the operation range, overlapping the operation range, or
/// after the operation range.
struct PeakLayout<F: Family> {
    /// Ops-tree peaks whose leaves all precede the operation range's starting location.
    prefix: Vec<(Position<F>, u32)>,
    /// Ops-tree peaks whose leaves intersect the operation range.
    range: Vec<(Position<F>, u32)>,
    /// Ops-tree peaks whose leaves all follow the operation range's ending location.
    after: Vec<(Position<F>, u32)>,
}

/// Return the number of leaves covered by `peaks`.
pub(super) fn covered_leaves<F: Family>(peaks: &[(Position<F>, u32)]) -> u64 {
    peaks
        .iter()
        .fold(0u64, |acc, (_pos, height)| acc + (1u64 << *height))
}

impl<F: Family> PeakLayout<F> {
    /// Bucket an ops tree's current peaks into prefix, range, and after sub-vectors.
    fn new(leaves: Location<F>, range: Range<Location<F>>) -> Result<Self, merkle::Error<F>> {
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

        Ok(Self {
            prefix,
            range: range_peaks,
            after,
        })
    }

    fn iter(&self) -> impl Iterator<Item = &(Position<F>, u32)> {
        self.prefix
            .iter()
            .chain(self.range.iter())
            .chain(self.after.iter())
    }

    const fn total_peaks(&self) -> usize {
        self.prefix.len() + self.range.len() + self.after.len()
    }
}

/// Merkle-family geometry for building or verifying a range proof. This collects the proven
/// operation range, the ops-tree peak layout around that range, the inactive peak prefix, and the
/// bitmap chunks touched by the range.
pub(super) struct RangeProofGeometry<F: Graftable> {
    leaves: Location<F>,
    range: Range<Location<F>>,
    layout: PeakLayout<F>,
    inactive_peaks: usize,
    start_chunk: u64,
    end_chunk: u64,
    grafting_height: u32,
    complete_chunks: u64,
}

impl<F: Graftable> RangeProofGeometry<F> {
    pub(super) fn new(
        leaves: Location<F>,
        range: Range<Location<F>>,
        inactive_peaks: usize,
        grafting_height: u32,
        complete_chunks: u64,
    ) -> Result<Self, merkle::Error<F>> {
        let layout = PeakLayout::new(leaves, range.clone())?;
        let end_loc = range.end.checked_sub(1).expect("range is non-empty");
        let start_chunk = *range.start >> grafting_height;
        let end_chunk = *end_loc >> grafting_height;

        Ok(Self {
            leaves,
            range,
            layout,
            inactive_peaks,
            start_chunk,
            end_chunk,
            grafting_height,
            complete_chunks,
        })
    }

    pub(super) const fn leaves(&self) -> Location<F> {
        self.leaves
    }

    pub(super) fn range(&self) -> Range<Location<F>> {
        self.range.clone()
    }

    pub(super) const fn inactive_peaks(&self) -> usize {
        self.inactive_peaks
    }

    pub(super) const fn grafting_height(&self) -> u32 {
        self.grafting_height
    }

    pub(super) fn prefix_peaks(&self) -> &[(Position<F>, u32)] {
        &self.layout.prefix
    }

    pub(super) fn range_peaks(&self) -> &[(Position<F>, u32)] {
        &self.layout.range
    }

    pub(super) fn after_peaks(&self) -> &[(Position<F>, u32)] {
        &self.layout.after
    }

    pub(super) const fn total_peaks(&self) -> usize {
        self.layout.total_peaks()
    }

    /// Return how many input ops-tree peaks each unfolded witness digest covers.
    ///
    /// `peaks` is a contiguous slice from one [`PeakLayout`] region, in left-to-right leaf order.
    /// Each returned count corresponds to one digest in the unfolded prefix/suffix witness. Most
    /// ops-tree peaks stay one-for-one and produce count `1`.
    ///
    /// Adjacent sub-grafting-height peaks are grouped when they belong to the same complete bitmap
    /// chunk. `complete_chunks` is the number of grafted-tree leaves, so chunk indexes at or above
    /// this boundary are incomplete and cannot be grouped here.
    ///
    /// For example, if `p1` and `p2` are adjacent sub-grafting-height peaks in complete chunk `7`,
    /// input peaks `[p0, p1, p2, p3]` produce counts `[1, 2, 1]`. If chunk `7` is incomplete,
    /// the same input produces `[1, 1, 1, 1]`.
    ///
    /// For MMRs this always returns one `1` per input peak. The grouping only matters for families
    /// such as MMB, where a complete chunk can be represented by multiple smaller ops-tree peaks.
    pub(super) fn witness_peak_counts(
        &self,
        peaks: &[(Position<F>, u32)],
        start_leaf: u64,
    ) -> Vec<usize> {
        let mut leaf_cursor = start_leaf;
        let mut counts = Vec::with_capacity(peaks.len());
        let mut current_chunk = None;

        for (_pos, height) in peaks {
            let peak_start = leaf_cursor;
            leaf_cursor += 1u64 << *height;

            let chunk_idx = peak_start >> self.grafting_height;
            if *height < self.grafting_height && chunk_idx < self.complete_chunks {
                if current_chunk == Some(chunk_idx) {
                    *counts.last_mut().unwrap() += 1;
                } else {
                    counts.push(1);
                    current_chunk = Some(chunk_idx);
                }
            } else {
                counts.push(1);
                current_chunk = None;
            }
        }

        counts
    }

    /// First leaf covered by the peaks that follow the proven operation range.
    pub(super) fn after_start(&self) -> u64 {
        covered_leaves(&self.layout.prefix) + covered_leaves(&self.layout.range)
    }

    /// Index in `layout.prefix` where prefix peaks stop being pre-grouped as grafted witnesses.
    ///
    /// Prefix peaks before this index are fully before the range's first bitmap chunk and can stay
    /// in grafted form. Peaks at or after this index may share a complete grafted chunk with the
    /// proven range, so reconstruction needs their ops-tree digests.
    pub(super) fn prefix_regroup_start(&self) -> usize {
        let chunk_start = self.start_chunk << self.grafting_height;
        let mut leaf_cursor = 0u64;
        for (idx, (_pos, height)) in self.layout.prefix.iter().enumerate() {
            leaf_cursor += 1u64 << *height;
            if leaf_cursor > chunk_start {
                return idx;
            }
        }
        self.layout.prefix.len()
    }

    /// Index in `layout.after` where after peaks start being pre-grouped as grafted witnesses.
    ///
    /// After peaks before this index may share a complete grafted chunk with the proven range, so
    /// reconstruction needs their ops-tree digests. Peaks at or after this index are fully after
    /// the range's last bitmap chunk and can stay in grafted form.
    pub(super) fn after_regroup_end(&self) -> usize {
        let chunk_end = (self.end_chunk + 1) << self.grafting_height;
        let mut leaf_cursor = self.after_start();
        for (idx, (_pos, height)) in self.layout.after.iter().enumerate() {
            if leaf_cursor >= chunk_end {
                return idx;
            }
            leaf_cursor += 1u64 << *height;
        }
        self.layout.after.len()
    }

    /// Return true when a generic range proof would hide boundary peaks needed for grafting.
    ///
    /// This happens when some ops-tree peak is smaller than a grafted chunk and belongs to a
    /// complete bitmap chunk represented by multiple ops-tree peaks. In that case the proof must
    /// include unfolded prefix/suffix peak digests so verification can regroup the complete chunk
    /// correctly.
    pub(super) fn needs_unfolded_boundary_peaks(&self) -> Result<bool, merkle::Error<F>> {
        let size = Position::<F>::try_from(self.leaves)?;
        let mut leaf_cursor = 0u64;

        Ok(self.layout.iter().any(|(_pos, height)| {
            let peak_start = leaf_cursor;
            leaf_cursor += 1u64 << *height;

            *height < self.grafting_height
                && self.has_multiple_ops_peaks(size, peak_start >> self.grafting_height)
        }))
    }

    /// Return true when `chunk_idx` is complete and spans more than one ops-tree peak.
    fn has_multiple_ops_peaks(&self, size: Position<F>, chunk_idx: u64) -> bool {
        chunk_idx < self.complete_chunks
            && F::chunk_peaks(size, chunk_idx, self.grafting_height)
                .nth(1)
                .is_some()
    }
}

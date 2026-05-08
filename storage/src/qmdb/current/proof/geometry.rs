//! Geometry for current range proofs.
//!
//! Current proofs combine two views of the operation log. The range proof is collected from the ops
//! tree, while the current root commits to activity bitmap chunks grafted onto that tree. This
//! module records how the requested operation range lines up with the ops-tree peaks so proof
//! generation and verification can translate between those two views.
//!
//! For MMR, each bitmap chunk corresponds to one ops-tree peak, so this translation is one-for-one.
//! For MMB-like families, one bitmap chunk can span multiple sub-grafting-height ops-tree peaks.
//! If the requested range covers only part of such a chunk, the ops-tree range proof may fold
//! the out-of-range peaks into its prefix or suffix witnesses. This module identifies those peaks so
//! the proof can carry their digests explicitly and verification can rebuild the bitmap chunk root.
//!
//! The grafting view splits the ops-tree peaks into five ordered segments:
//! pure prefix, prefix boundary, range, suffix boundary, and pure suffix. The pure prefix/suffix
//! segments are already grouped as bitmap chunk witnesses. The boundary segments stay as individual
//! ops-tree digests because they may need to be combined with the range segment to reconstruct a
//! bitmap chunk.

use crate::merkle::{self, Family, Graftable, Location, Position};
use core::ops::Range;

/// A contiguous segment of ops-tree peaks, along with the first leaf covered by the segment.
pub(super) struct PeakSegment<F: Family> {
    peaks: Vec<(Position<F>, u32)>,
    start_leaf: u64,
}

impl<F: Family> PeakSegment<F> {
    pub(super) const fn len(&self) -> usize {
        self.peaks.len()
    }

    pub(super) const fn start_leaf(&self) -> u64 {
        self.start_leaf
    }

    pub(super) fn positions(&self) -> impl Iterator<Item = Position<F>> + '_ {
        self.peaks.iter().map(|&(pos, _height)| pos)
    }

    pub(super) fn heights_with_digests<'a, D: Copy>(
        &'a self,
        digests: &'a [D],
    ) -> impl Iterator<Item = (u32, D)> + 'a {
        self.peaks
            .iter()
            .map(|(_pos, height)| *height)
            .zip(digests.iter().copied())
    }

    fn peak_starts_with_heights(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        let mut leaf_cursor = self.start_leaf;
        self.peaks.iter().map(move |(_pos, height)| {
            let peak_start = leaf_cursor;
            leaf_cursor += 1u64 << *height;
            (peak_start, *height)
        })
    }
}

/// Return the number of leaves covered by `peaks`.
fn covered_leaves<F: Family>(peaks: &[(Position<F>, u32)]) -> u64 {
    peaks
        .iter()
        .fold(0u64, |acc, (_pos, height)| acc + (1u64 << *height))
}

/// Grafting-aware geometry for building or verifying a current range proof.
pub(super) struct RangeProofGeometry<F: Graftable> {
    leaves: Location<F>,
    range: Range<Location<F>>,
    pure_prefix: PeakSegment<F>,
    prefix_boundary: PeakSegment<F>,
    range_peaks: PeakSegment<F>,
    suffix_boundary: PeakSegment<F>,
    pure_suffix: PeakSegment<F>,
    inactive_peaks: usize,
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
        if range.is_empty() {
            return Err(merkle::Error::Empty);
        }
        let end_loc = range.end.checked_sub(1).expect("range is non-empty");
        if end_loc >= leaves {
            return Err(merkle::Error::RangeOutOfBounds(range.end));
        }

        let size = Position::<F>::try_from(leaves)?;
        let mut prefix_peaks = Vec::new();
        let mut range_peaks = Vec::new();
        let mut after_peaks = Vec::new();
        let mut leaf_cursor = 0u64;

        for (peak_pos, height) in F::peaks(size) {
            let leaf_end = leaf_cursor + (1u64 << height);
            if leaf_end <= *range.start {
                prefix_peaks.push((peak_pos, height));
            } else if leaf_cursor >= *range.end {
                after_peaks.push((peak_pos, height));
            } else {
                range_peaks.push((peak_pos, height));
            }
            leaf_cursor = leaf_end;
        }

        let start_chunk = *range.start >> grafting_height;
        let end_chunk = *end_loc >> grafting_height;
        let prefix_boundary_start =
            Self::prefix_boundary_start(&prefix_peaks, start_chunk, grafting_height);
        let range_start_leaf = covered_leaves(&prefix_peaks);
        let suffix_boundary_start_leaf = range_start_leaf + covered_leaves(&range_peaks);
        let suffix_boundary_end = Self::suffix_boundary_end(
            &after_peaks,
            suffix_boundary_start_leaf,
            end_chunk,
            grafting_height,
        );

        let prefix_boundary_start_leaf = covered_leaves(&prefix_peaks[..prefix_boundary_start]);
        let pure_suffix_start_leaf =
            suffix_boundary_start_leaf + covered_leaves(&after_peaks[..suffix_boundary_end]);
        let prefix_boundary = prefix_peaks.split_off(prefix_boundary_start);
        let pure_prefix = prefix_peaks;
        let pure_suffix = after_peaks.split_off(suffix_boundary_end);
        let suffix_boundary = after_peaks;

        Ok(Self {
            leaves,
            range,
            pure_prefix: PeakSegment {
                peaks: pure_prefix,
                start_leaf: 0,
            },
            prefix_boundary: PeakSegment {
                peaks: prefix_boundary,
                start_leaf: prefix_boundary_start_leaf,
            },
            range_peaks: PeakSegment {
                peaks: range_peaks,
                start_leaf: range_start_leaf,
            },
            suffix_boundary: PeakSegment {
                peaks: suffix_boundary,
                start_leaf: suffix_boundary_start_leaf,
            },
            pure_suffix: PeakSegment {
                peaks: pure_suffix,
                start_leaf: pure_suffix_start_leaf,
            },
            inactive_peaks,
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

    /// Peaks fully before the first bitmap chunk touched by the range.
    pub(super) const fn pure_prefix(&self) -> &PeakSegment<F> {
        &self.pure_prefix
    }

    /// Prefix peaks that may share a bitmap chunk with the range.
    pub(super) const fn prefix_boundary(&self) -> &PeakSegment<F> {
        &self.prefix_boundary
    }

    /// Peaks intersecting the proven operation range.
    pub(super) const fn range_peaks(&self) -> &PeakSegment<F> {
        &self.range_peaks
    }

    /// After peaks that may share a bitmap chunk with the range.
    pub(super) const fn suffix_boundary(&self) -> &PeakSegment<F> {
        &self.suffix_boundary
    }

    /// Peaks fully after the last bitmap chunk touched by the range.
    pub(super) const fn pure_suffix(&self) -> &PeakSegment<F> {
        &self.pure_suffix
    }

    pub(super) const fn total_peaks(&self) -> usize {
        self.pure_prefix.len()
            + self.prefix_boundary.len()
            + self.range_peaks.len()
            + self.suffix_boundary.len()
            + self.pure_suffix.len()
    }

    /// Positions of all peaks before the range, in proof witness order.
    pub(super) fn prefix_positions(&self) -> impl Iterator<Item = Position<F>> + '_ {
        self.pure_prefix
            .positions()
            .chain(self.prefix_boundary.positions())
    }

    /// Positions of all peaks after the range, in proof witness order.
    pub(super) fn after_positions(&self) -> impl Iterator<Item = Position<F>> + '_ {
        self.suffix_boundary
            .positions()
            .chain(self.pure_suffix.positions())
    }

    pub(super) fn prefix_witness_len(&self) -> usize {
        self.bitmap_witness_counts(&self.pure_prefix).len() + self.prefix_boundary.len()
    }

    pub(super) fn suffix_witness_len(&self) -> usize {
        self.suffix_boundary.len() + self.bitmap_witness_counts(&self.pure_suffix).len()
    }

    /// Split prefix witnesses into bitmap witnesses for the pure prefix and ops-tree digests for
    /// the prefix boundary.
    pub(super) fn split_prefix_witnesses<'a, D>(
        &self,
        witnesses: &'a [D],
    ) -> Option<(Vec<usize>, &'a [D], &'a [D])> {
        let counts = self.bitmap_witness_counts(&self.pure_prefix);
        let expected_len = counts.len() + self.prefix_boundary.len();
        debug_assert_eq!(expected_len, self.prefix_witness_len());
        if witnesses.len() != expected_len {
            return None;
        }
        let (bitmap_witnesses, boundary_digests) = witnesses.split_at(counts.len());
        Some((counts, bitmap_witnesses, boundary_digests))
    }

    /// Split suffix witnesses into ops-tree digests for the suffix boundary and bitmap witnesses
    /// for the pure suffix.
    pub(super) fn split_suffix_witnesses<'a, D>(
        &self,
        witnesses: &'a [D],
    ) -> Option<(&'a [D], &'a [D], Vec<usize>)> {
        let counts = self.bitmap_witness_counts(&self.pure_suffix);
        let expected_len = self.suffix_boundary.len() + counts.len();
        debug_assert_eq!(expected_len, self.suffix_witness_len());
        if witnesses.len() != expected_len {
            return None;
        }
        let (boundary_digests, bitmap_witnesses) = witnesses.split_at(self.suffix_boundary.len());
        Some((boundary_digests, bitmap_witnesses, counts))
    }

    /// Return how many input ops-tree peaks each already-grouped witness digest covers.
    ///
    /// `segment` should be the pure prefix or pure suffix segment. Each returned count corresponds
    /// to one bitmap chunk witness digest. Most ops-tree peaks stay one-for-one and produce
    /// count `1`.
    ///
    /// Adjacent sub-grafting-height peaks are grouped when they belong to the same complete bitmap
    /// chunk. Peaks in a trailing partial chunk, which can appear in the pure suffix, stay
    /// one-for-one because that chunk is not part of the grafted bitmap root yet.
    ///
    /// For example, if `p1` and `p2` are adjacent sub-grafting-height peaks covered by chunk `7`,
    /// input peaks `[p0, p1, p2, p3]` produce counts `[1, 2, 1]`.
    ///
    /// For MMRs this always returns one `1` per input peak. The grouping only matters for families
    /// such as MMB, where a chunk can be represented by multiple
    /// sub-grafting-height ops-tree peaks.
    fn bitmap_witness_counts(&self, segment: &PeakSegment<F>) -> Vec<usize> {
        let mut counts = Vec::with_capacity(segment.peaks.len());
        let mut current_chunk = None;

        for (peak_start, height) in segment.peak_starts_with_heights() {
            let chunk_idx = peak_start >> self.grafting_height;
            if height < self.grafting_height && chunk_idx < self.complete_chunks {
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

    fn prefix_boundary_start(
        prefix_peaks: &[(Position<F>, u32)],
        start_chunk: u64,
        grafting_height: u32,
    ) -> usize {
        let chunk_start = start_chunk << grafting_height;
        let mut leaf_cursor = 0u64;
        for (idx, (_pos, height)) in prefix_peaks.iter().enumerate() {
            leaf_cursor += 1u64 << *height;
            if leaf_cursor > chunk_start {
                return idx;
            }
        }
        prefix_peaks.len()
    }

    fn suffix_boundary_end(
        after_peaks: &[(Position<F>, u32)],
        after_start_leaf: u64,
        end_chunk: u64,
        grafting_height: u32,
    ) -> usize {
        let chunk_end = (end_chunk + 1) << grafting_height;
        let mut leaf_cursor = after_start_leaf;
        for (idx, (_pos, height)) in after_peaks.iter().enumerate() {
            if leaf_cursor >= chunk_end {
                return idx;
            }
            leaf_cursor += 1u64 << *height;
        }
        after_peaks.len()
    }

    /// Return true when verification needs the grafted reconstruction path.
    pub(super) fn requires_grafted_reconstruction(&self) -> Result<bool, merkle::Error<F>> {
        let size = Position::<F>::try_from(self.leaves)?;

        Ok([
            &self.pure_prefix,
            &self.prefix_boundary,
            &self.range_peaks,
            &self.suffix_boundary,
            &self.pure_suffix,
        ]
        .into_iter()
        .flat_map(|segment| segment.peak_starts_with_heights())
        .any(|(peak_start, height)| {
            if height >= self.grafting_height {
                return false;
            }

            let chunk_idx = peak_start >> self.grafting_height;
            chunk_idx < self.complete_chunks
                && F::chunk_peaks(size, chunk_idx, self.grafting_height)
                    .nth(1)
                    .is_some()
        }))
    }
}

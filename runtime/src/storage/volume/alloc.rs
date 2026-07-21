//! Block-aligned extent allocator for the volume.
//!
//! The allocator is purely in-memory: it is rebuilt at open from the extents
//! referenced by the adopted blob table, so no allocation state is ever
//! persisted and allocator bugs cannot corrupt the volume. Frees are applied
//! by the caller only after the commit that stops referencing an extent
//! completes (see the commit protocol in the module docs), which is what makes
//! rollback to the previous commit safe.

use super::{OrderedMap, BLOCK};

/// A contiguous physical byte range in the volume file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Extent {
    pub offset: u64,
    pub len: u64,
}

/// In-memory free-space index over the volume file.
///
/// Free ranges are kept coalesced. Allocation is first-fit; when no free range
/// is large enough, the volume file is logically extended (the inner blob grows
/// on write, so no explicit resize is required).
pub(super) struct Allocator {
    /// Free ranges keyed by offset. Invariant: non-empty, block-aligned,
    /// non-adjacent (always coalesced), and entirely below `end`.
    /// Aliased so Kani proofs run over the solver-friendly container.
    free: OrderedMap<u64, u64>,
    /// High-water mark: everything at and beyond this offset is free.
    end: u64,
    /// Running total of the bytes in `free` (kept exact by every mutation).
    free_bytes: u64,
}

/// Round `len` up to a whole number of blocks.
pub(super) const fn block_align(len: u64) -> u64 {
    match checked_block_align(len) {
        Some(aligned) => aligned,
        None => panic!("block alignment overflow"),
    }
}

/// Round a potentially hostile length up to whole blocks without overflow.
pub(super) const fn checked_block_align(len: u64) -> Option<u64> {
    len.div_ceil(BLOCK).checked_mul(BLOCK)
}

impl Allocator {
    /// Create an allocator over a volume whose allocated extents are `used`.
    ///
    /// `reserved` is the offset where allocatable space begins (everything
    /// below it — the superblock region — is never handed out). `used` may be
    /// unsorted and empty, but extents must be block-aligned and disjoint.
    pub(super) fn rebuild(reserved: u64, used: impl IntoIterator<Item = Extent>) -> Self {
        let mut extents: Vec<Extent> = used.into_iter().collect();
        extents.sort_by_key(|e| e.offset);

        let mut free = OrderedMap::new();
        let mut free_bytes = 0;
        let mut cursor = reserved;
        for extent in extents {
            assert!(
                extent.offset.is_multiple_of(BLOCK)
                    && extent.len.is_multiple_of(BLOCK)
                    && extent.len > 0,
                "unaligned extent {extent:?}"
            );
            assert!(
                extent.offset >= cursor,
                "overlapping extents at {extent:?} (cursor {cursor})"
            );
            if extent.offset > cursor {
                free.insert(cursor, extent.offset - cursor);
                free_bytes += extent.offset - cursor;
            }
            cursor = extent.offset + extent.len;
        }

        Self {
            free,
            end: cursor,
            free_bytes,
        }
    }

    /// Allocate a block-aligned extent of at least `len` bytes (first-fit).
    pub(super) fn allocate(&mut self, len: u64) -> Extent {
        assert!(len > 0, "zero-length allocation");
        let len = block_align(len);

        // First fit: smallest offset wins to keep the file compact.
        let found = self
            .free
            .iter()
            .find(|(_, &flen)| flen >= len)
            .map(|(&offset, &flen)| (offset, flen));
        if let Some((offset, flen)) = found {
            self.free.remove(&offset);
            if flen > len {
                self.free.insert(offset + len, flen - len);
            }
            self.free_bytes -= len;
            return Extent { offset, len };
        }

        // Extend the file.
        let offset = self.end;
        self.end += len;
        Extent { offset, len }
    }

    /// Return an extent to the free index, coalescing with neighbors.
    ///
    /// Callers must only free extents after no durable superblock references
    /// them (deferred frees are the caller's responsibility).
    pub(super) fn free(&mut self, extent: Extent) {
        assert!(
            extent.offset.is_multiple_of(BLOCK)
                && extent.len.is_multiple_of(BLOCK)
                && extent.len > 0,
            "unaligned free {extent:?}"
        );
        let mut offset = extent.offset;
        let mut len = extent.len;
        assert!(offset + len <= self.end, "free past end {extent:?}");

        // Coalesce with the previous range.
        if let Some((&prev_offset, &prev_len)) = self.free.range(..offset).next_back() {
            assert!(prev_offset + prev_len <= offset, "double free {extent:?}");
            if prev_offset + prev_len == offset {
                self.free.remove(&prev_offset);
                offset = prev_offset;
                len += prev_len;
            }
        }

        // Coalesce with the next range.
        if let Some((&next_offset, &next_len)) = self.free.range(extent.offset..).next() {
            assert!(
                extent.offset + extent.len <= next_offset,
                "double free {extent:?}"
            );
            if extent.offset + extent.len == next_offset {
                self.free.remove(&next_offset);
                len += next_len;
            }
        }

        // A range touching the high-water mark lowers the mark instead of
        // lingering in the index (the file itself is never shrunk). The
        // coalesced neighbors leave the free total with it.
        if offset + len == self.end {
            self.end = offset;
            self.free_bytes -= len - extent.len;
        } else {
            self.free.insert(offset, len);
            self.free_bytes += extent.len;
        }
    }

    /// Offset one past the last allocated byte (the file's high-water mark).
    pub(super) const fn end(&self) -> u64 {
        self.end
    }

    /// Total bytes currently in the free index (excludes everything at and
    /// beyond [`Self::end`]).
    pub(super) const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Whether `extent` intersects any free range or the free tail beyond
    /// [`Self::end`] (tests only). An allocated (referenced) extent must
    /// never overlap free space.
    #[cfg(test)]
    pub(super) fn overlaps_free(&self, extent: Extent) -> bool {
        if extent.offset + extent.len > self.end {
            return true;
        }
        if let Some((&offset, &len)) = self.free.range(..extent.offset + extent.len).next_back() {
            if offset + len > extent.offset {
                return true;
            }
        }
        false
    }

    /// The free ranges, for audit diagnostics (tests only).
    #[cfg(test)]
    pub(super) fn free_ranges(&self) -> Vec<(u64, u64)> {
        self.free.iter().map(|(&o, &l)| (o, l)).collect()
    }

    /// Assert the free index's internal invariants: aligned, non-empty,
    /// coalesced, below the high-water mark, and an exact running total
    /// (tests and Kani proofs only).
    #[cfg(any(test, kani))]
    pub(super) fn audit(&self) {
        let mut total = 0;
        let mut prev_end = 0;
        for (&offset, &len) in &self.free {
            assert!(
                offset.is_multiple_of(BLOCK) && len.is_multiple_of(BLOCK) && len > 0,
                "unaligned free range ({offset}, {len})"
            );
            assert!(offset > prev_end, "uncoalesced free ranges");
            assert!(offset + len < self.end, "free range touches the end");
            prev_end = offset + len;
            total += len;
        }
        assert_eq!(total, self.free_bytes, "free byte total drifted");
    }
}

// Bounded Kani proof harnesses over the real [`Allocator`] (run via
// `just kani-alloc`). Only the generator-and-audit proof ships: the
// mutation harnesses (allocate, free with coalescing and byte
// conservation, rebuild) were built and stop-gated on solver budget —
// allocate and rebuild exceeded uncontended 2400-second gates and free
// a 1500-second gate, with zero failed property checks (formula depth,
// not refutation). Mutation-level allocator coverage remains with the
// volume model and the unit tests.
#[cfg(kani)]
mod verification {
    mod proofs {
        use super::super::{Allocator, OrderedMap, BLOCK};

        /// Free-range bound per symbolic allocator: three ranges give
        /// every relation the audit consults (a strictly lower
        /// neighbor, adjacency on both sides, and a strictly higher
        /// neighbor).
        const ENTRIES: u64 = 3;

        // Unwind bound: 6 covers the three-iteration generator and the
        // audit's scan over at most three free ranges.

        /// Geometry bound, in blocks, for generated free ranges and the
        /// high-water mark. Aligned quantities are generated as small
        /// block counts scaled by BLOCK: full-width byte offsets make
        /// the bit-blasted formula intractable, while whole-block
        /// magnitude adds no behavior — the audit is linear in whole
        /// blocks. Twelve blocks fit three free ranges of one to three
        /// blocks with gaps and slack below the mark, so every
        /// relational shape the audit consults still occurs.
        const MAX_BLOCKS: u64 = 12;

        /// A symbolic allocator with up to [`ENTRIES`] free ranges and a
        /// symbolic high-water mark, assumed into exactly the invariant
        /// [`Allocator::audit`] asserts: ranges non-empty, BLOCK-aligned
        /// (whole-block generation), disjoint and non-adjacent
        /// (coalesced), strictly below `end`, with `free_bytes` their
        /// exact sum. Ranges are generated in ascending order, which
        /// reaches every audit-valid shape of at most ENTRIES ranges
        /// within [`MAX_BLOCKS`]. `end` is additionally BLOCK-aligned:
        /// the audit does not state that, but every mutation preserves
        /// it from a rebuild over aligned extents, and extension
        /// alignment is false without it.
        /// [`allocator_symbolic_audited`] checks the construction
        /// against the audit as its proof obligation.
        fn any_allocator() -> Allocator {
            let n: u64 = kani::any();
            kani::assume(n <= ENTRIES);
            let mut free = OrderedMap::new();
            let mut free_bytes = 0u64;
            let mut cursor = 0u64;
            for i in 0..ENTRIES {
                if i >= n {
                    break;
                }
                let offset_blocks: u64 = kani::any();
                let len_blocks: u64 = kani::any();
                kani::assume(offset_blocks < MAX_BLOCKS && len_blocks < MAX_BLOCKS);
                kani::assume(len_blocks > 0 && offset_blocks + len_blocks < MAX_BLOCKS);
                kani::assume(offset_blocks * BLOCK > cursor);
                free.insert(offset_blocks * BLOCK, len_blocks * BLOCK);
                free_bytes += len_blocks * BLOCK;
                cursor = (offset_blocks + len_blocks) * BLOCK;
            }
            let end_blocks: u64 = kani::any();
            kani::assume(end_blocks <= MAX_BLOCKS && end_blocks * BLOCK > cursor);
            Allocator {
                free,
                end: end_blocks * BLOCK,
                free_bytes,
            }
        }

        /// Every state [`any_allocator`] generates satisfies the real
        /// audited invariant: the generator's assumptions (and the
        /// [`coherent`] mirror built from them) are exactly the
        /// invariant the other harnesses rely on.
        #[kani::proof]
        #[kani::unwind(6)]
        fn allocator_symbolic_audited() {
            let alloc = any_allocator();
            alloc.audit();
            // Skip the state's drop glue: Kani runs no leak checks and
            // the container deallocation otherwise pads the formula.
            std::mem::forget(alloc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESERVED: u64 = 2 * BLOCK;

    fn ext(offset: u64, len: u64) -> Extent {
        Extent { offset, len }
    }

    #[test]
    fn test_fresh_allocations_extend() {
        let mut alloc = Allocator::rebuild(RESERVED, []);
        assert_eq!(alloc.allocate(1), ext(RESERVED, BLOCK));
        assert_eq!(alloc.allocate(BLOCK + 1), ext(RESERVED + BLOCK, 2 * BLOCK));
        assert_eq!(alloc.end(), RESERVED + 3 * BLOCK);
    }

    #[test]
    fn test_free_and_reuse_first_fit() {
        let mut alloc = Allocator::rebuild(RESERVED, []);
        let a = alloc.allocate(BLOCK);
        let b = alloc.allocate(BLOCK);
        let c = alloc.allocate(BLOCK);
        alloc.free(a);
        alloc.free(c);
        // c touched the end and lowered the high-water mark, leaving a as
        // the only free range.
        assert_eq!(alloc.end(), b.offset + b.len);
        assert_eq!(alloc.allocate(BLOCK), a);
        // No free space left; extend.
        assert_eq!(alloc.allocate(BLOCK).offset, alloc.end() - BLOCK);
    }

    #[test]
    fn test_coalesce_both_sides() {
        let mut alloc = Allocator::rebuild(RESERVED, []);
        let a = alloc.allocate(BLOCK);
        let b = alloc.allocate(BLOCK);
        let c = alloc.allocate(BLOCK);
        let _d = alloc.allocate(BLOCK);
        alloc.free(a);
        alloc.free(c);
        alloc.free(b);
        // a+b+c coalesced into one range able to serve a 3-block request.
        assert_eq!(alloc.allocate(3 * BLOCK), ext(a.offset, 3 * BLOCK));
    }

    #[test]
    fn test_rebuild_infers_gaps() {
        let used = [
            ext(RESERVED + BLOCK, BLOCK),
            ext(RESERVED + 4 * BLOCK, 2 * BLOCK),
        ];
        let mut alloc = Allocator::rebuild(RESERVED, used);
        assert_eq!(alloc.end(), RESERVED + 6 * BLOCK);
        // Gaps: [RESERVED, +BLOCK) and [RESERVED+2*BLOCK, RESERVED+4*BLOCK).
        assert_eq!(
            alloc.allocate(2 * BLOCK),
            ext(RESERVED + 2 * BLOCK, 2 * BLOCK)
        );
        assert_eq!(alloc.allocate(BLOCK), ext(RESERVED, BLOCK));
        assert_eq!(alloc.allocate(BLOCK), ext(RESERVED + 6 * BLOCK, BLOCK));
    }

    #[test]
    fn test_split_leaves_remainder() {
        let mut alloc = Allocator::rebuild(RESERVED, [ext(RESERVED + 4 * BLOCK, BLOCK)]);
        // The 4-block gap below the used extent is split.
        assert_eq!(alloc.allocate(BLOCK), ext(RESERVED, BLOCK));
        assert_eq!(alloc.allocate(2 * BLOCK), ext(RESERVED + BLOCK, 2 * BLOCK));
        assert_eq!(alloc.allocate(BLOCK), ext(RESERVED + 3 * BLOCK, BLOCK));
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn test_double_free_panics() {
        let mut alloc = Allocator::rebuild(RESERVED, []);
        let a = alloc.allocate(BLOCK);
        let _b = alloc.allocate(BLOCK);
        alloc.free(a);
        alloc.free(a);
    }
}

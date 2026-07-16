//! Block-aligned extent allocator for the volume.
//!
//! The allocator is purely in-memory: it is rebuilt at open from the extents
//! referenced by the adopted blob table, so no allocation state is ever
//! persisted and allocator bugs cannot corrupt the volume. Frees are applied
//! by the caller only after the commit that stops referencing an extent
//! completes (see the commit protocol in the module docs), which is what makes
//! rollback to the previous commit safe.

use std::collections::BTreeMap;

/// Alignment unit for all extents.
///
/// This is the assumed physical tearing granularity of the inner blob: an
/// uncommitted write never lands in a block that holds committed bytes of a
/// DIFFERENT extent, so a torn write can only damage data that the adopted
/// table does not reference.
pub(super) const BLOCK: u64 = 4096;

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
    free: BTreeMap<u64, u64>,
    /// High-water mark: everything at and beyond this offset is free.
    end: u64,
}

/// Round `len` up to a whole number of blocks.
pub(super) const fn block_align(len: u64) -> u64 {
    len.div_ceil(BLOCK) * BLOCK
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

        let mut free = BTreeMap::new();
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
            }
            cursor = extent.offset + extent.len;
        }

        Self { free, end: cursor }
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

        // A range touching the high-water mark shrinks the file instead of
        // lingering in the index.
        if offset + len == self.end {
            self.end = offset;
        } else {
            self.free.insert(offset, len);
        }
    }

    /// Offset one past the last allocated byte.
    #[cfg(test)]
    pub(super) const fn end(&self) -> u64 {
        self.end
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
        // c touched the end, so the file shrank; a is the only free range.
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

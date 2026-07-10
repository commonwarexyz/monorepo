//! The in-memory tail of a paged [`Writer`](super::Writer).

use crate::{buffer::tip::Buffer, BufferPool, IoBuf};

/// The writer's in-memory tail: the logical suffix not yet published as written.
///
/// `full_pages` holds finished, page-aligned bytes as immutable, refcounted handles. `tip` is the
/// growing end: mutable and contiguous, so appends extend it in place and its CRC is computed
/// over one slice. Bytes move left to right exactly once:
///
/// ```text
///   append ──copy──▶ tip ──freeze full pages──▶ full_pages ──flush──▶ blob + page cache
///   append_owned (whole pages) ──zero-copy────▶ full_pages
/// ```
///
/// A flush may write tail bytes before it publishes that progress; cancellation leaves the tail
/// intact until [`Tail::advance_full_pages`] advances the written prefix. The tip may begin with
/// a committed partial page's bytes, kept in memory because appends extend them in place.
pub(super) struct Tail {
    /// Logical offset of the first tail byte; always page-aligned.
    start: u64,
    /// Finished page-aligned bytes awaiting their write.
    full_pages: Vec<IoBuf>,
    /// The growing final suffix. A flush moves its full-page prefix into `full_pages`.
    tip: Buffer,
    /// Logical page size.
    page_size: usize,
}

impl Tail {
    /// Start at page-aligned `start`, seeding the tip with `seed` (a recovered partial page,
    /// if any).
    pub(super) fn new(
        start: u64,
        seed: IoBuf,
        capacity: usize,
        page_size: usize,
        pool: BufferPool,
    ) -> Self {
        debug_assert!(seed.len() < page_size);
        Self {
            start,
            full_pages: Vec::new(),
            tip: Buffer::from(start, seed, capacity, pool),
            page_size,
        }
    }

    /// Logical offset of the first tail byte.
    pub(super) const fn start(&self) -> u64 {
        self.start
    }

    /// Size of the blob including the tail.
    pub(super) const fn size(&self) -> u64 {
        self.tip.size()
    }

    /// The finished page-aligned bytes awaiting their write.
    pub(super) fn full_pages(&self) -> &[IoBuf] {
        &self.full_pages
    }

    /// The tip bytes.
    pub(super) fn tip(&self) -> &[u8] {
        self.tip.as_ref()
    }

    /// True if the tip is empty.
    pub(super) const fn tip_is_empty(&self) -> bool {
        self.tip.is_empty()
    }

    /// Immutable tip bytes for `range`.
    pub(super) fn tip_slice(&self, range: impl std::ops::RangeBounds<usize>) -> IoBuf {
        self.tip.slice(range)
    }

    /// Append `buf`, returning the logical offset of its first byte.
    pub(super) fn append(&mut self, buf: &[u8]) -> u64 {
        let offset = self.tip.size();
        self.tip.append(buf);
        if self.tip.len() >= self.tip.capacity {
            self.spill_full_pages();
        }
        offset
    }

    /// Append owned bytes, returning the logical offset of the first. Whole pages of `buf` become
    /// retained without copying; only the bytes topping up the tip's page and the sub-page suffix
    /// are copied. The copied suffix keeps the tip extendable and releases the caller's allocation
    /// after the full pages flush.
    pub(super) fn append_owned(&mut self, buf: IoBuf) -> u64 {
        let fill = self.tip.len().next_multiple_of(self.page_size) - self.tip.len();
        if self.tip.len() + buf.len() <= self.tip.capacity || buf.len() < fill + self.page_size {
            return self.append(buf.as_ref());
        }

        let offset = self.tip.size();
        if fill > 0 {
            self.tip.append(&buf.as_ref()[..fill]);
        }
        self.spill_full_pages();
        debug_assert!(self.tip.is_empty());

        let full_bytes = (buf.len() - fill) / self.page_size * self.page_size;
        self.tip.offset += full_bytes as u64;
        self.full_pages.push(buf.slice(fill..fill + full_bytes));

        let suffix = &buf.as_ref()[fill + full_bytes..];
        if !suffix.is_empty() {
            self.tip.append(suffix);
        }
        offset
    }

    /// Move the tip's full-page prefix into immutable storage, leaving its partial suffix.
    pub(super) fn spill_full_pages(&mut self) {
        let full_bytes = self.tip.len() / self.page_size * self.page_size;
        if full_bytes == 0 {
            return;
        }
        self.full_pages.push(self.tip.slice(..full_bytes));
        self.tip.advance(full_bytes);
    }

    /// Record that all full pages were written. The tip's partial page stays in memory.
    pub(super) fn advance_full_pages(&mut self) {
        debug_assert!(self.tip.len() < self.page_size);
        self.full_pages.clear();
        self.start = self.tip.offset;
    }

    /// Restart at page-aligned `offset` with the tip seeded from `seed`, discarding all tail
    /// state. Used by shrinks, which flush first and then re-anchor at the shrunken boundary.
    pub(super) fn restart_at(&mut self, offset: u64, seed: &[u8]) {
        self.full_pages.clear();
        self.start = offset;
        self.tip.offset = offset;
        self.tip.clear();
        if !seed.is_empty() {
            self.append(seed);
        }
    }

    /// A borrowed, read-only view of this tail.
    pub(super) fn view(&self) -> View<'_> {
        View {
            start: self.start,
            full_pages: &self.full_pages,
            tip_offset: self.tip.offset,
            tip: self.tip.as_ref(),
        }
    }
}

/// A borrowed, read-only in-memory tail: the authoritative bytes at `[start, size)`.
#[derive(Clone, Copy)]
pub(super) struct View<'a> {
    /// First byte served by the tail; bytes below it come from the page cache or blob.
    pub(super) start: u64,
    /// Finished page-aligned bytes.
    pub(super) full_pages: &'a [IoBuf],
    /// Logical offset of the tip bytes.
    pub(super) tip_offset: u64,
    /// The tip bytes: the final, incomplete page.
    pub(super) tip: &'a [u8],
}

impl View<'_> {
    /// Copy the tail bytes at `[offset, offset + buf.len())` into `buf`. The range must lie
    /// entirely within the tail.
    pub(super) fn copy(&self, buf: &mut [u8], offset: u64) {
        let mut dst = buf;
        let mut pos = offset;
        let mut page_start = self.start;
        for pages in self.full_pages {
            let page_end = page_start + pages.len() as u64;
            if pos < page_end && !dst.is_empty() {
                let src = (pos - page_start) as usize;
                let n = dst.len().min((page_end - pos) as usize);
                let (head, rest) = dst.split_at_mut(n);
                head.copy_from_slice(&pages.as_ref()[src..src + n]);
                dst = rest;
                pos += n as u64;
            }
            page_start = page_end;
            if dst.is_empty() {
                return;
            }
        }
        if !dst.is_empty() {
            let src = (pos - self.tip_offset) as usize;
            let n = dst.len();
            dst.copy_from_slice(&self.tip[src..src + n]);
        }
    }

    /// Copy any tail overlap into `buf`, returning the remaining prefix length that must be
    /// served from the cache or blob.
    pub(super) fn copy_overlap(&self, buf: &mut [u8], offset: u64) -> usize {
        let tail_start = self.start.max(offset);
        let prefix_len = (tail_start - offset) as usize;
        let (_, tail_buf) = buf.split_at_mut(prefix_len);
        self.copy(tail_buf, tail_start);
        prefix_len
    }
}

//! Shared view for the paged buffer's read-capable types.
//!
//! [`Writer`](super::Writer) and [`Sealed`](super::Sealed) read the same way: logical bytes in
//! `[tail_offset, size)` come from in-memory tail chunks (the writer's tip buffer or the sealed
//! blob's partial last page), and bytes in `[0, tail_offset)` come from the page cache, falling
//! back to a blob read. Each type exposes itself as a borrowed [`View`] so this algorithm lives in
//! exactly one place.

use super::{CacheRef, tip::Buffer};
use crate::{Blob, Error, IoBufMut, IoBufs};
use commonware_utils::Widen;
use std::{num::NonZeroUsize, sync::Arc};

/// Logical bytes served from memory at the end of a paged blob.
#[derive(Clone, Copy)]
pub(super) enum Tail<'a> {
    /// Chunks retained by the writer's tip buffer.
    Buffered(&'a Buffer),
    /// A copied partial page owned by an immutable reader.
    Sealed(&'a [u8]),
}

impl<'a> Tail<'a> {
    /// Copy an in-bounds range relative to the start of the tail.
    fn copy_into(self, mut offset: usize, dst: &mut [u8]) {
        let tail = match self {
            Self::Sealed(tail) => tail,
            Self::Buffered(buffer) => {
                let (_, tail) = buffer.parts();
                let prefix_len = buffer.len() - tail.len();
                if offset < prefix_len {
                    self.cursor().copy_into(offset, dst);
                    return;
                }
                offset -= prefix_len;
                tail
            }
        };
        dst.copy_from_slice(&tail[offset..offset + dst.len()]);
    }

    fn cursor(self) -> Cursor<'a, impl Iterator<Item = &'a [u8]>> {
        let (prefix, tail) = match self {
            Self::Buffered(buffer) => {
                let (prefix, tail) = buffer.parts();
                (Some(prefix), tail)
            }
            Self::Sealed(tail) => (None, tail),
        };

        // An empty initial chunk lets the cursor enter either representation with the same
        // forward walk, including when the buffered prefix is empty.
        Cursor {
            chunks: prefix
                .into_iter()
                .flat_map(|bufs| bufs.iter().map(AsRef::as_ref))
                .chain(std::iter::once(tail)),
            chunk: &[],
            position: 0,
        }
    }
}

/// A forward cursor keeps sorted range reads linear in the number of buffered chunks and ranges.
struct Cursor<'a, I> {
    /// Chunks not yet entered.
    chunks: I,
    /// Unread suffix of the current chunk.
    chunk: &'a [u8],
    /// End of the last completed range, relative to the tail.
    position: usize,
}

impl<'a, I: Iterator<Item = &'a [u8]>> Cursor<'a, I> {
    /// Copy a range at or beyond the previous range's end and advance past it.
    ///
    /// The range must fit within the tail. Empty destinations do not advance the cursor.
    fn copy_into(&mut self, offset: usize, mut dst: &mut [u8]) {
        if dst.is_empty() {
            return;
        }
        let mut skip = offset
            .checked_sub(self.position)
            .expect("tail reads must be sorted");
        while skip >= self.chunk.len() {
            skip -= self.chunk.len();
            self.chunk = self.chunks.next().expect("tail read out of bounds");
        }
        self.chunk = &self.chunk[skip..];
        self.position = offset + dst.len();
        while !dst.is_empty() {
            if self.chunk.is_empty() {
                self.chunk = self.chunks.next().expect("tail read out of bounds");
                continue;
            }
            let len = self.chunk.len().min(dst.len());
            dst[..len].copy_from_slice(&self.chunk[..len]);
            dst = &mut dst[len..];
            self.chunk = &self.chunk[len..];
        }
    }
}

/// A borrowed view over a paged blob.
pub struct View<'a, B: Blob> {
    /// Underlying blob, used for bytes below `tail_offset` not resident in the cache.
    pub(super) blob: &'a Arc<B>,
    /// Page cache used for bytes below `tail_offset`.
    pub(super) cache_ref: &'a CacheRef,
    /// Page-cache id of the originating blob.
    pub(super) id: u64,
    /// Size of the blob, in bytes.
    pub(super) size: u64,
    /// Offset at which the in-memory `tail` bytes begin.
    pub(super) tail_offset: u64,
    /// Logical bytes at `[tail_offset, size)`. May be empty.
    pub(super) tail: Tail<'a>,
}

impl<B: Blob> Clone for View<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Blob> Copy for View<'_, B> {}

impl<B: Blob> View<'_, B> {
    /// Copy any in-memory tail overlap into `buf`, returning the remaining prefix length.
    fn copy_tail_overlap(&self, buf: &mut [u8], offset: u64) -> usize {
        let tail_start = self.tail_offset.max(offset);
        let prefix_len = (tail_start - offset) as usize;
        let tail_offset = (tail_start - self.tail_offset) as usize;
        let (_, tail_buf) = buf.split_at_mut(prefix_len);
        self.tail.copy_into(tail_offset, tail_buf);
        prefix_len
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from the page cache and/or the in-memory tail. When `false`
    /// is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        if end_offset > self.size {
            return false;
        }
        if buf.is_empty() {
            return true;
        }

        if end_offset <= self.tail_offset {
            return self.cache_ref.read_cached(self.id, buf, offset) == buf.len();
        }

        // Copy the suffix overlapping the tail, then serve any prefix below `tail_offset` from the
        // cache.
        let dst_start = self.copy_tail_overlap(buf, offset);

        if dst_start == 0 {
            return true;
        }

        self.cache_ref
            .read_cached(self.id, &mut buf[..dst_start], offset)
            == dst_start
    }

    /// Reads bytes starting at `offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let end_offset = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end_offset > self.size {
            return Err(Error::BlobInsufficientLength);
        }

        // Copy any suffix from the in-memory tail, leaving the prefix below `tail_offset` to be
        // served from the page cache or blob.
        let remaining = if end_offset <= self.tail_offset {
            buf.len()
        } else {
            self.copy_tail_overlap(buf, offset)
        };

        if remaining == 0 {
            return Ok(());
        }

        let cached = self
            .cache_ref
            .read_cached(self.id, &mut buf[..remaining], offset);
        if cached == remaining {
            return Ok(());
        }

        let uncached_offset = offset + cached as u64;
        let uncached_len = remaining - cached;
        self.cache_ref
            .read_after_miss(
                self.blob,
                self.id,
                &mut buf[cached..cached + uncached_len],
                uncached_offset,
            )
            .await
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // SAFETY: read_into below initializes all `len` bytes.
        let mut buf = unsafe { self.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Reads up to `len` bytes starting at `offset`, but only as many as are available.
    ///
    /// Returns the buffer (truncated to actual bytes read) and the number of bytes read. Returns an
    /// error if no bytes are available at the given offset.
    pub async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        let mut bufs = bufs.into();
        if len == 0 {
            bufs.truncate(0);
            return Ok((bufs, 0));
        }
        let available = self.size.saturating_sub(offset).min(Widen::widen(len)) as usize;
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        // SAFETY: read_into below fills all `available` bytes.
        unsafe { bufs.set_len(available) };
        self.read_into(bufs.as_mut(), offset).await?;
        Ok((bufs, available))
    }

    /// Read multiple fixed-size items at sorted byte offsets into a contiguous caller buffer.
    ///
    /// `buf` must be exactly `offsets.len() * item_size` bytes. All offsets must be sorted,
    /// non-overlapping, and within bounds.
    ///
    /// Returns the number of items fully served without a blob read (from the in-memory tail and
    /// the page cache). The remaining items required at least one blob read.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        let ranges = || offsets.iter().map(|&o| (o, item_size.get()));
        super::validate_read_ranges(buf.len(), ranges(), self.size)?;
        if offsets.is_empty() {
            return Ok(0);
        }

        let mut cache_ranges = split_read_ranges(buf, ranges(), self.tail_offset, self.tail);

        // Fast path: try the page cache for all ranges in a single lock acquisition.
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Keep the bulk-read state out of cache-hit futures. Only misses allocate it.
        Box::pin(
            self.cache_ref
                .read_many_after_faults(self.blob, self.id, cache_ranges),
        )
        .await?;

        Ok(offsets.len() - blob_reads)
    }

    /// Read sorted, non-overlapping `(offset, len)` ranges into one owned buffer, in range order.
    /// All ranges must be within bounds. Missing pages are coalesced across ranges.
    ///
    /// # Panics
    ///
    /// Panics if ranges are not sorted and non-overlapping.
    pub async fn read_ranges(&self, ranges: &[(u64, usize)]) -> Result<IoBufs, Error> {
        let len = ranges.iter().try_fold(0usize, |total, &(_, len)| {
            total.checked_add(len).ok_or(Error::OffsetOverflow)
        })?;
        super::validate_read_ranges(len, ranges.iter().copied(), self.size)?;
        // SAFETY: the tail/cache copies and read_many_after_faults fill every byte before the
        // buffer is returned. Any failed read drops the buffer without exposing its contents.
        let mut buf = unsafe { self.cache_ref.pool().alloc_len(len) };
        let mut cache_ranges = split_read_ranges(
            buf.as_mut(),
            ranges.iter().copied(),
            self.tail_offset,
            self.tail,
        );
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        if !cache_ranges.is_empty() {
            self.cache_ref
                .read_many_after_faults(self.blob, self.id, cache_ranges)
                .await?;
        }
        Ok(buf.into())
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only.
    ///
    /// Items fully served from the in-memory tail and page cache are written to their slots in
    /// `buf`. Returns the indices of items that require a blob read, which is every index when
    /// the offsets extend past the blob. Those slots hold unspecified bytes.
    pub fn try_read_many_sync_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Vec<usize> {
        let ranges = || offsets.iter().map(|&o| (o, item_size.get()));
        if super::validate_read_ranges(buf.len(), ranges(), self.size).is_err() {
            return (0..offsets.len()).collect();
        }
        if offsets.is_empty() {
            return Vec::new();
        }

        let mut cache_ranges = split_read_ranges(buf, ranges(), self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| (offsets[idx], item_size.get()))
    }

    /// Like [`Self::try_read_many_sync_into`], but for variable-length ranges: `buf` holds one
    /// slot per `(offset, len)` range, back to back. Returns the indices of ranges that require
    /// a blob read, which is every index when the ranges extend past the blob. Their slots hold
    /// unspecified bytes.
    pub fn try_read_ranges_sync_into(&self, buf: &mut [u8], ranges: &[(u64, usize)]) -> Vec<usize> {
        if super::validate_read_ranges(buf.len(), ranges.iter().copied(), self.size).is_err() {
            return (0..ranges.len()).collect();
        }
        if ranges.is_empty() {
            return Vec::new();
        }

        let mut cache_ranges =
            split_read_ranges(buf, ranges.iter().copied(), self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| ranges[idx])
    }
}

/// Partition a batch of variable-length range reads into bytes copied from the in-memory tail
/// and ranges that need cache/blob reads.
///
/// Ranges must be sorted and non-overlapping. `buf` holds one slot per range, back to back.
/// [super::validate_read_ranges] checks these preconditions and bounds every range by the
/// blob size.
///
/// `tail` holds the logical bytes starting at `tail_offset`: the writer's tip buffer or the sealed
/// blob's partial last page. Tail overlaps are copied into place. Prefixes below `tail_offset` are
/// returned as `(dest_slice, offset)` pairs for cache/blob reads. `split_at_mut` gives each range a
/// disjoint output slot, so returned slices never alias.
fn split_read_ranges<'a>(
    mut buf: &'a mut [u8],
    ranges: impl ExactSizeIterator<Item = (u64, usize)>,
    tail_offset: u64,
    tail: Tail<'_>,
) -> Vec<(&'a mut [u8], u64)> {
    let mut cache_ranges = Vec::with_capacity(ranges.len());
    let mut cursor = tail.cursor();
    for (offset, len) in ranges {
        let (slot, rest) = buf.split_at_mut(len);
        buf = rest;
        if len == 0 {
            continue;
        }
        let end = offset + len as u64;
        if end <= tail_offset {
            // Entirely below the tail bytes, so this needs a cache/blob read.
            cache_ranges.push((slot, offset));
        } else if offset >= tail_offset {
            // Entirely within the tail bytes.
            let src = (offset - tail_offset) as usize;
            cursor.copy_into(src, slot);
        } else {
            // Straddles the boundary: copy the suffix from the tail bytes, record the prefix
            // for a cache/blob read.
            let prefix_len = (tail_offset - offset) as usize;
            let (prefix, suffix) = slot.split_at_mut(prefix_len);
            cursor.copy_into(0, suffix);
            cache_ranges.push((prefix, offset));
        }
    }
    cache_ranges
}

/// Map unread suffixes back to their originating slot indices. Each suffix starts inside its
/// slot's `(offset, len)` range, and both lists are sorted. Zero-length slots never miss but may
/// share an offset with the slot that follows them, so they are skipped.
fn map_misses(
    missed: Vec<(&mut [u8], u64)>,
    mut slot: impl FnMut(usize) -> (u64, usize),
) -> Vec<usize> {
    let mut misses = Vec::with_capacity(missed.len());
    let mut idx = 0;
    for (_, offset) in missed {
        loop {
            let (slot_offset, slot_len) = slot(idx);
            if offset >= slot_offset && offset - slot_offset < slot_len as u64 {
                break;
            }
            idx += 1;
        }
        misses.push(idx);
        idx += 1;
    }
    misses
}

#[cfg(test)]
mod tests;

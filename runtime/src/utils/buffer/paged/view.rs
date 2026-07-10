//! Shared view for the paged buffer's read-capable types.
//!
//! [`Writer`](super::Writer) and [`Sealed`](super::Sealed) read the same way: logical bytes in
//! `[tail.start, size)` come from an in-memory tail view (the writer's tail, or the sealed
//! blob's partial last page), and bytes below come from the page cache, falling back to a blob
//! read. Each type exposes itself as a borrowed [`View`] so this algorithm lives in exactly
//! one place.

use super::{tail::View as TailView, CacheRef};
use crate::{Blob, Error, IoBufMut, IoBufs};
use futures::stream::{FuturesUnordered, StreamExt};
use std::num::NonZeroUsize;

/// A borrowed view over a paged blob.
pub struct View<'a, B: Blob> {
    /// Underlying blob, used for bytes below the tail not resident in the cache.
    pub(super) blob: &'a B,
    /// Page cache used for bytes below the tail.
    pub(super) cache_ref: &'a CacheRef,
    /// Page-cache id of the originating blob.
    pub(super) id: u64,
    /// Size of the blob, in bytes.
    pub(super) size: u64,
    /// The in-memory tail, serving bytes at `[tail.start, size)`.
    pub(super) tail: TailView<'a>,
}

impl<B: Blob> Clone for View<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Blob> Copy for View<'_, B> {}

impl<B: Blob> View<'_, B> {
    /// Split validated read ranges into tail copies (performed inline) and ranges needing a
    /// cache or blob read (returned with their slots).
    ///
    /// `buf` holds one slot per range, back to back. Ranges entirely within the tail are
    /// copied from memory; a range straddling the boundary is copied above it and returned
    /// below it.
    fn split_read_ranges<'b>(
        &self,
        mut buf: &'b mut [u8],
        ranges: impl ExactSizeIterator<Item = (u64, usize)>,
    ) -> Vec<(&'b mut [u8], u64)> {
        let mut cache_ranges = Vec::with_capacity(ranges.len());
        for (offset, len) in ranges {
            let (slot, rest) = buf.split_at_mut(len);
            buf = rest;
            if len == 0 {
                continue;
            }
            let end = offset + len as u64;
            if end <= self.tail.start {
                // Entirely below the tail, so this needs a cache/blob read.
                cache_ranges.push((slot, offset));
            } else if offset >= self.tail.start {
                // Entirely within the tail.
                self.tail.copy(slot, offset);
            } else {
                // Straddles the boundary: copy the suffix from the tail, record the prefix for
                // a cache/blob read.
                let prefix_len = (self.tail.start - offset) as usize;
                let (prefix, suffix) = slot.split_at_mut(prefix_len);
                self.tail.copy(suffix, self.tail.start);
                cache_ranges.push((prefix, offset));
            }
        }
        cache_ranges
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

        if end_offset <= self.tail.start {
            return self.cache_ref.read_cached(self.id, buf, offset) == buf.len();
        }

        // Copy the suffix overlapping the tail, then serve any prefix below it from the cache.
        let dst_start = self.tail.copy_overlap(buf, offset);

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

        // Copy any suffix from the tail, leaving the prefix below it to be served from the
        // page cache or blob.
        let remaining = if end_offset <= self.tail.start {
            buf.len()
        } else {
            self.tail.copy_overlap(buf, offset)
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
            .read(
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
        let available = (self.size.saturating_sub(offset) as usize).min(len);
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
    /// Returns the number of items fully served without a blob read (from the in-memory tail and the
    /// page cache). The remaining items required at least one blob read.
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

        let mut cache_ranges = self.split_read_ranges(buf, ranges());

        // Fast path: try the page cache for all ranges in a single lock acquisition.
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Slow path: read remaining ranges from the underlying blob, concurrently.
        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| self.cache_ref.read(self.blob, self.id, item_buf, *offset))
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(offsets.len() - blob_reads)
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

        let mut cache_ranges = self.split_read_ranges(buf, ranges());
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

        let mut cache_ranges = self.split_read_ranges(buf, ranges.iter().copied());
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| ranges[idx])
    }
}

/// Map missed cache reads back to their originating slot indices: each missed read starts at
/// its slot's `(offset, len)` range, and both lists are sorted. Zero-length slots never miss
/// but may share an offset with the slot that follows them, so they are skipped.
fn map_misses(
    missed: Vec<(&mut [u8], u64)>,
    mut slot: impl FnMut(usize) -> (u64, usize),
) -> Vec<usize> {
    let mut misses = Vec::with_capacity(missed.len());
    let mut idx = 0;
    for (_, offset) in missed {
        loop {
            let (slot_offset, slot_len) = slot(idx);
            if slot_len != 0 && slot_offset == offset {
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
mod tests {
    use crate::{buffer::paged::Writer, deterministic, Runner as _, Storage as _};
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    /// A read straddling the persisted prefix and the in-memory tail is served synchronously once
    /// the prefix page is cached (the unified `View` serves the prefix from the cache and the
    /// suffix from the tail in one call).
    #[test]
    fn test_view_try_read_sync_straddles_cache_and_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"view_straddle")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // A full page (flushed to the blob) followed by a partial tail kept in the tip buffer.
            let page_size = PAGE_SIZE.get() as usize;
            writer.append(&vec![0xAA; page_size]);
            writer.append(b"TAIL");
            writer.sync().await.unwrap();

            // Warm the cache for the first page, then read across the page/tail boundary.
            writer.read_at(0, page_size).await.unwrap();
            let mut buf = [0u8; 4];
            assert!(writer.try_read_sync_into(&mut buf, page_size as u64 - 2));
            assert_eq!(&buf, &[0xAA, 0xAA, b'T', b'A']);
        });
    }
}

//! Shared view for the paged buffer's read-capable types.
//!
//! [`Writer`](super::Writer) and [`Sealed`](super::Sealed) read the same way: logical bytes in
//! `[tail_offset, size)` come from an in-memory tail slice (the writer's tip buffer or the sealed
//! blob's partial last page), and bytes in `[0, tail_offset)` come from the page cache, falling back
//! to a blob read. Each type exposes itself as a borrowed [`View`] so this algorithm lives in
//! exactly one place.

use super::CacheRef;
use crate::{Blob, Error, IoBufMut, IoBufs};
use futures::stream::{FuturesUnordered, StreamExt};
use std::num::NonZeroUsize;

/// A borrowed view over a paged blob.
pub struct View<'a, B: Blob> {
    /// Underlying blob, used for bytes below `tail_offset` not resident in the cache.
    pub(super) blob: &'a B,
    /// Page cache used for bytes below `tail_offset`.
    pub(super) cache_ref: &'a CacheRef,
    /// Page-cache id of the originating blob.
    pub(super) id: u64,
    /// Size of the blob, in bytes.
    pub(super) size: u64,
    /// Offset at which the in-memory `tail` bytes begin.
    pub(super) tail_offset: u64,
    /// Logical bytes at `[tail_offset, size)`. May be empty.
    pub(super) tail: &'a [u8],
}

impl<B: Blob> Clone for View<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Blob> Copy for View<'_, B> {}

impl<B: Blob> View<'_, B> {
    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from the page cache and/or the in-memory tail. When `false`
    /// is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
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
        let overlap_start = self.tail_offset.max(offset);
        let dst_start = (overlap_start - offset) as usize;
        let src_start = (overlap_start - self.tail_offset) as usize;
        let copied = buf.len() - dst_start;
        buf[dst_start..].copy_from_slice(&self.tail[src_start..src_start + copied]);

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
            let overlap_start = self.tail_offset.max(offset);
            let dst_start = (overlap_start - offset) as usize;
            let src_start = (overlap_start - self.tail_offset) as usize;
            let copied = buf.len() - dst_start;
            buf[dst_start..].copy_from_slice(&self.tail[src_start..src_start + copied]);
            dst_start
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
        super::validate_read_many_into(buf.len(), offsets, item_size, self.size)?;
        if offsets.is_empty() {
            return Ok(0);
        }

        let mut cache_ranges =
            super::split_read_many(buf, offsets, item_size, self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

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
            writer.append(&vec![0xAA; page_size]).await.unwrap();
            writer.append(b"TAIL").await.unwrap();
            writer.sync().await.unwrap();

            // Warm the cache for the first page, then read across the page/tail boundary.
            writer.read_at(0, page_size).await.unwrap();
            let mut buf = [0u8; 4];
            assert!(writer.try_read_sync(page_size as u64 - 2, &mut buf));
            assert_eq!(&buf, &[0xAA, 0xAA, b'T', b'A']);
        });
    }
}

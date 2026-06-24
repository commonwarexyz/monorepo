//! Immutable read view of a cache-backed blob.

use super::CacheRef;
use crate::{Blob, Error, IoBuf, IoBufMut, IoBufs};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// An immutable read view of a cache-backed blob.
pub struct Snapshot<B: Blob> {
    inner: Arc<SnapshotInner<B>>,
}

impl<B: Blob> Clone for Snapshot<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct SnapshotInner<B: Blob> {
    /// Underlying blob used for bytes below [`Self::tail_offset`].
    blob: B,

    /// Logical size of the blob, in bytes.
    size: u64,

    /// Offset where tail bytes begin.
    tail_offset: u64,

    /// Copied tail bytes at `[tail_offset, size)`.
    tail: IoBuf,

    /// Page cache used for reads below [`Self::tail_offset`]. Those pages may not yet be cached.
    cache_ref: CacheRef,

    /// Page-cache id inherited from the originating [`super::Writer`].
    id: u64,

    /// Live snapshot count shared with the originating [`super::Writer`].
    snapshots: Arc<AtomicUsize>,
}

impl<B: Blob> Drop for SnapshotInner<B> {
    fn drop(&mut self) {
        self.snapshots.fetch_sub(1, Ordering::Release);
    }
}

impl<B: Blob> Snapshot<B> {
    pub(super) fn new(
        blob: B,
        size: u64,
        tail_offset: u64,
        tail: IoBuf,
        cache_ref: CacheRef,
        id: u64,
        snapshots: Arc<AtomicUsize>,
    ) -> Self {
        snapshots.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::new(SnapshotInner {
                blob,
                size,
                tail_offset,
                tail,
                cache_ref,
                id,
                snapshots,
            }),
        }
    }

    /// Returns the logical size of the blob.
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from either the page cache or the copied tail.
    /// When `false` is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        if end_offset > self.inner.size {
            return false;
        }
        if buf.is_empty() {
            return true;
        }

        if end_offset <= self.inner.tail_offset {
            return self.inner.cache_ref.read_cached(self.inner.id, buf, offset) == buf.len();
        }

        let overlap_start = self.inner.tail_offset.max(offset);
        let dst_start = (overlap_start - offset) as usize;
        let src_start = (overlap_start - self.inner.tail_offset) as usize;
        let copied = buf.len() - dst_start;
        buf[dst_start..].copy_from_slice(&self.inner.tail.as_ref()[src_start..src_start + copied]);

        if dst_start == 0 {
            return true;
        }

        self.inner
            .cache_ref
            .read_cached(self.inner.id, &mut buf[..dst_start], offset)
            == dst_start
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // SAFETY: read_into below initializes all `len` bytes.
        let mut buf = unsafe { self.inner.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Reads up to `len` bytes starting at `offset`, but only as many as are available.
    ///
    /// Returns the buffer (truncated to actual bytes read) and the number of bytes read. Returns
    /// an error if no bytes are available at the given offset.
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
        let available = (self.inner.size.saturating_sub(offset) as usize).min(len);
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
    /// Returns the number of items fully served without a blob read (from the copied tail and the
    /// page cache). The remaining items required at least one blob read.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        super::validate_read_many_into(buf.len(), offsets, item_size, self.inner.size)?;
        if offsets.is_empty() {
            return Ok(0);
        }

        let mut cache_ranges = super::split_read_many(
            buf,
            offsets,
            item_size,
            self.inner.tail_offset,
            self.inner.tail.as_ref(),
        );
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        self.inner
            .cache_ref
            .read_cached_many(self.inner.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| {
                self.inner
                    .cache_ref
                    .read(&self.inner.blob, self.inner.id, item_buf, *offset)
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(offsets.len() - blob_reads)
    }

    /// Reads bytes starting at `offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let end_offset = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end_offset > self.inner.size {
            return Err(Error::BlobInsufficientLength);
        }

        let remaining = if end_offset <= self.inner.tail_offset {
            buf.len()
        } else {
            let overlap_start = self.inner.tail_offset.max(offset);
            let dst_start = (overlap_start - offset) as usize;
            let src_start = (overlap_start - self.inner.tail_offset) as usize;
            let copied = buf.len() - dst_start;
            buf[dst_start..]
                .copy_from_slice(&self.inner.tail.as_ref()[src_start..src_start + copied]);
            dst_start
        };

        if remaining == 0 {
            return Ok(());
        }

        let cached = self
            .inner
            .cache_ref
            .read_cached(self.inner.id, &mut buf[..remaining], offset);
        if cached == remaining {
            return Ok(());
        }

        let uncached_offset = offset + cached as u64;
        let uncached_len = remaining - cached;
        self.inner
            .cache_ref
            .read(
                &self.inner.blob,
                self.inner.id,
                &mut buf[cached..cached + uncached_len],
                uncached_offset,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{buffer::paged::Writer, deterministic, Runner as _, Storage as _};
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test]
    fn test_snapshot_freezes_copied_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_freezes_tail")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let page = vec![0xAA; page_size];
            let tail = b"tail";
            writer.append(&page).await.unwrap();
            writer.append(tail).await.unwrap();
            writer.sync().await.unwrap();

            // The snapshot captures the current size and copied tail; later appends are invisible.
            let snapshot = writer.snapshot();
            let snapshot_size = snapshot.size();
            writer.append(b"new").await.unwrap();

            assert_eq!(snapshot.size(), snapshot_size);
            let read = snapshot
                .read_at(page_size as u64, tail.len())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), tail);
            assert!(matches!(
                snapshot.read_at(snapshot_size, 1).await,
                Err(Error::BlobInsufficientLength)
            ));
        });
    }

    #[test]
    fn test_snapshot_reads_prefix_after_cache_miss() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_prefix_miss")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let first = vec![0x11; page_size];
            let second = vec![0x22; page_size];
            writer.append(&first).await.unwrap();
            writer.append(&second).await.unwrap();
            writer.append(b"tail").await.unwrap();
            writer.sync().await.unwrap();

            // With a one-page cache, the oldest page must be fetched from the blob on demand.
            let snapshot = writer.snapshot();
            let mut probe = vec![0; page_size];
            assert!(
                !snapshot.try_read_sync(0, &mut probe),
                "first page should not already be resident in the one-page cache"
            );

            let read = snapshot.read_at(0, page_size).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), first.as_slice());

            let mut probe = vec![0; page_size];
            assert!(snapshot.try_read_sync(0, &mut probe));
            assert_eq!(probe.as_slice(), first.as_slice());
        });
    }

    #[test]
    fn test_snapshot_read_up_to_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_read_up_to")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            writer.append(b"abc").await.unwrap();
            let snapshot = writer.snapshot();

            // A zero-length read succeeds even at a valid offset without touching storage.
            let (buf, read) = snapshot
                .read_up_to(0, 0, IoBufMut::with_capacity(3))
                .await
                .unwrap();
            assert_eq!(read, 0);
            assert_eq!(buf.len(), 0);

            // Reads near EOF are truncated to the available bytes.
            let (buf, read) = snapshot
                .read_up_to(1, 10, IoBufMut::with_capacity(10))
                .await
                .unwrap();
            assert_eq!(read, 2);
            assert_eq!(buf.freeze().as_ref(), b"bc");

            // Starting at EOF with a positive length is an out-of-bounds read.
            assert!(matches!(
                snapshot
                    .read_up_to(snapshot.size(), 1, IoBufMut::with_capacity(1))
                    .await,
                Err(Error::BlobInsufficientLength)
            ));
        });
    }
}

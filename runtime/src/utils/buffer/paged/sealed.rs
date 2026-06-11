//! Read-only counterpart to [`super::Writer`]: an immutable, page-cache-backed read handle for
//! a blob whose logical content will no longer change.
//!
//! # Sealing and durability
//!
//! [`super::Writer::seal`] consumes the write handle and returns a [`Sealed`] handle without
//! fsyncing the underlying blob. Buffered logical bytes are flushed to the blob (so subsequent
//! reads observe them), but a crash before [`Sealed::sync`] may lose the most recently sealed
//! bytes. Callers that need durability must invoke [`Sealed::sync`] (typically driven from a
//! higher-level commit path).
//!
//! # Cheap sharing
//!
//! [`Sealed`] is `Clone` and shares its state via `Arc<SealedInner>`. Clones do not coordinate via
//! any lock; they share the underlying [`Blob`] handle (which provides its own synchronization)
//! and the page cache.

use super::{read::PageReader, CacheRef, Replay, CHECKSUM_SIZE};
use crate::{Blob, Error, IoBuf, IoBufs};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
};

/// An immutable, page-cache-backed read handle for a [Blob]. The read-only counterpart to
/// [`super::Writer`].
pub struct Sealed<B: Blob> {
    inner: Arc<SealedInner<B>>,
}

impl<B: Blob> Clone for Sealed<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct SealedInner<B: Blob> {
    /// The underlying blob being wrapped.
    blob: B,

    /// Logical size of the sealed view, in bytes.
    size: u64,

    /// Logical bytes of the partial last page, if the blob ends in one. Bytes at offsets
    /// `[size - partial_page.len(), size)` come from here; bytes below come from full pages on the
    /// blob (via the page cache).
    partial_page: Option<IoBuf>,

    /// Reference to the page cache used for reads of full pages.
    cache_ref: CacheRef,

    /// Page-cache id. Inherited from the originating [`super::Writer`] when constructed via
    /// [`super::Writer::seal`], so hot full pages remain valid across the transition.
    id: u64,
}

impl<B: Blob> Sealed<B> {
    /// Construct a [`Sealed`] from already-validated parts. Invoked by [`super::Writer::seal`].
    pub(super) fn new(
        blob: B,
        size: u64,
        partial_page: Option<IoBuf>,
        cache_ref: CacheRef,
        id: u64,
    ) -> Self {
        Self {
            inner: Arc::new(SealedInner {
                blob,
                size,
                partial_page,
                cache_ref,
                id,
            }),
        }
    }

    /// Returns the logical size of the sealed view.
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// Make pending bytes on the underlying blob durable. Idempotent.
    pub async fn sync(&self) -> Result<(), Error> {
        self.inner.blob.sync().await
    }

    /// Logical offset at which the partial-page bytes begin. Equal to `size` when there is no
    /// partial page.
    fn partial_offset(&self) -> u64 {
        self.inner.size
            - self
                .inner
                .partial_page
                .as_ref()
                .map_or(0, |p| p.len() as u64)
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // Allocate a single contiguous buffer and fill it via read_into.
        // SAFETY: read_into below initializes all `len` bytes.
        let mut buf = unsafe { self.inner.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from either the page cache or the in-memory partial page.
    /// When `false` is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        // Reject out-of-bounds requests up front: the partial-page arithmetic below assumes
        // `[offset, end_offset)` falls within the sealed view.
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        if end_offset > self.inner.size {
            return false;
        }
        if buf.is_empty() {
            return true;
        }

        let partial_offset = self.partial_offset();
        if end_offset <= partial_offset {
            return self.inner.cache_ref.read_cached(self.inner.id, buf, offset) == buf.len();
        }

        let Some(partial) = self.inner.partial_page.as_ref() else {
            return false;
        };
        if offset >= partial_offset {
            let src_start = (offset - partial_offset) as usize;
            buf.copy_from_slice(&partial.as_ref()[src_start..src_start + buf.len()]);
            return true;
        }

        let prefix_len = (partial_offset - offset) as usize;
        let suffix_len = buf.len() - prefix_len;
        if self
            .inner
            .cache_ref
            .read_cached(self.inner.id, &mut buf[..prefix_len], offset)
            != prefix_len
        {
            return false;
        }
        buf[prefix_len..].copy_from_slice(&partial.as_ref()[..suffix_len]);
        true
    }

    /// Reads bytes starting at `logical_offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], logical_offset: u64) -> Result<(), Error> {
        let end_offset = logical_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end_offset > self.inner.size {
            return Err(Error::BlobInsufficientLength);
        }

        let partial_offset = self.partial_offset();

        // Copy any suffix from the in-memory partial page, leaving the prefix below
        // `partial_offset` to be served from the page cache or blob.
        let remaining = if end_offset <= partial_offset {
            buf.len()
        } else {
            let overlap_start = partial_offset.max(logical_offset);
            let dst_start = (overlap_start - logical_offset) as usize;
            let src_start = (overlap_start - partial_offset) as usize;
            let copied = buf.len() - dst_start;
            let partial = self
                .inner
                .partial_page
                .as_ref()
                .expect("partial bytes exist when end_offset > partial_offset");
            buf[dst_start..].copy_from_slice(&partial.as_ref()[src_start..src_start + copied]);
            dst_start
        };

        if remaining == 0 {
            return Ok(());
        }

        // Try the page cache first.
        let cached =
            self.inner
                .cache_ref
                .read_cached(self.inner.id, &mut buf[..remaining], logical_offset);
        if cached == remaining {
            return Ok(());
        }

        // Slow path: read from the underlying blob (via the cache).
        let uncached_offset = logical_offset + cached as u64;
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

    /// Read multiple fixed-size items at sorted byte offsets into a contiguous caller buffer.
    ///
    /// `buf` must be exactly `offsets.len() * item_size` bytes. All offsets must be sorted,
    /// non-overlapping, and within bounds.
    ///
    /// Returns the number of items fully served without a blob read (from the in-memory partial
    /// page and the page cache). The remaining items required at least one blob read.
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

        // Copy items overlapping the in-memory partial page into place and collect the rest as
        // (slice, offset) pairs for cache/blob reads.
        let partial = self
            .inner
            .partial_page
            .as_ref()
            .map_or(&[][..], |p| p.as_ref());
        let mut cache_ranges =
            super::split_read_many(buf, offsets, item_size, self.partial_offset(), partial);
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Fast path: try the page cache for all ranges in a single lock acquisition.
        self.inner
            .cache_ref
            .read_cached_many(self.inner.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Slow path: read remaining ranges from the underlying blob, concurrently.
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

    /// Returns a [Replay] for sequentially reading all logical bytes of the sealed view.
    ///
    /// Sealed values have no write buffer to flush, so unlike [`super::Writer::replay`] this method
    /// is not async.
    pub fn replay(&self, buffer_size: NonZeroUsize) -> Result<Replay<B>, Error> {
        let logical_page_size = self.inner.cache_ref.page_size();
        let logical_page_size_nz =
            NonZeroU16::new(logical_page_size as u16).expect("page_size is non-zero");
        let physical_page_size = logical_page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        let prefetch_pages = (buffer_size.get() / physical_page_size as usize).max(1);

        let partial_len = self
            .inner
            .partial_page
            .as_ref()
            .map_or(0, |p| p.len() as u64);
        let full_pages = (self.inner.size - partial_len) / logical_page_size;
        let pages = full_pages + u64::from(partial_len > 0);
        let physical_blob_size = physical_page_size
            .checked_mul(pages)
            .ok_or(Error::OffsetOverflow)?;
        let logical_blob_size = self.inner.size;

        let reader = PageReader::new(
            self.inner.blob.clone(),
            physical_blob_size,
            logical_blob_size,
            prefetch_pages,
            logical_page_size_nz,
        );
        Ok(Replay::new(reader))
    }

    /// Page-cache id used for reads. Exposed for tests that verify the id is preserved across
    /// [`super::Writer::seal`].
    #[cfg(test)]
    pub(super) fn cache_id(&self) -> u64 {
        self.inner.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        buffer::{paged::Writer, tests::SyncTrackingBlob},
        deterministic, Buf, Runner as _, Storage as _,
    };
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky page size to test alignment
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    /// Seal a [Writer] and assert no fsync (full or range) occurred during the seal itself.
    #[test_traced("DEBUG")]
    fn test_seal_no_fsync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append some data crossing several pages but don't sync.
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            let (_durable_before, _writes_before, full_before, range_before) = blob.snapshot();

            // Seal -- this must flush logical bytes to the blob but NOT fsync.
            let sealed = append.seal().await.unwrap();

            let (_durable_after, _writes_after, full_after, range_after) = blob.snapshot();
            assert_eq!(full_after, full_before, "seal must not invoke Blob::sync");
            assert_eq!(
                range_after, range_before,
                "seal must not invoke Blob::write_at_sync"
            );

            assert_eq!(sealed.size(), 300);
        });
    }

    /// Sealing consumes the unique write handle; outstanding readers remain valid and agree
    /// with the sealed view.
    #[test_traced("DEBUG")]
    fn test_seal_succeeds_with_readers() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"readers").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let reader = writer.reader();
            let reader_clone = reader.clone();
            writer.append(b"hello world").await.unwrap();

            // Readers observe buffered bytes before the seal.
            assert_eq!(reader.size().await, 11);

            // Seal succeeds while readers exist.
            let sealed = writer.seal().await.unwrap();
            assert_eq!(sealed.size(), 11);

            // Both reader handles keep reading the frozen state and agree with the sealed view.
            for r in [&reader, &reader_clone] {
                assert_eq!(r.size().await, 11);
                let via_reader = r.read_at(0, 11).await.unwrap().coalesce();
                let via_sealed = sealed.read_at(0, 11).await.unwrap().coalesce();
                assert_eq!(via_reader.as_ref(), b"hello world");
                assert_eq!(via_sealed.as_ref(), via_reader.as_ref());
            }
        });
    }

    /// A reader created before sealing reads full pages and the partial page after the seal,
    /// from both the page cache and the blob.
    #[test_traced("DEBUG")]
    fn test_reader_full_pages_after_seal() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rdr_pages").await.unwrap();
            // A single-page cache forces most full-page reads to miss and hit the blob.
            let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let reader = writer.reader();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 3 + 7;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();

            let sealed = writer.seal().await.unwrap();
            assert_eq!(reader.size().await, total as u64);

            // Full range, a page-straddling range, and the partial page, each compared
            // against the sealed view.
            let cases = [
                (0u64, total),
                (page_size as u64 - 3, 6),
                ((page_size * 3) as u64, 7),
            ];
            for (offset, len) in cases {
                let via_reader = reader.read_at(offset, len).await.unwrap().coalesce();
                let via_sealed = sealed.read_at(offset, len).await.unwrap().coalesce();
                assert_eq!(
                    via_reader.as_ref(),
                    &data[offset as usize..offset as usize + len]
                );
                assert_eq!(via_sealed.as_ref(), via_reader.as_ref());
            }
        });
    }

    /// `Sealed::sync` forwards to the underlying blob's sync, making prior writes durable.
    #[test_traced("DEBUG")]
    fn test_sealed_sync_makes_blob_durable() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write data with no fsync.
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let (durable_before, _, full_before, _) = blob.snapshot();
            assert!(
                durable_before.is_empty(),
                "no bytes should be durable before Sealed::sync"
            );

            sealed.sync().await.unwrap();

            let (durable_after, _, full_after, _) = blob.snapshot();
            assert_eq!(
                full_after,
                full_before + 1,
                "Sealed::sync must invoke Blob::sync exactly once"
            );
            assert!(
                !durable_after.is_empty(),
                "blob bytes must be durable after Sealed::sync"
            );
        });
    }

    /// Sealing preserves the originating [Writer]'s page-cache id.
    #[test_traced("DEBUG")]
    fn test_seal_preserves_cache_id() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"cache_id").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let append_id = append.cache_id();
            let sealed = append.seal().await.unwrap();
            assert_eq!(sealed.cache_id(), append_id);
        });
    }

    /// Sealing an empty blob yields an empty sealed view.
    #[test_traced("DEBUG")]
    fn test_seal_empty_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"empty").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let sealed = append.seal().await.unwrap();

            assert_eq!(sealed.size(), 0);

            // Out-of-bounds reads error.
            let mut buf = [0u8; 1];
            let err = sealed.read_into(&mut buf, 0).await.unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    /// Sealing a blob whose logical size is exactly a page-multiple has no partial page.
    #[test_traced("DEBUG")]
    fn test_seal_full_pages_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"full").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append exactly two pages.
            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            assert_eq!(sealed.size(), data.len() as u64);

            // Read everything back.
            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    /// Sealing a blob whose logical size is smaller than one page yields only a partial page.
    #[test_traced("DEBUG")]
    fn test_seal_partial_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"partial").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append fewer than one page of data.
            let data: Vec<u8> = (0u8..=50).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            assert_eq!(sealed.size(), data.len() as u64);

            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    /// Reads that straddle the partial-page boundary stitch together cache and partial bytes.
    #[test_traced("DEBUG")]
    fn test_seal_full_plus_partial_straddle() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"straddle").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // One full page + a partial.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 17;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            assert_eq!(sealed.size(), total as u64);

            // Straddle read: 5 bytes before the boundary and 10 after.
            let off = (page_size - 5) as u64;
            let len = 15usize;
            let mut buf = vec![0u8; len];
            sealed.read_into(&mut buf, off).await.unwrap();
            assert_eq!(buf, data[page_size - 5..page_size - 5 + len]);

            // Read fully within partial.
            let off = page_size as u64;
            let mut buf = vec![0u8; 10];
            sealed.read_into(&mut buf, off).await.unwrap();
            assert_eq!(buf, data[page_size..page_size + 10]);

            // Read fully within first full page.
            let mut buf = vec![0u8; 20];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data[..20]);
        });
    }

    /// `Sealed::read_at` exposes the same data as `read_into`.
    #[test_traced("DEBUG")]
    fn test_sealed_read_at() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"read_at").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0u8..=255).cycle().take(250).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let bufs = sealed.read_at(0, data.len()).await.unwrap();
            let coalesced = bufs.coalesce();
            assert_eq!(coalesced.as_ref(), data.as_slice());
        });
    }

    /// `Sealed::read_many_into` returns items at sorted, possibly straddling, offsets.
    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two pages worth so reads exercise both cache and partial.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            // 4-byte items at three positions: pure cache, straddling boundary, pure partial.
            let offsets = [0u64, (page_size - 2) as u64, (page_size + 10) as u64];
            let item_size = 4usize;
            let mut out = vec![0u8; offsets.len() * item_size];
            sealed
                .read_many_into(&mut out, &offsets, NZUsize!(item_size))
                .await
                .unwrap();

            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &out[i * item_size..(i + 1) * item_size],
                    &data[off as usize..off as usize + item_size],
                );
            }
        });
    }

    /// `Sealed::read_many_into` falls back to blob reads for full-page cache misses.
    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into_cache_miss() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_miss").await.unwrap();
            let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let offsets = [0u64, page_size as u64];
            let item_size = 4usize;
            let mut out = vec![0u8; offsets.len() * item_size];
            sealed
                .read_many_into(&mut out, &offsets, NZUsize!(item_size))
                .await
                .unwrap();

            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &out[i * item_size..(i + 1) * item_size],
                    &data[off as usize..off as usize + item_size],
                );
            }
        });
    }

    /// `Sealed::read_many_into` validates all caller-provided offsets before reading.
    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into_rejects_invalid_offsets() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_bad").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[7; 32]).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let mut out = vec![0u8; 8];
            let err = sealed
                .read_many_into(&mut out, &[8, 4], NZUsize!(4))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)));

            let err = sealed
                .read_many_into(&mut out, &[u64::MAX - 1, 8], NZUsize!(4))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::OffsetOverflow));

            let err = sealed
                .read_many_into(&mut out, &[28, 32], NZUsize!(4))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    /// `try_read_sync` succeeds when bytes come purely from the in-memory partial page.
    #[test_traced("DEBUG")]
    fn test_sealed_try_read_sync_partial() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"trs_partial")
                .await
                .unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 30;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            // Read fully within partial.
            let mut buf = vec![0u8; 10];
            assert!(sealed.try_read_sync(page_size as u64, &mut buf));
            assert_eq!(buf, data[page_size..page_size + 10]);

            // Out of bounds returns false.
            let mut buf = vec![0u8; 10];
            assert!(!sealed.try_read_sync(total as u64, &mut buf));
        });
    }

    /// `try_read_sync` can stitch a cached full-page prefix to in-memory partial bytes.
    #[test_traced("DEBUG")]
    fn test_sealed_try_read_sync_straddles_cached_and_partial() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"trs_straddle")
                .await
                .unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 30;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let mut buf = vec![0u8; 12];
            assert!(sealed.try_read_sync((page_size - 4) as u64, &mut buf));
            assert_eq!(buf, data[page_size - 4..page_size + 8]);
        });
    }

    /// Synchronous reads past the sealed size are rejected.
    #[test_traced("DEBUG")]
    fn test_sealed_try_read_sync_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"trs_fail").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size + 5).collect();
            append.append(&data).await.unwrap();
            let sealed = append.seal().await.unwrap();

            let mut buf = vec![9u8; 10];
            assert!(!sealed.try_read_sync(data.len() as u64, &mut buf));
        });
    }

    /// `Sealed::replay` streams all logical bytes including the partial page.
    #[test_traced("DEBUG")]
    fn test_sealed_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"replay").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two pages + a partial, synced so the bytes are on disk before sealing.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 25;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            let sealed = append.seal().await.unwrap();

            let mut replay = sealed.replay(NZUsize!(BUFFER_SIZE)).unwrap();
            assert_eq!(replay.blob_size(), total as u64);

            // Drain all logical bytes.
            let mut out = Vec::with_capacity(total);
            while replay.ensure(1).await.unwrap() {
                let chunk = replay.chunk();
                let copy_len = chunk.len();
                out.extend_from_slice(chunk);
                replay.advance(copy_len);
            }
            assert_eq!(out, data);
        });
    }

    /// `Sealed::replay` works without a prior `Append::sync` because `Append::seal` writes bytes
    /// to the blob without fsyncing.
    #[test_traced("DEBUG")]
    fn test_seal_replay_without_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 25;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            // Seal without a prior append sync.
            let sealed = append.seal().await.unwrap();

            // Seal must not have fsynced.
            let (_durable, _writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(full_syncs, 0, "seal must not invoke Blob::sync");
            assert_eq!(range_syncs, 0, "seal must not invoke Blob::write_at_sync");

            // Replay must observe all bytes even though they were never fsynced.
            let mut replay = sealed.replay(NZUsize!(BUFFER_SIZE)).unwrap();
            assert_eq!(replay.blob_size(), total as u64);

            let mut out = Vec::with_capacity(total);
            while replay.ensure(1).await.unwrap() {
                let chunk = replay.chunk();
                let copy_len = chunk.len();
                out.extend_from_slice(chunk);
                replay.advance(copy_len);
            }
            assert_eq!(out, data);
        });
    }

    /// Bytes made durable via `Sealed::sync` can be reopened through the paged blob format.
    #[test_traced("DEBUG")]
    fn test_sealed_sync_reopens() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let data: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize + 17)
                .collect();
            {
                let (blob, blob_size) = context.open("test_partition", b"reopen").await.unwrap();
                let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                    .await
                    .unwrap();
                append.append(&data).await.unwrap();
                let sealed = append.seal().await.unwrap();
                sealed.sync().await.unwrap();
            }

            let (blob, blob_size) = context.open("test_partition", b"reopen").await.unwrap();
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let mut buf = vec![0; data.len()];
            append.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }
}

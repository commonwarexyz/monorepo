//! Read-only counterpart to [`super::Writer`]: an immutable, page-cache-backed read handle for
//! a blob whose logical content will no longer change.
//!
//! # Sealing
//!
//! [`super::Writer::seal`] returns a [`Sealed`] read handle and starts an fsync. Reads observe
//! flushed bytes immediately, while durability waits for the sync handle.
//!
//! # Cheap sharing
//!
//! [`Sealed`] is `Clone` and shares its state via `Arc<SealedInner>`. Clones do not coordinate via
//! any lock; they share the underlying [`Blob`] handle (which provides its own synchronization)
//! and the page cache.

use super::{
    CHECKSUM_SIZE, CacheRef, Replay,
    read::PageReader,
    view::{Tail, View},
};
use crate::{Blob, Error, IoBuf, IoBufMut, IoBufs, ReadOptions};
use commonware_utils::Widen;
use std::{num::NonZeroUsize, sync::Arc};

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
    blob: Arc<B>,

    /// Size of the sealed view, in bytes.
    size: u64,

    /// Logical bytes of the partial last page, if the blob ends in one. Bytes at offsets
    /// `[size - partial_page.len(), size)` come from here; bytes below come from full pages on the
    /// blob (via the page cache).
    partial_page: Option<IoBuf>,

    /// Reference to the page cache used for reads of full pages.
    cache_ref: CacheRef,

    /// Page-cache id. [`super::Writer::seal`] preserves the writer id so hot full pages remain
    /// valid across the transition. Snapshots share this identity. Full pages stay immutable within
    /// one writer incarnation, and each snapshot owns its frozen partial page.
    id: u64,
}

impl<B: Blob> Sealed<B> {
    /// Construct a [`Sealed`] from already-validated parts. Invoked by [`super::Writer::seal`].
    pub(super) fn new(
        blob: Arc<B>,
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

    /// Returns the size of the blob.
    pub fn size(&self) -> u64 {
        self.inner.size
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

    /// Returns a borrowed view over this blob.
    fn view(&self) -> View<'_, B> {
        View {
            blob: &self.inner.blob,
            cache_ref: &self.inner.cache_ref,
            id: self.inner.id,
            size: self.inner.size,
            tail_offset: self.partial_offset(),
            tail: Tail::Sealed(
                self.inner
                    .partial_page
                    .as_ref()
                    .map_or(&[][..], |p| p.as_ref()),
            ),
        }
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        self.view().read_at(offset, len).await
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from the page cache and/or the in-memory tail. When `false`
    /// is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        self.view().try_read_sync_into(buf, offset)
    }

    /// Reads bytes starting at `offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.view().read_into(buf, offset).await
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
        self.view().read_up_to(offset, len, bufs).await
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
        self.view().read_many_into(buf, offsets, item_size).await
    }

    /// Like [`Self::read_many_into`], but cache misses read from the blob without admitting
    /// pages into the page cache. Suited to bulk scans of items that will not be read again
    /// soon.
    pub async fn read_many_into_uncached(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        self.view()
            .read_many_into_uncached(buf, offsets, item_size)
            .await
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only. Returns the indices of
    /// items that require a blob read. Their slots in `buf` hold unspecified bytes.
    pub fn try_read_many_sync_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Vec<usize> {
        self.view().try_read_many_sync_into(buf, offsets, item_size)
    }

    /// Like [`Self::try_read_many_sync_into`], but for variable-length `(offset, len)` ranges:
    /// `buf` holds one slot per range, back to back.
    pub fn try_read_ranges_sync_into(&self, buf: &mut [u8], ranges: &[(u64, usize)]) -> Vec<usize> {
        self.view().try_read_ranges_sync_into(buf, ranges)
    }

    /// Returns a [Replay] for sequentially reading all logical bytes of the sealed view.
    ///
    /// Sealed values have no write buffer to flush, so unlike [`super::Writer::replay`] this method
    /// is not async. Replay validates full pages read from storage and uses the frozen partial
    /// page. Every underlying blob read uses `read_options`, including refills after seeking.
    pub fn replay(
        &self,
        buffer_size: NonZeroUsize,
        read_options: ReadOptions,
    ) -> Result<Replay<B>, Error> {
        let page_size_nz = self.inner.cache_ref.page_size();
        let page_size: u64 = page_size_nz.widen();
        let physical_page_size = page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        let prefetch_pages = (buffer_size.get() / physical_page_size as usize).max(1);

        let partial_len = self
            .inner
            .partial_page
            .as_ref()
            .map_or(0, |p| p.len() as u64);
        let full_pages = (self.inner.size - partial_len) / page_size;
        let pages = full_pages + u64::from(partial_len > 0);
        let physical_blob_size = physical_page_size
            .checked_mul(pages)
            .ok_or(Error::OffsetOverflow)?;
        let logical_blob_size = self.inner.size;

        let reader = PageReader::new(
            self.inner.blob.clone(),
            physical_blob_size,
            logical_blob_size,
            self.inner.partial_page.clone(),
            prefetch_pages,
            page_size_nz,
            read_options,
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
        Buf, Handle, IoBufsMut, Runner as _, Storage as _, WriteOptions,
        buffer::{
            paged::{CHECKSUM_SLOT_LEN_SIZE, Checksum, Writer},
            tests::SyncTrackingBlob,
        },
        deterministic,
        mocks::{DelayedSyncBlob, next_pending_sync},
    };
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZUsize, channel::oneshot, sync::Mutex};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky page size to test alignment
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    struct WritePause {
        offset: u64,
        prefix_len: usize,
        started: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    /// Exposes a successful write's prefix while its remaining bytes are still pending.
    struct SplitWriteBlob<B> {
        inner: B,
        pause: Mutex<Option<WritePause>>,
    }

    impl<B: Blob> Blob for SplitWriteBlob<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            let mut bufs = bufs.into();
            let pause = self.pause.lock().take();
            let Some(pause) = pause else {
                return self.inner.write_at(offset, bufs, options).await;
            };
            assert_eq!(offset, pause.offset);
            assert!(pause.prefix_len < bufs.len());
            self.inner
                .write_at(offset, bufs.split_to(pause.prefix_len), options)
                .await?;
            pause.started.send(()).unwrap();
            pause.resume.await.unwrap();
            self.inner
                .write_at(offset + Widen::widen(pause.prefix_len), bufs, options)
                .await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    /// Seal a [Writer] and assert the returned sync handle makes it durable.
    #[test_traced("DEBUG")]
    fn test_seal_starts_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let blob = Arc::new(blob);
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append some data crossing several pages but don't sync.
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            let (durable_before, _writes_before, full_before, range_before) = blob.snapshot();
            assert!(
                durable_before.is_empty(),
                "no bytes should be durable before the seal's sync"
            );

            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let (durable_after, _writes_after, full_after, range_after) = blob.snapshot();
            assert_eq!(full_after, full_before + 1);
            assert!(
                !durable_after.is_empty(),
                "the seal's sync handle must make the appended bytes durable"
            );
            assert_eq!(
                range_after, range_before,
                "seal must not invoke a range-scoped write"
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
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            writer.append(b"hello world").await.unwrap();

            // A snapshot captures the buffered bytes as an owned, frozen read handle.
            let reader = writer.snapshot().await.unwrap();
            let reader_clone = reader.clone();
            assert_eq!(reader.size(), 11);

            // Seal succeeds while snapshots exist.
            let (sealed, sync) = writer.seal().await.unwrap();
            sync.await.unwrap();
            assert_eq!(sealed.size(), 11);

            // Both snapshot handles keep reading the frozen state and agree with the sealed view.
            for r in [&reader, &reader_clone] {
                assert_eq!(r.size(), 11);
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
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 3 + 7;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();

            let reader = writer.snapshot().await.unwrap();
            let (sealed, sync) = writer.seal().await.unwrap();
            sync.await.unwrap();
            assert_eq!(reader.size(), total as u64);

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
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();
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
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            assert_eq!(sealed.size(), 0);

            // Out-of-bounds reads error.
            let mut buf = [0u8; 1];
            let err = sealed.read_into(&mut buf, 0).await.unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    /// Sealing a blob whose size is exactly a page-multiple has no partial page.
    #[test_traced("DEBUG")]
    fn test_seal_full_pages_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"full").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append exactly two pages.
            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            assert_eq!(sealed.size(), data.len() as u64);

            // Read everything back.
            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    /// Sealing a blob whose size is smaller than one page yields only a partial page.
    #[test_traced("DEBUG")]
    fn test_seal_partial_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"partial").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Append fewer than one page of data.
            let data: Vec<u8> = (0u8..=50).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // One full page + a partial.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 17;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0u8..=255).cycle().take(250).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two pages worth so reads exercise both cache and partial.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

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

    /// `Sealed::try_read_many_sync_into` serves cached pages and the in-memory tail, and maps
    /// missed ranges (including straddling prefixes) back to item indices.
    #[test_traced("DEBUG")]
    fn test_sealed_try_read_many_sync_into() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_sync").await.unwrap();
            // Capacity of one page makes hit/miss behavior deterministic: the cache holds
            // exactly the last page touched.
            let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two full pages plus a partial tail page held in memory by the sealed view.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            // Items: page 0, straddling pages 0 and 1, page 1, straddling page 1 and the tail,
            // and pure tail.
            let offsets = [
                0u64,
                (page_size - 2) as u64,
                (page_size + 2) as u64,
                (page_size * 2 - 2) as u64,
                (page_size * 2 + 10) as u64,
            ];
            let item_size = 4usize;
            let check = |out: &[u8], indices: &[usize]| {
                for &i in indices {
                    let off = offsets[i] as usize;
                    assert_eq!(
                        &out[i * item_size..(i + 1) * item_size],
                        &data[off..off + item_size],
                    );
                }
            };

            // With only page 0 cached, items touching page 1 are misses. The tail item is
            // served from the sealed view's in-memory bytes.
            sealed.read_at(0, page_size).await.unwrap();
            let mut out = vec![0u8; offsets.len() * item_size];
            let misses = sealed.try_read_many_sync_into(&mut out, &offsets, NZUsize!(item_size));
            assert_eq!(misses, vec![1, 2, 3]);
            check(&out, &[0, 4]);

            // With only page 1 cached, the first two items need page 0.
            sealed.read_at(page_size as u64, page_size).await.unwrap();
            let mut out = vec![0u8; offsets.len() * item_size];
            let misses = sealed.try_read_many_sync_into(&mut out, &offsets, NZUsize!(item_size));
            assert_eq!(misses, vec![0, 1]);
            check(&out, &[2, 3, 4]);
        });
    }

    /// `Sealed::try_read_ranges_sync_into` serves cached pages and the in-memory tail for
    /// variable-length ranges, and maps missed ranges back to range indices, including when a
    /// zero-length range shares its offset with the missed range that follows it.
    #[test_traced("DEBUG")]
    fn test_sealed_try_read_ranges_sync_into() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"rranges_sync")
                .await
                .unwrap();
            // Capacity of one page makes hit/miss behavior deterministic: the cache holds
            // exactly the last page touched.
            let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two full pages plus a partial tail page held in memory by the sealed view.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            // Ranges: page 0, a zero-length range sharing its offset with the page 1 range
            // that follows it, page 1, straddling page 1 and the tail, pure tail.
            let ranges = [
                (0u64, 3usize),
                (page_size as u64 + 5, 0),
                (page_size as u64 + 5, 7),
                ((page_size * 2 - 2) as u64, 4),
                ((page_size * 2 + 10) as u64, 4),
            ];
            let total_len: usize = ranges.iter().map(|&(_, len)| len).sum();
            let check = |out: &[u8], indices: &[usize]| {
                let mut start = 0;
                for (i, &(off, len)) in ranges.iter().enumerate() {
                    if indices.contains(&i) {
                        let off = off as usize;
                        assert_eq!(&out[start..start + len], &data[off..off + len]);
                    }
                    start += len;
                }
            };

            // With only page 0 cached, the page 1 range and the straddler's prefix miss. The
            // zero-length range never misses. The tail range is served in memory.
            sealed.read_at(0, page_size).await.unwrap();
            let mut out = vec![0u8; total_len];
            let misses = sealed.try_read_ranges_sync_into(&mut out, &ranges);
            assert_eq!(misses, vec![2, 3]);
            check(&out, &[0, 4]);

            // With only page 1 cached, range 0 becomes the miss and the rest are served.
            sealed.read_at(page_size as u64, page_size).await.unwrap();
            let mut out = vec![0u8; total_len];
            let misses = sealed.try_read_ranges_sync_into(&mut out, &ranges);
            assert_eq!(misses, vec![0]);
            check(&out, &[1, 2, 3, 4]);
        });
    }

    /// `Sealed::read_many_into` falls back to blob reads for full-page cache misses.
    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into_cache_miss() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_miss").await.unwrap();
            let cache_ref = super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

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

    /// `Sealed::read_many_into_uncached` serves cold reads correctly and leaves the page
    /// cache cold: a subsequent sync probe of the same offsets still misses everything.
    /// Offsets cover same-page clusters (served by one page fetch each) and a range that
    /// crosses a page boundary.
    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into_uncached_leaves_cache_cold() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_cold").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 4).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            // Drop pages admitted during the writer's flushes so the uncached read is cold.
            cache_ref.clear();

            let p = page_size as u64;
            let offsets = [0u64, 8, 40, p, p + 8, 2 * p - 2, 3 * p];
            let item_size = 4usize;
            let mut out = vec![0u8; offsets.len() * item_size];
            sealed
                .read_many_into_uncached(&mut out, &offsets, NZUsize!(item_size))
                .await
                .unwrap();
            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &out[i * item_size..(i + 1) * item_size],
                    &data[off as usize..off as usize + item_size],
                );
            }

            // Nothing was admitted: every offset still requires a blob read.
            let mut out = vec![0u8; offsets.len() * item_size];
            let misses = sealed.try_read_many_sync_into(&mut out, &offsets, NZUsize!(item_size));
            assert_eq!(misses, vec![0, 1, 2, 3, 4, 5, 6]);
        });
    }

    #[test_traced("DEBUG")]
    #[should_panic(expected = "ranges must be sorted and non-overlapping")]
    fn test_sealed_read_many_into_rejects_unsorted_offsets() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany_bad").await.unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[7; 32]).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let mut out = vec![0u8; 8];
            let _ = sealed.read_many_into(&mut out, &[8, 4], NZUsize!(4)).await;
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[7; 32]).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let mut out = vec![0u8; 8];
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

    /// `try_read_sync_into` succeeds when bytes come purely from the in-memory partial page.
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 30;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            // Read fully within partial.
            let mut buf = vec![0u8; 10];
            assert!(sealed.try_read_sync_into(&mut buf, page_size as u64));
            assert_eq!(buf, data[page_size..page_size + 10]);

            // Out of bounds returns false.
            let mut buf = vec![0u8; 10];
            assert!(!sealed.try_read_sync_into(&mut buf, total as u64));
        });
    }

    /// `try_read_sync_into` can stitch a cached full-page prefix to in-memory partial bytes.
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size + 30;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let mut buf = vec![0u8; 12];
            assert!(sealed.try_read_sync_into(&mut buf, (page_size - 4) as u64));
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size + 5).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let mut buf = vec![9u8; 10];
            assert!(!sealed.try_read_sync_into(&mut buf, data.len() as u64));
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Two pages + a partial, synced so the bytes are on disk before sealing.
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 25;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();
            sync.await.unwrap();

            let mut replay = sealed
                .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                .unwrap();
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

    /// Replaying a snapshot must stop at the snapshot's logical boundary, even if the live writer
    /// later extends the same physical page.
    #[test_traced("DEBUG")]
    fn test_snapshot_replay_stays_frozen_after_writer_growth() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_replay_growth")
                .await
                .unwrap();
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let mut original = vec![0xAA; page_size];
            original.extend_from_slice(b"old");
            writer.append(&original).await.unwrap();
            writer.sync().await.unwrap();

            let snapshot = writer.snapshot().await.unwrap();
            let snapshot_bytes = snapshot
                .read_at(0, snapshot.size() as usize)
                .await
                .unwrap()
                .coalesce();
            let mut replay = snapshot
                .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                .unwrap();
            assert_eq!(replay.blob_size(), original.len() as u64);

            writer.append(b"newtail").await.unwrap();
            writer.sync().await.unwrap();

            let mut out = Vec::new();
            while replay.ensure(1).await.unwrap() {
                let chunk = replay.chunk();
                let copy_len = chunk.len();
                out.extend_from_slice(chunk);
                replay.advance(copy_len);
            }

            assert_eq!(out.as_slice(), snapshot_bytes.as_ref());
            assert_eq!(out, original);
        });
    }

    /// Both replay constructors preserve the captured tail during a partial-page rewrite.
    /// The synced snapshot is a control whose fallback already covers the captured tail.
    /// The fallback length assertion verifies the expected disk state was actually reached.
    #[rstest::rstest]
    #[case::partial(0, 13, false, u64::MAX)]
    #[case::page_boundary(1, PAGE_SIZE.get() as usize, false, u64::MAX)]
    #[case::next_page(1, PAGE_SIZE.get() as usize + 7, false, u64::MAX)]
    #[case::synced_snapshot(1, 13, true, u64::MAX)]
    #[case::capped(1, 13, false, u64::from(PAGE_SIZE.get()) + 5)]
    fn test_replay_preserves_tail_during_partial_page_rewrite(
        #[case] full_pages: usize,
        #[case] next_len: usize,
        #[case] sync_snapshot: bool,
        #[case] cap: u64,
        #[values(false, true)] writer_replay: bool,
    ) {
        deterministic::Runner::default().start(|context| async move {
            const DURABLE_TAIL: usize = 3;
            const SNAPSHOT_TAIL: usize = 7;

            // Persist a short partial page, then extend it without advancing its durable slot.
            // The snapshot must retain the longer tail even if disk validation falls back.
            let page_size = PAGE_SIZE.get() as usize;
            let physical_page_size = page_size + CHECKSUM_SIZE as usize;
            let offset = Widen::widen(full_pages * physical_page_size);
            let (inner, size) = context.open("snapshot-replay-race", b"blob").await.unwrap();
            let blob = Arc::new(SplitWriteBlob {
                inner,
                pause: Mutex::new(None),
            });
            let cache = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), size, BUFFER_SIZE, cache)
                .await
                .unwrap();
            let mut expected = vec![0xAA; full_pages * page_size + DURABLE_TAIL];
            writer.append(&expected).await.unwrap();
            writer.sync().await.unwrap();
            let extension = vec![0xBB; SNAPSHOT_TAIL - DURABLE_TAIL];
            writer.append(&extension).await.unwrap();
            expected.extend_from_slice(&extension);
            let snapshot = writer.snapshot().await.unwrap();

            // The synced control has a durable fallback that already includes the snapshot.
            if sync_snapshot {
                writer.sync().await.unwrap();
            }

            // Locate the checksum slot the next flush will rewrite so the pause exposes the
            // new length before its matching checksum, leaving only the other slot valid.
            let page = blob
                .read_at(offset, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let active = Checksum::validate_page(page.as_ref()).unwrap();
            assert_eq!(active.len as usize, SNAPSHOT_TAIL);
            let rewritten_slot = if sync_snapshot {
                active.slot.other()
            } else {
                active.slot
            };

            // Capture each replay before the rewrite. A writer prefix may end inside the
            // frozen tail, beyond the shorter durable fallback. Sealed replay stays uncapped.
            let replay_len = if writer_replay {
                cap.min(Widen::widen(expected.len())) as usize
            } else {
                expected.len()
            };
            let mut replay = if writer_replay {
                writer
                    .replay_prefix(cap, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap()
            } else {
                snapshot
                    .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .unwrap()
            };
            assert_eq!(replay.blob_size(), Widen::widen(replay_len));

            // The writer supplies every byte. A short backend write exposes the new slot length
            // before its CRC, while the other slot still validates the durable prefix.
            writer
                .append(&vec![0xCC; next_len - SNAPSHOT_TAIL])
                .await
                .unwrap();
            let (started, entered) = oneshot::channel();
            let (resume, released) = oneshot::channel();
            *blob.pause.lock() = Some(WritePause {
                offset,
                prefix_len: page_size + rewritten_slot.offset() + CHECKSUM_SLOT_LEN_SIZE,
                started,
                resume: released,
            });
            let mut flushing = Box::pin(writer.snapshot());
            commonware_macros::select! {
                _ = entered => {},
                _ = flushing.as_mut() => panic!("write completed before its suffix was released"),
            }

            // Inspect the paused disk image and both read paths before the write can finish.
            let page = blob
                .read_at(offset, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let fallback_len = Checksum::validate_page(page.as_ref()).unwrap().len as usize;
            let read_at = snapshot
                .read_at(0, expected.len())
                .await
                .unwrap()
                .coalesce();
            let replayed = async {
                let mut out = Vec::new();
                while replay.ensure(1).await? {
                    let chunk = replay.chunk();
                    let len = chunk.len();
                    out.extend_from_slice(chunk);
                    replay.advance(len);
                }
                Ok::<_, Error>(out)
            }
            .await;

            // Complete the successful mutation before checking the independent snapshot read.
            resume.send(()).unwrap();
            flushing.await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(
                fallback_len,
                if sync_snapshot {
                    SNAPSHOT_TAIL
                } else {
                    DURABLE_TAIL
                }
            );
            assert_eq!(read_at.as_ref(), expected);
            let replayed = replayed.unwrap();
            assert_eq!(
                replayed.len(),
                replay_len,
                "replay shortened the immutable snapshot"
            );
            assert_eq!(replayed, expected[..replay_len]);
        });
    }

    /// `Sealed::replay` works without a prior `Append::sync` because `Append::seal` writes bytes
    /// to the blob before starting its sync.
    #[test_traced("DEBUG")]
    fn test_seal_replay_without_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let blob = Arc::new(blob);
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 25;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            let (sealed, sync) = append.seal().await.unwrap();

            let (_durable, _writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
            sync.await.unwrap();

            let mut replay = sealed
                .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                .unwrap();
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

    /// Reads and replay through `Sealed` observe flushed bytes while the seal's sync handle is
    /// still pending; they never wait for durability.
    #[test_traced("DEBUG")]
    fn test_sealed_reads_while_seal_sync_pending() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner);
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 2 + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();

            // Seal parks its sync; leave it parked while reading.
            let (sealed, sync) = append.seal().await.unwrap();
            assert_eq!(pending.lock().len(), 1, "the seal sync should be parked");

            let read = sealed.read_at(0, total).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..]);

            let mut replay = sealed
                .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                .unwrap();
            assert_eq!(replay.blob_size(), total as u64);
            let mut replayed = Vec::new();
            while replay.ensure(1).await.unwrap() {
                let n = {
                    let chunk = replay.chunk();
                    replayed.extend_from_slice(chunk);
                    chunk.len()
                };
                replay.advance(n);
            }
            assert_eq!(replayed, data);
            assert_eq!(
                pending.lock().len(),
                1,
                "reads must not consume the pending sync"
            );

            // Release the sync and confirm the handle completes.
            next_pending_sync(&pending).release.send(Ok(())).unwrap();
            sync.await.unwrap();
        });
    }

    /// Sealing a recovered, already-synced partial page must not rewrite it.
    #[test_traced("DEBUG")]
    fn test_seal_recovered_synced_partial_page_no_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let blob = Arc::new(blob);
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let data: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize - 17)
                .collect();

            {
                let mut writer = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref.clone())
                    .await
                    .unwrap();
                writer.append(&data).await.unwrap();
                writer.sync().await.unwrap();
            }

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            let mut recovered = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(recovered.size(), data.len() as u64);

            recovered.sync().await.unwrap();
            let (_, writes_after_sync, full_after_sync, range_after_sync) = blob.snapshot();
            assert_eq!(
                writes_after_sync, writes,
                "syncing an unchanged recovered partial page must not rewrite it"
            );
            assert_eq!(full_after_sync, full_syncs + 1);
            assert_eq!(range_after_sync, range_syncs);

            let (sealed, sync) = recovered.seal().await.unwrap();
            sync.await.unwrap();
            let (_, writes_after_seal, full_after_seal, range_after_seal) = blob.snapshot();
            assert_eq!(
                writes_after_seal, writes_after_sync,
                "sealing an unchanged recovered partial page must not rewrite it"
            );
            assert_eq!(full_after_seal, full_after_sync);
            assert_eq!(range_after_seal, range_after_sync);

            let read = sealed.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data.as_slice());
        });
    }
}

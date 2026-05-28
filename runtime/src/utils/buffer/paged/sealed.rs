use super::{
    read::{PageReader, Replay},
    read_and_trim, CacheRef, CHECKSUM_SIZE,
};
use crate::{Blob, Error, IoBuf, IoBufMut, IoBufs};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{num::NonZeroU16, sync::Arc};

/// A read-only paged blob wrapper.
///
/// `Sealed` is the counterpart to [`Append`](super::Append) for blobs whose content will no longer
/// change. It exposes only read APIs and contains no write buffer or mutable state, so cloned
/// handles share a fully immutable view and reads never coordinate with a writer.
///
/// All pages but the final one are full. The final page may be partial; its logical bytes are
/// retained in-memory because the page cache only stores full pages.
pub struct Sealed<B: Blob> {
    inner: Arc<SealedInner<B>>,
}

impl<B: Blob> Clone for Sealed<B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// How a `[offset, offset+len)` request splits across the partial-page boundary in a [`Sealed`].
///
/// The cache part always precedes the partial part in the caller's destination buffer because
/// the partial page (if any) sits at the tail of the blob.
#[derive(Clone, Copy)]
struct PartialSplit {
    /// Number of bytes at the start of the destination buffer served from the cache (or disk).
    /// Zero if the entire request lives in the partial page.
    cache_len: usize,
    /// Number of bytes at the end of the destination buffer served from the partial page.
    /// Zero if the entire request lives below the partial page.
    partial_len: usize,
    /// Start of the partial-page slice that supplies the partial part.
    partial_src: usize,
}

struct SealedInner<B: Blob> {
    /// The underlying blob.
    blob: B,

    /// The logical size of the blob in bytes.
    size: u64,

    /// Logical bytes of the final partial page, or `None` if the blob has no partial page (every
    /// page is full or the blob is empty).
    ///
    /// When `Some`, these bytes correspond to the logical range
    /// `[size - partial_page.len(), size)`.
    partial_page: Option<IoBuf>,

    /// Page cache for read caching of full pages.
    cache_ref: CacheRef,

    /// Unique id assigned to this blob by the page cache.
    id: u64,
}

impl<B: Blob> Sealed<B> {
    /// Open a read-only paged view of `blob` that is known to have `blob_size` physical bytes.
    ///
    /// Rewinds the blob if necessary to remove any trailing physical bytes that fail integrity
    /// validation, matching the recovery behavior of [`Append::new`](super::Append::new).
    pub async fn open(blob: B, blob_size: u64, cache_ref: CacheRef) -> Result<Self, Error> {
        let page_size = cache_ref.page_size();
        let (last, _trimmed) = read_and_trim(&blob, blob_size, page_size).await?;

        let (partial_page, full_pages) = match last.partial {
            Some((bytes, _)) => (Some(bytes), last.pages - 1),
            None => (None, last.pages),
        };
        let partial_len = partial_page.as_ref().map_or(0, |p| p.len() as u64);
        let size = full_pages * page_size + partial_len;
        let id = cache_ref.next_id();

        Ok(Self {
            inner: Arc::new(SealedInner {
                blob,
                size,
                partial_page,
                cache_ref,
                id,
            }),
        })
    }

    /// Construct a `Sealed` from already-validated parts.
    ///
    /// Used by [`Append::seal`](super::Append::seal) to avoid re-reading the blob on rollover.
    /// The caller guarantees that `size`, `partial_page`, and `id` are consistent with the
    /// underlying blob and the page cache identified by `cache_ref`.
    pub(super) fn from_parts(
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

    /// Returns the logical size of the blob.
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// The starting offset of the partial page, if the blob ends in a partial page.
    fn partial_page_start(&self) -> Option<u64> {
        self.inner
            .partial_page
            .as_ref()
            .map(|p| self.inner.size - p.len() as u64)
    }

    /// Split a `[offset, offset+len)` request into the cache prefix and partial-page suffix.
    ///
    /// The partial-page region (if any) is always at the tail of the blob, so the cache part
    /// always precedes the partial part in the caller's destination buffer.
    fn split_at_partial(&self, offset: u64, len: usize) -> PartialSplit {
        match self.partial_page_start() {
            Some(partial_start) if offset + len as u64 > partial_start => {
                if offset >= partial_start {
                    PartialSplit {
                        cache_len: 0,
                        partial_len: len,
                        partial_src: (offset - partial_start) as usize,
                    }
                } else {
                    let cache_len = (partial_start - offset) as usize;
                    PartialSplit {
                        cache_len,
                        partial_len: len - cache_len,
                        partial_src: 0,
                    }
                }
            }
            _ => PartialSplit {
                cache_len: len,
                partial_len: 0,
                partial_src: 0,
            },
        }
    }

    /// Copy the partial-page suffix described by `split` into `buf` (a no-op if there is no
    /// partial part). Bytes land at `buf[split.cache_len..]`.
    fn fill_partial(&self, buf: &mut [u8], split: PartialSplit) {
        if split.partial_len == 0 {
            return;
        }
        let partial = self.inner.partial_page.as_ref().unwrap();
        let src = &partial.as_ref()[split.partial_src..split.partial_src + split.partial_len];
        buf[split.cache_len..split.cache_len + split.partial_len].copy_from_slice(src);
    }

    /// Read `buf.len()` bytes if it can be done synchronously (no I/O). Returns `true` only if the
    /// full range was satisfied. The caller is responsible for keeping the request in bounds.
    pub fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        if end_offset > self.inner.size {
            return false;
        }

        let split = self.split_at_partial(offset, buf.len());
        if split.cache_len > 0 {
            let cached = self.inner.cache_ref.read_cached(
                self.inner.id,
                &mut buf[..split.cache_len],
                offset,
            );
            if cached != split.cache_len {
                return false;
            }
        }
        self.fill_partial(buf, split);
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
        if buf.is_empty() {
            return Ok(());
        }

        let split = self.split_at_partial(logical_offset, buf.len());
        self.fill_partial(buf, split);

        if split.cache_len == 0 {
            return Ok(());
        }

        // Fast path: page cache.
        let cache_buf = &mut buf[..split.cache_len];
        let cached = self
            .inner
            .cache_ref
            .read_cached(self.inner.id, cache_buf, logical_offset);
        if cached == split.cache_len {
            return Ok(());
        }

        // Slow path: fault remaining bytes from disk via the cache.
        self.inner
            .cache_ref
            .read(
                &self.inner.blob,
                self.inner.id,
                &mut cache_buf[cached..],
                logical_offset + cached as u64,
            )
            .await
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // SAFETY: `read_into` below initializes all `len` bytes.
        let mut buf = unsafe { self.inner.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Reads up to `len` bytes starting at `logical_offset`, returning whatever is available.
    pub async fn read_up_to(
        &self,
        logical_offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        let mut bufs = bufs.into();
        if len == 0 {
            bufs.truncate(0);
            return Ok((bufs, 0));
        }
        let available = (self.inner.size.saturating_sub(logical_offset) as usize).min(len);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        // SAFETY: `read_into` below fills all `available` bytes.
        unsafe { bufs.set_len(available) };
        self.read_into(bufs.as_mut(), logical_offset).await?;
        Ok((bufs, available))
    }

    /// Read multiple fixed-size items at sorted byte offsets into a contiguous caller buffer.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: usize,
    ) -> Result<(), Error> {
        assert_eq!(
            buf.len(),
            offsets
                .len()
                .checked_mul(item_size)
                .expect("read_many_into buffer length overflow"),
            "read_many_into requires buf.len() == offsets.len() * item_size"
        );
        if offsets.is_empty() {
            return Ok(());
        }
        if item_size == 0 {
            return Ok(());
        }
        // Sorted-ness is the precondition that lets us bounds-check only the last offset —
        // `split_at_partial` does unchecked `offset + item_size` arithmetic, and the sorted
        // invariant guarantees the largest end is at the last slot.
        assert!(
            offsets.is_sorted(),
            "read_many_into requires offsets to be sorted in ascending order"
        );
        let last_end = offsets[offsets.len() - 1]
            .checked_add(item_size as u64)
            .ok_or(Error::OffsetOverflow)?;
        if last_end > self.inner.size {
            return Err(Error::BlobInsufficientLength);
        }

        let mut cache_ranges: Vec<(&mut [u8], u64)> = Vec::new();
        for (item_buf, &offset) in buf.chunks_exact_mut(item_size).zip(offsets.iter()) {
            let split = self.split_at_partial(offset, item_size);
            self.fill_partial(item_buf, split);
            if split.cache_len > 0 {
                cache_ranges.push((&mut item_buf[..split.cache_len], offset));
            }
        }

        if cache_ranges.is_empty() {
            return Ok(());
        }

        // Try the cache for all ranges in one lock acquisition.
        self.inner
            .cache_ref
            .read_cached_many(self.inner.id, &mut cache_ranges);
        if cache_ranges.is_empty() {
            return Ok(());
        }

        // Read remaining cache-miss ranges from disk concurrently.
        let inner = &self.inner;
        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| {
                inner
                    .cache_ref
                    .read(&inner.blob, inner.id, item_buf, *offset)
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(())
    }

    /// Returns a [`Replay`] that sequentially reads all logical bytes from the blob, validating
    /// CRCs along the way.
    // Mirrors [`Append::replay`]'s async signature so callers can use either uniformly. `Sealed`
    // never needs to flush so no await actually occurs here.
    #[allow(clippy::unused_async)]
    pub async fn replay(&self, buffer_size: std::num::NonZeroUsize) -> Result<Replay<B>, Error> {
        let logical_page_size = self.inner.cache_ref.page_size();
        let logical_page_size_nz =
            NonZeroU16::new(logical_page_size as u16).expect("page_size is non-zero");
        let physical_page_size = logical_page_size + CHECKSUM_SIZE;

        let prefetch_pages = (buffer_size.get() / physical_page_size as usize).max(1);

        let partial_len = self
            .inner
            .partial_page
            .as_ref()
            .map(|p| p.len() as u64)
            .unwrap_or(0);
        let full_pages = (self.inner.size - partial_len) / logical_page_size;
        let total_pages = full_pages + u64::from(partial_len > 0);
        let physical_blob_size = physical_page_size * total_pages;
        let logical_blob_size = logical_page_size * full_pages + partial_len;

        let reader = PageReader::new(
            self.inner.blob.clone(),
            physical_blob_size,
            logical_blob_size,
            prefetch_pages,
            logical_page_size_nz,
        );
        Ok(Replay::new(reader))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::append::Append, *};
    use crate::{deterministic, Buf, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_PAGES: usize = 2;

    fn cache_ref(context: &deterministic::Context) -> CacheRef {
        CacheRef::from_pooler(context, PAGE_SIZE, NZUsize!(BUFFER_PAGES))
    }

    async fn write_and_seal(
        context: &deterministic::Context,
        name: &[u8],
        data: &[u8],
    ) -> Sealed<impl crate::Blob> {
        let (blob, size) = context.open("test_partition", name).await.unwrap();
        let append = Append::new(blob, size, BUFFER_PAGES * 115, cache_ref(context))
            .await
            .unwrap();
        if !data.is_empty() {
            append.append(data).await.unwrap();
        }
        append.seal().await.unwrap()
    }

    #[test_traced("DEBUG")]
    fn test_sealed_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let sealed = write_and_seal(&context, b"sealed_empty", &[]).await;
            assert_eq!(sealed.size(), 0);

            // Reading any bytes fails.
            let mut buf = [0u8; 1];
            assert!(sealed.read_into(&mut buf, 0).await.is_err());
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_full_pages() {
        // Exactly two full pages, no partial.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let data: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize * 2)
                .collect();
            let sealed = write_and_seal(&context, b"sealed_full", &data).await;
            assert_eq!(sealed.size(), data.len() as u64);

            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_partial_only() {
        // A single partial page (fewer than `page_size` logical bytes).
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let data: Vec<u8> = (0u8..50).collect();
            let sealed = write_and_seal(&context, b"sealed_partial", &data).await;
            assert_eq!(sealed.size(), data.len() as u64);

            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);

            // Reading from the middle works.
            let mut sub = vec![0u8; 20];
            sealed.read_into(&mut sub, 10).await.unwrap();
            assert_eq!(sub, &data[10..30]);

            // Out-of-bounds read fails.
            let mut over = [0u8; 1];
            assert!(sealed
                .read_into(&mut over, data.len() as u64)
                .await
                .is_err());
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_full_plus_partial_straddle() {
        // Two full pages + a partial last page; exercise reads in full pages, in partial, and
        // straddling the boundary.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page = PAGE_SIZE.get() as u64;
            let data: Vec<u8> = (0u8..=255).cycle().take(page as usize * 2 + 40).collect();
            let sealed = write_and_seal(&context, b"sealed_mix", &data).await;
            assert_eq!(sealed.size(), data.len() as u64);

            // Entirely in full pages: read first 100 bytes.
            let mut a = vec![0u8; 100];
            sealed.read_into(&mut a, 0).await.unwrap();
            assert_eq!(a, &data[..100]);

            // Entirely in partial page.
            let partial_start = page * 2;
            let mut b = vec![0u8; 20];
            sealed.read_into(&mut b, partial_start + 5).await.unwrap();
            assert_eq!(
                b,
                &data[(partial_start + 5) as usize..(partial_start + 25) as usize]
            );

            // Straddle the partial boundary (end of last full page into partial).
            let mut c = vec![0u8; 30];
            sealed.read_into(&mut c, partial_start - 10).await.unwrap();
            assert_eq!(
                c,
                &data[(partial_start - 10) as usize..(partial_start + 20) as usize]
            );

            // Whole blob.
            let mut all = vec![0u8; data.len()];
            sealed.read_into(&mut all, 0).await.unwrap();
            assert_eq!(all, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_read_at_and_read_up_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page = PAGE_SIZE.get() as u64;
            let data: Vec<u8> = (0u8..=255).cycle().take(page as usize * 2 + 17).collect();
            let sealed = write_and_seal(&context, b"sealed_read_at", &data).await;

            // read_at returns the bytes.
            let bufs = sealed.read_at(7, 25).await.unwrap();
            assert_eq!(bufs.coalesce().as_ref(), &data[7..32]);

            // read_up_to limited by request size.
            let pool = sealed.inner.cache_ref.pool().clone();
            let scratch = pool.alloc(64);
            let (out, n) = sealed.read_up_to(10, 20, scratch).await.unwrap();
            assert_eq!(n, 20);
            assert_eq!(out.as_ref(), &data[10..30]);

            // read_up_to limited by remaining bytes.
            let near_end = sealed.size() - 5;
            let scratch2 = pool.alloc(64);
            let (out2, n2) = sealed.read_up_to(near_end, 50, scratch2).await.unwrap();
            assert_eq!(n2, 5);
            assert_eq!(out2.as_ref(), &data[near_end as usize..]);

            // read_up_to past end errors.
            let scratch3 = pool.alloc(8);
            assert!(sealed.read_up_to(sealed.size(), 8, scratch3).await.is_err());
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_read_many_into() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page = PAGE_SIZE.get() as u64;
            let data: Vec<u8> = (0u8..=255).cycle().take(page as usize * 2 + 40).collect();
            let sealed = write_and_seal(&context, b"sealed_many", &data).await;

            // Mix of offsets entirely in full pages, in partial, and straddling.
            let item_size = 4usize;
            let partial_start = page * 2;
            let offsets = vec![
                0u64,
                10,
                page - 2,          // straddles end of page 0 into page 1
                partial_start - 2, // straddles full/partial boundary
                partial_start + 5, // in partial
            ];
            let mut buf = vec![0u8; offsets.len() * item_size];
            sealed
                .read_many_into(&mut buf, &offsets, item_size)
                .await
                .unwrap();
            for (i, &off) in offsets.iter().enumerate() {
                let slot = &buf[i * item_size..(i + 1) * item_size];
                assert_eq!(slot, &data[off as usize..off as usize + item_size]);
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_try_read_sync_partial() {
        // try_read_sync should succeed when bytes are in cache or in the partial page,
        // and bail (return false) when cache misses on the full-page region.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page = PAGE_SIZE.get() as u64;
            let data: Vec<u8> = (0u8..=255).cycle().take(page as usize * 2 + 30).collect();
            let sealed = write_and_seal(&context, b"sealed_sync", &data).await;
            let partial_start = page * 2;

            // Reads entirely in the partial page never need I/O.
            let mut b = [0u8; 10];
            assert!(sealed.try_read_sync(partial_start + 2, &mut b));
            assert_eq!(
                b,
                data[partial_start as usize + 2..partial_start as usize + 12]
            );

            // After sealing from a fresh Append, full pages were cached during append flush,
            // so a sync read should also succeed for full-page bytes.
            let mut c = [0u8; 10];
            assert!(sealed.try_read_sync(0, &mut c));
            assert_eq!(c, data[..10]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_replay_matches_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page = PAGE_SIZE.get() as u64;
            let data: Vec<u8> = (0u8..=255).cycle().take(page as usize * 3 + 7).collect();

            // Write through Append, take an Append replay snapshot.
            let (blob, size) = context
                .open("test_partition", b"sealed_replay")
                .await
                .unwrap();
            let append = Append::new(blob.clone(), size, BUFFER_PAGES * 115, cache_ref(&context))
                .await
                .unwrap();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let mut a_replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();
            assert!(a_replay.ensure(data.len()).await.unwrap());
            let mut a_bytes = Vec::with_capacity(data.len());
            while a_replay.remaining() > 0 {
                let c = a_replay.chunk();
                a_bytes.extend_from_slice(c);
                let len = c.len();
                a_replay.advance(len);
            }
            assert_eq!(a_bytes, data);

            // Now seal and replay; expect identical bytes.
            let sealed = append.seal().await.unwrap();
            let mut s_replay = sealed.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();
            assert!(s_replay.ensure(data.len()).await.unwrap());
            let mut s_bytes = Vec::with_capacity(data.len());
            while s_replay.remaining() > 0 {
                let c = s_replay.chunk();
                s_bytes.extend_from_slice(c);
                let len = c.len();
                s_replay.advance(len);
            }
            assert_eq!(s_bytes, a_bytes);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_open_trims_trailing_junk() {
        // Sealed::open must truncate trailing physical bytes that fail CRC validation.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, size) = context
                .open("test_partition", b"sealed_junk")
                .await
                .unwrap();
            let append = Append::new(blob.clone(), size, BUFFER_PAGES * 115, cache_ref(&context))
                .await
                .unwrap();
            let data: Vec<u8> = (0u8..50).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Append physical junk bytes after the last valid page footer.
            let (raw_blob, raw_size) = context
                .open("test_partition", b"sealed_junk")
                .await
                .unwrap();
            raw_blob.write_at(raw_size, vec![0xAB; 50]).await.unwrap();
            raw_blob.sync().await.unwrap();
            let appended_size = raw_size + 50;

            // Sealed::open should detect the trailing junk and truncate.
            let sealed = Sealed::open(raw_blob, appended_size, cache_ref(&context))
                .await
                .unwrap();
            assert_eq!(sealed.size(), data.len() as u64);
            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_open_empty_and_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Empty blob.
            let (blob, size) = context.open("test_partition", b"empty").await.unwrap();
            let sealed = Sealed::open(blob, size, cache_ref(&context)).await.unwrap();
            assert_eq!(sealed.size(), 0);

            // Full-page blob.
            let (blob, size) = context.open("test_partition", b"full").await.unwrap();
            let append = Append::new(blob.clone(), size, BUFFER_PAGES * 115, cache_ref(&context))
                .await
                .unwrap();
            let page = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page * 2).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (raw_blob, raw_size) = context.open("test_partition", b"full").await.unwrap();
            let sealed = Sealed::open(raw_blob, raw_size, cache_ref(&context))
                .await
                .unwrap();
            assert_eq!(sealed.size(), data.len() as u64);
            let mut buf = vec![0u8; data.len()];
            sealed.read_into(&mut buf, 0).await.unwrap();
            assert_eq!(buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sealed_clone_shares_state() {
        // Cloning Sealed should be cheap and produce a handle that observes the same bytes.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let data: Vec<u8> = (0u8..=255).cycle().take(200).collect();
            let sealed = write_and_seal(&context, b"sealed_clone", &data).await;
            let clone = sealed.clone();

            assert_eq!(sealed.size(), clone.size());
            let mut a = vec![0u8; data.len()];
            let mut b = vec![0u8; data.len()];
            sealed.read_into(&mut a, 0).await.unwrap();
            clone.read_into(&mut b, 0).await.unwrap();
            assert_eq!(a, b);
            assert_eq!(a, data);
        });
    }
}

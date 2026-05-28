use super::{read_and_trim, CacheRef, Checksum, CHECKSUM_SIZE};
use crate::{Blob, Buf, Error, IoBuf, IoBufMut, IoBufs};
use commonware_codec::FixedSize;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{collections::VecDeque, num::NonZeroU16, sync::Arc};
use tracing::error;

/// State for a single buffer of pages read from the blob.
///
/// Each fill produces one `BufferState` containing all pages read in that batch.
/// Navigation skips CRCs by computing offsets rather than creating separate
/// `Bytes` slices per page.
pub(super) struct BufferState {
    /// The raw physical buffer containing pages with interleaved CRCs.
    buffer: IoBuf,
    /// Number of pages in this buffer.
    num_pages: usize,
    /// Logical length of the last page (may be partial).
    last_page_len: usize,
}

/// Async I/O component that prefetches pages and validates CRCs.
///
/// This handles reading batches of pages from the blob, validating their
/// checksums, and producing `BufferState` for the sync buffering layer.
pub(super) struct PageReader<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// Physical page size (logical_page_size + CHECKSUM_SIZE).
    page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    logical_page_size: usize,
    /// The physical size of the blob.
    physical_blob_size: u64,
    /// The logical size of the blob.
    logical_blob_size: u64,
    /// Next page index to read from the blob.
    blob_page: u64,
    /// Number of pages to prefetch at once.
    prefetch_count: usize,
}

impl<B: Blob> PageReader<B> {
    /// Creates a new PageReader.
    ///
    /// The `physical_blob_size` must already exclude any trailing invalid data
    /// (e.g., junk pages from an interrupted write). Each physical page is the same
    /// size on disk, but the CRC record indicates how much logical data it contains.
    /// The last page may be logically partial (CRC length < logical page size), but
    /// all preceding pages must be logically full. A logically partial non-last page
    /// indicates corruption and will cause an `Error::InvalidChecksum`.
    pub(super) const fn new(
        blob: B,
        physical_blob_size: u64,
        logical_blob_size: u64,
        prefetch_count: usize,
        logical_page_size: NonZeroU16,
    ) -> Self {
        let logical_page_size = logical_page_size.get() as usize;
        let page_size = logical_page_size + Checksum::SIZE;

        Self {
            blob,
            page_size,
            logical_page_size,
            physical_blob_size,
            logical_blob_size,
            blob_page: 0,
            prefetch_count,
        }
    }

    /// Returns the logical size of the blob.
    pub(super) const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the physical page size.
    pub(super) const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the logical page size.
    pub(super) const fn logical_page_size(&self) -> usize {
        self.logical_page_size
    }

    /// Fills a buffer with the next batch of pages.
    ///
    /// Returns `Some((BufferState, logical_bytes))` if data was loaded,
    /// `None` if no more data available.
    pub(super) async fn fill(&mut self) -> Result<Option<(BufferState, usize)>, Error> {
        // Calculate physical read offset
        let start_offset = match self.blob_page.checked_mul(self.page_size as u64) {
            Some(o) => o,
            None => return Err(Error::OffsetOverflow),
        };
        if start_offset >= self.physical_blob_size {
            return Ok(None); // No more data
        }

        // Calculate how many pages to read
        let remaining_physical = (self.physical_blob_size - start_offset) as usize;
        let max_pages = remaining_physical / self.page_size;
        let pages_to_read = max_pages.min(self.prefetch_count);
        if pages_to_read == 0 {
            return Ok(None);
        }
        let bytes_to_read = pages_to_read * self.page_size;

        // Read physical data
        let physical_buf = self
            .blob
            .read_at(start_offset, bytes_to_read)
            .await?
            .coalesce()
            .freeze();

        // Validate CRCs and compute total logical bytes
        let mut total_logical = 0usize;
        let mut last_len = 0usize;
        let is_final_batch = pages_to_read == max_pages;
        for page_idx in 0..pages_to_read {
            let page_start = page_idx * self.page_size;
            let page_slice = &physical_buf.as_ref()[page_start..page_start + self.page_size];
            let Some(record) = Checksum::validate_page(page_slice) else {
                error!(page = self.blob_page + page_idx as u64, "CRC mismatch");
                return Err(Error::InvalidChecksum);
            };
            let (len, _) = record.get_crc();
            let len = len as usize;

            // Only the final page in the blob may have partial length
            let is_last_page_in_blob = is_final_batch && page_idx + 1 == pages_to_read;
            if !is_last_page_in_blob && len != self.logical_page_size {
                error!(
                    page = self.blob_page + page_idx as u64,
                    expected = self.logical_page_size,
                    actual = len,
                    "non-last page has partial length"
                );
                return Err(Error::InvalidChecksum);
            }

            total_logical += len;
            last_len = len;
        }
        self.blob_page += pages_to_read as u64;

        let state = BufferState {
            buffer: physical_buf,
            num_pages: pages_to_read,
            last_page_len: last_len,
        };

        Ok(Some((state, total_logical)))
    }
}

/// Sync buffering component that implements the `Buf` trait.
///
/// This accumulates `BufferState` from multiple fills and provides navigation
/// across pages while skipping CRCs. Consumed buffers are cleaned up in
/// `advance()`.
struct ReplayBuf {
    /// Physical page size (logical_page_size + CHECKSUM_SIZE).
    page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    logical_page_size: usize,
    /// Accumulated buffers from fills.
    buffers: VecDeque<BufferState>,
    /// Current page index within the front buffer.
    current_page: usize,
    /// Current offset within the current page's logical data.
    offset_in_page: usize,
    /// Total remaining logical bytes across all buffers.
    remaining: usize,
}

impl ReplayBuf {
    /// Creates a new ReplayBuf.
    const fn new(page_size: usize, logical_page_size: usize) -> Self {
        Self {
            page_size,
            logical_page_size,
            buffers: VecDeque::new(),
            current_page: 0,
            offset_in_page: 0,
            remaining: 0,
        }
    }

    /// Clears the buffer and resets the read offset to 0.
    fn clear(&mut self) {
        self.buffers.clear();
        self.current_page = 0;
        self.offset_in_page = 0;
        self.remaining = 0;
    }

    /// Adds a buffer from a fill operation.
    fn push(&mut self, state: BufferState, logical_bytes: usize) {
        // If buffers is empty, this is the first fill after a seek.
        // Skip bytes before the seek offset (offset_in_page).
        let skip = if self.buffers.is_empty() {
            self.offset_in_page
        } else {
            0
        };
        self.buffers.push_back(state);
        self.remaining += logical_bytes.saturating_sub(skip);
    }

    /// Returns the logical length of the given page in the given buffer.
    const fn page_len(buf: &BufferState, page_idx: usize, logical_page_size: usize) -> usize {
        if page_idx + 1 == buf.num_pages {
            buf.last_page_len
        } else {
            logical_page_size
        }
    }
}

impl Buf for ReplayBuf {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        let Some(buf) = self.buffers.front() else {
            return &[];
        };
        if self.current_page >= buf.num_pages {
            return &[];
        }
        let page_len = Self::page_len(buf, self.current_page, self.logical_page_size);
        let physical_start = self.current_page * self.page_size + self.offset_in_page;
        let physical_end = self.current_page * self.page_size + page_len;
        &buf.buffer.as_ref()[physical_start..physical_end]
    }

    fn advance(&mut self, mut cnt: usize) {
        self.remaining = self.remaining.saturating_sub(cnt);

        while cnt > 0 {
            let Some(buf) = self.buffers.front() else {
                break;
            };

            // Advance within current buffer
            while cnt > 0 && self.current_page < buf.num_pages {
                let page_len = Self::page_len(buf, self.current_page, self.logical_page_size);
                let available = page_len - self.offset_in_page;
                if cnt < available {
                    self.offset_in_page += cnt;
                    return;
                }
                cnt -= available;
                self.current_page += 1;
                self.offset_in_page = 0;
            }

            // Current buffer exhausted, move to next
            if self.current_page >= buf.num_pages {
                self.buffers.pop_front();
                self.current_page = 0;
                self.offset_in_page = 0;
            }
        }
    }
}

/// Replays logical data from a blob containing pages with interleaved CRCs.
///
/// This combines async I/O (`PageReader`) with sync buffering (`ReplayBuf`)
/// to provide an `ensure(n)` + `Buf` interface for codec decoding.
pub struct Replay<B: Blob> {
    /// Async I/O component.
    reader: PageReader<B>,
    /// Sync buffering component.
    buffer: ReplayBuf,
    /// Whether the blob has been fully read.
    exhausted: bool,
}

impl<B: Blob> Replay<B> {
    /// Creates a new Replay from a PageReader.
    pub(super) const fn new(reader: PageReader<B>) -> Self {
        let page_size = reader.page_size();
        let logical_page_size = reader.logical_page_size();
        Self {
            reader,
            buffer: ReplayBuf::new(page_size, logical_page_size),
            exhausted: false,
        }
    }

    /// Returns the logical size of the blob.
    pub const fn blob_size(&self) -> u64 {
        self.reader.blob_size()
    }

    /// Returns true if the reader has been exhausted (no more pages to read).
    ///
    /// When exhausted, the buffer may still contain data that hasn't been consumed.
    /// Callers should check `remaining()` to see if there's data left to process.
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Ensures at least `n` bytes are available in the buffer.
    ///
    /// This method fills the buffer from the blob until either:
    /// - At least `n` bytes are available (returns `Ok(true)`)
    /// - The blob is exhausted with fewer than `n` bytes (returns `Ok(false)`)
    /// - A read error occurs (returns `Err`)
    ///
    /// When `Ok(false)` is returned, callers should still attempt to process
    /// the remaining bytes in the buffer (check `remaining()`), as they may
    /// contain valid data that doesn't require the full `n` bytes.
    pub async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        while self.buffer.remaining < n && !self.exhausted {
            match self.reader.fill().await? {
                Some((state, logical_bytes)) => {
                    self.buffer.push(state, logical_bytes);
                }
                None => {
                    self.exhausted = true;
                }
            }
        }
        Ok(self.buffer.remaining >= n)
    }

    /// Seeks to `offset` in the blob, returning `Err(BlobInsufficientLength)` if `offset` exceeds
    /// the blob size.
    pub fn seek_to(&mut self, offset: u64) -> Result<(), Error> {
        if offset > self.reader.blob_size() {
            return Err(Error::BlobInsufficientLength);
        }

        self.buffer.clear();
        self.exhausted = false;

        let page_size = self.reader.logical_page_size as u64;
        self.reader.blob_page = offset / page_size;
        self.buffer.current_page = 0;
        self.buffer.offset_in_page = (offset % page_size) as usize;

        Ok(())
    }
}

impl<B: Blob> Buf for Replay<B> {
    fn remaining(&self) -> usize {
        self.buffer.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.buffer.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.buffer.advance(cnt);
    }
}

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
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_PAGES: usize = 2;

    #[test_traced("DEBUG")]
    fn test_replay_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Create Replay
            let mut replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Ensure all data is available
            replay.ensure(300).await.unwrap();

            // Verify we got all the data
            assert_eq!(replay.remaining(), 300);

            // Read all data via Buf interface
            let mut collected = Vec::new();
            while replay.remaining() > 0 {
                let chunk = replay.chunk();
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
            }
            assert_eq!(collected, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_partial_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data that doesn't fill the last page
            let data: Vec<u8> = (1u8..=(PAGE_SIZE.get() + 10) as u8).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let mut replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Ensure all data is available
            replay.ensure(data.len()).await.unwrap();

            assert_eq!(replay.remaining(), data.len());
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_cross_buffer_boundary() {
        // Use prefetch_count=1 to force separate BufferStates per page.
        // This tests navigation across multiple BufferStates in the VecDeque.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning 4 pages (4 * 103 = 412 bytes, with last page partial)
            let data: Vec<u8> = (0u8..=255).cycle().take(400).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Create Replay with buffer size that results in prefetch_count=1.
            // Physical page size = 103 + 12 = 115 bytes.
            // Buffer size of 115 gives prefetch_pages = 115/115 = 1.
            let mut replay = append.replay(NZUsize!(115)).await.unwrap();

            // Ensure all data - this requires 4 separate fill() calls (one per page).
            // Each fill() creates a new BufferState, so we'll have 4 BufferStates.
            assert!(replay.ensure(400).await.unwrap());
            assert_eq!(replay.remaining(), 400);

            // Read all data via Buf interface, verifying navigation across BufferStates.
            let mut collected = Vec::new();
            let mut chunks_read = 0;
            while replay.remaining() > 0 {
                let chunk = replay.chunk();
                assert!(
                    !chunk.is_empty(),
                    "chunk() returned empty but remaining > 0"
                );
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
                chunks_read += 1;
            }

            assert_eq!(collected, data);
            // With prefetch_count=1 and 4 pages, we expect at least 4 chunks
            // (one per page, though partial reads could result in more).
            assert!(
                chunks_read >= 4,
                "Expected at least 4 chunks for 4 pages, got {}",
                chunks_read
            );
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_empty_blob() {
        // Test that replaying an empty blob works correctly.
        // ensure() should return Ok(false) when no data is available.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Don't write any data - blob remains empty
            assert_eq!(append.size().await, 0);

            // Create Replay on empty blob
            let mut replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Verify initial state - remaining is 0, but not yet marked exhausted
            // (exhausted is set after first fill attempt)
            assert_eq!(replay.remaining(), 0);

            // ensure(0) should succeed (we have >= 0 bytes)
            assert!(replay.ensure(0).await.unwrap());

            // ensure(1) should return Ok(false) - not enough data, and marks exhausted
            assert!(!replay.ensure(1).await.unwrap());

            // Now should be marked as exhausted after the fill attempt
            assert!(replay.is_exhausted());

            // chunk() should return empty slice
            assert!(replay.chunk().is_empty());

            // remaining should still be 0
            assert_eq!(replay.remaining(), 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_replay_seek_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let mut replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Seek forward, read, then seek backward
            replay.seek_to(150).unwrap();
            replay.ensure(50).await.unwrap();
            assert_eq!(replay.get_u8(), data[150]);

            // Seek back to start
            replay.seek_to(0).unwrap();
            replay.ensure(1).await.unwrap();
            assert_eq!(replay.get_u8(), data[0]);

            // Seek beyond blob size should error
            assert!(replay.seek_to(data.len() as u64 + 1).is_err());

            // Test that remaining() is correct after seek by reading all data.
            let seek_offset = 150usize;
            replay.seek_to(seek_offset as u64).unwrap();
            let expected_remaining = data.len() - seek_offset;
            // Read all bytes and verify content
            let mut collected = Vec::new();
            loop {
                // Load more data if needed
                if !replay.ensure(1).await.unwrap() {
                    break; // No more data available
                }
                let chunk = replay.chunk();
                if chunk.is_empty() {
                    break;
                }
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                replay.advance(len);
            }
            assert_eq!(
                collected.len(),
                expected_remaining,
                "After seeking to {}, should read {} bytes but got {}",
                seek_offset,
                expected_remaining,
                collected.len()
            );
            assert_eq!(collected, &data[seek_offset..]);
        });
    }

    // ----- Sealed tests -----

    fn cache_ref(context: &deterministic::Context) -> super::super::CacheRef {
        super::super::CacheRef::from_pooler(context, PAGE_SIZE, NZUsize!(BUFFER_PAGES))
    }

    async fn write_and_seal(
        context: &deterministic::Context,
        name: &[u8],
        data: &[u8],
    ) -> super::Sealed<impl crate::Blob> {
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
            let sealed = super::Sealed::open(raw_blob, appended_size, cache_ref(&context))
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
            let sealed = super::Sealed::open(blob, size, cache_ref(&context))
                .await
                .unwrap();
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
            let sealed = super::Sealed::open(raw_blob, raw_size, cache_ref(&context))
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

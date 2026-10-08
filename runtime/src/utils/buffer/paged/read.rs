use super::{CacheRef, Checksum};
use crate::{Blob, Error, IoBuf, ReadOptions};
use bytes::{BufMut, Bytes, BytesMut, TryGetError};
use commonware_codec::{Buf, FixedSize};
use commonware_utils::Widen;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{error, warn};

/// Destination for the pages a [PageReader] validates.
pub(super) struct ReplayCache {
    /// Page cache to populate.
    pub(super) cache_ref: CacheRef,
    /// Cache key identifying the blob being read.
    pub(super) blob_id: u64,
    /// Shrink count of a recovering blob, paired with its value when the replay began. A shrink can
    /// replace pages read before it, so pages are published only while the count is unchanged. An
    /// append-only blob never shrinks and carries none.
    pub(super) shrinks: Option<(Arc<AtomicU64>, u64)>,
}

impl ReplayCache {
    /// Whether no shrink has happened since the replay began.
    fn current(&self) -> bool {
        self.shrinks
            .as_ref()
            .is_none_or(|(shrinks, start)| shrinks.load(Ordering::Relaxed) == *start)
    }
}

/// Buffered pages from storage or a frozen logical tail.
///
/// Storage batches contain pages with interleaved CRCs. The frozen tail contains one partial
/// logical page without CRCs. Navigation uses offsets rather than separate `Bytes` slices per page.
pub(super) struct BufferState {
    /// Page bytes, with interleaved CRCs when read from storage.
    buffer: Bytes,
    /// Number of pages in this buffer.
    num_pages: usize,
    /// Logical length of the last page (may be partial).
    last_page_len: usize,
}

/// How a [PageReader] handles a stored page that is not well-formed: one whose checksum is
/// invalid, or a logically partial page before the last.
#[derive(Clone, Copy)]
pub(super) enum Malformed {
    /// Fail the read with [Error::InvalidChecksum].
    Fail,
    /// End the blob's readable prefix before an invalid page, or after a partial one.
    End,
}

/// Async I/O component that prefetches pages and validates CRCs.
///
/// This handles reading batches of pages from the blob, validating their
/// checksums, and producing `BufferState` for the sync buffering layer.
pub(super) struct PageReader<B: Blob> {
    /// The underlying blob to read from.
    blob: Arc<B>,
    /// Physical page size (page_size + CHECKSUM_SIZE).
    physical_page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    page_size: usize,
    /// Physical bytes to read from storage, excluding the frozen partial page.
    physical_blob_size: u64,
    /// The size of the blob.
    logical_blob_size: u64,
    /// Immutable logical bytes of the final partial page.
    partial_page: Option<Bytes>,
    /// Next page index to read from the blob.
    blob_page: u64,
    /// Number of pages to prefetch at once.
    prefetch_count: usize,
    /// Destination for pages validated while filling a batch.
    cache: ReplayCache,
    /// Options applied to every blob read.
    read_options: ReadOptions,
    /// Handling of a stored page that is not well-formed.
    malformed: Malformed,
}

impl<B: Blob> PageReader<B> {
    /// Creates a new PageReader.
    ///
    /// The `physical_blob_size` must already exclude any trailing invalid data
    /// (e.g., junk pages from an interrupted write). Each physical page is the same
    /// size on disk, but the CRC record indicates how much logical data it contains.
    /// The last page may be logically partial (CRC length < logical page size), but
    /// all preceding pages must be logically full. A page with an invalid checksum or a
    /// logically partial non-last page is handled according to `malformed`.
    ///
    /// A frozen `partial_page` contains exactly the logical bytes of the final partial page.
    /// Its physical page is included in `physical_blob_size` but is not read from storage.
    /// Ending at an earlier malformed page discards the frozen page.
    ///
    /// Every full page validated while filling a batch is written into `cache`, so a replay warms
    /// the same cache ordinary reads use instead of leaving it cold.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        blob: Arc<B>,
        mut physical_blob_size: u64,
        logical_blob_size: u64,
        partial_page: Option<IoBuf>,
        prefetch_count: usize,
        cache: ReplayCache,
        read_options: ReadOptions,
        malformed: Malformed,
    ) -> Self {
        let page_size = cache.cache_ref.page_size().get() as usize;
        let physical_page_size = page_size + Checksum::SIZE;
        let physical_pages = physical_blob_size / physical_page_size as u64;
        let logical_pages = if logical_blob_size == 0 {
            0
        } else {
            ((logical_blob_size - 1) / page_size as u64) + 1
        };
        assert_eq!(physical_blob_size % physical_page_size as u64, 0);
        assert_eq!(physical_pages, logical_pages);
        if let Some(partial_page) = &partial_page {
            assert!(
                !partial_page.is_empty()
                    && Widen::widen(partial_page.len())
                        == logical_blob_size % Widen::widen(page_size),
                "frozen tail must match the final partial page"
            );
            physical_blob_size -= Widen::widen(physical_page_size);
        }

        Self {
            blob,
            physical_page_size,
            page_size,
            physical_blob_size,
            logical_blob_size,
            partial_page: partial_page.map(Bytes::from),
            blob_page: 0,
            prefetch_count,
            cache,
            read_options,
            malformed,
        }
    }

    /// End the readable prefix after `pages` pages and `logical_size` logical bytes.
    fn end_at(&mut self, pages: u64, logical_size: u64) -> Result<(), Error> {
        self.physical_blob_size = pages
            .checked_mul(Widen::widen(self.physical_page_size))
            .ok_or(Error::OffsetOverflow)?;
        self.logical_blob_size = self.logical_blob_size.min(logical_size);
        self.partial_page = None;
        Ok(())
    }

    /// Returns the size of the blob.
    pub(super) const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the physical page size.
    pub(super) const fn physical_page_size(&self) -> usize {
        self.physical_page_size
    }

    /// Returns the logical page size.
    pub(super) const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Fills a buffer with the next batch of pages.
    ///
    /// Returns `Some((BufferState, logical_bytes))` if data was loaded,
    /// `None` if no more data available.
    pub(super) async fn fill(&mut self) -> Result<Option<(BufferState, usize)>, Error> {
        // Calculate physical read offset
        let start_offset = match self.blob_page.checked_mul(self.physical_page_size as u64) {
            Some(o) => o,
            None => return Err(Error::OffsetOverflow),
        };
        if start_offset == self.physical_blob_size
            && let Some(partial_page) = &self.partial_page
        {
            self.blob_page += 1;
            let len = partial_page.len();
            return Ok(Some((
                BufferState {
                    buffer: partial_page.clone(),
                    num_pages: 1,
                    last_page_len: len,
                },
                len,
            )));
        }
        if start_offset >= self.physical_blob_size {
            return Ok(None); // No more data
        }

        // Keep the total page count in u64 and narrow only the bounded batch.
        let max_pages =
            (self.physical_blob_size - start_offset) / Widen::widen(self.physical_page_size);
        let pages_to_read = max_pages.min(Widen::widen(self.prefetch_count)) as usize;
        if pages_to_read == 0 {
            return Ok(None);
        }
        let bytes_to_read = pages_to_read * self.physical_page_size;

        // Read physical data
        let physical_buf = Bytes::from(
            self.blob
                .read_at(start_offset, bytes_to_read, self.read_options)
                .await?
                .coalesce()
                .freeze(),
        );

        // Validate CRCs and compute total logical bytes. Ending at a malformed page keeps only
        // the pages before it, plus the page itself when it is valid but partial.
        let mut pages = pages_to_read;
        let mut total_logical = 0usize;
        let mut last_len = 0usize;
        let is_final_batch = Widen::widen(pages_to_read) == max_pages;
        for page_idx in 0..pages_to_read {
            let page = self.blob_page + page_idx as u64;
            let logical_start = page
                .checked_mul(self.page_size as u64)
                .ok_or(Error::OffsetOverflow)?;
            let page_start = page_idx * self.physical_page_size;
            let page_slice =
                &physical_buf.as_ref()[page_start..page_start + self.physical_page_size];
            let Some(checksum) = Checksum::validate_page(page_slice) else {
                if matches!(self.malformed, Malformed::End) {
                    warn!(page, "replay ends before page with invalid checksum");
                    pages = page_idx;
                    self.end_at(page, logical_start)?;
                    break;
                }
                error!(page, "CRC mismatch");
                return Err(Error::InvalidChecksum);
            };
            let len = checksum.len as usize;

            // Only the final page in the blob may have partial length
            let is_last_page_in_blob =
                self.partial_page.is_none() && is_final_batch && page_idx + 1 == pages_to_read;
            let partial_interior = !is_last_page_in_blob && len != self.page_size;
            if partial_interior && matches!(self.malformed, Malformed::Fail) {
                error!(
                    page,
                    expected = self.page_size,
                    actual = len,
                    "non-last page has partial length"
                );
                return Err(Error::InvalidChecksum);
            }

            let logical_remaining = self.logical_blob_size.saturating_sub(logical_start);
            let logical_remaining_in_page = logical_remaining.min(self.page_size as u64) as usize;
            let exposed_len = len.min(logical_remaining_in_page);

            total_logical += exposed_len;
            last_len = exposed_len;

            // A valid partial page ends the prefix wherever it appears.
            if partial_interior {
                warn!(page, len, "replay ends at partial page");
                pages = page_idx + 1;
                let logical_end = logical_start
                    .checked_add(len as u64)
                    .ok_or(Error::OffsetOverflow)?;
                self.end_at(page + 1, logical_end)?;
                break;
            }
        }

        // Cache every validated page that is logically full; a page exposing fewer bytes sits at
        // the blob's current end and is not page-aligned for the cache.
        let full_pages = if pages > 0 && last_len == self.page_size {
            pages
        } else {
            pages.saturating_sub(1)
        };
        if full_pages > 0 {
            let physical_page_size = self.physical_page_size;
            let page_size = self.page_size;

            // A shrink bumps the count before the writer re-caches any page it replaces, and
            // re-caching takes the same lock, so this check cannot let old bytes overwrite new ones.
            self.cache.cache_ref.cache_pages_if(
                self.cache.blob_id,
                (0..full_pages).map(|idx| {
                    let start = idx * physical_page_size;
                    &physical_buf.as_ref()[start..start + page_size]
                }),
                self.blob_page * page_size as u64,
                || self.cache.current(),
            );
        }

        self.blob_page += Widen::widen(pages);
        if pages == 0 {
            return Ok(None);
        }

        let state = BufferState {
            buffer: physical_buf,
            num_pages: pages,
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
    /// Physical page size (page_size + CHECKSUM_SIZE).
    physical_page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    page_size: usize,
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
    const fn new(physical_page_size: usize, page_size: usize) -> Self {
        Self {
            physical_page_size,
            page_size,
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
            // A recoverable replay can end its prefix before the seek offset, which leaves the
            // cursor at the new end.
            self.offset_in_page =
                self.offset_in_page
                    .min(Self::page_len(&state, 0, self.page_size));
            self.offset_in_page
        } else {
            0
        };
        self.buffers.push_back(state);
        self.remaining += logical_bytes.saturating_sub(skip);
    }

    /// Returns the logical length of the given page in the given buffer.
    const fn page_len(buf: &BufferState, page_idx: usize, page_size: usize) -> usize {
        if page_idx + 1 == buf.num_pages {
            buf.last_page_len
        } else {
            page_size
        }
    }
}

impl Buf for ReplayBuf {}

impl bytes::Buf for ReplayBuf {
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(len <= self.remaining, "copy_to_bytes out of bounds");
        if len == 0 {
            return Bytes::new();
        }
        if len <= self.chunk().len() {
            let buffer = &self.buffers.front().expect("readable buffer").buffer;
            let start = self.current_page * self.physical_page_size + self.offset_in_page;
            let bytes = buffer.slice(start..start + len);
            self.advance(len);
            return bytes;
        }

        // A field spanning pages must be coalesced around the interleaved checksums
        let mut bytes = BytesMut::with_capacity(len);
        bytes.put(self.take(len));
        bytes.freeze()
    }

    fn remaining(&self) -> usize {
        self.remaining
    }

    #[inline(always)]
    fn try_copy_to_slice(&mut self, mut dst: &mut [u8]) -> Result<(), TryGetError> {
        if dst.len() > self.remaining {
            return Err(TryGetError {
                requested: dst.len(),
                available: self.remaining,
            });
        }

        // Fast path: the request ends strictly inside the current page, so the cursor
        // stays on this page and no page or buffer transition is needed.
        let chunk = self.chunk();
        if dst.len() < chunk.len() {
            dst.copy_from_slice(&chunk[..dst.len()]);
            self.offset_in_page += dst.len();
            self.remaining -= dst.len();
            return Ok(());
        }

        while !dst.is_empty() {
            let src = self.chunk();
            let cnt = usize::min(src.len(), dst.len());
            dst[..cnt].copy_from_slice(&src[..cnt]);
            dst = &mut dst[cnt..];
            self.advance(cnt);
        }
        Ok(())
    }

    fn chunk(&self) -> &[u8] {
        let Some(buf) = self.buffers.front() else {
            return &[];
        };
        if self.current_page >= buf.num_pages {
            return &[];
        }
        let page_len = Self::page_len(buf, self.current_page, self.page_size);
        let physical_start = self.current_page * self.physical_page_size + self.offset_in_page;
        let physical_end = self.current_page * self.physical_page_size + page_len;
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
                let page_len = Self::page_len(buf, self.current_page, self.page_size);
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
///
/// Nonempty byte fields within one page share the allocation backing the entire prefetched batch.
/// Retaining such a field keeps that allocation alive after the replay advances or is dropped,
/// delaying reuse of pooled buffers. Fields spanning pages are copied into separate allocations.
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
        let physical_page_size = reader.physical_page_size();
        let page_size = reader.page_size();
        Self {
            reader,
            buffer: ReplayBuf::new(physical_page_size, page_size),
            exhausted: false,
        }
    }

    /// Returns the size of the blob.
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

        let page_size = self.reader.page_size as u64;
        self.reader.blob_page = offset / page_size;
        self.buffer.current_page = 0;
        self.buffer.offset_in_page = (offset % page_size) as usize;

        Ok(())
    }
}

impl<B: Blob> Buf for Replay<B> {}

impl<B: Blob> bytes::Buf for Replay<B> {
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.buffer.copy_to_bytes(len)
    }

    fn remaining(&self) -> usize {
        self.buffer.remaining()
    }

    #[inline(always)]
    fn try_copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), TryGetError> {
        self.buffer.try_copy_to_slice(dst)
    }

    fn chunk(&self) -> &[u8] {
        self.buffer.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.buffer.advance(cnt);
    }
}

#[cfg(test)]
mod tests {
    use super::{super::writer::Writer, *};
    use crate::{Runner as _, Storage as _, deterministic};
    use bytes::Buf as _;
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZUsize};
    use std::num::NonZeroU16;

    #[test]
    fn test_replay_buf_bytes_share_pages() {
        let source = bytes::Bytes::from_static(b"abcd............efgh............");
        let range = source.as_ptr_range();
        let mut replay = ReplayBuf::new(16, 4);
        replay.push(
            BufferState {
                buffer: source,
                num_pages: 2,
                last_page_len: 4,
            },
            8,
        );

        let first = replay.copy_to_bytes(3);
        assert_eq!(first.as_ref(), b"abc");
        assert!(range.contains(&first.as_ptr()));

        let crossing = replay.copy_to_bytes(3);
        assert_eq!(crossing.as_ref(), b"def");
        assert!(!range.contains(&crossing.as_ptr()));

        let last = replay.copy_to_bytes(2);
        assert_eq!(last.as_ref(), b"gh");
        assert!(range.contains(&last.as_ptr()));
        assert_eq!(replay.remaining(), 0);
    }

    #[test]
    fn test_replay_buf_copy_to_slice_page_boundaries() {
        let source = bytes::Bytes::from_static(b"abcd............efgh............ijkl............");
        let mut replay = ReplayBuf::new(16, 4);
        replay.push(
            BufferState {
                buffer: source,
                num_pages: 3,
                last_page_len: 4,
            },
            12,
        );

        // Ends inside the first page.
        let mut inside = [0u8; 3];
        replay.try_copy_to_slice(&mut inside).unwrap();
        assert_eq!(&inside, b"abc");
        assert_eq!(replay.chunk(), b"d");
        assert_eq!(replay.remaining(), 9);

        // Ends exactly at the end of a non-final page.
        let mut boundary = [0u8; 1];
        replay.try_copy_to_slice(&mut boundary).unwrap();
        assert_eq!(&boundary, b"d");
        assert_eq!(replay.chunk(), b"efgh");
        assert_eq!(replay.remaining(), 8);

        // Spans the page boundary.
        let mut spanning = [0u8; 6];
        replay.try_copy_to_slice(&mut spanning).unwrap();
        assert_eq!(&spanning, b"efghij");
        assert_eq!(replay.chunk(), b"kl");
        assert_eq!(replay.remaining(), 2);

        // Ends exactly at the end of the last page.
        let mut tail = [0u8; 2];
        replay.try_copy_to_slice(&mut tail).unwrap();
        assert_eq!(&tail, b"kl");
        assert_eq!(replay.chunk(), b"");
        assert_eq!(replay.remaining(), 0);

        let err = replay.try_copy_to_slice(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.requested, 1);
        assert_eq!(err.available, 0);
    }

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
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            // Create Replay
            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data that doesn't fill the last page
            let data: Vec<u8> = (1u8..=(PAGE_SIZE.get() + 10) as u8).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning 4 pages (4 * 103 = 412 bytes, with last page partial)
            let data: Vec<u8> = (0u8..=255).cycle().take(400).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            // Create Replay with buffer size that results in prefetch_count=1.
            // Physical page size = 103 + 12 = 115 bytes.
            // Buffer size of 115 gives prefetch_pages = 115/115 = 1.
            let (_, mut replay) = append
                .replay(NZUsize!(115), ReadOptions::default())
                .await
                .unwrap();

            // Load all four logical pages with one-page prefetches and a frozen partial tail.
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
            let append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Don't write any data - blob remains empty
            assert_eq!(append.size(), 0);

            // Create Replay on empty blob
            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_PAGES * 115, cache_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            (append, _) = append.append(&data).await.unwrap();
            append = append.sync().await.unwrap();

            let (_, mut replay) = append
                .replay(NZUsize!(BUFFER_PAGES), ReadOptions::default())
                .await
                .unwrap();

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

            // Seek into the blob, then drain the remaining bytes and verify their exact contents.
            let seek_offset = 150usize;
            replay.seek_to(seek_offset as u64).unwrap();
            let expected_remaining = data.len() - seek_offset;
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

            // Seeking into the frozen tail must work after exhaustion, including at EOF.
            for offset in [data.len(), 250, 299] {
                replay.seek_to(Widen::widen(offset)).unwrap();
                let remaining = data.len() - offset;
                assert!(!replay.ensure(remaining + 1).await.unwrap());
                assert_eq!(replay.copy_to_bytes(remaining).as_ref(), &data[offset..]);
            }
        });
    }
}

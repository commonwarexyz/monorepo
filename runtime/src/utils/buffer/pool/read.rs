use super::Checksum;
use crate::{Blob, Buf, Error, IoBufMut};
use commonware_codec::FixedSize;
use std::{collections::VecDeque, num::NonZeroU16};
use tracing::error;

/// State for a single buffer of pages read from the blob.
///
/// Each fill produces one `BufferState` containing all pages read in that batch.
/// Navigation skips CRCs by computing offsets rather than creating separate
/// `Bytes` slices per page.
pub(super) struct BufferState {
    /// The raw physical buffer containing pages with interleaved CRCs.
    buffer: Vec<u8>,
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
        let buf = IoBufMut::zeroed(bytes_to_read);
        let physical_buf = self
            .blob
            .read_at(start_offset, buf)
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
            buffer: physical_buf.into(),
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
        &buf.buffer[physical_start..physical_end]
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
    pub async fn seek_to(&mut self, offset: u64) -> Result<(), Error> {
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

            let pool_ref = super::super::PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
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

            let pool_ref = super::super::PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
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

            let pool_ref = super::super::PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
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

            let pool_ref = super::super::PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
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

            let pool_ref = super::super::PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let mut replay = append.replay(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Seek forward, read, then seek backward
            replay.seek_to(150).await.unwrap();
            replay.ensure(50).await.unwrap();
            assert_eq!(replay.get_u8(), data[150]);

            // Seek back to start
            replay.seek_to(0).await.unwrap();
            replay.ensure(1).await.unwrap();
            assert_eq!(replay.get_u8(), data[0]);

            // Seek beyond blob size should error
            assert!(replay.seek_to(data.len() as u64 + 1).await.is_err());

            // Test that remaining() is correct after seek by reading all data.
            let seek_offset = 150usize;
            replay.seek_to(seek_offset as u64).await.unwrap();
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
}

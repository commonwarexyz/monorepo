use super::Checksum;
use crate::{Blob, Error};
use bytes::{Buf, Bytes};
use commonware_codec::FixedSize;
use std::{collections::VecDeque, num::NonZeroU16};
use tracing::error;

/// Fetches pages from a blob, validates CRCs, and yields logical bytes per page.
///
/// This is the async I/O component of the replay system. It prefetches pages in batches
/// and validates checksums. Use `fill()` to load pages, then `next_page()` to get them.
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
    /// Current page index in the blob.
    blob_page: u64,
    /// Buffer holding prefetched physical data.
    buffer: Bytes,
    /// Logical length of each page in the buffer.
    page_lengths: Vec<u16>,
    /// Index of next page to yield from buffer.
    buffer_idx: usize,
    /// Number of pages to prefetch at once.
    prefetch_count: usize,
}

impl<B: Blob> PageReader<B> {
    /// Creates a new PageReader.
    ///
    /// - `blob`: The blob to read from.
    /// - `physical_blob_size`: Total size of the blob on disk (multiple of page_size).
    /// - `logical_blob_size`: Total logical data size (excluding CRCs and padding).
    /// - `prefetch_count`: Number of pages to prefetch at once.
    /// - `logical_page_size`: Size of the logical data in each page (excluding CRC).
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
            buffer: Bytes::new(),
            page_lengths: Vec::new(),
            buffer_idx: 0,
            prefetch_count,
        }
    }

    /// Returns the logical size of the blob.
    pub const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Fills the buffer with the next batch of pages.
    ///
    /// Returns the number of pages fetched (0 = no more data).
    pub async fn fill(&mut self) -> Result<usize, Error> {
        // Calculate physical read offset
        let start_offset = match self.blob_page.checked_mul(self.page_size as u64) {
            Some(o) => o,
            None => return Err(Error::OffsetOverflow),
        };

        if start_offset >= self.physical_blob_size {
            return Ok(0); // No more data
        }

        // Calculate how many pages to read
        let remaining_physical = (self.physical_blob_size - start_offset) as usize;
        let max_pages = remaining_physical / self.page_size;
        let pages_to_read = max_pages.min(self.prefetch_count);
        if pages_to_read == 0 {
            return Ok(0);
        }

        let bytes_to_read = pages_to_read * self.page_size;

        // Read physical data
        let physical_buf: Vec<u8> = self
            .blob
            .read_at(vec![0u8; bytes_to_read], start_offset)
            .await?
            .into();
        let physical_buf = Bytes::from(physical_buf);

        // Validate CRCs and record page lengths
        self.page_lengths.clear();
        self.page_lengths.reserve(pages_to_read);

        for page_idx in 0..pages_to_read {
            let page_start = page_idx * self.page_size;
            let page_slice = &physical_buf[page_start..page_start + self.page_size];
            let Some(record) = Checksum::validate_page(page_slice) else {
                error!(page = self.blob_page + page_idx as u64, "CRC mismatch");
                return Err(Error::InvalidChecksum);
            };
            let (len, _) = record.get_crc();

            // Check if this is the last page in the blob
            let is_last_page_in_blob = start_offset + (page_idx + 1) as u64 * self.page_size as u64
                >= self.physical_blob_size;

            if is_last_page_in_blob {
                self.page_lengths.push(len);
            } else if (len as usize) != self.logical_page_size {
                error!(
                    page = self.blob_page + page_idx as u64,
                    expected = self.logical_page_size,
                    actual = len,
                    "non-last page has partial length"
                );
                return Err(Error::InvalidChecksum);
            } else {
                self.page_lengths.push(len);
            }
        }

        self.buffer = physical_buf;
        self.buffer_idx = 0;
        self.blob_page += pages_to_read as u64;

        Ok(pages_to_read)
    }

    /// Gets the next page's logical bytes (zero-copy via Bytes::slice).
    ///
    /// Returns None when all pages in the current buffer have been consumed.
    /// Call `fill()` to load more pages.
    pub fn next_page(&mut self) -> Option<Bytes> {
        if self.buffer_idx >= self.page_lengths.len() {
            return None;
        }

        let page_start = self.buffer_idx * self.page_size;
        let page_len = self.page_lengths[self.buffer_idx] as usize;
        self.buffer_idx += 1;

        // Return just the logical data portion (no CRC)
        Some(self.buffer.slice(page_start..page_start + page_len))
    }
}

/// A buffer that chains pages together and implements `Buf` for ergonomic decoding.
///
/// This is the sync buffering component of the replay system. It holds pages from
/// `PageReader` and provides a contiguous `Buf` interface for codec decoding.
#[derive(Default)]
struct ReplayBuf {
    /// Queue of pages (each is a Bytes from PageReader).
    pages: VecDeque<Bytes>,
    /// Current offset within the first page.
    offset: usize,
}

impl ReplayBuf {
    /// Creates a new empty ReplayBuf.
    pub fn new() -> Self {
        Self {
            pages: VecDeque::new(),
            offset: 0,
        }
    }

    /// Adds a page to the buffer (zero-copy, just moves Bytes into VecDeque).
    fn push(&mut self, page: Bytes) {
        self.pages.push_back(page);
    }
}

impl Buf for ReplayBuf {
    fn remaining(&self) -> usize {
        let first = self
            .pages
            .front()
            .map(|p| p.len().saturating_sub(self.offset))
            .unwrap_or(0);
        let rest: usize = self.pages.iter().skip(1).map(|p| p.len()).sum();
        first + rest
    }

    fn chunk(&self) -> &[u8] {
        self.pages.front().map(|p| &p[self.offset..]).unwrap_or(&[])
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let Some(first) = self.pages.front() else {
                break;
            };
            let available = first.len() - self.offset;
            if cnt < available {
                self.offset += cnt;
                break;
            }
            cnt -= available;
            self.pages.pop_front();
            self.offset = 0;
        }
    }
}

/// Combines PageReader and ReplayBuf for convenient replay operations.
///
/// This helper encapsulates the common pattern of filling a buffer from a page reader
/// and provides a `Buf` interface for decoding. It tracks whether the reader has been
/// exhausted to help callers handle end-of-data scenarios.
pub struct Replay<B: Blob> {
    reader: PageReader<B>,
    buf: ReplayBuf,
    exhausted: bool,
}

impl<B: Blob> Replay<B> {
    /// Creates a new Replay from a PageReader.
    pub(super) fn new(reader: PageReader<B>) -> Self {
        Self {
            reader,
            buf: ReplayBuf::new(),
            exhausted: false,
        }
    }

    /// Returns the logical size of the underlying blob.
    pub fn blob_size(&self) -> u64 {
        self.reader.blob_size()
    }

    /// Returns true if the reader has been exhausted (no more pages to read).
    ///
    /// When exhausted, the buffer may still contain data that hasn't been consumed.
    /// Callers should check `remaining()` to see if there's data left to process.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Ensures at least `n` bytes are available in the buffer.
    ///
    /// This method fills the buffer from the page reader until either:
    /// - At least `n` bytes are available (returns `Ok(true)`)
    /// - The reader is exhausted with fewer than `n` bytes (returns `Ok(false)`)
    /// - A read error occurs (returns `Err`)
    ///
    /// When `Ok(false)` is returned, callers should still attempt to process
    /// the remaining bytes in the buffer (check `remaining()`), as they may
    /// contain valid data that doesn't require the full `n` bytes.
    pub async fn ensure(&mut self, n: usize) -> Result<bool, Error> {
        while self.buf.remaining() < n && !self.exhausted {
            match self.reader.fill().await {
                Ok(0) => {
                    self.exhausted = true;
                }
                Ok(_) => {
                    while let Some(page) = self.reader.next_page() {
                        self.buf.push(page);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(self.buf.remaining() >= n)
    }
}

impl<B: Blob> Buf for Replay<B> {
    fn remaining(&self) -> usize {
        self.buf.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.buf.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.buf.advance(cnt);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{append::Append, PoolRef},
        *,
    };
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_PAGES: usize = 2;

    #[test_traced("DEBUG")]
    fn test_replay_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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
    fn test_replay_buf_advance() {
        let mut buf = ReplayBuf::new();

        // Add some pages
        buf.push(Bytes::from_static(b"hello"));
        buf.push(Bytes::from_static(b"world"));

        assert_eq!(buf.remaining(), 10);

        // Read first chunk
        assert_eq!(buf.chunk(), b"hello");
        buf.advance(3);
        assert_eq!(buf.chunk(), b"lo");
        assert_eq!(buf.remaining(), 7);

        // Advance past first page
        buf.advance(2);
        assert_eq!(buf.chunk(), b"world");
        assert_eq!(buf.remaining(), 5);

        // Advance past everything
        buf.advance(5);
        assert_eq!(buf.remaining(), 0);
        assert_eq!(buf.chunk(), b"");
    }

    #[test_traced("DEBUG")]
    fn test_replay_buf_copy_to_bytes() {
        let mut buf = ReplayBuf::new();
        buf.push(Bytes::from_static(b"hello"));
        buf.push(Bytes::from_static(b"world"));

        // Use the default Buf::copy_to_bytes implementation
        let copied = buf.copy_to_bytes(7);
        assert_eq!(&copied[..], b"hellowo");
        assert_eq!(buf.remaining(), 3);
        assert_eq!(buf.chunk(), b"rld");
    }

    #[test_traced("DEBUG")]
    fn test_replay_partial_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
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
}

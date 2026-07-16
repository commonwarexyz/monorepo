use crate::{Blob, Buf, Error, IoBuf};
use std::{collections::VecDeque, num::NonZeroU16};

/// Async I/O component that prefetches batches of pages.
///
/// This reads batches of raw logical bytes from the blob in page-aligned
/// chunks for the sync buffering layer.
pub(super) struct PageReader<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// Number of logical bytes per page.
    page_size: usize,
    /// The size of the blob.
    blob_size: u64,
    /// Next page index to read from the blob.
    blob_page: u64,
    /// Number of pages to prefetch at once.
    prefetch_count: usize,
}

impl<B: Blob> PageReader<B> {
    /// Creates a new PageReader over the first `blob_size` bytes of `blob`.
    ///
    /// Bytes are stored raw, so a page's blob offset is its page index times `page_size` and
    /// only the last page may be partial.
    pub(super) const fn new(
        blob: B,
        blob_size: u64,
        prefetch_count: usize,
        page_size: NonZeroU16,
    ) -> Self {
        Self {
            blob,
            page_size: page_size.get() as usize,
            blob_size,
            blob_page: 0,
            prefetch_count,
        }
    }

    /// Returns the size of the blob.
    pub(super) const fn blob_size(&self) -> u64 {
        self.blob_size
    }

    /// Fills a buffer with the next batch of pages.
    ///
    /// Returns `Some(bytes)` if data was loaded, `None` if no more data is available. All
    /// returned batches start at a page boundary, and only the final batch may end off one.
    pub(super) async fn fill(&mut self) -> Result<Option<IoBuf>, Error> {
        let start_offset = self
            .blob_page
            .checked_mul(self.page_size as u64)
            .ok_or(Error::OffsetOverflow)?;
        if start_offset >= self.blob_size {
            return Ok(None); // No more data
        }

        // Read up to `prefetch_count` pages, capped at the end of the blob (the last page may
        // be partial).
        let remaining = self.blob_size - start_offset;
        let bytes_to_read = remaining.min((self.prefetch_count * self.page_size) as u64) as usize;
        let buf = self
            .blob
            .read_at(start_offset, bytes_to_read)
            .await?
            .coalesce()
            .freeze();
        self.blob_page += bytes_to_read.div_ceil(self.page_size) as u64;

        Ok(Some(buf))
    }
}

/// Sync buffering component that implements the `Buf` trait.
///
/// This accumulates buffers from multiple fills and provides navigation across them. Consumed
/// buffers are cleaned up in `advance()`.
struct ReplayBuf {
    /// Accumulated buffers from fills.
    buffers: VecDeque<IoBuf>,
    /// Offset of the next unread byte within the front buffer. When `buffers` is empty, holds
    /// the number of bytes to skip from the next fill (set by a seek to mid-page).
    offset: usize,
    /// Total remaining unread bytes across all buffers.
    remaining: usize,
}

impl ReplayBuf {
    /// Creates a new ReplayBuf.
    const fn new() -> Self {
        Self {
            buffers: VecDeque::new(),
            offset: 0,
            remaining: 0,
        }
    }

    /// Clears the buffer and resets the read offset to 0.
    fn clear(&mut self) {
        self.buffers.clear();
        self.offset = 0;
        self.remaining = 0;
    }

    /// Adds a buffer from a fill operation.
    fn push(&mut self, buf: IoBuf) {
        // If buffers is empty, this is the first fill after a seek. Bytes before the seek
        // offset (`offset`) stay unread.
        let skip = if self.buffers.is_empty() {
            self.offset
        } else {
            0
        };
        self.remaining += buf.len().saturating_sub(skip);
        self.buffers.push_back(buf);
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
        &buf.as_ref()[self.offset..]
    }

    fn advance(&mut self, mut cnt: usize) {
        self.remaining = self.remaining.saturating_sub(cnt);

        while cnt > 0 {
            let Some(buf) = self.buffers.front() else {
                break;
            };
            let available = buf.len() - self.offset;
            if cnt < available {
                self.offset += cnt;
                return;
            }
            cnt -= available;
            self.buffers.pop_front();
            self.offset = 0;
        }
    }
}

/// Replays the logical bytes of a blob sequentially.
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
        Self {
            reader,
            buffer: ReplayBuf::new(),
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
                Some(buf) => {
                    self.buffer.push(buf);
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

        // Resume filling at the page containing `offset`, skipping the bytes before it.
        let page_size = self.reader.page_size as u64;
        self.reader.blob_page = offset / page_size;
        self.buffer.offset = (offset % page_size) as usize;

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
    use super::{super::writer::Writer, *};
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_PAGES: usize = 2;
    const BUFFER_SIZE: usize = BUFFER_PAGES * PAGE_SIZE.get() as usize;

    #[test_traced("DEBUG")]
    fn test_replay_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
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
            let mut append = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
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
        // Use prefetch_count=1 to force one fill (and one buffer) per page.
        // This tests navigation across multiple buffers in the VecDeque.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                super::super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let mut append = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write data spanning 4 pages (4 * 103 = 412 bytes, with last page partial)
            let data: Vec<u8> = (0u8..=255).cycle().take(400).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Create Replay with a buffer size of one page so prefetch_count=1.
            let mut replay = append
                .replay(NZUsize!(PAGE_SIZE.get() as usize))
                .await
                .unwrap();

            // Ensure all data - this requires 4 separate fill() calls (one per page).
            assert!(replay.ensure(400).await.unwrap());
            assert_eq!(replay.remaining(), 400);

            // Read all data via Buf interface, verifying navigation across buffers.
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
            let mut append = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Don't write any data - blob remains empty
            assert_eq!(append.size(), 0);

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
            let mut append = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
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
}

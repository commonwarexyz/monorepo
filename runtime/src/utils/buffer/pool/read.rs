use super::{Checksum, CHECKSUM_SIZE};
use crate::{Blob, Error};
use commonware_utils::StableBuf;
use std::num::NonZeroUsize;
use tracing::{debug, error};

const CHECKSUM_SIZE_USIZE: usize = CHECKSUM_SIZE as usize;

/// A reader that buffers content from a [Blob] with page-level CRCs to optimize the performance of
/// a full scan of contents.
///
/// The buffer stores physical pages (including CRCs) and navigates around them during reads,
/// avoiding the overhead of copying logical bytes to a separate buffer.
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The physical size of the blob (always a multiple of physical page size).
    physical_blob_size: u64,
    /// The logical size of the blob (actual data bytes, not including CRCs or padding).
    logical_blob_size: u64,
    /// The buffer storing physical pages read from the blob (includes CRC records).
    buffer: Vec<u8>,
    /// The validated logical length of each page in the buffer.
    page_lengths: Vec<usize>,
    /// The current page index within the buffer (0-indexed into page_lengths).
    current_page: usize,
    /// The current offset within the current page's logical bytes.
    offset_in_page: usize,
    /// The starting page number in the blob for the current buffer contents.
    blob_page: u64,
    /// The capacity of the buffer. Must be a multiple of the physical page size.
    buffer_capacity: usize,
    /// The physical page size (logical page size + CHECKSUM_SIZE).
    page_size: usize,
}

impl<B: Blob> Read<B> {
    /// Creates a new `Read` that reads from the given blob with the specified buffer size. The
    /// `logical_page_size` is the size of the logical data portion of each page (not including the
    /// Checksum). If the buffer capacity is not a multiple of the physical page size, it will be
    /// rounded up to the nearest.
    ///
    /// The `physical_blob_size` is the size of the underlying blob on disk (must be a multiple of
    /// the physical page size). The `logical_blob_size` is the actual data size (not including
    /// CRCs or padding in partial pages).
    pub fn new(
        blob: B,
        physical_blob_size: u64,
        logical_blob_size: u64,
        capacity: NonZeroUsize,
        logical_page_size: NonZeroUsize,
    ) -> Self {
        let page_size = logical_page_size.get() + CHECKSUM_SIZE_USIZE;
        let mut capacity = capacity.get();
        if !capacity.is_multiple_of(page_size) {
            capacity += page_size - capacity % page_size;
            debug!(
                capacity,
                "rounded buffer capacity up to nearest multiple of page_size"
            );
        }

        let max_pages = capacity / page_size;

        Self {
            blob,
            physical_blob_size,
            logical_blob_size,
            buffer: Vec::with_capacity(capacity),
            page_lengths: Vec::with_capacity(max_pages),
            blob_page: 0,
            current_page: 0,
            offset_in_page: 0,
            buffer_capacity: capacity,
            page_size,
        }
    }

    /// Returns the logical size of the blob in bytes.
    pub const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the current logical position in the blob.
    pub fn position(&self) -> u64 {
        let logical_page_size = (self.page_size - CHECKSUM_SIZE_USIZE) as u64;
        // Position = (blob_page + pages before current in buffer) * logical_page_size + offset_in_page
        // But we need to account for partial pages, so sum up actual lengths
        let mut pos = self.blob_page * logical_page_size;
        for i in 0..self.current_page {
            pos += self.page_lengths[i] as u64;
        }
        pos + self.offset_in_page as u64
    }

    /// Reads up to `buf.len()` bytes from the current position, but only as many as are available.
    ///
    /// This is useful for reading variable-length prefixes (like varints) where you want to read up
    /// to a maximum number of bytes but the actual remaining bytes in the blob might be less.
    ///
    /// Returns the number of bytes actually read into the buffer, which will be [0, buf.len()).
    pub async fn read_up_to(
        &mut self,
        buf: impl Into<StableBuf> + Send,
    ) -> Result<(StableBuf, usize), Error> {
        let mut buf = buf.into();
        if buf.is_empty() {
            return Ok((buf, 0));
        }
        let current_pos = self.position();
        let blob_size = self.blob_size();
        let available = (blob_size.saturating_sub(current_pos) as usize).min(buf.len());
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        self.read_exact(buf.as_mut(), available).await?;

        Ok((buf, available))
    }

    /// Reads exactly `size` bytes into the provided buffer. Returns [Error::BlobInsufficientLength]
    /// if not enough bytes are available.
    ///
    /// # Panics
    ///
    /// Panics if `size` is greater than the length of `buf`.
    pub async fn read_exact(&mut self, buf: &mut [u8], size: usize) -> Result<(), Error> {
        assert!(size <= buf.len());

        let mut bytes_copied = 0;
        while bytes_copied < size {
            // Refill buffer if we've exhausted all pages
            if self.current_page >= self.page_lengths.len() {
                self.fill_buffer().await?;
            }

            // Get available bytes in current page
            let page_logical_len = self.page_lengths[self.current_page];
            let available_in_page = page_logical_len.saturating_sub(self.offset_in_page);

            if available_in_page == 0 {
                // Move to next page
                self.current_page += 1;
                self.offset_in_page = 0;
                continue;
            }

            // Calculate where this page's data starts in the buffer
            let page_start_in_buffer = self.current_page * self.page_size;
            let read_start = page_start_in_buffer + self.offset_in_page;

            // Copy bytes from current page
            let bytes_to_copy = (size - bytes_copied).min(available_in_page);
            buf[bytes_copied..bytes_copied + bytes_to_copy]
                .copy_from_slice(&self.buffer[read_start..read_start + bytes_to_copy]);

            bytes_copied += bytes_to_copy;
            self.offset_in_page += bytes_to_copy;
        }

        Ok(())
    }

    /// Fills the buffer from the blob starting at the current physical position and verifies the
    /// CRC of each page (including any trailing partial page).
    ///
    /// The buffer stores physical pages (with CRCs) and we record the validated logical length
    /// of each page. This avoids copying data - we just navigate around CRCs during reads.
    async fn fill_buffer(&mut self) -> Result<(), Error> {
        let logical_page_size = self.page_size - CHECKSUM_SIZE_USIZE;

        // Advance blob_page by the number of pages we had in the buffer
        self.blob_page += self.page_lengths.len() as u64;

        // Reset position. If we had pages in the buffer, we're continuing a sequential read
        // so start at the beginning of the new buffer. If empty (e.g. after seek), preserve offset.
        let preserve_offset = self.page_lengths.is_empty();
        if !preserve_offset {
            self.current_page = 0;
            self.offset_in_page = 0;
        }

        // Calculate physical read parameters
        let start_offset = match self.blob_page.checked_mul(self.page_size as u64) {
            Some(o) => o,
            None => return Err(Error::OffsetOverflow),
        };

        if start_offset >= self.physical_blob_size {
            return Err(Error::BlobInsufficientLength);
        }

        let bytes_to_read =
            ((self.physical_blob_size - start_offset) as usize).min(self.buffer_capacity);
        if bytes_to_read == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        // Read physical pages directly into self.buffer (no intermediate copy)
        self.buffer.clear();
        self.buffer.resize(bytes_to_read, 0);
        let buf = std::mem::take(&mut self.buffer);
        let buf = self.blob.read_at(buf, start_offset).await?;
        self.buffer = buf.into();

        // Validate CRCs and record logical lengths (no data copying!)
        self.page_lengths.clear();
        let mut read_offset = 0;
        let physical_len = self.buffer.len();

        while read_offset < physical_len {
            let remaining = physical_len - read_offset;

            // Check if full page or partial
            if remaining >= self.page_size {
                let page_slice = &self.buffer[read_offset..read_offset + self.page_size];
                let Some(record) = Checksum::validate_page(page_slice) else {
                    error!(
                        page = self.blob_page + self.page_lengths.len() as u64,
                        "CRC mismatch"
                    );
                    return Err(Error::InvalidChecksum);
                };
                // For non-last pages, the validated length must equal logical_page_size.
                let (len, _) = record.get_crc();
                let len = len as usize;
                let is_last_page = start_offset + read_offset as u64 + self.page_size as u64
                    >= self.physical_blob_size;
                if !is_last_page && len != logical_page_size {
                    error!(
                        page = self.blob_page + self.page_lengths.len() as u64,
                        expected = logical_page_size,
                        actual = len,
                        "non-last page has partial length"
                    );
                    return Err(Error::InvalidChecksum);
                }
                // Record the validated logical length (no copy!)
                self.page_lengths.push(len);
                read_offset += self.page_size;
                continue;
            }

            // Partial page - must have at least CHECKSUM_SIZE bytes
            if remaining < CHECKSUM_SIZE_USIZE {
                error!(
                    page = self.blob_page + self.page_lengths.len() as u64,
                    "short page"
                );
                return Err(Error::InvalidChecksum);
            }
            let page_slice = &self.buffer[read_offset..];
            let Some(record) = Checksum::validate_page(page_slice) else {
                error!(
                    page = self.blob_page + self.page_lengths.len() as u64,
                    "CRC mismatch"
                );
                return Err(Error::InvalidChecksum);
            };
            let (len, _) = record.get_crc();
            let logical_len = len as usize;
            // Record the validated logical length (no copy!)
            self.page_lengths.push(logical_len);
            break;
        }

        // If we sought to a position that is beyond what we read, error.
        if preserve_offset && self.current_page < self.page_lengths.len() {
            let current_page_len = self.page_lengths[self.current_page];
            if self.offset_in_page >= current_page_len {
                return Err(Error::BlobInsufficientLength);
            }
        }

        Ok(())
    }

    /// Repositions the buffer to read from the specified logical position in the blob.
    pub fn seek_to(&mut self, position: u64) -> Result<(), Error> {
        let logical_page_size = (self.page_size - CHECKSUM_SIZE_USIZE) as u64;

        // Calculate which blob page this position falls into and offset within that page
        let target_blob_page = position / logical_page_size;
        let target_offset_in_page = (position % logical_page_size) as usize;

        // Check if the target page is within our current buffer
        let buffer_start_page = self.blob_page;
        let buffer_end_page = self.blob_page + self.page_lengths.len() as u64;

        if target_blob_page >= buffer_start_page && target_blob_page < buffer_end_page {
            // Position is in the buffer - just update current_page and offset
            self.current_page = (target_blob_page - buffer_start_page) as usize;
            self.offset_in_page = target_offset_in_page;
            return Ok(());
        }

        // Position is outside buffer - invalidate and set up for next fill
        self.blob_page = target_blob_page;
        self.current_page = 0;
        self.offset_in_page = target_offset_in_page;
        self.buffer.clear();
        self.page_lengths.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{append::Append, PoolRef};
    use crate::{deterministic, Blob, Error, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // Logical page size (intentionally odd to test alignment)
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test_traced("DEBUG")]
    fn test_read_after_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Create a blob and write data using Append
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), blob_size, BUFFER_SIZE, pool_ref)
                .await
                .unwrap();

            // Write data that spans multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            // Create a Read to read the data back
            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_SIZE)).await.unwrap();

            // Verify initial position
            assert_eq!(reader.position(), 0);

            // Read all data back
            let mut read_buf = vec![0u8; 300];
            reader.read_exact(&mut read_buf, 300).await.unwrap();
            assert_eq!(read_buf, data);

            // Verify position after read
            assert_eq!(reader.position(), 300);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_with_seek() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Create a blob and write data using Append
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), blob_size, BUFFER_SIZE, pool_ref)
                .await
                .unwrap();

            // Write data that spans multiple pages (300 bytes = ~3 logical pages)
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_SIZE)).await.unwrap();

            // Read first 50 bytes
            let mut buf = vec![0u8; 50];
            reader.read_exact(&mut buf, 50).await.unwrap();
            assert_eq!(buf, &data[0..50]);
            assert_eq!(reader.position(), 50);

            // Seek to middle of second page (position 150)
            reader.seek_to(150).unwrap();
            assert_eq!(reader.position(), 150);

            // Read 50 bytes from position 150
            reader.read_exact(&mut buf, 50).await.unwrap();
            assert_eq!(buf, &data[150..200]);
            assert_eq!(reader.position(), 200);

            // Seek back to beginning
            reader.seek_to(0).unwrap();
            assert_eq!(reader.position(), 0);

            // Read all data to verify seek worked
            let mut full_buf = vec![0u8; 300];
            reader.read_exact(&mut full_buf, 300).await.unwrap();
            assert_eq!(full_buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_partial_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Create a blob and write data that doesn't fill the last page
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), blob_size, BUFFER_SIZE, pool_ref)
                .await
                .unwrap();

            // Write exactly one full logical page plus 10 more bytes
            let data: Vec<u8> = (1u8..=(PAGE_SIZE.get() + 10) as u8).collect();
            assert_eq!(data.len(), PAGE_SIZE.get() as usize + 10);
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_SIZE)).await.unwrap();

            // Read all data back
            let mut read_buf = vec![0u8; data.len()];
            reader.read_exact(&mut read_buf, data.len()).await.unwrap();
            assert_eq!(read_buf, data);

            // Verify we can seek to partial page and read
            reader.seek_to(PAGE_SIZE.get() as u64).unwrap();
            let mut partial_buf = vec![0u8; 10];
            reader.read_exact(&mut partial_buf, 10).await.unwrap();
            assert_eq!(partial_buf, &data[PAGE_SIZE.get() as usize..]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_across_page_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), blob_size, BUFFER_SIZE, pool_ref)
                .await
                .unwrap();

            // Write 200 bytes spanning multiple pages
            let data: Vec<u8> = (0u8..200).collect();
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_SIZE)).await.unwrap();

            // Seek to position 90 (13 bytes before first page boundary at 103)
            reader.seek_to(90).unwrap();

            // Read 20 bytes across the page boundary
            let mut buf = vec![0u8; 20];
            reader.read_exact(&mut buf, 20).await.unwrap();
            assert_eq!(buf, &data[90..110]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_rejects_partial_crc_on_non_last_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), blob_size, BUFFER_SIZE, pool_ref)
                .await
                .unwrap();

            // Two full pages.
            let data: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize * 2)
                .collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Corrupt page 0 to claim a shorter (partial) length with a valid CRC.
            let page_size = PAGE_SIZE.get() as u64;
            let short_len = page_size / 2;
            let crc = crc32fast::hash(&data[..short_len as usize]);
            let record = super::Checksum::new(short_len as u16, crc);
            let crc_offset = page_size; // CRC record starts after logical page bytes
            blob.write_at(record.to_bytes().to_vec(), crc_offset)
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Capacity of one page => bug reproduces if last-page check is buffer-based.
            let mut reader = append
                .as_blob_reader(NZUsize!(page_size as usize))
                .await
                .unwrap();
            let mut buf = vec![0u8; page_size as usize];
            let result = reader.read_exact(&mut buf, page_size as usize).await;

            assert!(matches!(result, Err(Error::InvalidChecksum)));
        });
    }
}

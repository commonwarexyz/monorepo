use super::Checksum;
use crate::{Blob, Error};
use bytes::{buf::Chain, Buf, Bytes, BytesMut};
use commonware_codec::{CodecFixed, DecodeExt as _, Error as CodecError, FixedSize};
use commonware_utils::StableBuf;
use std::num::NonZeroUsize;
use tracing::{debug, error};

/// A buffer that can hold either a single contiguous [`Bytes`] or two chained [`Bytes`].
///
/// This allows zero-copy reads that span buffer boundaries by chaining the tail
/// of one buffer with the head of the next, rather than copying into a new allocation.
#[derive(Debug)]
pub enum BytesList {
    /// A single contiguous buffer (common case: data fits in current buffer).
    Single(Bytes),
    /// Two buffers chained together (data spans buffer boundary).
    Two(Chain<Bytes, Bytes>),
}

impl Buf for BytesList {
    fn remaining(&self) -> usize {
        match self {
            Self::Single(b) => b.remaining(),
            Self::Two(c) => c.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Single(b) => b.chunk(),
            Self::Two(c) => c.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match self {
            Self::Single(b) => b.advance(cnt),
            Self::Two(c) => c.advance(cnt),
        }
    }
}

/// A reader that buffers content from a [Blob] with page-level CRCs to optimize the performance of
/// a full scan of contents.
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The physical size of the blob (always a multiple of physical page size).
    physical_blob_size: u64,
    /// The logical size of the blob (actual data bytes, not including CRCs or padding).
    logical_blob_size: u64,
    /// The buffer storing the data read from the blob. The buffer stores logical bytes only.
    /// Uses Bytes for ref-counted slicing, allowing cross-boundary reads without copying.
    buffer: Bytes,
    /// The current page in the blob from where the buffer was filled (the buffer always starts at a
    /// page boundary).
    blob_page: u64,
    /// The current position within the buffer containing the next byte to be read.
    buffer_position: usize,
    /// The capacity of the buffer.  We always fully fill the buffer, unless we are at the end of
    /// the blob. The buffer capacity must be a multiple of the page size.
    buffer_capacity: usize,
    /// The physical page size of each full page in the blob, including its 12-byte Checksum.
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
        let page_size = logical_page_size.get() + Checksum::SIZE;
        let mut capacity = capacity.get();
        if !capacity.is_multiple_of(page_size) {
            capacity += page_size - capacity % page_size;
            debug!(
                capacity,
                "rounded buffer capacity up to nearest multiple of page_size"
            );
        }

        Self {
            blob,
            physical_blob_size,
            logical_blob_size,
            buffer: Bytes::new(),
            blob_page: 0,
            buffer_position: 0,
            buffer_capacity: capacity,
            page_size,
        }
    }

    /// Returns the logical size of the blob in bytes.
    pub const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the current logical position in the blob.
    pub const fn position(&self) -> u64 {
        let logical_page_size = (self.page_size - Checksum::SIZE) as u64;
        self.blob_page * logical_page_size + self.buffer_position as u64
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
            // Refill buffer if exhausted
            if self.buffer_position >= self.buffer.len() {
                self.fill_buffer().await?;
            }

            // Copy logical bytes
            let available = self.buffer.len() - self.buffer_position;
            // The buffer might be empty if we're at the end of the blob.
            if available == 0 {
                return Err(Error::BlobInsufficientLength);
            }

            let bytes_to_copy = (size - bytes_copied).min(available);
            buf[bytes_copied..bytes_copied + bytes_to_copy].copy_from_slice(
                &self.buffer[self.buffer_position..self.buffer_position + bytes_to_copy],
            );

            bytes_copied += bytes_to_copy;
            self.buffer_position += bytes_to_copy;
        }

        Ok(())
    }

    /// Decodes a batch of fixed-size items from the buffer, calling a transform function for each.
    ///
    /// This method is optimized for high-throughput replay of fixed-size journal items. It fills
    /// the buffer once, then decodes as many complete items as fit in a tight loop without any
    /// async overhead between items.
    ///
    /// # Arguments
    ///
    /// * `batch` - Output vector where transformed items are pushed. The caller provides this
    ///   to avoid allocation overhead when the transform produces a different type than `T`.
    /// * `f` - Transform function called as `f(index_in_batch, decode_result)` for each item.
    ///   The index is relative to this batch (starts at 0), not the absolute position.
    ///
    /// # Returns
    ///
    /// * `Ok((items_decoded, trailing_bytes))` - Number of items decoded and bytes remaining
    ///   that don't form a complete item. When `trailing_bytes > 0` and we're at the end of
    ///   the blob, this indicates corrupted/truncated data that the caller may want to handle.
    /// * `Ok((0, 0))` - End of blob reached (no more data).
    /// * `Err(_)` - I/O or checksum error.
    ///
    /// # Cross-Page Boundary Handling
    ///
    /// If the buffer contains less than one item's worth of data but the blob has more data
    /// available, this method uses `read_fixed` internally to handle the cross-page read.
    pub async fn decode_batch_fixed<T, R, F>(
        &mut self,
        batch: &mut Vec<R>,
        mut f: F,
    ) -> Result<(usize, usize), Error>
    where
        T: CodecFixed<Cfg = ()>,
        F: FnMut(usize, Result<T, CodecError>) -> R,
    {
        // Fill buffer from blob. Returns 0 when at end of blob.
        if self.fill().await? == 0 {
            return Ok((0, 0));
        }

        let available = self.available().len();
        if available < T::SIZE {
            // Buffer has less than one item. This happens when an item spans a page boundary.
            // Use read_bytes which handles cross-page reads via chaining.
            match self.read_bytes(T::SIZE).await {
                Ok(bytes) => {
                    let item = T::decode(bytes).map_err(|e| Error::Codec(e.to_string()))?;

                    batch.push(f(0, Ok(item)));
                    // After cross-page read, check remaining bytes. If less than one item,
                    // report as trailing (caller will check if at end of blob).
                    let remaining = self.available().len();
                    let trailing = if remaining >= T::SIZE { 0 } else { remaining };
                    return Ok((1, trailing));
                }
                // No more data in blob - return available as trailing bytes for caller to handle
                Err(Error::BlobInsufficientLength) => return Ok((0, available)),
                Err(err) => return Err(err),
            }
        }

        // Fast path: decode all complete items directly from buffer without copying
        let buf = self.available();
        let items_in_buf = buf.len() / T::SIZE;
        let trailing = buf.len() % T::SIZE;

        batch.reserve(items_in_buf);
        for i in 0..items_in_buf {
            let slice = &buf[i * T::SIZE..][..T::SIZE];
            batch.push(f(i, T::decode(slice)));
        }

        self.advance(items_in_buf * T::SIZE);
        Ok((items_in_buf, trailing))
    }

    /// Fills the buffer from the blob starting at the current physical position and verifies the
    /// CRC of each page (including any trailing partial page).
    async fn fill_buffer(&mut self) -> Result<(), Error> {
        let logical_page_size = self.page_size - Checksum::SIZE;

        // Advance blob_page based on how much of the buffer we've consumed. We use ceiling division
        // because even a partial page counts as a "page" read from the blob.
        let pages_consumed = self.buffer.len().div_ceil(logical_page_size);
        self.blob_page += pages_consumed as u64;

        // Reset position to the offset within the new page. If the buffer was not empty, we are
        // continuing a sequential read, so we start at the beginning of the next page. If the
        // buffer was empty (e.g. after a seek), we preserve the offset set by seek_to.
        if !self.buffer.is_empty() {
            self.buffer_position = 0;
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

        // Allocate new BytesMut for this fill. Old Bytes stays alive if anyone holds a reference.
        let buf = BytesMut::zeroed(bytes_to_read);

        // Read physical data into BytesMut
        let stable_buf: StableBuf = buf.into();
        let stable_buf = self.blob.read_at(stable_buf, start_offset).await?;

        // Convert back to BytesMut for in-place compaction
        let mut buf: BytesMut = match stable_buf {
            StableBuf::BytesMut(b) => b,
            StableBuf::Vec(v) => BytesMut::from(v.as_slice()),
        };

        // Validate CRCs and compact by removing CRC records in-place.
        let mut read_offset = 0;
        let mut write_offset = 0;
        let physical_len = buf.len();

        while read_offset < physical_len {
            let remaining = physical_len - read_offset;

            // Check if full page or partial
            if remaining >= self.page_size {
                let page_slice = &buf[read_offset..read_offset + self.page_size];
                let Some(record) = Checksum::validate_page(page_slice) else {
                    error!(
                        page = self.blob_page + (read_offset / self.page_size) as u64,
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
                        page = self.blob_page + (read_offset / self.page_size) as u64,
                        expected = logical_page_size,
                        actual = len,
                        "non-last page has partial length"
                    );
                    return Err(Error::InvalidChecksum);
                }
                // Compact: move logical data to remove CRC record gap
                if write_offset != read_offset {
                    buf.as_mut()
                        .copy_within(read_offset..read_offset + len, write_offset);
                }
                write_offset += len;
                read_offset += self.page_size;
                continue;
            }

            // Partial page - must have at least CHECKSUM_SIZE bytes
            if remaining < Checksum::SIZE {
                error!(
                    page = self.blob_page + (read_offset / self.page_size) as u64,
                    "short page"
                );
                return Err(Error::InvalidChecksum);
            }
            let page_slice = &buf[read_offset..];
            let Some(record) = Checksum::validate_page(page_slice) else {
                error!(
                    page = self.blob_page + (read_offset / self.page_size) as u64,
                    "CRC mismatch"
                );
                return Err(Error::InvalidChecksum);
            };
            let (len, _) = record.get_crc();
            let logical_len = len as usize;
            // Compact: move logical data
            if write_offset != read_offset {
                buf.as_mut()
                    .copy_within(read_offset..read_offset + logical_len, write_offset);
            }
            write_offset += logical_len;
            break;
        }

        // Truncate buffer to only contain logical data and freeze to Bytes
        buf.truncate(write_offset);
        self.buffer = buf.freeze();

        // If we sought to a position that is beyond the end of what we just read, error.
        if self.buffer_position >= self.buffer.len() {
            return Err(Error::BlobInsufficientLength);
        }

        Ok(())
    }

    /// Returns available buffered data without copying.
    pub fn available(&self) -> &[u8] {
        &self.buffer[self.buffer_position..]
    }

    /// Fills buffer if empty. Returns bytes available (0 if at end of blob).
    pub async fn fill(&mut self) -> Result<usize, Error> {
        if self.buffer_position >= self.buffer.len() {
            match self.fill_buffer().await {
                Ok(()) => {}
                Err(Error::BlobInsufficientLength) => return Ok(0),
                Err(err) => return Err(err),
            }
        }
        Ok(self.available().len())
    }

    /// Advances the buffer position by `n` bytes.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `n` would advance past the end of the buffer.
    pub fn advance(&mut self, n: usize) {
        debug_assert!(
            self.buffer_position + n <= self.buffer.len(),
            "advance({}) would exceed buffer length {}",
            n,
            self.buffer.len()
        );
        self.buffer_position += n;
    }

    /// Repositions the buffer to read from the specified logical position in the blob.
    pub fn seek_to(&mut self, position: u64) -> Result<(), Error> {
        let logical_page_size = (self.page_size - Checksum::SIZE) as u64;

        // Check if the position is within the current buffer.
        let buffer_start = self.blob_page * logical_page_size;
        let buffer_end = buffer_start + self.buffer.len() as u64;
        if position >= buffer_start && position < buffer_end {
            self.buffer_position = (position - buffer_start) as usize;
            return Ok(());
        }

        self.blob_page = position / logical_page_size;
        self.buffer_position = (position % logical_page_size) as usize;
        self.buffer = Bytes::new(); // Invalidate buffer, will be refilled on next read

        Ok(())
    }

    /// Returns available buffer content as Bytes (zero-copy, ref-counted).
    ///
    /// The returned Bytes remains valid even after `fill_buffer()` is called,
    /// making it safe to hold across async operations that may refill the buffer.
    pub fn available_bytes(&self) -> Bytes {
        self.buffer.slice(self.buffer_position..)
    }

    /// Reads exactly `size` bytes, returning a [BytesList].
    ///
    /// Returns [BytesList] to avoid copying when data spans buffer boundaries.
    /// Uses `chain()` to combine pieces without allocation.
    pub async fn read_bytes(&mut self, size: usize) -> Result<BytesList, Error> {
        // Fast path: fits entirely in current buffer
        if self.buffer_position + size <= self.buffer.len() {
            let result = self
                .buffer
                .slice(self.buffer_position..self.buffer_position + size);
            self.buffer_position += size;
            return Ok(BytesList::Single(result));
        }

        let remaining_in_buffer = self.buffer.len() - self.buffer_position;

        // Check if item spans 3+ buffers (larger than remaining + one full buffer).
        // Read directly from blob - more efficient than multiple buffer fills.
        if size > remaining_in_buffer + self.buffer_capacity {
            let first = self.buffer.slice(self.buffer_position..);
            self.buffer_position = self.buffer.len();

            let rest_size = size - remaining_in_buffer;
            let mut rest = vec![0u8; rest_size];
            self.read_exact(&mut rest, rest_size).await?;

            return Ok(BytesList::Two(first.chain(Bytes::from(rest))));
        }

        // Slow path: spans 2 buffers - chain pieces
        let first = self.buffer.slice(self.buffer_position..);
        let first_len = first.len();
        self.buffer_position = self.buffer.len();

        self.fill_buffer().await?;
        if self.buffer.is_empty() {
            return Err(Error::BlobInsufficientLength);
        }

        let second_len = size - first_len;
        let second = self.buffer.slice(..second_len);
        self.buffer_position = second_len;
        Ok(BytesList::Two(first.chain(second)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{append::Append, PoolRef};
    use crate::{deterministic, Blob, Error, Runner as _, Storage as _};
    use commonware_cryptography::Crc32;
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
            let crc = Crc32::checksum(&data[..short_len as usize]);
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

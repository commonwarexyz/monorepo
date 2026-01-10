use super::Checksum;
use crate::{Blob, Error};
use bytes::{buf::Chain, Buf, Bytes};
use commonware_codec::{CodecFixed, DecodeExt as _, Error as CodecError, FixedSize, ReadExt as _};
use commonware_utils::StableBuf;
use std::num::{NonZeroU16, NonZeroUsize};
use tracing::error;

/// A buffer that provides a logical view over physical page data, skipping CRC regions.
///
/// Physical pages have the layout: `[logical_data (logical_page_size bytes)][CRC (12 bytes)]`
/// This buffer presents a contiguous view of just the logical data across multiple pages.
#[derive(Clone)]
pub struct PhysicalBuf {
    /// The physical buffer containing pages with CRC regions.
    buffer: Bytes,
    /// Physical page size (logical_page_size + CHECKSUM_SIZE).
    page_size: usize,
    /// Logical page size (data bytes per page, not including CRC).
    logical_page_size: usize,
    /// Total pages in buffer.
    pages_in_buffer: usize,
    /// Length of the last page (may be < logical_page_size for partial pages).
    last_page_length: usize,

    /// Current page index within the buffer.
    current_page: usize,
    /// Current offset within the current page's logical data.
    offset_in_page: usize,
}

impl PhysicalBuf {
    /// Returns the logical length of the specified page.
    #[inline]
    const fn page_length(&self, page_idx: usize) -> usize {
        if page_idx == self.pages_in_buffer - 1 {
            self.last_page_length
        } else {
            self.logical_page_size
        }
    }

    /// Returns the total logical bytes remaining from current position.
    pub const fn logical_remaining(&self) -> usize {
        if self.current_page >= self.pages_in_buffer {
            return 0;
        }

        // Current page remaining
        let mut total = self.page_length(self.current_page) - self.offset_in_page;

        // Full pages between current and last
        if self.current_page + 1 < self.pages_in_buffer {
            let full_pages_between = self.pages_in_buffer - self.current_page - 2;
            total += full_pages_between * self.logical_page_size;

            // Last page
            total += self.last_page_length;
        }

        total
    }

    /// Returns the total logical bytes remaining (alias for remaining()).
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining()
    }

    /// Returns true if no logical bytes remain.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Copies all remaining logical bytes to a new Vec.
    ///
    /// This is useful when contiguous access is needed (e.g., for parsing variable-length items).
    /// For zero-copy access, iterate using `chunk()` and `advance()`.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = self.clone();
        let mut result = Vec::with_capacity(buf.remaining());
        while buf.remaining() > 0 {
            let chunk = buf.chunk();
            result.extend_from_slice(chunk);
            buf.advance(chunk.len());
        }
        result
    }
}

impl Buf for PhysicalBuf {
    fn remaining(&self) -> usize {
        self.logical_remaining()
    }

    fn chunk(&self) -> &[u8] {
        if self.current_page >= self.pages_in_buffer {
            return &[];
        }
        let page_start = self.current_page * self.page_size;
        let page_len = self.page_length(self.current_page);
        &self.buffer[page_start + self.offset_in_page..page_start + page_len]
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 && self.current_page < self.pages_in_buffer {
            let remaining_in_page = self.page_length(self.current_page) - self.offset_in_page;
            if cnt < remaining_in_page {
                self.offset_in_page += cnt;
                break;
            }
            cnt -= remaining_in_page;
            self.current_page += 1;
            self.offset_in_page = 0;
        }
    }
}

/// A buffer that can hold either a single [`PhysicalBuf`] or two chained [`PhysicalBuf`]s.
///
/// This allows zero-copy reads that span buffer boundaries by chaining the tail
/// of one buffer with the head of the next, rather than copying into a new allocation.
pub enum PhysicalBufList {
    /// A single buffer (common case: data fits in current buffer).
    Single(PhysicalBuf),
    /// Two buffers chained together (data spans buffer boundary).
    Two(Chain<PhysicalBuf, PhysicalBuf>),
}

impl Buf for PhysicalBufList {
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
///
/// This implementation keeps physical bytes (with CRCs) in memory and provides a zero-copy view
/// via [`PhysicalBuf`] that skips over CRC regions during iteration.
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The physical size of the blob (always a multiple of physical page size).
    physical_blob_size: u64,
    /// The logical size of the blob (actual data bytes, not including CRCs or padding).
    logical_blob_size: u64,
    /// The buffer storing physical data (with CRCs validated but not removed).
    buffer: Bytes,
    /// The starting page index in the blob from where the buffer was filled.
    blob_page: u64,
    /// Current page index within the buffer.
    page_position: usize,
    /// Current offset within the current page's logical data.
    offset_in_page: usize,
    /// Number of pages in the current buffer.
    pages_in_buffer: usize,
    /// Length of the last page's logical data (may be < logical_page_size).
    last_page_length: u16,
    /// The capacity of the buffer in pages.
    buffer_capacity_pages: usize,
    /// The physical page size (logical_page_size + Checksum::SIZE).
    page_size: usize,
    /// The logical page size (data bytes per page, not including CRC).
    logical_page_size: usize,
}

impl<B: Blob> Read<B> {
    /// Creates a new `Read` that reads from the given blob with the specified buffer size in pages.
    ///
    /// The `logical_page_size` is the size of the logical data portion of each page (not including
    /// the Checksum).
    ///
    /// The `physical_blob_size` is the size of the underlying blob on disk (must be a multiple of
    /// the physical page size). The `logical_blob_size` is the actual data size (not including
    /// CRCs or padding in partial pages).
    pub const fn new(
        blob: B,
        physical_blob_size: u64,
        logical_blob_size: u64,
        capacity_pages: NonZeroUsize,
        logical_page_size: NonZeroU16,
    ) -> Self {
        let logical_page_size = logical_page_size.get() as usize;
        let page_size = logical_page_size + Checksum::SIZE;

        Self {
            blob,
            physical_blob_size,
            logical_blob_size,
            buffer: Bytes::new(),
            blob_page: 0,
            page_position: 0,
            offset_in_page: 0,
            pages_in_buffer: 0,
            last_page_length: 0,
            buffer_capacity_pages: capacity_pages.get(),
            page_size,
            logical_page_size,
        }
    }

    /// Returns the logical size of the blob in bytes.
    pub const fn blob_size(&self) -> u64 {
        self.logical_blob_size
    }

    /// Returns the current logical position in the blob.
    pub fn position(&self) -> u64 {
        // Pages before current buffer (all full)
        let mut pos = self.blob_page * self.logical_page_size as u64;

        // Sum actual page lengths for pages consumed in current buffer
        for i in 0..self.page_position {
            pos += self.page_length(i) as u64;
        }

        // Add current offset within page
        pos + self.offset_in_page as u64
    }

    /// Returns the logical length of the specified page in the buffer.
    #[inline]
    const fn page_length(&self, page_idx: usize) -> usize {
        if page_idx == self.pages_in_buffer - 1 {
            self.last_page_length as usize
        } else {
            self.logical_page_size
        }
    }

    /// Returns the total logical bytes available in the current buffer from current position.
    const fn available_len(&self) -> usize {
        if self.page_position >= self.pages_in_buffer {
            return 0;
        }

        // Current page remaining
        let mut total = self.page_length(self.page_position) - self.offset_in_page;

        // Full pages between current and last
        if self.page_position + 1 < self.pages_in_buffer {
            let full_pages_between = self.pages_in_buffer - self.page_position - 2;
            total += full_pages_between * self.logical_page_size;

            // Last page
            total += self.last_page_length as usize;
        }

        total
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
            if self.page_position >= self.pages_in_buffer {
                self.fill_buffer().await?;
            }

            // Copy logical bytes from current page
            let page_len = self.page_length(self.page_position);
            let available_in_page = page_len - self.offset_in_page;
            if available_in_page == 0 {
                // Move to next page
                self.page_position += 1;
                self.offset_in_page = 0;
                continue;
            }

            let bytes_to_copy = (size - bytes_copied).min(available_in_page);
            let page_start = self.page_position * self.page_size;
            buf[bytes_copied..bytes_copied + bytes_to_copy].copy_from_slice(
                &self.buffer[page_start + self.offset_in_page
                    ..page_start + self.offset_in_page + bytes_to_copy],
            );

            bytes_copied += bytes_to_copy;
            self.offset_in_page += bytes_to_copy;

            // Move to next page if we've consumed the current one
            if self.offset_in_page >= page_len {
                self.page_position += 1;
                self.offset_in_page = 0;
            }
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
    /// available, this method uses [`read_buf`](Self::read_buf) to handle the cross-page read.
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

        let available = self.available_len();
        if available < T::SIZE {
            // Buffer has less than one item. This happens when an item spans a page boundary.
            // Use read_buf which handles cross-page reads via chaining.
            match self.read_buf(T::SIZE).await {
                Ok(mut bytes) => {
                    let item = T::decode(&mut bytes)?;
                    batch.push(f(0, Ok(item)));

                    // After cross-page read, check remaining bytes. If less than one item,
                    // report as trailing (caller will check if at end of blob).
                    let remaining = self.available_len();
                    let trailing = if remaining >= T::SIZE { 0 } else { remaining };
                    return Ok((1, trailing));
                }
                // No more data in blob - return available as trailing bytes for caller to handle
                Err(Error::BlobInsufficientLength) => return Ok((0, available)),
                Err(err) => return Err(err),
            }
        }

        // Fast path: read all complete items directly from buffer without copying
        // Note: We use T::read (not T::decode) because read doesn't check for remaining
        // bytes, allowing us to read multiple items from the same buffer.
        let mut buf = self.available();
        let items_in_buf = available / T::SIZE;
        let trailing = available % T::SIZE;

        batch.reserve(items_in_buf);
        for i in 0..items_in_buf {
            batch.push(f(i, T::read(&mut buf)));
        }

        self.advance_by(items_in_buf * T::SIZE);
        Ok((items_in_buf, trailing))
    }

    /// Fills the buffer from the blob starting at the current physical position and verifies the
    /// CRC of each page.
    ///
    /// The buffer stores physical data (CRCs validated but not removed) for zero-copy reads.
    async fn fill_buffer(&mut self) -> Result<(), Error> {
        // Advance blob_page based on how many pages we consumed from the buffer.
        self.blob_page += self.pages_in_buffer as u64;

        // Reset position. If the buffer was not empty, we're continuing sequential read.
        // If the buffer was empty (e.g. after a seek), preserve offset set by seek_to.
        if self.pages_in_buffer > 0 {
            self.page_position = 0;
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

        // Calculate how many pages to read
        let remaining_physical = (self.physical_blob_size - start_offset) as usize;
        let max_pages = remaining_physical / self.page_size;
        let pages_to_read = max_pages.min(self.buffer_capacity_pages);
        if pages_to_read == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        let bytes_to_read = pages_to_read * self.page_size;

        // Read physical data (single allocation)
        let physical_buf: Vec<u8> = self
            .blob
            .read_at(vec![0u8; bytes_to_read], start_offset)
            .await?
            .into();
        let physical_buf = Bytes::from(physical_buf);

        // Validate CRCs for each page (but don't strip them - keep physical layout)
        let mut last_page_length = self.logical_page_size as u16;
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
                last_page_length = len;
            } else if (len as usize) != self.logical_page_size {
                error!(
                    page = self.blob_page + page_idx as u64,
                    expected = self.logical_page_size,
                    actual = len,
                    "non-last page has partial length"
                );
                return Err(Error::InvalidChecksum);
            }
        }

        self.buffer = physical_buf;
        self.pages_in_buffer = pages_to_read;
        self.last_page_length = last_page_length;

        // If we sought to a position that is beyond what we just read, error.
        if self.page_position >= self.pages_in_buffer
            || (self.page_position == self.pages_in_buffer - 1
                && self.offset_in_page >= self.last_page_length as usize)
        {
            return Err(Error::BlobInsufficientLength);
        }

        Ok(())
    }

    /// Returns available buffered data as a [`PhysicalBuf`] (zero-copy view over physical buffer).
    pub fn available(&self) -> PhysicalBuf {
        PhysicalBuf {
            buffer: self.buffer.clone(), // Ref-counted, no copy
            page_size: self.page_size,
            logical_page_size: self.logical_page_size,
            pages_in_buffer: self.pages_in_buffer,
            last_page_length: self.last_page_length as usize,
            current_page: self.page_position,
            offset_in_page: self.offset_in_page,
        }
    }

    /// Fills buffer if empty. Returns bytes available (0 if at end of blob).
    pub async fn fill(&mut self) -> Result<usize, Error> {
        if self.page_position >= self.pages_in_buffer {
            match self.fill_buffer().await {
                Ok(()) => {}
                Err(Error::BlobInsufficientLength) => return Ok(0),
                Err(err) => return Err(err),
            }
        }
        Ok(self.available_len())
    }

    /// Advances the logical position by `n` bytes.
    pub const fn advance_by(&mut self, mut n: usize) {
        while n > 0 && self.page_position < self.pages_in_buffer {
            let remaining_in_page = self.page_length(self.page_position) - self.offset_in_page;
            if n < remaining_in_page {
                self.offset_in_page += n;
                break;
            }
            n -= remaining_in_page;
            self.page_position += 1;
            self.offset_in_page = 0;
        }
    }

    /// Advances the logical position by `n` bytes (alias for advance_by).
    #[inline]
    pub const fn advance(&mut self, n: usize) {
        self.advance_by(n);
    }

    /// Returns available buffer content as Bytes by copying logical data.
    ///
    /// Note: This method copies data to produce contiguous bytes. For zero-copy access,
    /// use [`available()`](Self::available) which returns a [`PhysicalBuf`].
    pub fn available_bytes(&self) -> Bytes {
        let mut buf = self.available();
        let mut result = Vec::with_capacity(buf.remaining());
        while buf.remaining() > 0 {
            let chunk = buf.chunk();
            result.extend_from_slice(chunk);
            buf.advance(chunk.len());
        }
        Bytes::from(result)
    }

    /// Reads exactly `size` bytes, returning a [`BytesList`].
    ///
    /// Note: This method may copy data. For zero-copy access, use [`read_buf()`](Self::read_buf).
    pub async fn read_bytes(&mut self, size: usize) -> Result<BytesList, Error> {
        // Collect logical bytes into a contiguous buffer
        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf, size).await?;
        Ok(BytesList::Single(Bytes::from(buf)))
    }

    /// Repositions the buffer to read from the specified logical position in the blob.
    pub fn seek_to(&mut self, position: u64) -> Result<(), Error> {
        let logical_page_size = self.logical_page_size as u64;

        // Calculate which page and offset within that page
        let target_page = position / logical_page_size;
        let target_offset = (position % logical_page_size) as usize;

        // Check if the position is within the current buffer
        let buffer_start_page = self.blob_page;
        let buffer_end_page = self.blob_page + self.pages_in_buffer as u64;

        if target_page >= buffer_start_page && target_page < buffer_end_page {
            let page_in_buffer = (target_page - buffer_start_page) as usize;

            // Verify offset is valid for the target page
            let page_len = self.page_length(page_in_buffer);
            if target_offset <= page_len {
                self.page_position = page_in_buffer;
                self.offset_in_page = target_offset;
                return Ok(());
            }
        }

        // Position is outside current buffer - need to refill
        self.blob_page = target_page;
        self.page_position = 0;
        self.offset_in_page = target_offset;
        self.pages_in_buffer = 0;
        self.buffer = Bytes::new();

        Ok(())
    }

    /// Returns available buffer content as a [`PhysicalBuf`] (zero-copy, ref-counted).
    ///
    /// The returned buffer remains valid even after `fill_buffer()` is called,
    /// making it safe to hold across async operations that may refill the buffer.
    pub fn available_buf(&self) -> PhysicalBuf {
        self.available()
    }

    /// Reads exactly `size` logical bytes, returning a [`PhysicalBufList`].
    ///
    /// Returns [`PhysicalBufList`] to avoid copying when data spans buffer boundaries.
    /// Uses `chain()` to combine pieces without allocation.
    pub async fn read_buf(&mut self, size: usize) -> Result<PhysicalBufList, Error> {
        // Fast path: fits entirely in current buffer
        let available = self.available_len();
        if available >= size {
            let buf = PhysicalBuf {
                buffer: self.buffer.clone(),
                page_size: self.page_size,
                logical_page_size: self.logical_page_size,
                pages_in_buffer: self.pages_in_buffer,
                last_page_length: self.last_page_length as usize,
                current_page: self.page_position,
                offset_in_page: self.offset_in_page,
            };
            self.advance_by(size);
            return Ok(PhysicalBufList::Single(buf));
        }

        // Check if item spans 3+ buffers - use read_exact fallback
        let logical_buffer_capacity = self.buffer_capacity_pages * self.logical_page_size;
        if size > available + logical_buffer_capacity {
            // Item is larger than remaining + one full buffer - read directly
            let first_buf = self.available();
            let first_len = first_buf.remaining();
            self.advance_by(first_len);

            let rest_size = size - first_len;
            let mut rest = vec![0u8; rest_size];
            self.read_exact(&mut rest, rest_size).await?;

            // Create a PhysicalBuf from the copied data (this path is rare)
            let rest_buf = PhysicalBuf {
                buffer: Bytes::from(rest),
                page_size: rest_size, // Treat as single "page" of logical data
                logical_page_size: rest_size,
                pages_in_buffer: 1,
                last_page_length: rest_size,
                current_page: 0,
                offset_in_page: 0,
            };

            return Ok(PhysicalBufList::Two(first_buf.chain(rest_buf)));
        }

        // Slow path: spans 2 buffers - chain pieces
        let first = PhysicalBuf {
            buffer: self.buffer.clone(),
            page_size: self.page_size,
            logical_page_size: self.logical_page_size,
            pages_in_buffer: self.pages_in_buffer,
            last_page_length: self.last_page_length as usize,
            current_page: self.page_position,
            offset_in_page: self.offset_in_page,
        };
        let first_len = first.remaining();

        // Consume rest of current buffer
        self.page_position = self.pages_in_buffer;
        self.offset_in_page = 0;

        // Fill next buffer
        self.fill_buffer().await?;
        if self.pages_in_buffer == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        let second_len = size - first_len;
        let second = PhysicalBuf {
            buffer: self.buffer.clone(),
            page_size: self.page_size,
            logical_page_size: self.logical_page_size,
            pages_in_buffer: self.pages_in_buffer,
            last_page_length: self.last_page_length as usize,
            current_page: 0,
            offset_in_page: 0,
        };

        self.advance_by(second_len);
        Ok(PhysicalBufList::Two(first.chain(second)))
    }
}

// Keep the old BytesList type for backwards compatibility with existing code
// that might use read_bytes directly. We can deprecate this later.

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

#[cfg(test)]
mod tests {
    use super::{
        super::{append::Append, PoolRef},
        *,
    };
    use crate::{deterministic, Blob, Error, Runner as _, Storage as _};
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // Logical page size (intentionally odd to test alignment)
    const BUFFER_PAGES: usize = 2;

    #[test_traced("DEBUG")]
    fn test_read_after_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Create a blob and write data using Append
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write data that spans multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            // Create a Read to read the data back
            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_PAGES)).await.unwrap();

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

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write data that spans multiple pages (300 bytes = ~3 logical pages)
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_PAGES)).await.unwrap();

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

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write exactly one full logical page plus 10 more bytes
            let data: Vec<u8> = (1u8..=(PAGE_SIZE.get() + 10) as u8).collect();
            assert_eq!(data.len(), PAGE_SIZE.get() as usize + 10);
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_PAGES)).await.unwrap();

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

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write 200 bytes spanning multiple pages
            let data: Vec<u8> = (0u8..200).collect();
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_PAGES)).await.unwrap();

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

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
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
            let record = super::super::Checksum::new(short_len as u16, crc);
            let crc_offset = page_size; // CRC record starts after logical page bytes
            blob.write_at(record.to_bytes().to_vec(), crc_offset)
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Capacity of one page => bug reproduces if last-page check is buffer-based.
            let mut reader = append.as_blob_reader(NZUsize!(1)).await.unwrap();
            let mut buf = vec![0u8; page_size as usize];
            let result = reader.read_exact(&mut buf, page_size as usize).await;

            assert!(matches!(result, Err(Error::InvalidChecksum)));
        });
    }

    #[test_traced("DEBUG")]
    fn test_physical_buf_iteration() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();

            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(BUFFER_PAGES));
            let append = Append::new(blob.clone(), blob_size, BUFFER_PAGES * 115, pool_ref)
                .await
                .unwrap();

            // Write data spanning multiple pages
            let data: Vec<u8> = (0u8..=255).cycle().take(250).collect();
            append.append(&data).await.unwrap();

            let mut reader = append.as_blob_reader(NZUsize!(BUFFER_PAGES)).await.unwrap();

            // Fill and get PhysicalBuf
            reader.fill().await.unwrap();
            let mut buf = reader.available();

            // Verify we can iterate through the data correctly
            let mut collected = Vec::new();
            while buf.remaining() > 0 {
                let chunk = buf.chunk();
                collected.extend_from_slice(chunk);
                let len = chunk.len();
                buf.advance(len);
            }

            // Should have collected all data up to buffer capacity
            assert!(!collected.is_empty());
            assert_eq!(&collected[..], &data[..collected.len()]);
        });
    }
}

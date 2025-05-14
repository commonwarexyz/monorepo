use crate::{Blob, Error};

/// A reader that buffers content from a [Blob] to optimize the performance
/// of a full scan of contents.
///
/// # Performance Considerations
///
/// - Choose an appropriate buffer size based on your access patterns:
///   - Larger buffers (e.g., 1 MB) for sequential scanning of large files
///   - Medium buffers (e.g., 64 KB) for general purpose usage
///   - Smaller buffers (e.g., 4 KB) for random access patterns or memory-constrained environments
///
/// - For sequential reading, let the buffer's automatic refilling handle data loading
/// - For random access patterns, use `seek_to` followed by `refill` for best performance
/// - Use `peek` when you need to examine data without committing to consuming it
/// - Check `blob_remaining()` to avoid attempting to read past the end of the blob
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, Buffer, Blob, Error, Storage, deterministic};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob and add some data (e.g., a journal file)
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     let data = b"Hello, world! This is a test.";
///     blob.write_at(data, 0).await.expect("unable to write data");
///     let size = data.len() as u64;
///
///     // Create a buffer
///     let buffer = 64 * 1024;
///     let mut reader = Buffer::new(blob, size, buffer);
///
///     // Read data sequentially
///     let mut header = [0u8; 16];
///     reader.read_exact(&mut header, 16).await.expect("unable to read data");
///     println!("Read header: {:?}", header);
///
///     // Peek at upcoming data without advancing the read position
///     let peek_size = 8;
///     let peeked_data = reader.peek(peek_size).await.expect("unable to peek data");
///     println!("Peeked data: {:?}", peeked_data);
///
///     // Position is still at 16 (after header)
///     assert_eq!(reader.position(), 16);
/// });
/// ```
pub struct Buffer<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The buffer storing the data read from the blob.
    buffer: Vec<u8>,
    /// The current position in the blob from where the buffer was filled.
    blob_position: u64,
    /// The size of the blob.
    blob_size: u64,
    /// The current position within the buffer for reading.
    buffer_position: usize,
    /// The valid data length in the buffer.
    buffer_valid_len: usize,
    /// The maximum size of the buffer.
    buffer_size: usize,
}

impl<B: Blob> Buffer<B> {
    /// Creates a new `Buffer` that reads from the given blob with the specified buffer size.
    ///
    /// # Panics
    ///
    /// Panics if `buffer_size` is zero.
    pub fn new(blob: B, blob_size: u64, buffer_size: usize) -> Self {
        assert!(buffer_size > 0, "Buffer size must be greater than zero");
        Self {
            blob,
            buffer: vec![0; buffer_size],
            blob_position: 0,
            blob_size,
            buffer_position: 0,
            buffer_valid_len: 0,
            buffer_size,
        }
    }

    /// Returns how many valid bytes are remaining in the buffer.
    pub fn buffer_remaining(&self) -> usize {
        self.buffer_valid_len - self.buffer_position
    }

    /// Returns how many bytes remain in the blob from the current position.
    pub fn blob_remaining(&self) -> u64 {
        self.blob_size
            .saturating_sub(self.blob_position + self.buffer_position as u64)
    }

    /// Refills the buffer from the blob starting at the current blob position.
    /// Returns the number of bytes read or an error if the read failed.
    pub async fn refill(&mut self) -> Result<usize, Error> {
        // Update blob position to account for consumed bytes
        self.blob_position += self.buffer_position as u64;
        self.buffer_position = 0;
        self.buffer_valid_len = 0;

        // Calculate how many bytes remain in the blob
        let blob_remaining = self.blob_size.saturating_sub(self.blob_position);
        if blob_remaining == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        // Calculate how much to read (minimum of buffer size and remaining bytes)
        let bytes_to_read = std::cmp::min(self.buffer_size as u64, blob_remaining) as usize;

        // Read the data - we only need a single read operation since we know exactly how much data is available
        self.blob
            .read_at(&mut self.buffer[..bytes_to_read], self.blob_position)
            .await?;
        self.buffer_valid_len = bytes_to_read;

        Ok(bytes_to_read)
    }

    /// Reads exactly `size` bytes into the provided buffer.
    /// Returns an error if not enough bytes are available.
    pub async fn read_exact(&mut self, buf: &mut [u8], size: usize) -> Result<(), Error> {
        // Quick check if we have enough bytes total before attempting reads
        if (self.buffer_remaining() + self.blob_remaining() as usize) < size {
            return Err(Error::BlobInsufficientLength);
        }

        // Read until we have enough bytes
        let mut bytes_read = 0;
        while bytes_read < size {
            // Check if we need to refill
            if self.buffer_position >= self.buffer_valid_len {
                self.refill().await?;
            }

            // Calculate how many bytes we can copy from the buffer
            let bytes_to_copy = std::cmp::min(
                size - bytes_read,
                self.buffer_valid_len - self.buffer_position,
            );

            // Copy bytes from buffer to output
            buf[bytes_read..(bytes_read + bytes_to_copy)].copy_from_slice(
                &self.buffer[self.buffer_position..(self.buffer_position + bytes_to_copy)],
            );

            self.buffer_position += bytes_to_copy;
            bytes_read += bytes_to_copy;
        }

        Ok(())
    }

    /// Peeks at the next `size` bytes without advancing the read position.
    /// Returns a slice to the peeked data or an error if not enough bytes are available.
    pub async fn peek(&mut self, size: usize) -> Result<&[u8], Error> {
        // Quick check if we already have enough data in the buffer
        if self.buffer_remaining() >= size {
            return Ok(&self.buffer[self.buffer_position..(self.buffer_position + size)]);
        }

        // Check if enough total bytes are available
        let total_available = (self.buffer_remaining() as u64 + self.blob_remaining()) as usize;
        if total_available < size {
            return Err(Error::BlobInsufficientLength);
        }

        // We need to do a more complex operation: copy remaining data to beginning,
        // then refill the rest of the buffer
        let remaining = self.buffer_remaining();
        if remaining > 0 {
            // Copy the remaining data to the beginning of the buffer
            self.buffer
                .copy_within(self.buffer_position..self.buffer_valid_len, 0);
        }

        // Update positions
        self.blob_position += self.buffer_position as u64;
        self.buffer_valid_len = remaining;
        self.buffer_position = 0;

        // Read more data into the buffer after the remaining data
        let read_pos = self.blob_position + remaining as u64;
        let bytes_blob_remaining = self.blob_size.saturating_sub(read_pos);
        let read_size =
            std::cmp::min((self.buffer_size - remaining) as u64, bytes_blob_remaining) as usize;
        if read_size > 0 {
            match self
                .blob
                .read_at(&mut self.buffer[remaining..remaining + read_size], read_pos)
                .await
            {
                Ok(read) => {
                    self.buffer_valid_len = remaining + read_size;
                }
                Err(e) => return Err(e),
            }
        }

        // If we could not fill the buffer, return an error
        if self.buffer_valid_len < size {
            return Err(Error::BlobInsufficientLength);
        }

        Ok(&self.buffer[0..size])
    }

    /// Advances the read position by `bytes` without reading data.
    pub fn advance(&mut self, bytes: usize) -> Result<(), Error> {
        if self.buffer_position + bytes > self.buffer_valid_len {
            return Err(Error::BlobInsufficientLength);
        }

        self.buffer_position += bytes;
        Ok(())
    }

    /// Returns the current absolute position in the blob.
    pub fn position(&self) -> u64 {
        self.blob_position + self.buffer_position as u64
    }

    /// Repositions the buffer to read from the specified position in the blob.
    pub fn seek_to(&mut self, position: u64) -> Result<(), Error> {
        // Check if the seek position is valid
        if position > self.blob_size {
            return Err(Error::BlobInsufficientLength);
        }

        // Reset buffer state
        self.blob_position = position;
        self.buffer_position = 0;
        self.buffer_valid_len = 0;

        Ok(())
    }

    /// Truncates the blob to the specified size.
    ///
    /// This may be useful if reading some blob after unclean shutdown.
    pub async fn truncate(self, size: u64) -> Result<(), Error> {
        self.blob.truncate(size).await?;
        self.blob.sync().await
    }
}

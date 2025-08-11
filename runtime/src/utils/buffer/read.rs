use crate::{Blob, Error};
use commonware_utils::StableBuf;
use std::num::NonZeroUsize;

/// A reader that buffers content from a [Blob] to optimize the performance
/// of a full scan of contents.
///
/// # Example
///
/// ```
/// use commonware_utils::NZUsize;
/// use commonware_runtime::{Runner, buffer::Read, Blob, Error, Storage, deterministic};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob and add some data (e.g., a journal file)
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     let data = b"Hello, world! This is a test.".to_vec();
///     let size = data.len() as u64;
///     blob.write_at(data, 0).await.expect("unable to write data");
///
///     // Create a buffer
///     let buffer = 64 * 1024;
///     let mut reader = Read::new(blob, size, NZUsize!(buffer));
///
///     // Read data sequentially
///     let mut header = [0u8; 16];
///     reader.read_exact(&mut header, 16).await.expect("unable to read data");
///     println!("Read header: {:?}", header);
///
///     // Position is still at 16 (after header)
///     assert_eq!(reader.position(), 16);
/// });
/// ```
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The buffer storing the data read from the blob.
    buffer: StableBuf,
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

impl<B: Blob> Read<B> {
    /// Creates a new `Read` that reads from the given blob with the specified buffer size.
    ///
    /// # Panics
    ///
    /// Panics if `buffer_size` is zero.
    pub fn new(blob: B, blob_size: u64, buffer_size: NonZeroUsize) -> Self {
        Self {
            blob,
            buffer: vec![0; buffer_size.get()].into(),
            blob_position: 0,
            blob_size,
            buffer_position: 0,
            buffer_valid_len: 0,
            buffer_size: buffer_size.get(),
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

    /// Returns the number of bytes in the blob, as provided at construction.
    pub fn blob_size(&self) -> u64 {
        self.blob_size
    }

    /// Refills the buffer from the blob starting at the current blob position.
    /// Returns the number of bytes read or an error if the read failed.
    async fn refill(&mut self) -> Result<usize, Error> {
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

        // Read the data - we only need a single read operation since we know exactly how much data is available.
        if bytes_to_read < self.buffer_size {
            // Read into a temp buffer for the end-of-blob case to avoid truncating underlying buffer.
            let mut tmp_buffer = vec![0u8; bytes_to_read];
            tmp_buffer = self
                .blob
                .read_at(tmp_buffer, self.blob_position)
                .await?
                .into();
            self.buffer.as_mut()[0..bytes_to_read].copy_from_slice(&tmp_buffer[0..bytes_to_read]);
        } else {
            self.buffer = self
                .blob
                .read_at(std::mem::take(&mut self.buffer), self.blob_position)
                .await?;
        }
        self.buffer_valid_len = bytes_to_read;

        Ok(bytes_to_read)
    }

    /// Reads exactly `size` bytes into the provided buffer. Returns an error if not enough bytes
    /// are available.
    ///
    /// # Panics
    ///
    /// Panics if `size` is greater than the length of `buf`.
    pub async fn read_exact(&mut self, buf: &mut [u8], size: usize) -> Result<(), Error> {
        assert!(
            size <= buf.len(),
            "provided buffer is too small for requested size"
        );

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
            let bytes_to_copy = std::cmp::min(size - bytes_read, self.buffer_remaining());

            // Copy bytes from buffer to output
            buf[bytes_read..(bytes_read + bytes_to_copy)].copy_from_slice(
                &self.buffer.as_ref()[self.buffer_position..(self.buffer_position + bytes_to_copy)],
            );

            self.buffer_position += bytes_to_copy;
            bytes_read += bytes_to_copy;
        }

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

        // Check if the position is within the current buffer
        let buffer_start = self.blob_position;
        let buffer_end = self.blob_position + self.buffer_valid_len as u64;

        if position >= buffer_start && position < buffer_end {
            // Position is within the current buffer, adjust buffer_position
            self.buffer_position = (position - self.blob_position) as usize;
        } else {
            // Position is outside the current buffer, reset buffer state
            self.blob_position = position;
            self.buffer_position = 0;
            self.buffer_valid_len = 0;
        }

        Ok(())
    }

    /// Resizes the blob to the specified len and syncs the blob.
    ///
    /// This may be useful if reading some blob after unclean shutdown.
    pub async fn resize(self, len: u64) -> Result<(), Error> {
        self.blob.resize(len).await?;
        self.blob.sync().await
    }
}

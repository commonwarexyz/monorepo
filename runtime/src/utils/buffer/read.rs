use crate::{Blob, Buf as _, Error, IoBufs};
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
///     blob.write_at(0, data).await.expect("unable to write data");
///
///     // Create a buffer
///     let buffer = 64 * 1024;
///     let mut reader = Read::new(blob, size, NZUsize!(buffer));
///
///     // Read data sequentially
///     let header = reader.read_exact(16).await.expect("unable to read data");
///     println!("Read header: {:?}", header.coalesce());
///
///     // Position is still at 16 (after header)
///     assert_eq!(reader.position(), 16);
/// });
/// ```
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The buffered unread bytes.
    buffer: IoBufs,
    /// The next absolute position to fetch from the blob.
    fetch_position: u64,
    /// The size of the blob.
    blob_size: u64,
    /// The maximum size of the buffer.
    buffer_size: usize,
}

impl<B: Blob> Read<B> {
    /// Creates a new `Read` that reads from the given blob with the specified buffer size.
    pub fn new(blob: B, blob_size: u64, buffer_size: NonZeroUsize) -> Self {
        Self {
            blob,
            buffer: IoBufs::default(),
            fetch_position: 0,
            blob_size,
            buffer_size: buffer_size.get(),
        }
    }

    /// Returns how many valid bytes are remaining in the buffer.
    pub fn buffer_remaining(&self) -> usize {
        self.buffer.len()
    }

    /// Returns how many bytes remain in the blob from the current position.
    pub fn blob_remaining(&self) -> u64 {
        self.blob_size.saturating_sub(self.position())
    }

    /// Returns the number of bytes in the blob, as provided at construction.
    pub const fn blob_size(&self) -> u64 {
        self.blob_size
    }

    /// Refills the buffer from the blob starting at the current blob position.
    /// Returns the number of bytes read or an error if the read failed.
    async fn refill(&mut self) -> Result<usize, Error> {
        // Calculate how many bytes remain in the blob from the fetch cursor.
        let blob_remaining = self.blob_size.saturating_sub(self.fetch_position);
        if blob_remaining == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        // Calculate how much to read (minimum of buffer size and remaining bytes)
        let bytes_to_read = std::cmp::min(self.buffer_size as u64, blob_remaining) as usize;

        let read = self
            .blob
            .read_at(self.fetch_position, bytes_to_read)
            .await?
            .freeze();
        self.fetch_position = self
            .fetch_position
            .checked_add(bytes_to_read as u64)
            .ok_or(Error::OffsetOverflow)?;
        self.buffer.extend(read);

        Ok(bytes_to_read)
    }

    /// Reads exactly `size` bytes and returns them as immutable buffers.
    pub async fn read_exact(&mut self, size: usize) -> Result<IoBufs, Error> {
        if size == 0 {
            return Ok(IoBufs::default());
        }
        // Quick check if we have enough bytes total before attempting reads.
        if self.blob_remaining() < size as u64 {
            return Err(Error::BlobInsufficientLength);
        }

        while self.buffer_remaining() < size {
            self.refill().await?;
        }

        Ok(self.buffer.split_to(size))
    }

    /// Reads up to `max_len` bytes and returns available bytes as immutable buffers.
    pub async fn read_up_to(&mut self, max_len: usize) -> Result<IoBufs, Error> {
        if max_len == 0 {
            return Ok(IoBufs::default());
        }
        // `blob_remaining()` already includes unread buffered bytes because
        // `position()` is derived from `fetch_position - buffer_remaining()`.
        let available = std::cmp::min(max_len, self.blob_remaining() as usize);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        self.read_exact(available).await
    }

    /// Returns the current absolute position in the blob.
    pub fn position(&self) -> u64 {
        self.fetch_position
            .saturating_sub(self.buffer_remaining() as u64)
    }

    /// Repositions the buffer to read from the specified position in the blob.
    pub fn seek_to(&mut self, position: u64) -> Result<(), Error> {
        // Check if the seek position is valid
        if position > self.blob_size {
            return Err(Error::BlobInsufficientLength);
        }

        // Check if the position is within the currently buffered range.
        let buffer_start = self.position();
        let buffer_end = self.fetch_position;
        if position >= buffer_start && position < buffer_end {
            // Position is within buffered data: advance within current buffer.
            self.buffer.advance((position - buffer_start) as usize);
        } else {
            // Position is outside current buffer, reset read state.
            self.fetch_position = position;
            self.buffer = IoBufs::default();
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

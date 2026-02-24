use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufs};
use std::num::NonZeroUsize;

/// A reader that buffers content from a [Blob] to optimize the performance
/// of a full scan of contents.
///
/// # Example
///
/// ```
/// use commonware_utils::NZUsize;
/// use commonware_runtime::{Runner, buffer::Read, Blob, Error, Storage, deterministic, BufferPooler};
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
///     let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(buffer));
///
///     // Read data sequentially
///     let header = reader.read_exact(16).await.expect("unable to read data");
///     println!("Read header: {:?}", header.coalesce().as_ref());
///
///     // Position is still at 16 (after header)
///     assert_eq!(reader.position(), 16);
/// });
/// ```
pub struct Read<B: Blob> {
    /// The underlying blob to read from.
    blob: B,
    /// The buffer storing the data read from the blob.
    buffer: IoBuf,
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
    /// Buffer pool used for internal allocations.
    pool: BufferPool,
}

impl<B: Blob> Read<B> {
    /// Creates a new `Read` that reads from the given blob with the specified buffer size.
    pub fn new(blob: B, blob_size: u64, buffer_size: NonZeroUsize, pool: BufferPool) -> Self {
        Self {
            blob,
            buffer: pool.alloc(buffer_size.get()).freeze(),
            blob_position: 0,
            blob_size,
            buffer_position: 0,
            buffer_valid_len: 0,
            buffer_size: buffer_size.get(),
            pool,
        }
    }

    /// Creates a new `Read`, extracting the storage [BufferPool] from a [BufferPooler].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        blob: B,
        blob_size: u64,
        buffer_size: NonZeroUsize,
    ) -> Self {
        Self::new(
            blob,
            blob_size,
            buffer_size,
            pooler.storage_buffer_pool().clone(),
        )
    }

    /// Returns how many valid bytes are remaining in the buffer.
    pub const fn buffer_remaining(&self) -> usize {
        self.buffer_valid_len - self.buffer_position
    }

    /// Returns how many bytes remain in the blob from the current position.
    pub const fn blob_remaining(&self) -> u64 {
        self.blob_size
            .saturating_sub(self.blob_position + self.buffer_position as u64)
    }

    /// Returns the number of bytes in the blob, as provided at construction.
    pub const fn blob_size(&self) -> u64 {
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

        // Reuse existing allocation when uniquely owned. If readers still hold slices from
        // previous reads, allocate a replacement and leave old memory alive until dropped.
        let current = std::mem::take(&mut self.buffer);
        let buf = match current.try_into_mut() {
            Ok(mut reusable) if reusable.capacity() >= bytes_to_read => {
                reusable.clear();
                reusable
            }
            Ok(_) | Err(_) => self.pool.alloc(bytes_to_read),
        };
        let read_result = self
            .blob
            .read_at_buf(self.blob_position, bytes_to_read, buf)
            .await?;
        self.buffer = read_result.coalesce_with_pool(&self.pool).freeze();
        self.buffer_valid_len = self.buffer.len();

        Ok(self.buffer_valid_len)
    }

    /// Reads exactly `len` bytes and returns them as immutable bytes.
    ///
    /// Returned bytes are composed of zero-copy slices from the internal read cache.
    /// Returns an error if not enough bytes are available.
    pub async fn read_exact(&mut self, len: usize) -> Result<IoBufs, Error> {
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Quick check if we have enough bytes total before attempting reads
        if (self.buffer_remaining() + self.blob_remaining() as usize) < len {
            return Err(Error::BlobInsufficientLength);
        }

        let mut out = IoBufs::default();
        let mut remaining = len;

        // Read until we have enough bytes
        while remaining > 0 {
            // Check if we need to refill
            if self.buffer_position >= self.buffer_valid_len {
                self.refill().await?;
            }

            // Calculate how many bytes we can take from the buffer
            let bytes_to_take = std::cmp::min(remaining, self.buffer_remaining());

            // Append bytes from buffer to output
            out.append(
                self.buffer
                    .slice(self.buffer_position..(self.buffer_position + bytes_to_take)),
            );

            self.buffer_position += bytes_to_take;
            remaining -= bytes_to_take;
        }

        Ok(out)
    }

    /// Returns the current absolute position in the blob.
    pub const fn position(&self) -> u64 {
        self.blob_position + self.buffer_position as u64
    }

    /// Repositions the buffer to read from the specified position in the blob.
    pub const fn seek_to(&mut self, position: u64) -> Result<(), Error> {
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

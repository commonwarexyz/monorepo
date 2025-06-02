use crate::{Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::sync::Arc;

/// The internal state of a [Write] buffer.
struct Inner<B: Blob> {
    /// The underlying blob to write to.
    blob: B,
    /// The buffer storing data to be written to the blob.
    ///
    /// The buffer always represents data at the "tip" of the logical blob,
    /// starting at `position` and extending for `buffer.len()` bytes.
    buffer: Vec<u8>,
    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where `buffer[0]` would be written.
    /// The buffer is maintained at the "tip" to support efficient size calculation and appends.
    position: u64,
    /// The maximum size of the buffer.
    capacity: usize,
}

impl<B: Blob> Inner<B> {
    /// Appends bytes to the internal buffer, maintaining the "buffer at tip" invariant.
    ///
    /// If the buffer capacity would be exceeded, it is flushed first. If the data
    /// is larger than the buffer capacity, it is written directly to the blob.
    ///
    /// Returns an error if the write to the underlying [Blob] fails (may be due to a `flush` of data not
    /// related to the data being written).
    async fn write<S: Into<StableBuf>>(&mut self, buf: S) -> Result<(), Error> {
        // If the buffer capacity will be exceeded, flush the buffer first
        let buf = buf.into();
        let buf_len = buf.len();

        // Flush buffer if adding this data would exceed capacity
        if self.buffer.len() + buf_len > self.capacity {
            self.flush().await?;
        }

        // Write directly to blob if data is larger than buffer capacity
        if buf_len > self.capacity {
            self.blob.write_at(buf, self.position).await?;
            self.position += buf_len as u64;
            return Ok(());
        }

        // Append to buffer (buffer is now guaranteed to have space)
        self.buffer.extend_from_slice(buf.as_ref());
        Ok(())
    }

    /// Flushes buffered data to the underlying [Blob] and advances the position.
    ///
    /// After flushing, the buffer is reset and positioned at the new tip.
    /// Does nothing if the buffer is empty.
    ///
    /// # Returns
    ///
    /// An error if the write to the underlying [Blob] fails. On failure,
    /// the buffer is reset and pending data is lost.
    async fn flush(&mut self) -> Result<(), Error> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Take the buffer contents and write to blob
        let buf = std::mem::take(&mut self.buffer);
        let len = buf.len() as u64;
        self.blob.write_at(buf, self.position).await?;

        // Advance position to the new tip and reset buffer
        self.position += len;
        self.buffer = Vec::with_capacity(self.capacity);
        Ok(())
    }

    /// Flushes buffered data and ensures it is durably persisted to the underlying [Blob].
    ///
    /// Returns an error if either the flush or sync operation fails.
    async fn sync(&mut self) -> Result<(), Error> {
        self.flush().await?;
        self.blob.sync().await
    }

    /// Closes the writer and ensures all buffered data is durably persisted to the underlying [Blob].
    ///
    /// Returns an error if the close operation fails.
    async fn close(&mut self) -> Result<(), Error> {
        // Ensure all buffered data is durably persisted
        self.sync().await?;

        // Close the underlying blob.
        //
        // We use clone here to ensure we retain the close semantics of the blob provided (if
        // called multiple times, the blob determines whether to error).
        self.blob.clone().close().await
    }
}

/// A writer that buffers content to a [Blob] to optimize the performance
/// of appending or updating data.
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, buffer::{Write, Read}, Blob, Error, Storage, deterministic};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob for writing
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     assert_eq!(size, 0);
///
///     // Create a buffered writer with 16-byte buffer
///     let mut blob = Write::new(blob, 0, 16);
///     blob.write_at(b"hello".to_vec(), 0).await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Write more data in multiple flushes
///     blob.write_at(b" world".to_vec(), 5).await.expect("write failed");
///     blob.write_at(b"!".to_vec(), 11).await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Read back the data to verify
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to reopen blob");
///     let mut reader = Read::new(blob, size, 8);
///     let mut buf = vec![0u8; size as usize];
///     reader.read_exact(&mut buf, size as usize).await.expect("read failed");
///     assert_eq!(&buf, b"hello world!");
/// });
/// ```
#[derive(Clone)]
pub struct Write<B: Blob> {
    inner: Arc<RwLock<Inner<B>>>,
}

impl<B: Blob> Write<B> {
    /// Creates a new `Write` that buffers writes to a [Blob] with the provided size and buffer capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(blob: B, size: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be greater than zero");
        Self {
            inner: Arc::new(RwLock::new(Inner {
                blob,
                buffer: Vec::with_capacity(capacity),
                position: size,
                capacity,
            })),
        }
    }

    /// Returns the current logical size of the blob including any buffered data.
    ///
    /// This represents the total size of data that would be present after flushing.
    #[allow(clippy::len_without_is_empty)]
    pub async fn size(&self) -> u64 {
        let inner = self.inner.read().await;
        inner.position + inner.buffer.len() as u64
    }
}

impl<B: Blob> Blob for Write<B> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        // Acquire a read lock on the inner state
        let inner = self.inner.read().await;

        // Ensure offset read doesn't overflow
        let mut buf = buf.into();
        let data_len = buf.len();
        let data_end = offset
            .checked_add(data_len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // If the data required is beyond the buffer end, return an error
        let buffer_start = inner.position;
        let buffer_end = buffer_start + inner.buffer.len() as u64;

        // Ensure we don't read beyond the logical end of the blob
        if data_end > buffer_end {
            return Err(Error::BlobInsufficientLength);
        }

        // Case 1: Read entirely from the underlying blob (before buffer)
        if data_end <= buffer_start {
            return inner.blob.read_at(buf, offset).await;
        }

        // Case 2: Read entirely from the buffer
        if offset >= buffer_start {
            let buffer_offset = (offset - buffer_start) as usize;
            let end_offset = buffer_offset + data_len;

            if end_offset > inner.buffer.len() {
                return Err(Error::BlobInsufficientLength);
            }

            buf.put_slice(&inner.buffer[buffer_offset..end_offset]);
            return Ok(buf);
        }

        // Case 3: Read spans both blob and buffer
        let blob_bytes = (buffer_start - offset) as usize;
        let buffer_bytes = data_len - blob_bytes;

        // Read from blob first
        let blob_part = vec![0u8; blob_bytes];
        let blob_part = inner.blob.read_at(blob_part, offset).await?;

        // Copy blob data and buffer data to result
        buf.as_mut()[..blob_bytes].copy_from_slice(blob_part.as_ref());
        buf.as_mut()[blob_bytes..].copy_from_slice(&inner.buffer[..buffer_bytes]);

        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        // Acquire a write lock on the inner state
        let mut inner = self.inner.write().await;

        // Prepare the buf to be written
        let buf = buf.into();
        let data = buf.as_ref();
        let data_len = data.len();

        // Current state of the buffer in the blob
        let buffer_start = inner.position;
        let buffer_end = buffer_start + inner.buffer.len() as u64;

        // Case 1: Simple append to buffered data (most common case)
        if offset == buffer_end {
            return inner.write(buf).await;
        }

        // Case 2: Write can be merged into existing buffer.
        //
        // This handles overwrites and extensions within the buffer's current capacity,
        // including writes that create gaps (filled with zeros) in the buffer.
        let can_merge_into_buffer = offset >= buffer_start
            && (offset - buffer_start) + data_len as u64 <= inner.capacity as u64;
        if can_merge_into_buffer {
            let buffer_offset = (offset - buffer_start) as usize;
            let required_len = buffer_offset + data_len;

            // Expand buffer if necessary (fills with zeros)
            if required_len > inner.buffer.len() {
                inner.buffer.resize(required_len, 0);
            }

            // Copy data into buffer
            inner.buffer[buffer_offset..required_len].copy_from_slice(data);
            return Ok(());
        }

        // Case 3: Write cannot be merged - flush buffer and write directly.
        //
        // This includes: writes before the buffer, writes that would exceed capacity,
        // or non-contiguous writes that can't be merged.
        if !inner.buffer.is_empty() {
            inner.flush().await?;
        }
        inner.blob.write_at(buf, offset).await?;

        // Update position to maintain "buffer at tip" invariant.
        //
        // Position should advance to the end of this write if it extends the logical blob
        let write_end = offset + data_len as u64;
        if write_end > inner.position {
            inner.position = write_end;
        }

        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Acquire a write lock on the inner state
        let mut inner = self.inner.write().await;

        // Determine the current buffer boundaries
        let buffer_start = inner.position;
        let buffer_end = buffer_start + inner.buffer.len() as u64;

        // Adjust buffer content based on truncation point
        if len <= buffer_start {
            // Truncation point is before or at the start of the buffer.
            //
            // All buffered data is now beyond the new length and should be discarded.
            inner.buffer.clear();
            inner.blob.truncate(len).await?;
            inner.position = len;
        } else if len < buffer_end {
            // Truncation point is within the buffer.
            //
            // Keep only the portion of the buffer up to the truncation point.
            let new_buffer_len = (len - buffer_start) as usize;
            inner.buffer.truncate(new_buffer_len);
        } else {
            // Truncation point is at or after the end of the buffer.
            //
            // No changes needed to the buffer content.
        }
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.close().await
    }
}

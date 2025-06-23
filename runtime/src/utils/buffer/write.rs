use crate::{Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::sync::Arc;

/// The state of any buffered data yet to be written to a [Blob].
///
/// The buffer always represents data at the "tip" of the logical blob, starting at `position` and
/// extending for `data.len()` bytes.
struct Buffer {
    /// The data to be written to the blob.
    data: Vec<u8>,
    /// The offset in the blob where the buffered data starts.
    ///
    /// This represents the logical position in the blob where `data[0]` would be written. The
    /// buffer is maintained at the "tip" to support efficient size calculation and appends.
    position: u64,
    /// The maximum size of the buffer.
    capacity: usize,
}

impl Buffer {
    /// Returns the current logical size of the blob including any buffered data.
    fn size(&self) -> u64 {
        self.position + self.data.len() as u64
    }

    /// Appends `buf` to the internal `data` buffer, maintaining the "buffer at tip" invariant.
    ///
    /// If the buffer capacity would be exceeded, it is flushed first. If the data is larger than
    /// the buffer capacity, it is written directly to the blob.
    ///
    /// Returns an error if the write to `blob` fails (may be due to a `flush` of data not related
    /// to the data being written).
    async fn write(
        &mut self,
        blob: &impl Blob,
        buf: impl Into<StableBuf> + Send,
    ) -> Result<(), Error> {
        // If the buffer capacity will be exceeded, flush the buffer first
        let buf = buf.into();
        let buf_len = buf.len();

        // Flush buffer if adding this data would exceed capacity.
        if self.data.len() + buf_len > self.capacity {
            self.flush(blob).await?;
        }

        // Write directly to blob if data is larger than buffer capacity.
        if buf_len > self.capacity {
            blob.write_at(buf, self.position).await?;
            self.position += buf_len as u64;
            return Ok(());
        }

        // Append `buf` to `data` (which is now guaranteed to have space).
        self.data.extend_from_slice(buf.as_ref());
        Ok(())
    }

    /// Flushes buffered data to `blob` and advances the position.
    ///
    /// After flushing, the buffer is reset and positioned at the new tip.
    /// Does nothing if the buffer is empty.
    ///
    /// # Returns
    ///
    /// An error if the write to `blob` fails. On failure, the buffer is reset
    /// and pending data is lost.
    async fn flush(&mut self, blob: &impl Blob) -> Result<(), Error> {
        if self.data.is_empty() {
            return Ok(());
        }

        // Write `data` to the blob after replacing it with a new vector.
        let buf = std::mem::replace(&mut self.data, Vec::with_capacity(self.capacity));
        let len = buf.len() as u64;
        blob.write_at(buf, self.position).await?;

        // Advance position to the new tip.
        self.position += len;

        Ok(())
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
    /// The underlying blob to write to.
    blob: B,

    /// The internal blob buffer.
    buffer: Arc<RwLock<Buffer>>,
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers writes to a [Blob] with the provided size and buffer
    /// capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(blob: B, size: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be greater than zero");

        Self {
            blob,
            buffer: Arc::new(RwLock::new(Buffer {
                data: Vec::with_capacity(capacity),
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
        let buffer = self.buffer.read().await;

        buffer.size()
    }

    /// Consumes the [Write] and returns the underlying blob.
    ///
    /// # Warning
    ///
    /// Any buffered data that hasn't been flushed or synced will be discarded.
    pub fn take_blob(self) -> B {
        self.blob
    }

    /// Clones the underlying blob.
    ///
    /// # Warning
    ///
    /// The returned blob will not include any data that has yet to be flushed from the buffer.
    pub fn clone_blob(&self) -> B {
        self.blob.clone()
    }
}

impl<B: Blob> Blob for Write<B> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        // Acquire a read lock on the buffer.
        let buffer = self.buffer.read().await;

        // Ensure offset read doesn't overflow.
        let mut buf = buf.into();
        let buf_len = buf.len(); // number of bytes to read
        let buffer_offset = buffer.position; // offset of first byte in buffer
        let end_offset = offset
            .checked_add(buf_len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Case 1: Read entirely from the underlying blob (before buffer).
        if end_offset <= buffer_offset {
            return self.blob.read_at(buf, offset).await;
        }

        // Case 2: Read entirely from the buffer.
        if offset >= buffer_offset {
            let start = (offset - buffer_offset) as usize;
            let end = start + buf_len;
            assert!(end <= buffer.data.len()); // should hold due to previous check

            buf.put_slice(&buffer.data[start..end]);
            return Ok(buf);
        }

        // Case 3: Read spans both blob and buffer.
        let blob_bytes = (buffer_offset - offset) as usize;
        let buffer_bytes = buf_len - blob_bytes;

        // Read from blob first.
        let blob_part = vec![0u8; blob_bytes];
        let blob_part = self.blob.read_at(blob_part, offset).await?;

        // Copy blob data and buffer data to result.
        buf.as_mut()[..blob_bytes].copy_from_slice(blob_part.as_ref());
        buf.as_mut()[blob_bytes..].copy_from_slice(&buffer.data[..buffer_bytes]);

        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Case 1: Simple append to buffered data (most common case).
        if offset == buffer.size() {
            return buffer.write(&self.blob, buf).await;
        }

        // Prepare `buf` to be written.
        let buf = buf.into();
        let buf_len = buf.len(); // number of bytes to write

        // Offset of the first byte in the buffer.
        let buffer_offset = buffer.position;

        // Case 2: Write can be merged into existing buffer.
        //
        // This handles overwrites and extensions within the buffer's current capacity,
        // including writes that create gaps (filled with zeros) in the buffer.
        let end_offset = offset
            .checked_add(buf_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        let can_merge_into_buffer =
            offset >= buffer_offset && end_offset <= buffer_offset + buffer.capacity as u64;
        if can_merge_into_buffer {
            let start = (offset - buffer_offset) as usize;
            let end = start + buf_len;
            // Expand buffer if necessary (fills with zeros).
            if end > buffer.data.len() {
                buffer.data.resize(end, 0);
            }

            // Copy data into buffer
            buffer.data[start..end].copy_from_slice(buf.as_ref());
            return Ok(());
        }

        // Case 3: Write cannot be merged - flush buffer and write directly.
        //
        // This includes: writes before the buffer, writes that would exceed capacity,
        // or non-contiguous writes that can't be merged.
        if !buffer.data.is_empty() {
            buffer.flush(&self.blob).await?;
        }
        self.blob.write_at(buf, offset).await?;

        // Update position to maintain "buffer at tip" invariant.
        //
        // Position should advance to the end of this write if it extends the logical blob
        let write_end = offset + buf_len as u64;
        if write_end > buffer.position {
            buffer.position = write_end;
        }

        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        let buffer_offset = buffer.position; // offset of first byte in buffer

        // Adjust buffer content based on truncation point.
        if len <= buffer_offset {
            // Truncation point is before or at the start of the buffer.
            //
            // All buffered data is now beyond the new length and should be discarded.
            buffer.data.clear();
            self.blob.truncate(len).await?;
            buffer.position = len;
        } else if len < buffer.size() {
            // Truncation point is within the buffer.
            //
            // Keep only the portion of the buffer up to the truncation point.
            let new_buffer_len = (len - buffer_offset) as usize;
            buffer.data.truncate(new_buffer_len);
        } else {
            // Truncation point is at or after the end of the buffer.
            //
            // No changes needed to the buffer content.
        }
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        buffer.flush(&self.blob).await?;
        self.blob.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        self.sync().await?;
        // We use clone here to ensure we retain the close semantics of the blob provided (if
        // called multiple times, the blob determines whether to error).
        self.blob.clone().close().await
    }
}

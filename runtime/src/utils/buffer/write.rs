use crate::{buffer::tip::Buffer, Blob, Buf, BufferPool, BufferPooler, Error, IoBuf, IoBufs};
use commonware_utils::sync::AsyncRwLock;
use std::{num::NonZeroUsize, sync::Arc};

/// A writer that buffers the raw content of a [Blob] to optimize the performance of appending or
/// updating data.
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, BufferPooler, buffer::{Write, Read}, Blob, Error, Storage, deterministic};
/// use commonware_utils::NZUsize;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob for writing
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     assert_eq!(size, 0);
///
///     // Create a buffered writer with 16-byte buffer
///     let mut blob = Write::from_pooler(&context, blob, 0, NZUsize!(16));
///     blob.write_at(0, b"hello").await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Write more data in multiple flushes
///     blob.write_at(5, b" world").await.expect("write failed");
///     blob.write_at(11, b"!").await.expect("write failed");
///     blob.sync().await.expect("sync failed");
///
///     // Read back the data to verify
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to reopen blob");
///     let mut reader = Read::from_pooler(&context, blob, size, NZUsize!(8));
///     let buf = reader.read_exact(size as usize).await.expect("read failed");
///     assert_eq!(buf.as_ref(), b"hello world!");
/// });
/// ```
#[derive(Clone)]
pub struct Write<B: Blob> {
    /// The underlying blob to write to.
    blob: B,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob.
    buffer: Arc<AsyncRwLock<Buffer>>,
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers up to `capacity` bytes of data to be appended to the tip
    /// of `blob` with the provided `size`.
    pub fn new(blob: B, size: u64, capacity: NonZeroUsize, pool: BufferPool) -> Self {
        Self {
            blob,
            buffer: Arc::new(AsyncRwLock::new(Buffer::new(size, capacity.get(), pool))),
        }
    }

    /// Creates a new [Write], extracting the storage [BufferPool] from a [BufferPooler].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        blob: B,
        size: u64,
        capacity: NonZeroUsize,
    ) -> Self {
        Self::new(blob, size, capacity, pooler.storage_buffer_pool().clone())
    }

    /// Returns the current logical size of the blob including any buffered data.
    ///
    /// This represents the total size of data that would be present after flushing.
    #[allow(clippy::len_without_is_empty)]
    pub async fn size(&self) -> u64 {
        let buffer = self.buffer.read().await;
        buffer.size()
    }

    /// Reads up to `max_len` bytes starting at `offset`, but only as many as are available.
    pub async fn read_at_up_to(&self, offset: u64, max_len: usize) -> Result<IoBufs, Error> {
        if max_len == 0 {
            return Ok(IoBufs::default());
        }
        let size = self.size().await;
        let available = (size.saturating_sub(offset) as usize).min(max_len);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        self.read_at(offset, available).await
    }

    /// Read immutable bytes starting at `offset`.
    ///
    /// This method holds the tip-buffer read lock for the entire read, including persisted blob
    /// I/O, to preserve a consistent view when concurrent writes may flush or mutate overlapping
    /// ranges.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        if len == 0 {
            return Ok(IoBufs::default());
        }

        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        let buffer = self.buffer.read().await;
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Entirely in buffered tip.
        if offset >= buffer.offset {
            let start = (offset - buffer.offset) as usize;
            let end = start + len;
            return Ok(IoBuf::copy_from_slice(&buffer.data.as_ref()[start..end]).into());
        }

        // Entirely persisted.
        if end_offset <= buffer.offset {
            return Ok(self.blob.read_at(offset, len).await?.freeze());
        }

        // Overlaps persisted range and buffered tip.
        let persisted_len = (buffer.offset - offset) as usize;
        let tip_len = len - persisted_len;
        let tip = IoBuf::copy_from_slice(&buffer.data.as_ref()[..tip_len]);

        let mut persisted = self.blob.read_at(offset, persisted_len).await?.freeze();
        persisted.append(tip);
        Ok(persisted)
    }

    /// Write bytes from `buf` at `offset`.
    ///
    /// Data is merged into the in-memory tip buffer when possible; otherwise buffered data may be
    /// flushed and chunks are written directly to the underlying blob.
    ///
    /// Returns [Error::OffsetOverflow] when `offset + buf.len()` overflows.
    pub async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut buf = buf.into();

        // Ensure the write doesn't overflow.
        offset
            .checked_add(buf.remaining() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Process each chunk of the input buffer, attempting to merge into the tip buffer
        // or writing directly to the underlying blob.
        let mut current_offset = offset;
        while buf.has_remaining() {
            let chunk = buf.chunk();
            let chunk_len = chunk.len();

            // Chunk falls entirely within the buffer's current range and can be merged.
            if buffer.merge(chunk, current_offset) {
                buf.advance(chunk_len);
                current_offset += chunk_len as u64;
                continue;
            }

            // Chunk cannot be merged, so flush the buffer if the range overlaps, and check
            // if merge is possible after.
            let chunk_end = current_offset + chunk_len as u64;
            if buffer.offset < chunk_end {
                if let Some((old_buf, old_offset)) = buffer.take() {
                    self.blob.write_at(old_offset, old_buf).await?;
                    if buffer.merge(chunk, current_offset) {
                        buf.advance(chunk_len);
                        current_offset += chunk_len as u64;
                        continue;
                    }
                }
            }

            // Chunk could not be merged (exceeds buffer capacity or outside its range), so
            // write directly. Note that we may end up writing an intersecting range twice:
            // once when the buffer is flushed above, then again when we write the chunk
            // below. Removing this inefficiency may not be worth the additional complexity.
            let direct = buf.split_to(chunk_len);
            self.blob.write_at(current_offset, direct).await?;
            current_offset += chunk_len as u64;

            // Maintain the "buffer at tip" invariant by advancing offset to the end of this
            // write if it extended the underlying blob.
            buffer.offset = buffer.offset.max(current_offset);
        }

        Ok(())
    }

    /// Resize the logical blob to `len`.
    ///
    /// If buffered data exists and the resize extends beyond current size, buffered data is flushed
    /// before resizing the underlying blob.
    pub async fn resize(&self, len: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Flush buffered data to the underlying blob.
        //
        // This can only happen if the new size is greater than the current size.
        if let Some((buf, offset)) = buffer.resize(len) {
            self.blob.write_at(offset, buf).await?;
        }

        // Resize the underlying blob.
        self.blob.resize(len).await?;

        Ok(())
    }

    /// Flush buffered bytes and durably sync the underlying blob.
    pub async fn sync(&self) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        if let Some((buf, offset)) = buffer.take() {
            self.blob.write_at(offset, buf).await?;
        }
        self.blob.sync().await
    }
}

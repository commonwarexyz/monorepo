use crate::{buffer::tip::Buffer, Blob, Buf, BufferPool, BufferPooler, Error, IoBufs};
use commonware_utils::sync::AsyncRwLock;
use std::{num::NonZeroUsize, sync::Arc};

/// A writer that buffers the raw content of a [Blob] to optimize the performance of appending or
/// updating data.
///
/// # Allocation Semantics
///
/// - [Self::new] allocates tip backing eagerly at `capacity` via [Buffer::new].
/// - Most writes reuse that backing, copy-on-write allocation only occurs when buffered data is
///   shared (for example, after handing out immutable views) or a merge needs more capacity.
/// - Sparse writes merged into tip extend logical length and zero-fill any gap in-buffer.
/// - Flush paths ([Self::sync], [Self::resize], overlap flushes in [Self::write_at]) drain
///   logical bytes to the blob while keeping tip backing available for reuse.
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
///     assert_eq!(buf.coalesce().as_ref(), b"hello world!");
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

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a read lock on the buffer.
        let buffer = self.buffer.read().await;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Entirely in buffered tip.
        if offset >= buffer.offset {
            let start = (offset - buffer.offset) as usize;
            let end = start + len;
            return Ok(buffer.slice(start..end).into());
        }

        // Entirely in blob.
        if end_offset <= buffer.offset {
            return Ok(self.blob.read_at(offset, len).await?.freeze());
        }

        // Overlaps blob and buffered tip.
        let blob_len = (buffer.offset - offset) as usize;
        let tip_len = len - blob_len;
        let tip = buffer.slice(..tip_len);

        let mut blob = self.blob.read_at(offset, blob_len).await?.freeze();
        blob.append(tip);
        Ok(blob)
    }

    /// Write bytes from `buf` at `offset`.
    ///
    /// Data is merged into the in-memory tip buffer when possible, otherwise buffered data may be
    /// flushed and chunks are written directly to the underlying blob.
    ///
    /// Returns [Error::OffsetOverflow] when `offset + bufs.len()` overflows.
    pub async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut bufs = bufs.into();

        // Ensure the write doesn't overflow.
        offset
            .checked_add(bufs.remaining() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Process each chunk of the input buffer, attempting to merge into the tip buffer
        // or writing directly to the underlying blob.
        let mut current_offset = offset;
        while bufs.has_remaining() {
            let chunk = bufs.chunk();
            let chunk_len = chunk.len();

            // Chunk falls entirely within the buffer's current range and can be merged.
            if buffer.merge(chunk, current_offset) {
                bufs.advance(chunk_len);
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
                        bufs.advance(chunk_len);
                        current_offset += chunk_len as u64;
                        continue;
                    }
                }
            }

            // Chunk could not be merged (exceeds buffer capacity or outside its range), so
            // write directly. Note that we may end up writing an intersecting range twice:
            // once when the buffer is flushed above, then again when we write the chunk
            // below. Removing this inefficiency may not be worth the additional complexity.
            let direct = bufs.split_to(chunk_len);
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

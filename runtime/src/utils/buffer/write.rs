use crate::{
    buffer::tip::Buffer, Blob, Buf, BufferPool, Error, IoBufMut, IoBufs, IoBufsMut, RwLock,
};
use std::{num::NonZeroUsize, sync::Arc};

/// A writer that buffers the raw content of a [Blob] to optimize the performance of appending or
/// updating data.
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, buffer::{Write, Read}, Blob, BufferPooler, Error, Storage, deterministic};
/// use commonware_utils::NZUsize;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob for writing
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     assert_eq!(size, 0);
///
///     // Create a buffered writer with 16-byte buffer
///     let mut blob = Write::new(blob, 0, NZUsize!(16), context.storage_buffer_pool().clone());
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
///     let mut reader = Read::new(blob, size, NZUsize!(8), context.storage_buffer_pool().clone());
///     let mut buf = vec![0u8; size as usize];
///     reader.read_exact(&mut buf, size as usize).await.expect("read failed");
///     assert_eq!(&buf, b"hello world!");
/// });
/// ```
#[derive(Clone)]
pub struct Write<B: Blob> {
    /// The underlying blob to write to.
    blob: B,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob.
    buffer: Arc<RwLock<Buffer>>,
    /// Buffer pool used for internal allocations.
    _pool: BufferPool,
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers up to `capacity` bytes of data to be appended to the tip
    /// of `blob` with the provided `size`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(blob: B, size: u64, capacity: NonZeroUsize, pool: BufferPool) -> Self {
        Self {
            blob,
            buffer: Arc::new(RwLock::new(Buffer::new(size, capacity.get(), pool.clone()))),
            _pool: pool,
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
}

impl<B: Blob> Blob for Write<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, IoBufMut::with_capacity(len))
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        buf: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut buf = buf.into();
        // SAFETY: `len` bytes are filled via extract + blob read below.
        unsafe { buf.set_len(len) };

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

        match buf {
            // For single buffers, work directly to avoid copies.
            IoBufsMut::Single(mut single) => {
                // Extract any bytes from the buffer that overlap with the requested range.
                let remaining = buffer.extract(single.as_mut(), offset);

                // If bytes remain, read directly from the blob. Any remaining bytes reside at the beginning
                // of the range.
                if remaining > 0 {
                    let blob_result = self.blob.read_at(offset, remaining).await?;
                    single.as_mut()[..remaining].copy_from_slice(blob_result.coalesce().as_ref());
                }
                Ok(IoBufsMut::Single(single))
            }
            // For chunked buffers, read into temp and copy back to preserve structure.
            IoBufsMut::Chunked(chunks) => {
                let mut temp = self._pool.alloc(len);
                // SAFETY: We initialize all bytes via extract/blob read before copying out.
                unsafe { temp.set_len(len) };
                // Extract any bytes from the buffer that overlap with the
                // requested range, into a temporary contiguous buffer
                let remaining = buffer.extract(temp.as_mut(), offset);

                // If bytes remain, read directly from the blob. Any remaining bytes reside at the beginning
                // of the range.
                if remaining > 0 {
                    let blob_result = self.blob.read_at(offset, remaining).await?;
                    temp.as_mut()[..remaining].copy_from_slice(blob_result.coalesce().as_ref());
                }
                // Copy back to original chunks
                let mut bufs = IoBufsMut::Chunked(chunks);
                bufs.copy_from_slice(temp.as_ref());
                Ok(bufs)
            }
        }
    }

    async fn write_at(&self, offset: u64, buf: impl Into<IoBufs> + Send) -> Result<(), Error> {
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
            self.blob
                .write_at(current_offset, IoBufMut::from(chunk))
                .await?;
            buf.advance(chunk_len);
            current_offset += chunk_len as u64;

            // Maintain the "buffer at tip" invariant by advancing offset to the end of this
            // write if it extended the underlying blob.
            buffer.offset = buffer.offset.max(current_offset);
        }

        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
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

    async fn sync(&self) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        if let Some((buf, offset)) = buffer.take() {
            self.blob.write_at(offset, buf).await?;
        }
        self.blob.sync().await
    }
}

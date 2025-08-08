use crate::{buffer::tip::Buffer, Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::{num::NonZeroUsize, sync::Arc};

/// A writer that buffers content to a [Blob] to optimize the performance
/// of appending or updating data.
///
/// # Example
///
/// ```
/// use commonware_runtime::{Runner, buffer::{Write, Read}, Blob, Error, Storage, deterministic};
/// use commonware_utils::NZUsize;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Open a blob for writing
///     let (blob, size) = context.open("my_partition", b"my_data").await.expect("unable to open blob");
///     assert_eq!(size, 0);
///
///     // Create a buffered writer with 16-byte buffer
///     let mut blob = Write::new(blob, 0, NZUsize!(16));
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
///     let mut reader = Read::new(blob, size, NZUsize!(8));
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
}

impl<B: Blob> Write<B> {
    /// Creates a new [Write] that buffers up to `capacity` bytes of data to be appended to the tip
    /// of `blob` with the provided `size`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(blob: B, size: u64, capacity: NonZeroUsize) -> Self {
        Self {
            blob,
            buffer: Arc::new(RwLock::new(Buffer::new(size, capacity))),
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
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        // Prepare `buf` to capture the read data.
        let mut buf = buf.into();
        let buf_len = buf.len(); // number of bytes to read

        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(buf_len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a read lock on the buffer.
        let buffer = self.buffer.read().await;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Extract any bytes from the buffer that overlap with the requested range.
        let remaining = buffer.extract(buf.as_mut(), offset);
        if remaining == 0 {
            return Ok(buf);
        }

        // If bytes remain, read directly from the blob. Any remaining bytes reside at the beginning
        // of the range.
        let blob_part = self.blob.read_at(vec![0u8; remaining], offset).await?;
        buf.as_mut()[..remaining].copy_from_slice(blob_part.as_ref());

        Ok(buf)
    }

    async fn write_at(&self, buf: impl Into<StableBuf> + Send, offset: u64) -> Result<(), Error> {
        // Prepare `buf` to be written.
        let buf = buf.into();
        let buf_len = buf.len(); // number of bytes to write

        // Ensure the write doesn't overflow.
        let end_offset = offset
            .checked_add(buf_len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Write falls entirely within the buffer's current range and can be merged.
        if buffer.merge(buf.as_ref(), offset) {
            return Ok(());
        }

        // Write cannot be merged, so flush the buffer if the range overlaps, and check if merge is
        // possible after.
        if buffer.offset < end_offset {
            if let Some((old_buf, old_offset)) = buffer.take() {
                self.blob.write_at(old_buf, old_offset).await?;
                if buffer.merge(buf.as_ref(), offset) {
                    return Ok(());
                }
            }
        }

        // Write could not be merged (exceeds buffer capacity or outside its range), so write
        // directly. Note that we end up writing an intersecting range twice: once when the buffer
        // is flushed above, then again when we write the `buf` below. Removing this inefficiency
        // may not be worth the additional complexity.
        self.blob.write_at(buf, offset).await?;

        // Maintain the "buffer at tip" invariant by advancing offset to the end of this write if it
        // extended the underlying blob.
        buffer.offset = buffer.offset.max(end_offset);

        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Flush buffered data to the underlying blob.
        //
        // This can only happen if the new size is greater than the current size.
        if let Some((buf, offset)) = buffer.resize(len) {
            self.blob.write_at(buf, offset).await?;
        }

        // Resize the underlying blob.
        self.blob.resize(len).await?;

        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        if let Some((buf, offset)) = buffer.take() {
            self.blob.write_at(buf, offset).await?;
        }
        self.blob.sync().await
    }
}

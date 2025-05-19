use crate::{Blob, Error, RwLock};
use commonware_utils::{StableBuf, StableBufMut};
use std::sync::Arc;

/// The internal state of a [Write] buffer.
struct Inner<B: Blob> {
    /// The underlying blob to write to.
    blob: B,
    /// The buffer storing data to be written to the blob.
    buffer: Vec<u8>,
    /// The current position in the blob where the next flush will write.
    position: u64,
    /// The maximum size of the buffer.
    capacity: usize,
}

impl<B: Blob> Inner<B> {
    /// Returns the current position of the writer, including buffered but not-yet-flushed bytes.
    async fn position(&self) -> u64 {
        self.position + self.buffer.len() as u64
    }

    /// Appends bytes to the internal buffer. If the buffer capacity is exceeded, it will be flushed to the
    /// underlying [Blob].
    ///
    /// If the size of the provided bytes is larger than the buffer capacity, the bytes will be written
    /// directly to the underlying [Blob]. If this occurs regularly, the buffer capacity should be increased (or
    /// the buffer will not be effective).
    async fn write<Buf: StableBuf>(&mut self, buf: Buf) -> Result<(), Error> {
        // If the buffer capacity will be exceeded, flush the buffer first
        let buf_len = buf.len();
        if self.buffer.len() + buf_len > self.capacity {
            Self::flush(self).await?;
        }

        // Write directly to the blob (if the buffer is too small) or append to the buffer
        if buf_len > self.capacity {
            self.blob.write_at(buf, self.position).await?;
            self.position += buf_len as u64;
        } else {
            self.buffer.extend_from_slice(buf.as_ref());
        }
        Ok(())
    }

    /// Flushes buffered data to the underlying blob. Does nothing if the buffer is empty.
    ///
    /// If the write to the underlying blob fails, the buffer will be reset (and any pending data not yet
    /// written will be lost).
    async fn flush(&mut self) -> Result<(), Error> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.buffer);
        let len = buf.len() as u64;
        self.blob.write_at(buf, self.position).await?;
        self.position += len;
        self.buffer = Vec::with_capacity(self.capacity);
        Ok(())
    }

    /// Flushes buffered data and ensures it is durably persisted to the underlying blob.
    ///
    /// Returns an error if either the flush or sync operation fails.
    async fn sync(&mut self) -> Result<(), Error> {
        self.flush().await?;
        self.blob.sync().await
    }

    /// Closes the writer and ensures all buffered data is durably persisted to the underlying blob.
    ///
    /// Returns an error if the close operation fails.
    async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        self.blob.close().await
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
///     // Create a buffered writer with 8-byte buffer
///     let mut writer = Write::new(blob.clone(), 0, 8);
///     writer.write("hello".as_bytes()).await.expect("write failed");
///     assert_eq!(writer.position(), 5);
///     writer.sync().await.expect("sync failed");
///
///     // Write more data in multiple flushes
///     writer.write(" world".as_bytes()).await.expect("write failed");
///     writer.write("!".as_bytes()).await.expect("write failed");
///     writer.sync().await.expect("sync failed");
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
    /// Creates a new `Write` that writes to the given blob starting at `position` with the specified buffer capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(blob: B, position: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "Buffer capacity must be greater than zero");
        let inner = Arc::new(RwLock::new(Inner {
            blob,
            buffer: Vec::with_capacity(capacity),
            position,
            capacity,
        }));
        Self { inner }
    }
}

impl<B: Blob> Blob for Write<B> {
    async fn read_at<T: StableBufMut>(&self, mut buf: T, offset: u64) -> Result<T, Error> {
        // Acquire a read lock on the inner state.
        let inner = self.inner.read().await;

        // Ensure offset read is valid
        let len = buf.len();
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // If the data required doesn't involve the buffer, read from the blob
        let buffer_start = inner.position;
        let buffer_end = inner.position + inner.buffer.len() as u64;
        if end <= buffer_start {
            return inner.blob.read_at(buf, offset).await;
        }

        // If the data required is outside the buffer, return an error
        if offset >= buffer_end {
            return Err(Error::BlobInsufficientLength);
        }

        // If the data is entirely within the buffer, read it
        if offset >= buffer_start {
            let start = (offset - buffer_start) as usize;
            if start + len > inner.buffer.len() {
                return Err(Error::BlobInsufficientLength);
            }
            buf.put_slice(&inner.buffer[start..start + len]);
            return Ok(buf);
        }

        // If the data is a combination of blob and buffer, populate accordingly
        let blob_bytes = (buffer_start - offset) as usize;
        let blob_part = vec![0u8; blob_bytes];
        let blob_part = inner.blob.read_at(blob_part, offset).await?;
        let buf_bytes = len - blob_bytes;
        if buf_bytes > inner.buffer.len() {
            return Err(Error::BlobInsufficientLength);
        }
        buf.deref_mut()[..blob_bytes].copy_from_slice(&blob_part);
        buf.deref_mut()[blob_bytes..].copy_from_slice(&inner.buffer[..buf_bytes]);
        Ok(buf)
    }

    async fn write_at<T: StableBuf>(&self, buf: T, offset: u64) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if offset != inner.position().await {
            inner.flush().await?;
            inner.blob.write_at(buf, offset).await
        } else {
            inner.write(buf).await
        }
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.flush().await?;
        inner.blob.truncate(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.sync().await
    }

    async fn close(self) -> Result<(), Error> {
        let inner = Arc::into_inner(self.inner).unwrap().into_inner();
        inner.close().await
    }
}

use std::sync::Arc;

use commonware_utils::StableBuf;

use crate::{Blob, Error, RwLock};

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

    /// Appends bytes to the internal buffer. If the buffer capacity is exceeded, it will be flushed to the
    /// underlying [Blob].
    ///
    /// If the size of the provided bytes is larger than the buffer capacity, the bytes will be written
    /// directly to the underlying [Blob]. If this occurs regularly, the buffer capacity should be increased (or
    /// the buffer will not be effective).
    pub async fn write<Buf: StableBuf>(&mut self, buf: Buf) -> Result<(), Error> {
        // Acquire a write lock on the inner
        let mut inner = self.inner.write().await;

        // If the buffer capacity will be exceeded, flush the buffer first
        let buf_len = buf.len();
        if inner.buffer.len() + buf_len > inner.capacity {
            Self::flush(&mut inner).await?;
        }

        // Write directly to the blob (if the buffer is too small) or append to the buffer
        if buf_len > inner.capacity {
            inner.blob.write_at(buf, inner.position).await?;
            inner.position += buf_len as u64;
        } else {
            inner.buffer.extend_from_slice(buf.as_ref());
        }
        Ok(())
    }

    /// Flushes buffered data to the underlying blob. Does nothing if the buffer is empty.
    ///
    /// If the write to the underlying blob fails, the buffer will be reset (and any pending data not yet
    /// written will be lost).
    async fn flush(inner: &mut Inner<B>) -> Result<(), Error> {
        if inner.buffer.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut inner.buffer);
        let len = buf.len() as u64;
        inner.blob.write_at(buf, inner.position).await?;
        inner.position += len;
        inner.buffer = Vec::with_capacity(inner.capacity);
        Ok(())
    }

    /// Flushes buffered data and ensures it is durably persisted to the underlying blob.
    ///
    /// Returns an error if either the flush or sync operation fails.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        Self::flush(&mut inner).await?;
        inner.blob.sync().await
    }
}

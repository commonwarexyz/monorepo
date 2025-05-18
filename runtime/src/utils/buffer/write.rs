use crate::{Blob, Error};

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
///     writer.write(b"hello");
///     assert_eq!(writer.position(), 5);
///     writer.sync().await.expect("sync failed");
///
///     // Write more data in multiple flushes
///     writer.write(b" world");
///     writer.flush().await.expect("flush failed");
///     writer.write(b"!");
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
pub struct Write<B: Blob> {
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
        assert!(capacity > 0, "buffer capacity must be greater than zero");
        Self {
            blob,
            buffer: Vec::with_capacity(capacity),
            position,
            capacity,
        }
    }

    /// Returns the current position in the blob, including buffered but not-yet-flushed bytes.
    pub fn position(&self) -> u64 {
        self.position + self.buffer.len() as u64
    }

    /// Appends bytes to the internal buffer. Data is not written to the blob until [`flush`] or [`sync`] is called.
    pub fn write(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Flushes buffered data to the underlying blob. Does nothing if the buffer is empty.
    ///
    /// Returns an error if the underlying blob write fails.
    pub async fn flush(&mut self) -> Result<(), Error> {
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
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.flush().await?;
        self.blob.sync().await
    }
}

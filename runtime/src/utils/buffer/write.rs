use crate::{Blob, Error};

/// A buffered writer for a [`Blob`].
///
/// Data is written to an internal buffer and flushed to the underlying
/// `Blob` when [`flush`] or [`sync`] is called.
/// This allows callers to append to a blob without waiting for storage
/// operations on each write.
pub struct Write<B: Blob> {
    blob: B,
    buffer: Vec<u8>,
    position: u64,
    capacity: usize,
}

impl<B: Blob> Write<B> {
    /// Create a new `Write` starting at `position` with the
    /// specified buffer capacity.
    pub fn new(blob: B, position: u64, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be greater than zero");
        Self {
            blob,
            buffer: Vec::with_capacity(capacity),
            position,
            capacity,
        }
    }

    /// Current position in the blob, accounting for buffered bytes.
    pub fn position(&self) -> u64 {
        self.position + self.buffer.len() as u64
    }

    /// Write bytes to the internal buffer.
    pub fn write(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Flush buffered data to the underlying blob.
    pub async fn flush(&mut self) -> Result<(), Error> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.buffer);
        let len = buf.len() as u64;
        self.blob.write_at(buf, self.position).await?;
        self.position += len;
        self.buffer = Vec::with_capacity(self.capacity);
        Ok(())
    }

    /// Flush buffered data and ensure it is durably persisted.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.flush().await?;
        self.blob.sync().await
    }

    /// Truncate the underlying blob to the given length.
    pub async fn truncate(mut self, size: u64) -> Result<(), Error> {
        self.flush().await?;
        self.blob.truncate(size).await?;
        self.blob.sync().await
    }

    /// Consume the buffer and return the inner blob.
    pub fn into_inner(mut self) -> B {
        self.buffer.clear();
        self.blob
    }
}

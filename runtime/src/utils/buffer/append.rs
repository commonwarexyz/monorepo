use crate::{
    buffer::{tip::Buffer, PoolRef},
    Blob, Error, RwLock,
};
use commonware_utils::StableBuf;
use std::sync::Arc;

/// A [Blob] wrapper that supports appending new data that is both read and write cached, and
/// provides buffer-pool managed read caching of older data.
#[derive(Clone)]
pub struct Append<B: Blob> {
    /// The underlying blob being wrapped.
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u64,

    /// Buffer pool to consult for caching.
    pool_ref: PoolRef,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob, as well
    /// as up to the final page_size-1 bytes from the underlying blob (to ensure the buffer's offset
    /// is always at a page boundary).
    ///
    /// # Invariants
    ///
    /// - The buffer's `offset` into the blob is always page aligned.
    /// - The range of bytes in this buffer never overlaps with any page buffered by `pool`. (See
    ///   the warning in [Self::resize] for one uncommon exception.)
    buffer: Arc<RwLock<Buffer>>,
}

impl<B: Blob> Append<B> {
    /// Create a new [Append] of provided `size` using the provided `pool` for read caching, and a
    /// write buffer with capacity `buffer_size`.
    pub async fn new(
        blob: B,
        size: u64,
        mut buffer_size: usize,
        pool_ref: PoolRef,
    ) -> Result<Self, Error> {
        // Set a floor on the write buffer size to make sure we always write at least 1 page of new
        // data with each flush. We multiply page_size by two here since we could be storing up to
        // page_size-1 bytes of already written data in the append buffer to maintain page
        // alignment.
        buffer_size = buffer_size.max(pool_ref.page_size * 2);

        // Initialize the append buffer to contain the last non-full page of bytes from the blob to
        // ensure its offset into the blob is always page aligned.
        let leftover_size = size % pool_ref.page_size as u64;
        let page_aligned_size = size - leftover_size;
        let mut buffer = Buffer::new(page_aligned_size, buffer_size);
        if leftover_size != 0 {
            let page_buf = vec![0; leftover_size as usize];
            let buf = blob.read_at(page_buf, page_aligned_size).await?;
            assert!(!buffer.append(buf.as_ref()));
        }

        Ok(Self {
            blob,
            id: pool_ref.next_id().await,
            pool_ref,
            buffer: Arc::new(RwLock::new(buffer)),
        })
    }

    /// Change the capacity of the write buffer.
    ///
    /// The buffer will be flushed, leaving an empty buffer upon return.
    pub async fn reset_buffer(&mut self, buffer_size: usize) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        self.flush(&mut buffer).await?;
        buffer.capacity = buffer_size.max(self.pool_ref.page_size * 2);

        Ok(())
    }

    /// Append all bytes in `buf` to the tip of the blob.
    pub async fn append(&self, buf: impl Into<StableBuf> + Send) -> Result<(), Error> {
        // Prepare `buf` to be written.
        let buf = buf.into();

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Ensure the write doesn't overflow.
        buffer
            .size()
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;

        if buffer.append(buf.as_ref()) {
            // Buffer is over capacity, flush it to the underlying blob.
            return self.flush(&mut buffer).await;
        }

        Ok(())
    }

    /// Returns the current logical size of the blob including any buffered data.
    ///
    /// This represents the total size of data that would be present after flushing.
    #[allow(clippy::len_without_is_empty)]
    pub async fn size(&self) -> u64 {
        let buffer = self.buffer.read().await;
        buffer.size()
    }

    /// Flush the append buffer to the underlying blob, caching each page worth of written data in
    /// the buffer pool.
    async fn flush(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Take the buffered data, if any.
        let Some((buf, offset)) = buffer.take() else {
            return Ok(());
        };

        // Insert the flushed data into the buffer pool. This step isn't just to ensure recently
        // written data remains cached for future reads, but is in fact required to purge
        // potentially stale cache data which might result from the edge the case of rewinding a
        // blob across a page boundary.
        let remaining = self.pool_ref.cache(self.id, &buf, offset).await;

        // If there's any data left over that doesn't constitute an entire page, re-buffer it into
        // the append buffer to maintain its page-boundary alignment.
        if remaining != 0 {
            buffer.offset -= remaining as u64;
            buffer.data.extend_from_slice(&buf[buf.len() - remaining..])
        }

        // Write the data buffer to the underlying blob. Note that the implementation will rewrite
        // the last (blob_size % page_size) "trailing bytes" of the underlying blob since the
        // write's starting offset is always page aligned. We don't expect this inefficiency to be a
        // significant performance concern, but would be easy enough to avoid by maintaining the
        // underlying blob's size.
        self.blob.write_at(buf, offset).await?;

        Ok(())
    }

    /// Clones and returns the underlying blob.
    pub fn clone_blob(&self) -> B {
        self.blob.clone()
    }
}

impl<B: Blob> Blob for Append<B> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        // Prepare `buf` to capture the read data.
        let mut buf = buf.into();

        // Ensure the read doesn't overflow.
        let end_offset = offset
            .checked_add(buf.len() as u64)
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

        // If there are bytes remaining to be read, use the buffer pool to get them.
        self.pool_ref
            .read(&self.blob, self.id, &mut buf.as_mut()[..remaining], offset)
            .await?;

        Ok(buf)
    }

    /// This [Blob] trait method is unimplemented by [Append] and unconditionally panics.
    ///
    /// TODO(<https://github.com/commonwarexyz/monorepo/issues/1207>): Extend the buffer pool to
    /// support arbitrary writes.
    async fn write_at(&self, _buf: impl Into<StableBuf> + Send, _offset: u64) -> Result<(), Error> {
        unimplemented!("append-only blob type does not support write_at")
    }

    async fn sync(&self) -> Result<(), Error> {
        {
            let mut buffer = self.buffer.write().await;
            self.flush(&mut buffer).await?;
        }
        self.blob.sync().await
    }

    /// Resize the blob to the provided `size`.
    async fn resize(&self, size: u64) -> Result<(), Error> {
        // Implementation note: rewinding the blob across a page boundary potentially results in
        // stale data remaining in the buffer pool's cache. We don't proactively purge the data
        // within this function since it would be inaccessible anyway. Instead we ensure it is
        // always updated should the blob grow back to the point where we have new data for the same
        // page, if any old data hasn't expired naturally by then.

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Flush any buffered bytes to the underlying blob. (Note that a fancier implementation
        // might avoid flushing those bytes that are backed up over by the next step, if any.)
        self.flush(&mut buffer).await?;

        // Resize the underlying blob.
        self.blob.resize(size).await?;

        // Reset the append buffer to the new size, ensuring its page alignment.
        let leftover_size = size % self.pool_ref.page_size as u64;
        buffer.offset = size - leftover_size; // page aligned size
        buffer.data.clear();
        if leftover_size != 0 {
            let page_buf = vec![0; leftover_size as usize];
            let buf = self.blob.read_at(page_buf, buffer.offset).await?;
            assert!(!buffer.append(buf.as_ref()));
        }

        Ok(())
    }

    async fn close(self) -> Result<(), Error> {
        self.sync().await?;
        self.blob.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Runner, Storage as _};
    use commonware_macros::test_traced;

    const PAGE_SIZE: usize = 1024;
    const BUFFER_SIZE: usize = PAGE_SIZE * 2;

    #[test_traced]
    #[should_panic(expected = "not implemented")]
    fn test_append_blob_write_panics() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            let pool_ref = PoolRef::new(PAGE_SIZE, 10);
            let blob = Append::new(blob, size, BUFFER_SIZE, pool_ref.clone())
                .await
                .unwrap();
            assert_eq!(blob.size().await, 0);
            blob.write_at(vec![0], 0).await.unwrap();
        });
    }

    #[test_traced]
    fn test_append_blob_append() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);

            // Wrap the blob, then append 11 consecutive pages of data.
            let pool_ref = PoolRef::new(PAGE_SIZE, 10);
            let blob = Append::new(blob, size, BUFFER_SIZE, pool_ref.clone())
                .await
                .unwrap();
            for i in 0..11 {
                let buf = vec![i as u8; PAGE_SIZE];
                blob.append(buf).await.unwrap();
            }
            assert_eq!(blob.size().await, 11 * PAGE_SIZE as u64);

            blob.close().await.expect("Failed to close blob");

            // Make sure blob has expected size when reopened.
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 11 * PAGE_SIZE as u64);
            blob.close().await.expect("Failed to close blob");
        });
    }

    #[test_traced]
    fn test_append_blob_read() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);

            let pool_ref = PoolRef::new(PAGE_SIZE, 10);
            let blob = Append::new(blob, size, BUFFER_SIZE, pool_ref.clone())
                .await
                .unwrap();

            // Append one byte & sync to ensure we have "trailing bytes".
            blob.append(vec![42]).await.unwrap();
            blob.sync().await.unwrap();

            // Append 11 consecutive pages of data.
            for i in 0..11 {
                let buf = vec![i as u8; PAGE_SIZE];
                blob.append(buf).await.unwrap();
            }

            // Read from the blob across a page boundary but well outside any write buffered data.
            let mut buf = vec![0; 100];
            buf = blob
                .read_at(buf, 1 + PAGE_SIZE as u64 - 50)
                .await
                .unwrap()
                .into();
            let mut expected = vec![0; 50];
            expected.extend_from_slice(&[1; 50]);
            assert_eq!(buf, expected);

            // Read from the blob across a page boundary but within the write buffered data.
            let mut buf = vec![0; 100];
            buf = blob
                .read_at(buf, 1 + (PAGE_SIZE as u64 * 10) - 50)
                .await
                .unwrap()
                .into();
            let mut expected = vec![9; 50];
            expected.extend_from_slice(&[10; 50]);
            assert_eq!(buf, expected);

            // Read across read-only and write-buffered section, all the way up to the very last
            // byte.
            let buf_size = PAGE_SIZE * 4;
            let mut buf = vec![0; buf_size];
            buf = blob
                .read_at(buf, blob.size().await - buf_size as u64)
                .await
                .unwrap()
                .into();
            let mut expected = vec![7; PAGE_SIZE];
            expected.extend_from_slice(&[8; PAGE_SIZE]);
            expected.extend_from_slice(&[9; PAGE_SIZE]);
            expected.extend_from_slice(&[10; PAGE_SIZE]);
            assert_eq!(buf, expected);

            // Exercise more boundary conditions by reading every possible 2-byte slice.
            for i in 0..blob.size().await - 1 {
                let mut buf = vec![0; 2];
                buf = blob.read_at(buf, i).await.unwrap().into();
                let page_num = (i / PAGE_SIZE as u64) as u8;
                if i == 0 {
                    assert_eq!(buf, &[42, 0]);
                } else if i % PAGE_SIZE as u64 == 0 {
                    assert_eq!(buf, &[page_num - 1, page_num], "i = {i}");
                } else {
                    assert_eq!(buf, &[page_num; 2], "i = {i}");
                }
            }

            // Confirm all bytes are as expected after syncing the blob.
            blob.sync().await.unwrap();
            buf = blob.read_at(vec![0], 0).await.unwrap().into();
            assert_eq!(buf, &[42]);

            for i in 0..11 {
                let mut buf = vec![0; PAGE_SIZE];
                buf = blob
                    .read_at(buf, 1 + i * PAGE_SIZE as u64)
                    .await
                    .unwrap()
                    .into();
                assert_eq!(buf, &[i as u8; PAGE_SIZE]);
            }

            blob.close().await.expect("Failed to close blob");
        });
    }
}

use crate::{
    buffer::{tip::Buffer, PoolRef},
    Blob, Error, RwLock,
};
use commonware_utils::{NZUsize, StableBuf};
use std::{num::NonZeroUsize, sync::Arc};

/// A [Blob] wrapper that supports appending new data that is both read and write cached, and
/// provides buffer-pool managed read caching of older data.
///
/// # Concurrent Access
///
/// This implementation allows readers to proceed while flush I/O is in progress, as long as they
/// are reading from the write buffer or the pool cache. Readers that need to access data from the
/// underlying blob (cache miss) will wait for any in-progress write to complete.
///
/// The implementation involves two locks: one for the write buffer (and blob size metadata), and
/// one for the underlying blob itself. To avoid deadlocks, the buffer lock is always acquired
/// before the blob lock.
#[derive(Clone)]
pub struct Append<B: Blob> {
    /// The underlying blob being wrapped, protected by a lock for I/O coordination.
    blob: Arc<RwLock<B>>,

    /// Unique id assigned by the buffer pool.
    id: u64,

    /// Buffer pool to consult for caching.
    pool_ref: PoolRef,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob, as well
    /// as up to the final page_size-1 bytes from the underlying blob (to ensure the buffer's offset
    /// is always at a page boundary), paired with the actual size of the underlying blob on disk.
    ///
    /// # Invariants
    ///
    /// - The buffer's `offset` into the blob is always page aligned.
    /// - The range of bytes in this buffer never overlaps with any page buffered by `pool`. (See
    ///   the warning in [Self::resize] for one uncommon exception.)
    buffer: Arc<RwLock<(Buffer, u64)>>,
}

impl<B: Blob> Append<B> {
    /// Create a new [Append] of provided `size` using the provided `pool` for read caching, and a
    /// write buffer with capacity `buffer_size`.
    pub async fn new(
        blob: B,
        size: u64,
        buffer_size: NonZeroUsize,
        pool_ref: PoolRef,
    ) -> Result<Self, Error> {
        // Set a floor on the write buffer size to make sure we always write at least 1 page of new
        // data with each flush. We multiply page_size by two here since we could be storing up to
        // page_size-1 bytes of already written data in the append buffer to maintain page
        // alignment.
        let mut buffer_size = buffer_size.get();
        buffer_size = buffer_size.max(pool_ref.page_size * 2);

        // Initialize the append buffer to contain the last non-full page of bytes from the blob to
        // ensure its offset into the blob is always page aligned.
        let leftover_size = size % pool_ref.page_size as u64;
        let page_aligned_size = size - leftover_size;
        let mut buffer = Buffer::new(page_aligned_size, NZUsize!(buffer_size));
        if leftover_size != 0 {
            let page_buf = vec![0; leftover_size as usize];
            let buf = blob.read_at(page_buf, page_aligned_size).await?;
            assert!(!buffer.append(buf.as_ref()));
        }

        Ok(Self {
            blob: Arc::new(RwLock::new(blob)),
            id: pool_ref.next_id().await,
            pool_ref,
            buffer: Arc::new(RwLock::new((buffer, size))),
        })
    }

    /// Append all bytes in `buf` to the tip of the blob.
    pub async fn append(&self, buf: impl Into<StableBuf> + Send) -> Result<(), Error> {
        // Prepare `buf` to be written.
        let buf = buf.into();

        // Acquire a write lock on the buffer and blob_size.
        let mut guard = self.buffer.write().await;
        let (buffer, _) = &mut *guard;

        // Ensure the write doesn't overflow.
        buffer
            .size()
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;

        if buffer.append(buf.as_ref()) {
            // Buffer is over capacity, flush it to the underlying blob.
            return self.flush_internal(guard).await;
        }

        Ok(())
    }

    /// Returns the current logical size of the blob including any buffered data.
    ///
    /// This represents the total size of data that would be present after flushing.
    #[allow(clippy::len_without_is_empty)]
    pub async fn size(&self) -> u64 {
        self.buffer.read().await.0.size()
    }

    /// Flush the append buffer to the underlying blob, caching each page worth of written data in
    /// the buffer pool.
    ///
    /// This method acquires the blob write lock before releasing the buffer lock, ensuring readers
    /// that need blob access will wait for the write to complete.
    async fn flush_internal(
        &self,
        mut guard: crate::RwLockWriteGuard<'_, (Buffer, u64)>,
    ) -> Result<(), Error> {
        let (buffer, blob_size) = &mut *guard;

        // Prepare the data to be written.
        let Some((buf, write_offset)) = self.prepare_flush_data(buffer, *blob_size).await else {
            return Ok(());
        };

        // Update blob_size *before* releasing the lock. We do this optimistically; if the write
        // fails below, the program will return an error and likely abort/panic, so maintaining
        // exact consistency on error isn't strictly required.
        *blob_size = write_offset + buf.len() as u64;

        // Acquire blob write lock BEFORE releasing buffer lock. This ensures no reader can access
        // the blob until the write completes.
        let blob_guard = self.blob.write().await;

        // Release buffer lock, allowing concurrent buffered reads while the write is in progress.
        // Any attempts to read from the blob will block until the write completes.
        drop(guard);

        // Perform the write while holding only blob lock.
        blob_guard.write_at(buf, write_offset).await?;

        Ok(())
    }

    /// Prepares data from the buffer to be flushed to the blob.
    ///
    /// This method:
    /// 1. Takes the data from the write buffer.
    /// 2. Caches it in the buffer pool.
    /// 3. Returns the data to be written and the offset to write it at (if any).
    async fn prepare_flush_data(
        &self,
        buffer: &mut Buffer,
        blob_size: u64,
    ) -> Option<(Vec<u8>, u64)> {
        // Take the buffered data, if any.
        let (mut buf, offset) = buffer.take()?;

        // Insert the flushed data into the buffer pool.
        let remaining = self.pool_ref.cache(self.id, &buf, offset).await;

        // If there's any data left over that doesn't constitute an entire page, re-buffer it into
        // the append buffer to maintain its page-boundary alignment.
        if remaining != 0 {
            buffer.offset -= remaining as u64;
            buffer.data.extend_from_slice(&buf[buf.len() - remaining..])
        }

        // Calculate where new data starts in the buffer to skip already-written trailing bytes.
        let new_data_start = blob_size.saturating_sub(offset) as usize;

        // Early exit if there's no new data to write.
        if new_data_start >= buf.len() {
            return None;
        }

        if new_data_start > 0 {
            buf.drain(0..new_data_start);
        }

        // Return the data to write, and the offset where to write it within the blob.
        Some((buf, blob_size))
    }

    /// Clones and returns the underlying blob.
    pub async fn clone_blob(&self) -> B {
        self.blob.read().await.clone()
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
        let guard = self.buffer.read().await;
        let (buffer, _) = &*guard;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Extract any bytes from the buffer that overlap with the requested range.
        let remaining = buffer.extract(buf.as_mut(), offset);

        // Release buffer lock before potential I/O.
        drop(guard);

        if remaining == 0 {
            return Ok(buf);
        }

        // Fast path: try to read *only from pool cache without acquiring blob lock. This allows
        // concurrent reads even while a flush is in progress.
        let cached = self
            .pool_ref
            .read_cached(self.id, &mut buf.as_mut()[..remaining], offset)
            .await;

        if cached == remaining {
            // All bytes found in cache.
            return Ok(buf);
        }

        // Slow path: cache miss (partial or full), acquire blob read lock to ensure any in-flight
        // write completes before we read from the blob.
        let blob_guard = self.blob.read().await;

        // Read remaining bytes that were not already obtained from the earlier cache read.
        let uncached_offset = offset + cached as u64;
        let uncached_len = remaining - cached;
        self.pool_ref
            .read(
                &*blob_guard,
                self.id,
                &mut buf.as_mut()[cached..cached + uncached_len],
                uncached_offset,
            )
            .await?;

        Ok(buf)
    }

    /// This [Blob] trait method is unimplemented by [Append] and unconditionally panics.
    async fn write_at(&self, _buf: impl Into<StableBuf> + Send, _offset: u64) -> Result<(), Error> {
        // TODO(<https://github.com/commonwarexyz/monorepo/issues/1207>): Extend the buffer pool to
        // support arbitrary writes.
        unimplemented!("append-only blob type does not support write_at")
    }

    async fn sync(&self) -> Result<(), Error> {
        // Flush any buffered data. When flush_internal returns, the write_at has completed
        // and data is in the OS buffer.
        {
            let guard = self.buffer.write().await;
            self.flush_internal(guard).await?;
        }
        // Sync the OS buffer to disk. We need the blob read lock here since sync() requires
        // access to the blob, but only a read lock since we're not modifying blob state.
        self.blob.read().await.sync().await
    }

    /// Resize the blob to the provided `size`.
    async fn resize(&self, size: u64) -> Result<(), Error> {
        // Implementation note: rewinding the blob across a page boundary potentially results in
        // stale data remaining in the buffer pool's cache. We don't proactively purge the data
        // within this function since it would be inaccessible anyway. Instead we ensure it is
        // always updated should the blob grow back to the point where we have new data for the same
        // page, if any old data hasn't expired naturally by then.

        // Acquire buffer lock first.
        // NOTE: We MUST acquire the buffer lock before the blob lock to avoid deadlocks with
        // `append`, which acquires buffer then blob (via `flush_internal`).
        let mut guard = self.buffer.write().await;
        let (buffer, blob_size) = &mut *guard;

        // Acquire blob write lock to prevent concurrent reads throughout the resize.
        let blob_guard = self.blob.write().await;

        // Flush any buffered bytes first, using the helper.
        // We hold both locks here, so no concurrent operations can happen.
        if let Some((buf, write_offset)) = self.prepare_flush_data(buffer, *blob_size).await {
            // Write the data to the blob.
            let len = buf.len() as u64;
            blob_guard.write_at(buf, write_offset).await?;

            // Update blob_size to reflect the flush.
            *blob_size = write_offset + len;
        }

        // Resize the underlying blob.
        blob_guard.resize(size).await?;

        // Update the blob size.
        *blob_size = size;

        // Reset the append buffer to the new size, ensuring its page alignment.
        let leftover_size = size % self.pool_ref.page_size as u64;
        buffer.offset = size - leftover_size; // page aligned size
        buffer.data.clear();
        if leftover_size != 0 {
            let page_buf = vec![0; leftover_size as usize];
            let buf = blob_guard.read_at(page_buf, buffer.offset).await?;
            assert!(!buffer.append(buf.as_ref()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Runner, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::NZUsize;

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
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
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
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
                .await
                .unwrap();
            for i in 0..11 {
                let buf = vec![i as u8; PAGE_SIZE];
                blob.append(buf).await.unwrap();
            }
            assert_eq!(blob.size().await, 11 * PAGE_SIZE as u64);

            blob.sync().await.expect("Failed to sync blob");

            // Make sure blob has expected size when reopened.
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 11 * PAGE_SIZE as u64);
            blob.sync().await.expect("Failed to sync blob");
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

            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
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

            blob.sync().await.expect("Failed to sync blob");
        });
    }

    #[test_traced]
    fn test_append_blob_tracks_physical_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");

            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            let blob = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
                .await
                .unwrap();

            // Initially blob_size should be 0.
            assert_eq!(blob.buffer.read().await.1, 0);

            // Write 100 bytes and sync.
            blob.append(vec![1u8; 100]).await.unwrap();
            blob.sync().await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 100);

            // Append more data but don't sync yet, blob_size shouldn't change.
            blob.append(vec![2u8; 200]).await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 100);

            // Force a flush by exceeding buffer.
            blob.append(vec![3u8; BUFFER_SIZE]).await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 100 + 200 + BUFFER_SIZE as u64);

            // Test resize down and up.
            blob.resize(50).await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 50);

            blob.resize(150).await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 150);

            // Append after resize and sync.
            blob.append(vec![4u8; 100]).await.unwrap();
            blob.sync().await.unwrap();
            assert_eq!(blob.buffer.read().await.1, 250);

            // Close and reopen.
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to reopen blob");

            let blob = Append::new(blob, size, NZUsize!(BUFFER_SIZE), pool_ref.clone())
                .await
                .unwrap();
            assert_eq!(blob.buffer.read().await.1, 250);

            // Verify data integrity after all operations.
            let mut buf = vec![0u8; 250];
            buf = blob.read_at(buf, 0).await.unwrap().into();
            assert_eq!(&buf[0..50], &vec![1u8; 50][..]);
            assert_eq!(&buf[50..150], &vec![0u8; 100][..]); // Zeros from resize up to 150
            assert_eq!(&buf[150..250], &vec![4u8; 100][..]);
        });
    }
}

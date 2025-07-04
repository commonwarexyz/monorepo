use crate::{
    buffer::{tip::Buffer, Pool, PoolRef},
    Blob, Error, RwLock,
};
use commonware_utils::StableBuf;
use std::sync::Arc;

/// A [Blob] wrapper that supports appending new data that is both read and write cached, and
/// provides buffer-pool managed read caching of older data.
#[derive(Clone)]
pub struct Append<B: Blob, const PAGE_SIZE: usize> {
    /// The underlying blob being wrapped.
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u64,

    /// Buffer pool to consult for caching.
    pool: PoolRef<PAGE_SIZE>,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob, as well
    /// as up to the final PAGE_SIZE-1 bytes from the underlying blob (to ensure the buffer's offset
    /// is always at a page boundary).
    ///
    /// # Invariants
    ///
    /// - The buffer's `offset` into the blob is always page aligned.
    /// - The range of bytes in this buffer never overlaps with any page buffered by `pool`. (See
    ///   the warning in [Self::resize] for one uncommon exception.)
    buffer: Arc<RwLock<Buffer>>,
}

impl<B: Blob, const PAGE_SIZE: usize> Append<B, PAGE_SIZE> {
    const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

    /// Create a new [Append] of provided `size` using the provided `pool` for read caching, and a
    /// write buffer with capacity `buffer_size`.
    pub async fn new(
        blob: B,
        size: u64,
        mut buffer_size: usize,
        pool: PoolRef<PAGE_SIZE>,
    ) -> Result<Self, Error> {
        // Set a floor on the write buffer size to make sure we always write at least 1 page of new
        // data with each flush. We multiply PAGE_SIZE by two here since we could be storing up to
        // PAGE_SIZE-1 bytes of already written data in the append buffer to maintain page
        // alignment.
        buffer_size = buffer_size.max(PAGE_SIZE * 2);

        // Initialize the append buffer to contain the last non-full page of bytes from the blob to
        // ensure its offset into the blob is always page aligned.
        let leftover_size = size % Self::PAGE_SIZE_U64;
        let page_aligned_size = size - leftover_size;
        let mut buffer = Buffer::new(page_aligned_size, buffer_size);
        if leftover_size != 0 {
            let page_buf = vec![0; leftover_size as usize];
            let buf = blob.read_at(page_buf, page_aligned_size).await?;
            assert!(!buffer.append(buf.as_ref()));
        }

        let id = {
            let mut pool_guard = pool.write().await;
            pool_guard.next_id()
        };

        Ok(Self {
            blob,
            id,
            pool,
            buffer: Arc::new(RwLock::new(buffer)),
        })
    }

    /// Change the capacity of the write buffer.
    ///
    /// The buffer will be flushed, leaving an empty buffer upon return.
    pub async fn reset_buffer(&mut self, buffer_size: usize) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        self.flush(&mut buffer).await?;
        buffer.capacity = buffer_size.max(PAGE_SIZE * 2);

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
    ///
    /// # Warning
    ///
    /// The implementation will rewrite the last (blob_size % PAGE_SIZE) "trailing bytes" of the
    /// underlying blob since the write's starting offset is page aligned. We don't expect this
    /// inefficiency to be a significant performance concern, but would be easy enough to avoid by
    /// maintaining the underlying blob's size.
    async fn flush(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Take the buffered data, if any.
        let Some((mut buf, offset)) = buffer.take() else {
            return Ok(());
        };

        // Insert the flushed data into the buffer pool. This step isn't just to ensure recently
        // written data remains cached for future reads, but is in fact required to purge
        // potentially stale cache data which might result from the edge the case of rewinding a
        // blob across a page boundary.
        let mut buf_slice: &mut [u8] = buf.as_mut();
        let (mut page_num, offset_in_page) = Pool::<PAGE_SIZE>::offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        {
            // Write lock the buffer pool.
            let mut buffer_pool = self.pool.write().await;
            while buf_slice.len() >= PAGE_SIZE {
                buffer_pool.cache(&buf_slice[..PAGE_SIZE], self.id, page_num);
                buf_slice = &mut buf_slice[PAGE_SIZE..];
                page_num += 1;
            }
        }

        // If there's any data left over that doesn't constitute an entire page, re-buffer it into
        // the append buffer to maintain its page-boundary alignment.
        if !buf_slice.is_empty() {
            buffer.offset -= buf_slice.len() as u64;
            buffer.data.extend_from_slice(buf_slice)
        }

        // Write the data buffer to the underlying blob.
        self.blob.write_at(buf, offset).await?;

        Ok(())
    }

    /// Clones and returns the underlying blob.
    pub fn clone_blob(&self) -> B {
        self.blob.clone()
    }
}

impl<B: Blob, const PAGE_SIZE: usize> Blob for Append<B, PAGE_SIZE> {
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
        Pool::read(
            self.pool.clone(),
            &self.blob,
            self.id,
            &mut buf.as_mut()[..remaining],
            offset,
        )
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
    ///
    /// # Warning
    ///
    /// Rewinding the blob across a page boundary potentially results in stale data remaining in the
    /// buffer pool's cache. We don't proactively purge the data within this function since it would
    /// be inaccessible anyway. Instead we ensure it is always updated should the blob grow back to
    /// the point where we have new data for the same page, if any old data hasn't expired naturally
    /// by then.
    async fn resize(&self, size: u64) -> Result<(), Error> {
        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Flush any buffered bytes to the underlying blob. (Note that a fancier implementation
        // might avoid flushing those bytes that are backed up over by the next step, if any.)
        self.flush(&mut buffer).await?;

        // Resize the underlying blob.
        self.blob.resize(size).await?;

        // Reset the append buffer to the new size, ensuring its page alignment.
        let leftover_size = size % Self::PAGE_SIZE_U64;
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

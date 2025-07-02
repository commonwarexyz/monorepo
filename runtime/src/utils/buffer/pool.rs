use crate::{buffer::Buffer, Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::{collections::HashMap, sync::Arc};

/// A [BufferPool] caches pages of [Blob] data in memory.
///
/// A single buffer pool can be used to cache data from multiple blobs by assigning a unique id to
/// each.
#[derive(Default)]
pub struct BufferPool<const PAGE_SIZE: usize> {
    /// The page cache, indexed by the blob id and the page number.
    cache: HashMap<(u32, u64), Box<[u8; PAGE_SIZE]>>,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: u32,
}

impl<const PAGE_SIZE: usize> BufferPool<PAGE_SIZE> {
    const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

    /// Return a new empty buffer pool with an initial next-blob id of 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign and return the next unique blob id.
    async fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    fn offset_to_page(offset: u64) -> (u64, usize) {
        (
            offset / Self::PAGE_SIZE_U64,
            (offset % Self::PAGE_SIZE_U64) as usize,
        )
    }

    /// Attempt to read blob data from the buffer pool. Returns the number of bytes read, which
    /// could be 0 if the first page in the requested range isn't buffered, and is never more than
    /// PAGE_SIZE bytes.
    fn read_at(&self, blob_id: u32, buf: &mut [u8], offset: u64) -> usize {
        let (page_num, offset_in_page) = Self::offset_to_page(offset);
        let page = self.cache.get(&(blob_id, page_num));
        let Some(page) = page else {
            return 0;
        };

        let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset_in_page);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Put the given `page` into the buffer pool. Note that because blobs don't always end on page
    /// boundaries, it's possible for the provided page to be smaller than the PAGE_SIZE.
    fn cache(&mut self, page: &mut [u8], blob_id: u32, page_num: u64) {
        assert!(page.len() <= PAGE_SIZE);

        let page_array = if page.len() < PAGE_SIZE {
            let mut page_array = [0u8; PAGE_SIZE];
            page_array[..page.len()].copy_from_slice(page);
            page_array
        } else {
            page.try_into().unwrap()
        };

        self.cache.insert((blob_id, page_num), Box::new(page_array));
    }

    /// Read the specified bytes, preferentially from the buffer pool cache. Bytes not found in the
    /// buffer pool will be read from the provided `blob` and cached for future reads.
    async fn read<B: Blob>(
        pool: Arc<RwLock<BufferPool<PAGE_SIZE>>>,
        blob: &B,
        blob_id: u32,
        blob_len: u64,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        // Read up to a page worth of data at a time from either the buffer pool or the underlying
        // blob, until the requested data is fully read.
        while !buf.is_empty() {
            // Get a read lock on the buffer pool and see if we can get (some of) the data from it.
            {
                let buffer_pool = pool.read().await;
                let count = buffer_pool.read_at(blob_id, buf, offset);
                if count != 0 {
                    offset += count as u64;
                    buf = &mut buf[count..];
                    continue;
                }
            }

            // Fetch the page from the blob since it wasn't in the buffer pool.
            let (page_num, offset_in_page) = Self::offset_to_page(offset);
            let page_offset = page_num * Self::PAGE_SIZE_U64;

            let bytes_to_read = if page_offset + Self::PAGE_SIZE_U64 > blob_len {
                blob_len - page_offset
            } else {
                Self::PAGE_SIZE_U64
            };
            let mut page_buf = vec![0; bytes_to_read as usize];
            page_buf = blob.read_at(page_buf, page_offset).await?.into();

            // Get a write lock on the buffer pool and put the page in its cache.
            {
                let mut buffer_pool = pool.write().await;
                buffer_pool.cache(&mut page_buf, blob_id, page_num);
            }

            // Copy the requested portion of the page into the buffer.
            let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset_in_page);
            buf[..bytes_to_copy]
                .copy_from_slice(&page_buf[offset_in_page..offset_in_page + bytes_to_copy]);
            offset += bytes_to_copy as u64;
            buf = &mut buf[bytes_to_copy..];
        }

        Ok(())
    }
}

/// A blob wrapper providing buffer-pool managed caching of data for immutable blobs.
#[derive(Clone)]
pub struct Immutable<B: Blob, const PAGE_SIZE: usize> {
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u32,

    /// size of the blob.
    size: u64,

    /// Buffer pool to consult for caching.
    pool: Arc<RwLock<BufferPool<PAGE_SIZE>>>,
}

impl<B: Blob, const PAGE_SIZE: usize> Immutable<B, PAGE_SIZE> {
    /// Return a new [Immutable] wrapper that uses `pool` to provide read caching for `blob`.
    pub async fn new(blob: B, size: u64, pool: Arc<RwLock<BufferPool<PAGE_SIZE>>>) -> Self {
        let id = {
            let mut pool_guard = pool.write().await;
            pool_guard.next_id().await
        };

        Self {
            blob,
            id,
            pool,
            size,
        }
    }

    pub fn take_blob(self) -> B {
        self.blob
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<B: Blob, const PAGE_SIZE: usize> Blob for Immutable<B, PAGE_SIZE> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let buf_slice = buf.as_mut();

        // Make sure we aren't trying to read past the end of the blob, since the buffer pool
        // doesn't keep track of the blob length and could return invalid results.
        if offset
            .checked_add(buf_slice.len() as u64)
            .ok_or(Error::OffsetOverflow)?
            > self.size
        {
            return Err(Error::BlobInsufficientLength);
        }

        BufferPool::read(
            self.pool.clone(),
            &self.blob,
            self.id,
            self.size,
            buf_slice,
            offset,
        )
        .await?;

        Ok(buf)
    }

    async fn write_at(&self, _buf: impl Into<StableBuf> + Send, _offset: u64) -> Result<(), Error> {
        panic!("Immutable blobs do not support writes");
    }

    async fn sync(&self) -> Result<(), Error> {
        Ok(()) // No-op for immutable blobs.
    }

    async fn resize(&self, _len: u64) -> Result<(), Error> {
        panic!("Immutable blobs do not support resize");
    }

    async fn close(self) -> Result<(), Error> {
        self.blob.close().await
    }
}

/// A [Blob] wrapper that supports appending new data that is both read and write cached, and
/// provides buffer-pool managed read caching of older data.
#[derive(Clone)]
pub struct Append<B: Blob, const PAGE_SIZE: usize> {
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u32,

    /// Buffer pool to consult for caching.
    pool: Arc<RwLock<BufferPool<PAGE_SIZE>>>,

    /// The buffer containing the data yet to be appended to the tip of the underlying blob, as well
    /// up to the final PAGE_SIZE-1 bytes from the underlying blob (to ensure the buffer's offset is
    /// always at a page boundary).
    ///
    /// # Invariants
    ///
    /// - The buffer's `offset` into the blob is always page aligned.
    /// - The bytes in this buffer are always exclusive to those in `pool`.
    buffer: Arc<RwLock<Buffer>>,
}

impl<B: Blob, const PAGE_SIZE: usize> Append<B, PAGE_SIZE> {
    const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

    pub async fn new(
        blob: B,
        size: u64,
        mut buffer_size: usize,
        pool: Arc<RwLock<BufferPool<PAGE_SIZE>>>,
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
            pool_guard.next_id().await
        };

        Ok(Self {
            blob,
            id,
            pool,
            buffer: Arc::new(RwLock::new(buffer)),
        })
    }

    /// Append all bytes in `buf` to the tip of the blob.
    pub async fn append(&self, buf: impl Into<StableBuf> + Send) -> Result<(), Error> {
        // Prepare `buf` to be written.
        let buf = buf.into();

        // Acquire a write lock on the buffer.
        let mut buffer = self.buffer.write().await;

        // Ensure the write doesn't overflow.
        let _ = buffer
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
    /// A repeated flush may still result in a write if there are trailing bytes that don't end on a
    /// page boundary, since we don't (currently) keep track which of the trailing bytes have
    /// already been written.
    async fn flush(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Take the buffered data, if any.
        let Some((mut buf, offset)) = buffer.take() else {
            return Ok(());
        };

        // Insert the flushed data into the buffer pool. This step isn't absolutely necessary, but
        // in general it's a good policy to keep recently written data cached for reads.
        let mut buf_slice: &mut [u8] = buf.as_mut();
        let (mut page_num, offset_in_page) = BufferPool::<PAGE_SIZE>::offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        {
            // Write lock the buffer pool.
            let mut buffer_pool = self.pool.write().await;
            while buf_slice.len() >= PAGE_SIZE {
                buffer_pool.cache(&mut buf_slice[..PAGE_SIZE], self.id, page_num);
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

    /// Consumes the [Append] and returns the underlying blob.
    pub fn take_blob(self) -> B {
        self.blob
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
        BufferPool::read(
            self.pool.clone(),
            &self.blob,
            self.id,
            buffer.offset,
            &mut buf.as_mut()[..remaining],
            offset,
        )
        .await?;

        Ok(buf)
    }

    /// This [Blob] trait method is unimplemented by [Append] and unconditionally panics.
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

use crate::{Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::{collections::HashMap, sync::Arc};
use tracing::debug;

/// Size of a buffer pool page in bytes.
const PAGE_SIZE: usize = 16384;
const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

#[derive(Default)]
pub struct BufferPool {
    /// The page cache, indexed by the blob id and the page number.
    cache: HashMap<(u32, u64), [u8; PAGE_SIZE]>,

    /// For assigning blobs unique ids.
    next_id: u32,
}

/// A blob wrapper providing buffer-pool managed caching of data for immutable blobs.
#[derive(Clone)]
pub struct Immutable<B: Blob> {
    blob: B,

    /// Unique id assigned by the buffer pool.
    id: u32,

    /// size of the blob.
    size: u64,

    /// Buffer pool to consult for caching.
    pool: Arc<RwLock<BufferPool>>,
}

impl<B: Blob> Immutable<B> {
    pub async fn new(blob: B, size: u64, pool: Arc<RwLock<BufferPool>>) -> Self {
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

impl<B: Blob> Blob for Immutable<B> {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        mut offset: u64,
    ) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        let mut buf_slice = buf.as_mut();
        let blob_len = self.size;

        // Make sure we aren't trying to read past the end of the blob, since the buffer pool
        // doesn't keep track of the blob length and could return invalid results.
        if offset
            .checked_add(buf_slice.len() as u64)
            .ok_or(Error::OffsetOverflow)?
            > blob_len
        {
            return Err(Error::BlobInsufficientLength);
        }

        while !buf_slice.is_empty() {
            // Get a read lock on the buffer pool and see if we can get (some of) the data from it.
            let buffer_pool = self.pool.read().await;
            let mut count = buffer_pool.read_at(self.id, buf_slice, offset);
            if count != 0 {
                debug!("read from buffer pool: {count} bytes at offset {}", offset,);
                offset += count as u64;
                buf_slice = &mut buf_slice[count..];
                continue;
            }
            drop(buffer_pool); // We'll need to upgrade lock to a write lock later.

            // Fetch the page from the blob since it wasn't in the buffer pool.
            let (page_num, _) = BufferPool::offset_to_page(offset);
            let page_offset = page_num * PAGE_SIZE_U64;

            let bytes_to_read = if page_offset + PAGE_SIZE_U64 > blob_len {
                blob_len - page_offset
            } else {
                PAGE_SIZE_U64
            };
            let mut page_buf = vec![0; bytes_to_read as usize];
            page_buf = self.blob.read_at(page_buf, page_offset).await?.into();

            // Put the page in the cache, which reads the appropriate bytes from it.
            {
                // Get a write lock on the buffer pool.
                let mut buffer_pool = self.pool.write().await;
                count = buffer_pool.cache_page(&mut page_buf, self.id, buf_slice, offset);
            }
            offset += count as u64;
            buf_slice = &mut buf_slice[count..];
        }

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

impl BufferPool {
    pub fn new() -> Self {
        Self::default()
    }

    async fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    fn offset_to_page(offset: u64) -> (u64, u64) {
        (offset / PAGE_SIZE_U64, offset % PAGE_SIZE_U64)
    }

    /// Attempt to read blob data from the buffer pool. Returns the number of bytes read, which
    /// could be 0 if the first page in the requested range isn't buffered, and is never more than
    /// PAGE_SIZE bytes.
    fn read_at(&self, blob_id: u32, buf: &mut [u8], offset: u64) -> usize {
        let (page_num, offset) = Self::offset_to_page(offset);
        let page = self.cache.get(&(blob_id, page_num));
        let Some(page) = page else {
            return 0;
        };

        let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset as usize);
        buf[..bytes_to_copy]
            .copy_from_slice(&page[offset as usize..offset as usize + bytes_to_copy]);

        bytes_to_copy
    }

    /// Cache the page containing the byte at the given offset, and perform a read from that page at
    /// the given offset.
    fn cache_page(&mut self, page: &mut [u8], blob_id: u32, buf: &mut [u8], offset: u64) -> usize {
        let (page_num, offset) = Self::offset_to_page(offset);

        let page_array = if page.len() < PAGE_SIZE {
            let mut page_array = [0u8; PAGE_SIZE];
            page_array[..page.len()].copy_from_slice(page);
            page_array
        } else {
            page.try_into().unwrap()
        };

        self.cache.insert((blob_id, page_num), page_array);

        // Copy the requested portion of the page into the buffer.
        let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset as usize);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_array[offset as usize..offset as usize + bytes_to_copy]);

        bytes_to_copy
    }
}

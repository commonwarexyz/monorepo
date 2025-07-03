use crate::{buffer::Buffer, Blob, Error, RwLock};
use commonware_utils::StableBuf;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// A [BufferPool] caches pages of [Blob] data in memory.
///
/// A single buffer pool can be used to cache data from multiple blobs by assigning a unique id to
/// each.
pub struct BufferPool<const PAGE_SIZE: usize> {
    /// The page cache index, indexed by the blob id and the page number, mapping to the index of
    /// the cache entry for the page.
    index: HashMap<(u32, u64), usize>,

    /// The page cache.
    cache: Vec<CacheEntry<PAGE_SIZE>>,

    /// The current clock hand index into `cache` for the CLOCK replacement policy.
    clock: usize,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: u32,

    /// The maximum number of pages that will be cached.
    capacity: usize,
}

struct CacheEntry<const PAGE_SIZE: usize> {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u32, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,

    /// The cached page itself.
    data: Box<[u8; PAGE_SIZE]>,
}

impl<const PAGE_SIZE: usize> BufferPool<PAGE_SIZE> {
    const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

    /// Return a new empty buffer pool with an initial next-blob id of 0, and a max cache capacity
    /// of `capacity` pages.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            index: HashMap::new(),
            cache: Vec::new(),
            clock: 0,
            next_id: 0,
            capacity,
        }
    }

    /// Assign and return the next unique blob id.
    fn next_id(&mut self) -> u32 {
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
        let page_index = self.index.get(&(blob_id, page_num));
        let Some(&page_index) = page_index else {
            return 0;
        };
        let page = &self.cache[page_index];
        assert_eq!(page.key, (blob_id, page_num));
        page.referenced.store(true, Ordering::Relaxed);
        let page = &page.data;

        let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset_in_page);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Put the given `page` into the buffer pool.
    ///
    /// # Panics
    ///
    /// Panics if the provided page is not exactly PAGE_SIZE bytes long.
    fn cache(&mut self, page: &mut [u8], blob_id: u32, page_num: u64) {
        assert_eq!(page.len(), PAGE_SIZE);
        if self.index.contains_key(&(blob_id, page_num)) {
            // This can happen if different threads fault on the same page.
            return;
        }

        let page_array = page.try_into().unwrap();

        let key = (blob_id, page_num);
        if self.cache.len() < self.capacity {
            self.index.insert(key, self.cache.len());
            self.cache.push(CacheEntry {
                key,
                referenced: AtomicBool::new(true),
                data: Box::new(page_array),
            });
            return;
        }

        // Cache is full, find a page to evict.
        while self.cache[self.clock].referenced.load(Ordering::Relaxed) {
            self.cache[self.clock]
                .referenced
                .store(false, Ordering::Relaxed);
            self.clock = (self.clock + 1) % self.cache.len();
        }

        // Evict the page by replacing it with the new page.
        let entry = &mut self.cache[self.clock];
        entry.referenced.store(true, Ordering::Relaxed);
        assert!(self.index.remove(&entry.key).is_some());
        self.index.insert(key, self.clock);
        entry.key = key;
        *entry.data = page_array;

        // Move the clock forward.
        self.clock = (self.clock + 1) % self.cache.len();
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

            // Page fault: fetch the page from the underlying blob since it wasn't in the buffer
            // pool.
            //
            // Note that we hold no locks at this point, so it's possible multiple threads can fault
            // on the same page. In this scenario, each such thread might make its own call to
            // retrieve the same data from the underlying blob. We in fact see this happen in the
            // fixed_read_random benchmark under concurrent reads.
            //
            // TODO: Consider making the buffer pool aware of any in-progress page requests to avoid
            // this wasteful race condition.
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

    /// Create a new [Append] of provided `size` using the provided `pool` for read caching, and a
    /// write buffer with capacity `buffer_size`.
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

use crate::{Blob, Error, RwLock};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// A [Pool] caches pages of [Blob] data in memory.
///
/// A single buffer pool can be used to cache data from multiple blobs by assigning a unique id to
/// each.
///
/// Implements the [Clock](https://en.wikipedia.org/wiki/Page_replacement_algorithm#Clock)
/// replacement policy, which is a lightweight approximation of LRU. The page `cache` is a circular
/// list of recently accessed pages, and `clock` is the index of the next page within it to examine
/// for replacement. When a page needs to be evicted, we start the search at `clock` within `cache`,
/// searching for the first page with a false reference bit, and setting any skipped page's
/// reference bit to false along the way.
pub struct Pool<const PAGE_SIZE: usize> {
    /// The page cache index, indexed by the blob id and the page number, mapping to the index of
    /// the cache entry for the page.
    index: HashMap<(u64, u64), usize>,

    /// The page cache.
    cache: Vec<CacheEntry<PAGE_SIZE>>,

    /// The Clock replacement policy's clock hand index into `cache`.
    clock: usize,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: u64,

    /// The maximum number of pages that will be cached.
    capacity: usize,
}

struct CacheEntry<const PAGE_SIZE: usize> {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u64, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,

    /// The cached page itself.
    data: Box<[u8; PAGE_SIZE]>,
}

/// A reference to a [Pool] that can be shared across threads.
pub type PoolRef<const PAGE_SIZE: usize> = Arc<RwLock<Pool<PAGE_SIZE>>>;

impl<const PAGE_SIZE: usize> Pool<PAGE_SIZE> {
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
    pub(super) fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    pub(super) fn offset_to_page(offset: u64) -> (u64, usize) {
        (
            offset / Self::PAGE_SIZE_U64,
            (offset % Self::PAGE_SIZE_U64) as usize,
        )
    }

    /// Attempt to read blob data from the buffer pool. Returns the number of bytes read, which
    /// could be 0 if the first page in the requested range isn't buffered, and is never more than
    /// PAGE_SIZE bytes.
    fn read_at(&self, blob_id: u64, buf: &mut [u8], offset: u64) -> usize {
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
    pub(super) fn cache(&mut self, page: &[u8], blob_id: u64, page_num: u64) {
        assert_eq!(page.len(), PAGE_SIZE);
        if self.index.contains_key(&(blob_id, page_num)) {
            // This can happen if different threads fault on the same page.
            return;
        }

        let key = (blob_id, page_num);
        if self.cache.len() < self.capacity {
            self.index.insert(key, self.cache.len());
            self.cache.push(CacheEntry {
                key,
                referenced: AtomicBool::new(true),
                data: Box::new(page.try_into().unwrap()),
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
        entry.data.copy_from_slice(page);

        // Move the clock forward.
        self.clock = (self.clock + 1) % self.cache.len();
    }

    /// Read the specified bytes, preferentially from the buffer pool cache. Bytes not found in the
    /// buffer pool will be read from the provided `blob` and cached for future reads.
    ///
    /// # Warning
    ///
    /// Attempts to read the last (blob_size % PAGE_SIZE) "trailing bytes" of the blob will result
    /// in a ReadFailed error since the buffer pool only deals with page sized chunks. Trailing
    /// bytes need to be dealt with outside of the buffer pool. For example, [crate::buffer::Append]
    /// uses a [crate::buffer::tip::Buffer] to buffer them.
    pub(super) async fn read<B: Blob>(
        pool: PoolRef<PAGE_SIZE>,
        blob: &B,
        blob_id: u64,
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
            let (page_num, offset_in_page) = Self::offset_to_page(offset);
            let page_buf =
                Self::fetch_and_cache_page(pool.clone(), blob, blob_id, page_num).await?;

            // Copy the requested portion of the page into the buffer.
            let bytes_to_copy = std::cmp::min(buf.len(), PAGE_SIZE - offset_in_page);
            buf[..bytes_to_copy]
                .copy_from_slice(&page_buf[offset_in_page..offset_in_page + bytes_to_copy]);
            offset += bytes_to_copy as u64;
            buf = &mut buf[bytes_to_copy..];
        }

        Ok(())
    }

    /// Fetch a page from the underlying blob, cache it in the buffer pool, and return it.
    async fn fetch_and_cache_page<B: Blob>(
        pool: PoolRef<PAGE_SIZE>,
        blob: &B,
        blob_id: u64,
        page_num: u64,
    ) -> Result<Vec<u8>, Error> {
        // Note that we hold no locks at this point, so it's possible multiple threads can fault on
        // the same page and each initiate its own read of the same data from the underlying blob.
        //
        // TODO: Consider making the buffer pool aware of any in-progress page requests to avoid
        // this wasteful race condition.
        let mut page_buf = vec![0; PAGE_SIZE];
        page_buf = blob
            .read_at(page_buf, page_num * Self::PAGE_SIZE_U64)
            .await?
            .into();

        // Get a write lock on the buffer pool and put the page in its cache.
        {
            let mut buffer_pool = pool.write().await;
            buffer_pool.cache(&page_buf, blob_id, page_num);
        }

        Ok(page_buf)
    }
}

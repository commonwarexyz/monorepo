use crate::{Blob, Error, RwLock};
use commonware_utils::StableBuf;
use futures::{future::Shared, FutureExt};
use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tracing::{debug, trace, warn};

// Type alias for the future we'll be storing for each in-flight page fetch.
//
// We wrap [Error] in an Arc so it will be cloneable, which is required for the future to be
// [Shared].
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<StableBuf, Arc<Error>>> + Send>>>;

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
    /// The page cache index, with a key composed of (blob id, page number), that maps each cached
    /// page to the index of its `cache` entry.
    ///
    /// # Invariants
    ///
    /// Each `index` entry maps to exactly one `cache` entry, and that cache entry always has a
    /// matching key.
    index: HashMap<(u64, u64), usize>,

    /// The page cache.
    ///
    /// Each `cache` entry has exactly one corresponding `index` entry.
    cache: Vec<CacheEntry<PAGE_SIZE>>,

    /// The Clock replacement policy's clock hand index into `cache`.
    clock: usize,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: u64,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: HashMap<(u64, u64), PageFetchFut>,
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
            page_fetches: HashMap::new(),
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

    /// Attempt to fetch blob data starting at `offset` from the buffer pool. Returns the number of
    /// bytes read, which could be 0 if the first page in the requested range isn't buffered, and is
    /// never more than PAGE_SIZE or the length of `buf`. The returned bytes won't cross a page
    /// boundary, so multiple reads may be required even if all data in the desired range is
    /// buffered.
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
    pub(super) fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), PAGE_SIZE);

        let key = (blob_id, page_num);
        let index_entry = self.index.entry(key);
        if let Entry::Occupied(index_entry) = index_entry {
            // This case should be rare, but not impossible. It can result due to either of:
            //   1. a race condition in page fetching where the "first fetcher" releases the buffer
            //   pool write lock after caching the page, and there's another thread that has just
            //   faulted on the same page.
            //   2. a blob is truncated across a page boundary, and later grows back to (beyond) its
            //   original size, caching new data for the same page.
            debug!(blob_id, page_num, "updating duplicate page");

            // Update the stale data with the new page.
            let entry = &mut self.cache[*index_entry.get()];
            assert_eq!(entry.key, key);
            entry.referenced.store(true, Ordering::Relaxed);
            entry.data.copy_from_slice(page);
            return;
        }

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
    /// Attempts to read any of the last (blob_size % PAGE_SIZE) "trailing bytes" of the blob will
    /// result in a ReadFailed error since the buffer pool only deals with page sized chunks.
    /// Trailing bytes need to be dealt with outside of the buffer pool. For example,
    /// [crate::buffer::Append] uses a [crate::buffer::tip::Buffer] to buffer them.
    pub(super) async fn read<B: Blob>(
        pool: PoolRef<PAGE_SIZE>,
        blob: &B,
        blob_id: u64,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        // Read up to a page worth of data at a time from either the buffer pool or the `blob`,
        // until the requested data is fully read.
        while !buf.is_empty() {
            // Read lock the buffer pool and see if we can get (some of) the data from it.
            {
                let buffer_pool = pool.read().await;
                let count = buffer_pool.read_at(blob_id, buf, offset);
                if count != 0 {
                    offset += count as u64;
                    buf = &mut buf[count..];
                    continue;
                }
            }

            // Page fault: fetch the page from `blob` since it wasn't in the buffer pool.
            let (page_num, offset_in_page) = Self::offset_to_page(offset);
            trace!(page_num, blob_id, "page fault");

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

    /// Fetch the specified page from `blob`, cache it in `pool`, and return it.
    async fn fetch_and_cache_page<B: Blob>(
        pool: PoolRef<PAGE_SIZE>,
        blob: &B,
        blob_id: u64,
        page_num: u64,
    ) -> Result<Vec<u8>, Error> {
        let key = (blob_id, page_num);

        // Create or clone a future that retrieves the desired page from the underlying blob. This
        // requires a write lock on the buffer pool since we may need to modify `page_fetches` if
        // this is the first fetcher.
        let fetch_future: PageFetchFut;
        let is_first_fetcher: bool;
        {
            let mut buffer_pool = pool.write().await;

            let entry = buffer_pool.page_fetches.entry(key);

            (fetch_future, is_first_fetcher) = match entry {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page, so clone its existing future.
                    (o.get().clone(), false)
                }
                Entry::Vacant(v) => {
                    // Nobody is currently fetching this page, so create a future that will do the work.
                    let blob = blob.clone();
                    let future = async move {
                        blob.read_at(vec![0; PAGE_SIZE], page_num * Self::PAGE_SIZE_U64)
                            .await
                            .map_err(Arc::new)
                    };

                    // Make the future shareable and insert it into the map.
                    let shareable = future.boxed().shared();
                    v.insert(shareable.clone());

                    (shareable, true)
                }
            };
        }

        // Await the future and get the page buffer. If this isn't the task that initiated the
        // fetch, we can return immediately with the result. Note that we cannot return immediately
        // on error, since we'd bypass the cleanup required of the first fetcher.
        let fetch_result = fetch_future.await;
        if !is_first_fetcher {
            return Ok(fetch_result.map_err(|_| Error::ReadFailed)?.into());
        }

        // This is the task that initiated the fetch, so it is responsible for cleaning up the
        // inserted entry, and caching the page in the buffer pool if the fetch didn't error out.
        // This requires a write lock on the buffer pool to modify `page_fetches` and cache the
        // page.
        let mut buffer_pool = pool.write().await;
        let _ = buffer_pool.page_fetches.remove(&key);

        let Ok(page_buf) = fetch_result else {
            return Err(Error::ReadFailed);
        };
        buffer_pool.cache(blob_id, page_buf.as_ref(), page_num);

        Ok(page_buf.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_macros::test_traced;

    const TEST_PAGE_SIZE: usize = 1024;

    #[test_traced]
    fn test_pool_basic() {
        let mut pool: Pool<TEST_PAGE_SIZE> = Pool::new(10);
        assert_eq!(pool.next_id(), 0);
        assert_eq!(pool.next_id(), 1);

        let mut buf = vec![0; TEST_PAGE_SIZE];
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        pool.cache(0, &[1; TEST_PAGE_SIZE], 0);
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, TEST_PAGE_SIZE);
        assert_eq!(buf, [1; TEST_PAGE_SIZE]);

        // Test replacement -- should log a duplicate page warning but still work.
        pool.cache(0, &[2; TEST_PAGE_SIZE], 0);
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, TEST_PAGE_SIZE);
        assert_eq!(buf, [2; TEST_PAGE_SIZE]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            pool.cache(0, &[i as u8; TEST_PAGE_SIZE], i);
        }
        // Page 0 should have been evicted.
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = pool.read_at(0, &mut buf, i * TEST_PAGE_SIZE as u64);
            assert_eq!(bytes_read, TEST_PAGE_SIZE);
            assert_eq!(buf, [i as u8; TEST_PAGE_SIZE]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full page.
        let mut buf = vec![0; TEST_PAGE_SIZE];
        let bytes_read = pool.read_at(0, &mut buf, TEST_PAGE_SIZE as u64 + 2);
        assert_eq!(bytes_read, TEST_PAGE_SIZE - 2);
        assert_eq!(&buf[..TEST_PAGE_SIZE - 2], [1; TEST_PAGE_SIZE - 2]);
    }

    #[test_traced]
    fn test_pool_read_with_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            // Populate a blob with 11 consecutive pages of data.
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);
            for i in 0..11 {
                let buf = vec![i as u8; TEST_PAGE_SIZE];
                blob.write_at(buf, i * TEST_PAGE_SIZE as u64).await.unwrap();
            }

            // Fill the buffer pool with the blob's data.
            let pool: Pool<TEST_PAGE_SIZE> = Pool::new(10);
            let pool_ref = Arc::new(RwLock::new(pool));
            for i in 0..11 {
                let mut buf = vec![0; TEST_PAGE_SIZE];
                Pool::read(
                    pool_ref.clone(),
                    &blob,
                    0,
                    &mut buf,
                    i * TEST_PAGE_SIZE as u64,
                )
                .await
                .unwrap();
                assert_eq!(buf, [i as u8; TEST_PAGE_SIZE]);
            }

            // Repeat the read to exercise reading from the buffer pool. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let mut buf = vec![0; TEST_PAGE_SIZE];
                Pool::read(
                    pool_ref.clone(),
                    &blob,
                    0,
                    &mut buf,
                    i * TEST_PAGE_SIZE as u64,
                )
                .await
                .unwrap();
                assert_eq!(buf, [i as u8; TEST_PAGE_SIZE]);
            }

            // Cleanup.
            blob.close().await.expect("Failed to destroy blob");
        });
    }
}

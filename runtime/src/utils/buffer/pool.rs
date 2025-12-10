use crate::{Blob, Error, RwLock};
use commonware_utils::StableBuf;
use futures::{future::Shared, FutureExt};
use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{debug, trace};

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
pub struct Pool {
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
    cache: Vec<CacheEntry>,

    /// The Clock replacement policy's clock hand index into `cache`.
    clock: usize,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: HashMap<(u64, u64), PageFetchFut>,
}

struct CacheEntry {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u64, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,

    /// The cached page itself.
    data: Vec<u8>,
}

/// A reference to a [Pool] that can be shared across threads via cloning, along with the page size
/// that will be used with it. Provides the API for interacting with the buffer pool in a
/// thread-safe manner.
#[derive(Clone)]
pub struct PoolRef {
    /// The size of each page in the buffer pool.
    pub(super) page_size: usize,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: Arc<AtomicU64>,

    /// Shareable reference to the buffer pool.
    pool: Arc<RwLock<Pool>>,
}

impl PoolRef {
    /// Returns a new [PoolRef] with the given `page_size` and `capacity`.
    pub fn new(page_size: NonZeroUsize, capacity: NonZeroUsize) -> Self {
        Self {
            page_size: page_size.get(),
            next_id: Arc::new(AtomicU64::new(0)),
            pool: Arc::new(RwLock::new(Pool::new(capacity.get()))),
        }
    }

    /// Returns a unique id for the next blob that will use this buffer pool.
    pub async fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    pub const fn offset_to_page(&self, offset: u64) -> (u64, usize) {
        Pool::offset_to_page(self.page_size, offset)
    }

    /// Read the specified bytes, preferentially from the buffer pool cache. Bytes not found in the
    /// buffer pool will be read from the provided `blob` and cached for future reads.
    ///
    /// # Warning
    ///
    /// Attempts to read any of the last (blob_size % page_size) "trailing bytes" of the blob will
    /// result in a ReadFailed error since the buffer pool only deals with page sized chunks.
    /// Trailing bytes need to be dealt with outside of the buffer pool. For example,
    /// [crate::buffer::Append] uses a [crate::buffer::tip::Buffer] to buffer them.
    pub(super) async fn read<B: Blob>(
        &self,
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
                let buffer_pool = self.pool.read().await;
                let count = buffer_pool.read_at(self.page_size, blob_id, buf, offset);
                if count != 0 {
                    offset += count as u64;
                    buf = &mut buf[count..];
                    continue;
                }
            }

            // Handle page fault.
            let count = self
                .read_after_page_fault(blob, blob_id, buf, offset)
                .await?;
            offset += count as u64;
            buf = &mut buf[count..];
        }

        Ok(())
    }

    /// Fetch the specified page after encountering a page fault, which may involve retrieving it
    /// from `blob` & caching the result in `pool`. Returns the number of bytes read, which should
    /// always be non-zero.
    async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        assert!(!buf.is_empty());

        let (page_num, offset_in_page) = Pool::offset_to_page(self.page_size, offset);
        let page_size = self.page_size;
        trace!(page_num, blob_id, "page fault");

        // Create or clone a future that retrieves the desired page from the underlying blob. This
        // requires a write lock on the buffer pool since we may need to modify `page_fetches` if
        // this is the first fetcher.
        let (fetch_future, is_first_fetcher) = {
            let mut pool = self.pool.write().await;

            // There's a (small) chance the page was fetched & buffered by another task before we
            // were able to acquire the write lock, so check the cache before doing anything else.
            let count = pool.read_at(page_size, blob_id, buf, offset);
            if count != 0 {
                return Ok(count);
            }

            let entry = pool.page_fetches.entry((blob_id, page_num));
            match entry {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page, so clone its existing future.
                    (o.get().clone(), false)
                }
                Entry::Vacant(v) => {
                    // Nobody is currently fetching this page, so create a future that will do the work.
                    let blob = blob.clone();
                    let future = async move {
                        blob.read_at(vec![0; page_size], page_num * page_size as u64)
                            .await
                            .map_err(Arc::new)
                    };

                    // Make the future shareable and insert it into the map.
                    let shareable = future.boxed().shared();
                    v.insert(shareable.clone());

                    (shareable, true)
                }
            }
        };

        // Await the future and get the page buffer. If this isn't the task that initiated the
        // fetch, we can return immediately with the result. Note that we cannot return immediately
        // on error, since we'd bypass the cleanup required of the first fetcher.
        let fetch_result = fetch_future.await;
        if !is_first_fetcher {
            // Copy the requested portion of the page into the buffer and return immediately.
            let page_buf: Vec<u8> = fetch_result.map_err(|_| Error::ReadFailed)?.into();
            let bytes_to_copy = std::cmp::min(buf.len(), page_size - offset_in_page);
            buf[..bytes_to_copy]
                .copy_from_slice(&page_buf[offset_in_page..offset_in_page + bytes_to_copy]);
            return Ok(bytes_to_copy);
        }

        // This is the task that initiated the fetch, so it is responsible for cleaning up the
        // inserted entry, and caching the page in the buffer pool if the fetch didn't error out.
        // This requires a write lock on the buffer pool to modify `page_fetches` and cache the
        // page.
        let mut pool = self.pool.write().await;

        // Remove the entry from `page_fetches`.
        let _ = pool.page_fetches.remove(&(blob_id, page_num));

        // Cache the result in the buffer pool.
        let Ok(page_buf) = fetch_result else {
            return Err(Error::ReadFailed);
        };
        pool.cache(page_size, blob_id, page_buf.as_ref(), page_num);

        // Copy the requested portion of the page into the buffer.
        let page_buf: Vec<u8> = page_buf.into();
        let bytes_to_copy = std::cmp::min(buf.len(), page_size - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf[offset_in_page..offset_in_page + bytes_to_copy]);

        Ok(bytes_to_copy)
    }

    /// Cache the provided slice of data in the buffer pool, returning the remaining bytes that
    /// didn't fill a whole page. `offset` must be page aligned.
    ///
    /// If the next page index would overflow `u64`, caching stops and the uncached bytes are
    /// returned. This can only occur with 1-byte pages on 64-bit architectures. On 32-bit
    /// architectures it cannot occur because the buffer length is bounded by `usize::MAX` (2^32-1),
    /// so even starting at page `u64::MAX` with 1-byte pages, at most 2^32-1 pages can be cached.
    /// On 64-bit architectures with page_size >= 2, the maximum starting page (`u64::MAX / 2`)
    /// plus maximum cacheable pages (`usize::MAX / 2`) equals `u64::MAX - 1`.
    ///
    /// # Panics
    ///
    /// Panics if `offset` is not page aligned.
    pub async fn cache(&self, blob_id: u64, mut buf: &[u8], offset: u64) -> usize {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        {
            // Write lock the buffer pool.
            let mut buffer_pool = self.pool.write().await;
            while buf.len() >= self.page_size {
                buffer_pool.cache(self.page_size, blob_id, &buf[..self.page_size], page_num);
                buf = &buf[self.page_size..];
                page_num = match page_num.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
            }
        }

        buf.len()
    }
}

impl Pool {
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
            capacity,
            page_fetches: HashMap::new(),
        }
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    const fn offset_to_page(page_size: usize, offset: u64) -> (u64, usize) {
        (
            offset / page_size as u64,
            (offset % page_size as u64) as usize,
        )
    }

    /// Attempt to fetch blob data starting at `offset` from the buffer pool. Returns the number of
    /// bytes read, which could be 0 if the first page in the requested range isn't buffered, and is
    /// never more than `self.page_size` or the length of `buf`. The returned bytes won't cross a
    /// page boundary, so multiple reads may be required even if all data in the desired range is
    /// buffered.
    fn read_at(&self, page_size: usize, blob_id: u64, buf: &mut [u8], offset: u64) -> usize {
        let (page_num, offset_in_page) = Self::offset_to_page(page_size, offset);
        let page_index = self.index.get(&(blob_id, page_num));
        let Some(&page_index) = page_index else {
            return 0;
        };
        let page = &self.cache[page_index];
        assert_eq!(page.key, (blob_id, page_num));
        page.referenced.store(true, Ordering::Relaxed);
        let page = &page.data;

        let bytes_to_copy = std::cmp::min(buf.len(), page_size - offset_in_page);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Put the given `page` into the buffer pool.
    ///
    /// # Panics
    ///
    /// Panics if the provided page is not exactly PAGE_SIZE bytes long.
    fn cache(&mut self, page_size: usize, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), page_size);

        let key = (blob_id, page_num);
        let index_entry = self.index.entry(key);
        if let Entry::Occupied(index_entry) = index_entry {
            // This case can result when a blob is truncated across a page boundary, and later grows
            // back to (beyond) its original size. It will also become expected behavior once we
            // allow cached pages to be writable.
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
                data: page.into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_macros::test_traced;
    use commonware_utils::NZUsize;

    const PAGE_SIZE: usize = 1024;

    #[test_traced]
    fn test_pool_basic() {
        let mut pool: Pool = Pool::new(10);

        let mut buf = vec![0; PAGE_SIZE];
        let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        pool.cache(PAGE_SIZE, 0, &[1; PAGE_SIZE], 0);
        let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE);
        assert_eq!(buf, [1; PAGE_SIZE]);

        // Test replacement -- should log a duplicate page warning but still work.
        pool.cache(PAGE_SIZE, 0, &[2; PAGE_SIZE], 0);
        let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE);
        assert_eq!(buf, [2; PAGE_SIZE]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            pool.cache(PAGE_SIZE, 0, &[i as u8; PAGE_SIZE], i);
        }
        // Page 0 should have been evicted.
        let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, i * PAGE_SIZE as u64);
            assert_eq!(bytes_read, PAGE_SIZE);
            assert_eq!(buf, [i as u8; PAGE_SIZE]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full page.
        let mut buf = vec![0; PAGE_SIZE];
        let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, PAGE_SIZE as u64 + 2);
        assert_eq!(bytes_read, PAGE_SIZE - 2);
        assert_eq!(&buf[..PAGE_SIZE - 2], [1; PAGE_SIZE - 2]);
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
                let buf = vec![i as u8; PAGE_SIZE];
                blob.write_at(buf, i * PAGE_SIZE as u64).await.unwrap();
            }

            // Fill the buffer pool with the blob's data.
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(10));
            assert_eq!(pool_ref.next_id().await, 0);
            assert_eq!(pool_ref.next_id().await, 1);
            for i in 0..11 {
                let mut buf = vec![0; PAGE_SIZE];
                pool_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE as u64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE]);
            }

            // Repeat the read to exercise reading from the buffer pool. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let mut buf = vec![0; PAGE_SIZE];
                pool_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE as u64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE]);
            }

            // Cleanup.
            blob.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_pool_cache_max_page() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            let pool_ref = PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(2));

            // Use the largest page-aligned offset representable for the configured PAGE_SIZE.
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE as u64);

            // Caching exactly one page at the maximum offset should succeed.
            let remaining = pool_ref
                .cache(0, vec![42; PAGE_SIZE].as_slice(), aligned_max_offset)
                .await;
            assert_eq!(remaining, 0);

            let mut buf = vec![0u8; PAGE_SIZE];
            let pool = pool_ref.pool.read().await;
            let bytes_read = pool.read_at(PAGE_SIZE, 0, &mut buf, aligned_max_offset);
            assert_eq!(bytes_read, PAGE_SIZE);
            assert!(buf.iter().all(|b| *b == 42));
        });
    }

    #[test_traced]
    fn test_pool_cache_page_overflow_partial() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            // Use the minimum page size to force the page index to reach u64::MAX and trigger the
            // overflow guard.
            let pool_ref = PoolRef::new(NZUsize!(1), NZUsize!(2));

            // Caching across the maximum page should stop before overflow and report the remainder.
            let remaining = pool_ref.cache(0, &[1, 2], u64::MAX).await;
            assert_eq!(remaining, 1);

            let mut buf = [0u8; 1];
            let pool = pool_ref.pool.read().await;
            assert_eq!(pool.read_at(1, 0, &mut buf, u64::MAX), 1);
            assert_eq!(buf, [1]);
        });
    }
}

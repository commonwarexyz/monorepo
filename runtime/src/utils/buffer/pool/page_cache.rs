//! A buffer pool for caching _logical_ pages of [Blob] data in memory. The buffer pool is unaware
//! of the physical page format used by the blob, which is left to the blob implementation.

use super::get_page_from_blob;
use crate::{Blob, Error, RwLock};
use bytes::{Buf, Bytes};
use commonware_utils::StableBuf;
use futures::{future::Shared, FutureExt};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{debug, error, trace};

// Type alias for the future we'll be storing for each in-flight page fetch.
//
// We wrap [Error] in an Arc so it will be cloneable, which is required for the future to be
// [Shared]. The StableBuf contains only the logical (validated) bytes of the page.
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<StableBuf, Arc<Error>>> + Send>>>;

/// A [Pool] caches pages of [Blob] data in memory after verifying the integrity of each.
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

    /// The cached page itself. Only logical bytes are cached, so the buffer will be 12 bytes
    /// shorter than the physical page size. Uses Bytes for zero-copy slicing.
    data: Bytes,
}

/// A reference to a page cache that can be shared across threads via cloning, along with the page
/// size that will be used with it. Provides the API for interacting with the buffer pool in a
/// thread-safe manner.
#[derive(Clone)]
pub struct PoolRef {
    /// The size of each page in the underlying blobs managed by this buffer pool.
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. (Reads
    /// on blobs that were written with a different page size will fail their integrity check.)
    page_size: u64,

    /// The next id to assign to a blob that will be managed by this pool.
    next_id: Arc<AtomicU64>,

    /// Shareable reference to the buffer pool.
    pool: Arc<RwLock<Pool>>,
}

impl PoolRef {
    /// Returns a new [PoolRef] that will buffer up to `capacity` pages with the
    /// given `page_size`.
    pub fn new(page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size = page_size.get() as u64;

        Self {
            page_size,
            next_id: Arc::new(AtomicU64::new(0)),
            pool: Arc::new(RwLock::new(Pool::new(capacity.get()))),
        }
    }

    /// The page size used by this buffer pool.
    #[inline]
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }

    /// Returns a unique id for the next blob that will use this buffer pool.
    pub async fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Convert a logical offset into the number of the page it belongs to and the offset within
    /// that page.
    pub const fn offset_to_page(&self, offset: u64) -> (u64, u64) {
        Pool::offset_to_page(self.page_size, offset)
    }

    /// Cache the provided pages of data in the buffer pool, returning the remaining bytes that
    /// didn't fill a whole page. `offset` must be page aligned.
    ///
    /// # Panics
    ///
    /// - Panics if `offset` is not page aligned.
    /// - If the buffer is not the size of a page.
    pub async fn cache(&self, blob_id: u64, mut buf: &[u8], offset: u64) -> usize {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        {
            // Write lock the buffer pool.
            let page_size = self.page_size as usize;
            let mut buffer_pool = self.pool.write().await;
            while buf.len() >= page_size {
                buffer_pool.cache(self.page_size, blob_id, &buf[..page_size], page_num);
                buf = &buf[page_size..];
                page_num = match page_num.checked_add(1) {
                    Some(next) => next,
                    None => break,
                };
            }
        }

        buf.len()
    }

    /// Returns a `CachedBuf` for zero-copy reading from cache.
    ///
    /// This ensures all required pages are cached (fetching from blob if needed),
    /// then returns a `Buf` implementation that reads directly from cached pages
    /// without any copying.
    pub async fn read_buf<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        mut offset: u64,
        mut len: usize,
    ) -> Result<CachedBuf, Error> {
        // Ensure all required pages are in cache
        let mut slices = VecDeque::new();

        while len > 0 {
            // Try to get slice from cache
            let slice = {
                let pool = self.pool.read().await;
                pool.get_slice(self.page_size, blob_id, offset, len)
            };

            if let Some(slice) = slice {
                let slice_len = slice.len();
                slices.push_back(slice);
                offset += slice_len as u64;
                len -= slice_len;
            } else {
                // Cache miss - ensure the page is cached without copying
                let (page_num, _) = self.offset_to_page(offset);
                self.ensure_page_cached(blob, blob_id, page_num).await?;
                // Page is now cached, retry in next iteration
            }
        }

        Ok(CachedBuf::new(slices))
    }

    /// Ensures a page is in the cache, fetching it from the blob if necessary.
    ///
    /// Unlike `read_after_page_fault`, this method does not copy data to a buffer -
    /// it only ensures the page is cached for subsequent zero-copy reads.
    async fn ensure_page_cached<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        page_num: u64,
    ) -> Result<(), Error> {
        trace!(page_num, blob_id, "ensuring page is cached");

        // Create or clone a future that retrieves the desired page from the underlying blob.
        let (fetch_future, is_first_fetcher) = {
            let mut pool = self.pool.write().await;

            // Check if page is already cached (may have been fetched by another task).
            if pool.index.contains_key(&(blob_id, page_num)) {
                return Ok(());
            }

            let entry = pool.page_fetches.entry((blob_id, page_num));
            match entry {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page.
                    (o.get().clone(), false)
                }
                Entry::Vacant(v) => {
                    // Create a future to fetch the page.
                    let blob = blob.clone();
                    let page_size = self.page_size;
                    let future = async move {
                        let page = get_page_from_blob(&blob, page_num, page_size)
                            .await
                            .map_err(Arc::new)?;
                        let len = page.as_ref().len();
                        if len != page_size as usize {
                            error!(
                                page_num,
                                expected = page_size,
                                actual = len,
                                "attempted to fetch partial page from blob"
                            );
                            return Err(Arc::new(Error::InvalidChecksum));
                        }
                        Ok(page)
                    };

                    let shareable = future.boxed().shared();
                    v.insert(shareable.clone());
                    (shareable, true)
                }
            }
        };

        // Await the fetch.
        let fetch_result = fetch_future.await;

        if !is_first_fetcher {
            // Just ensure the fetch succeeded.
            fetch_result.map_err(|_| Error::ReadFailed)?;
            return Ok(());
        }

        // First fetcher: clean up and cache the page.
        let mut pool = self.pool.write().await;
        let _ = pool.page_fetches.remove(&(blob_id, page_num));

        let page_buf = match fetch_result {
            Ok(page_buf) => page_buf,
            Err(err) => {
                error!(page_num, ?err, "Page fetch failed");
                return Err(Error::ReadFailed);
            }
        };

        pool.cache(self.page_size, blob_id, page_buf.as_ref(), page_num);
        Ok(())
    }
}

/// A buffer backed by cached pages for zero-copy reading.
///
/// This struct implements `Buf` and navigates through multiple cached page slices
/// without copying data. Created by `PoolRef::read_buf()`.
#[derive(Debug)]
pub struct CachedBuf {
    /// Slices from cached pages, consumed as data is read.
    slices: VecDeque<Bytes>,
    /// Total remaining bytes across all slices.
    remaining: usize,
}

impl CachedBuf {
    /// Creates a new CachedBuf from a collection of page slices.
    pub(super) fn new(slices: VecDeque<Bytes>) -> Self {
        let remaining = slices.iter().map(|s| s.len()).sum();
        Self { slices, remaining }
    }

    /// Creates an empty CachedBuf.
    pub(super) const fn empty() -> Self {
        Self {
            slices: VecDeque::new(),
            remaining: 0,
        }
    }

    /// Creates a CachedBuf from a collection of Bytes slices.
    pub(super) fn from_bytes(slices: VecDeque<Bytes>) -> Self {
        let remaining = slices.iter().map(|s| s.len()).sum();
        Self { slices, remaining }
    }

    /// Appends multiple Bytes slices to the end of this buffer.
    pub(super) fn extend(&mut self, slices: VecDeque<Bytes>) {
        for slice in slices {
            self.remaining += slice.len();
            self.slices.push_back(slice);
        }
    }
}

impl Buf for CachedBuf {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        self.slices.front().map(|s| s.as_ref()).unwrap_or(&[])
    }

    fn advance(&mut self, mut cnt: usize) {
        self.remaining = self.remaining.saturating_sub(cnt);

        while cnt > 0 {
            let Some(front) = self.slices.front_mut() else {
                break;
            };

            if cnt < front.len() {
                front.advance(cnt);
                return;
            }

            cnt -= front.len();
            self.slices.pop_front();
        }
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
    const fn offset_to_page(page_size: u64, offset: u64) -> (u64, u64) {
        (offset / page_size, offset % page_size)
    }

    /// Attempt to fetch blob data starting at `offset` from the buffer pool. Returns the number of
    /// bytes read, which could be 0 if the first page in the requested range isn't buffered, and is
    /// never more than `self.page_size` or the length of `buf`. The returned bytes won't cross a
    /// page boundary, so multiple reads may be required even if all data in the desired range is
    /// buffered.
    #[cfg(test)]
    fn read_at(&self, page_size: u64, blob_id: u64, buf: &mut [u8], logical_offset: u64) -> usize {
        let (page_num, offset_in_page) = Self::offset_to_page(page_size, logical_offset);
        let page_index = self.index.get(&(blob_id, page_num));
        let Some(&page_index) = page_index else {
            return 0;
        };
        let page = &self.cache[page_index];
        assert_eq!(page.key, (blob_id, page_num));
        page.referenced.store(true, Ordering::Relaxed);
        let page = &page.data;

        let logical_page_size = page_size as usize;
        let bytes_to_copy = std::cmp::min(buf.len(), logical_page_size - offset_in_page as usize);
        buf[..bytes_to_copy].copy_from_slice(
            &page[offset_in_page as usize..offset_in_page as usize + bytes_to_copy],
        );

        bytes_to_copy
    }

    /// Returns a Bytes slice from cache for zero-copy access, or None on cache miss.
    ///
    /// Unlike `read_at`, this returns a `Bytes` slice that shares the underlying memory
    /// with the cache entry, avoiding any copying.
    fn get_slice(
        &self,
        page_size: u64,
        blob_id: u64,
        logical_offset: u64,
        max_len: usize,
    ) -> Option<Bytes> {
        let (page_num, offset_in_page) = Self::offset_to_page(page_size, logical_offset);
        let page_index = self.index.get(&(blob_id, page_num))?;
        let page = &self.cache[*page_index];
        assert_eq!(page.key, (blob_id, page_num));
        page.referenced.store(true, Ordering::Relaxed);

        let offset = offset_in_page as usize;
        let available = page.data.len() - offset;
        let len = max_len.min(available);
        Some(page.data.slice(offset..offset + len))
    }

    /// Put the given `page` into the buffer pool.
    fn cache(&mut self, page_size: u64, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), page_size as usize);
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
            entry.data = Bytes::copy_from_slice(page);
            return;
        }

        if self.cache.len() < self.capacity {
            self.index.insert(key, self.cache.len());
            self.cache.push(CacheEntry {
                key,
                referenced: AtomicBool::new(true),
                data: Bytes::copy_from_slice(page),
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
        entry.data = Bytes::copy_from_slice(page);

        // Move the clock forward.
        self.clock = (self.clock + 1) % self.cache.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{buffer::pool::CHECKSUM_SIZE, deterministic, Runner as _};
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    // Logical page size (what PoolRef uses and what gets cached).
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    #[test_traced]
    fn test_pool_basic() {
        let mut pool: Pool = Pool::new(10);

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        pool.cache(PAGE_SIZE_U64, 0, &[1; PAGE_SIZE.get() as usize], 0);
        let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- should log a duplicate page warning but still work.
        pool.cache(PAGE_SIZE_U64, 0, &[2; PAGE_SIZE.get() as usize], 0);
        let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            pool.cache(PAGE_SIZE_U64, 0, &[i as u8; PAGE_SIZE.get() as usize], i);
        }
        // Page 0 should have been evicted.
        let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, i * PAGE_SIZE_U64);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full logical page.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, PAGE_SIZE_U64 + 2);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize - 2);
        assert_eq!(
            &buf[..PAGE_SIZE.get() as usize - 2],
            [1; PAGE_SIZE.get() as usize - 2]
        );
    }

    #[test_traced]
    fn test_pool_cache_max_page() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(2));

            // Use the largest page-aligned offset representable for the configured PAGE_SIZE.
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE_U64);

            // PoolRef::cache expects only logical bytes (no CRC).
            let logical_data = vec![42u8; PAGE_SIZE.get() as usize];

            // Caching exactly one page at the maximum offset should succeed.
            let remaining = pool_ref
                .cache(0, logical_data.as_slice(), aligned_max_offset)
                .await;
            assert_eq!(remaining, 0);

            // Reading from the pool should return the logical bytes.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let pool = pool_ref.pool.read().await;
            let bytes_read = pool.read_at(PAGE_SIZE_U64, 0, &mut buf, aligned_max_offset);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert!(buf.iter().all(|b| *b == 42));
        });
    }

    #[test_traced]
    fn test_pool_cache_at_high_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            // Use the minimum page size (CHECKSUM_SIZE + 1 = 13) with high offset.
            const MIN_PAGE_SIZE: u64 = CHECKSUM_SIZE + 1;
            let pool_ref = PoolRef::new(NZU16!(MIN_PAGE_SIZE as u16), NZUsize!(2));

            // Create two pages worth of logical data (no CRCs - PoolRef::cache expects logical only).
            let data = vec![1u8; MIN_PAGE_SIZE as usize * 2];

            // Cache pages at a high (but not max) aligned offset so we can verify both pages.
            // Use an offset that's a few pages below max to avoid overflow when verifying.
            let aligned_max_offset = u64::MAX - (u64::MAX % MIN_PAGE_SIZE);
            let high_offset = aligned_max_offset - (MIN_PAGE_SIZE * 2);
            let remaining = pool_ref.cache(0, &data, high_offset).await;
            // Both pages should be cached.
            assert_eq!(remaining, 0);

            // Verify the first page was cached correctly.
            let mut buf = vec![0u8; MIN_PAGE_SIZE as usize];
            let pool = pool_ref.pool.read().await;
            assert_eq!(
                pool.read_at(MIN_PAGE_SIZE, 0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));

            // Verify the second page was cached correctly.
            assert_eq!(
                pool.read_at(MIN_PAGE_SIZE, 0, &mut buf, high_offset + MIN_PAGE_SIZE),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
        });
    }
}

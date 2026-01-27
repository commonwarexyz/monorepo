//! A buffer pool for caching _logical_ pages of [Blob] data in memory. The buffer pool is unaware
//! of the physical page format used by the blob, which is left to the blob implementation.

use super::get_page_from_blob;
use crate::{Blob, Error, RwLock};
use futures::{future::Shared, FutureExt};
use std::{
    collections::{hash_map::Entry, HashMap},
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
// [Shared]. The Vec<u8> contains only the logical (validated) bytes of the page.
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<Vec<u8>, Arc<Error>>> + Send>>>;

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
struct Pool {
    /// The page cache index, with a key composed of (blob id, page number), that maps each cached
    /// page to the index of its slot in `entries` and `arena`.
    ///
    /// # Invariants
    ///
    /// Each `index` entry maps to exactly one `entries` slot, and that entry always has a
    /// matching key.
    index: HashMap<(u64, u64), usize>,

    /// Metadata for each cache slot.
    ///
    /// Each `entries` slot has exactly one corresponding `index` entry.
    entries: Vec<CacheEntry>,

    /// Pre-allocated arena containing all page data contiguously.
    /// Slot i's data is at `arena[i * page_size .. (i+1) * page_size]`.
    arena: Vec<u8>,

    /// Size of each page in bytes.
    page_size: usize,

    /// The Clock replacement policy's clock hand index into `entries`.
    clock: usize,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: HashMap<(u64, u64), PageFetchFut>,
}

/// Metadata for a single cache entry (page data stored in arena).
struct CacheEntry {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u64, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,
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
        let page_size_u64 = page_size.get() as u64;

        Self {
            page_size: page_size_u64,
            next_id: Arc::new(AtomicU64::new(0)),
            pool: Arc::new(RwLock::new(Pool::new(page_size, capacity))),
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

    /// Try to read the specified bytes from the buffer pool cache only. Returns the number of
    /// bytes successfully read from cache and copied to `buf` before a page fault, if any.
    pub(super) async fn read_cached(
        &self,
        blob_id: u64,
        mut buf: &mut [u8],
        mut logical_offset: u64,
    ) -> usize {
        let original_len = buf.len();
        let buffer_pool = self.pool.read().await;
        while !buf.is_empty() {
            let count = buffer_pool.read_at(blob_id, buf, logical_offset);
            if count == 0 {
                // Cache miss - return how many bytes we successfully read
                break;
            }
            logical_offset += count as u64;
            buf = &mut buf[count..];
        }
        original_len - buf.len()
    }

    /// Read the specified bytes, preferentially from the buffer pool cache. Bytes not found in the
    /// buffer pool will be read from the provided `blob` and cached for future reads.
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
                let count = buffer_pool.read_at(blob_id, buf, offset);
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

    /// Fetch the requested page after encountering a page fault, which may involve retrieving it
    /// from `blob` & caching the result in `pool`. Returns the number of bytes read, which should
    /// always be non-zero.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        assert!(!buf.is_empty());

        let (page_num, offset_in_page) = Pool::offset_to_page(self.page_size, offset);
        let offset_in_page = offset_in_page as usize;
        trace!(page_num, blob_id, "page fault");

        // Create or clone a future that retrieves the desired page from the underlying blob. This
        // requires a write lock on the buffer pool since we may need to modify `page_fetches` if
        // this is the first fetcher.
        let (fetch_future, is_first_fetcher) = {
            let mut pool = self.pool.write().await;

            // There's a (small) chance the page was fetched & buffered by another task before we
            // were able to acquire the write lock, so check the cache before doing anything else.
            let count = pool.read_at(blob_id, buf, offset);
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
                    // Nobody is currently fetching this page, so create a future that will do the
                    // work. get_page_from_blob handles CRC validation and returns only logical bytes.
                    let blob = blob.clone();
                    let page_size = self.page_size;
                    let future = async move {
                        let page = get_page_from_blob(&blob, page_num, page_size)
                            .await
                            .map_err(Arc::new)?;
                        // We should never be fetching partial pages through the buffer pool. This can happen
                        // if a non-last page is corrupted and falls back to a partial CRC.
                        let len = page.len();
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
            let page_buf = fetch_result.map_err(|_| Error::ReadFailed)?;
            let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
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

        // Cache the result in the buffer pool. get_page_from_blob already validated the CRC.
        let page_buf = match fetch_result {
            Ok(page_buf) => page_buf,
            Err(err) => {
                error!(page_num, ?err, "Page fetch failed");
                return Err(Error::ReadFailed);
            }
        };

        pool.cache(blob_id, &page_buf, page_num);

        // Copy the requested portion of the page into the buffer.
        let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf[offset_in_page..offset_in_page + bytes_to_copy]);

        Ok(bytes_to_copy)
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
                buffer_pool.cache(blob_id, &buf[..page_size], page_num);
                buf = &buf[page_size..];
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
    /// of `capacity` pages, each of size `page_size` bytes.
    ///
    /// The arena is pre-allocated to hold all pages contiguously.
    pub fn new(page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size = page_size.get() as usize;
        let capacity = capacity.get();
        Self {
            index: HashMap::new(),
            entries: Vec::with_capacity(capacity),
            arena: vec![0u8; capacity * page_size],
            page_size,
            clock: 0,
            capacity,
            page_fetches: HashMap::new(),
        }
    }

    /// Returns a slice to the page data for the given slot index.
    #[inline]
    fn page_slice(&self, slot: usize) -> &[u8] {
        assert!(slot < self.capacity);
        let start = slot * self.page_size;
        &self.arena[start..start + self.page_size]
    }

    /// Returns a mutable slice to the page data for the given slot index.
    #[inline]
    fn page_slice_mut(&mut self, slot: usize) -> &mut [u8] {
        assert!(slot < self.capacity);
        let start = slot * self.page_size;
        &mut self.arena[start..start + self.page_size]
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
    fn read_at(&self, blob_id: u64, buf: &mut [u8], logical_offset: u64) -> usize {
        let (page_num, offset_in_page) =
            Self::offset_to_page(self.page_size as u64, logical_offset);
        let Some(&slot) = self.index.get(&(blob_id, page_num)) else {
            return 0;
        };
        let entry = &self.entries[slot];
        assert_eq!(entry.key, (blob_id, page_num));
        entry.referenced.store(true, Ordering::Relaxed);

        let page = self.page_slice(slot);
        let bytes_to_copy = std::cmp::min(buf.len(), self.page_size - offset_in_page as usize);
        buf[..bytes_to_copy].copy_from_slice(
            &page[offset_in_page as usize..offset_in_page as usize + bytes_to_copy],
        );

        bytes_to_copy
    }

    /// Put the given `page` into the buffer pool.
    fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), self.page_size);
        let key = (blob_id, page_num);

        // Check for existing entry (update case)
        if let Some(&slot) = self.index.get(&key) {
            // This case can result when a blob is truncated across a page boundary, and later grows
            // back to (beyond) its original size. It will also become expected behavior once we
            // allow cached pages to be writable.
            debug!(blob_id, page_num, "updating duplicate page");

            // Update the stale data with the new page.
            let entry = &self.entries[slot];
            assert_eq!(entry.key, key);
            entry.referenced.store(true, Ordering::Relaxed);
            self.page_slice_mut(slot).copy_from_slice(page);
            return;
        }

        // New entry - check if we need to evict
        if self.entries.len() < self.capacity {
            // Still growing: use next available slot
            let slot = self.entries.len();
            self.index.insert(key, slot);
            self.entries.push(CacheEntry {
                key,
                referenced: AtomicBool::new(true),
            });
            self.page_slice_mut(slot).copy_from_slice(page);
            return;
        }

        // Cache full: find slot to evict using Clock algorithm
        while self.entries[self.clock].referenced.load(Ordering::Relaxed) {
            self.entries[self.clock]
                .referenced
                .store(false, Ordering::Relaxed);
            self.clock = (self.clock + 1) % self.entries.len();
        }

        // Evict and replace
        let slot = self.clock;
        let entry = &mut self.entries[slot];
        assert!(self.index.remove(&entry.key).is_some());
        self.index.insert(key, slot);
        entry.key = key;
        entry.referenced.store(true, Ordering::Relaxed);
        self.page_slice_mut(slot).copy_from_slice(page);

        // Move the clock forward.
        self.clock = (self.clock + 1) % self.entries.len();
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Checksum, *};
    use crate::{buffer::pool::CHECKSUM_SIZE, deterministic, Runner as _, Storage as _};
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    // Logical page size (what PoolRef uses and what gets cached).
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    #[test_traced]
    fn test_pool_basic() {
        let mut pool: Pool = Pool::new(PAGE_SIZE, NZUsize!(10));

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        pool.cache(0, &[1; PAGE_SIZE.get() as usize], 0);
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- should log a duplicate page warning but still work.
        pool.cache(0, &[2; PAGE_SIZE.get() as usize], 0);
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            pool.cache(0, &[i as u8; PAGE_SIZE.get() as usize], i);
        }
        // Page 0 should have been evicted.
        let bytes_read = pool.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = pool.read_at(0, &mut buf, i * PAGE_SIZE_U64);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full logical page.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = pool.read_at(0, &mut buf, PAGE_SIZE_U64 + 2);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize - 2);
        assert_eq!(
            &buf[..PAGE_SIZE.get() as usize - 2],
            [1; PAGE_SIZE.get() as usize - 2]
        );
    }

    #[test_traced]
    fn test_pool_read_with_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            // Physical page size = logical + CRC record.
            let physical_page_size = PAGE_SIZE_U64 + CHECKSUM_SIZE;

            // Populate a blob with 11 consecutive pages of CRC-protected data.
            let (blob, size) = context
                .open("test", "blob".as_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0);
            for i in 0..11 {
                // Write logical data followed by Checksum.
                let logical_data = vec![i as u8; PAGE_SIZE.get() as usize];
                let crc = Crc32::checksum(&logical_data);
                let record = Checksum::new(PAGE_SIZE.get(), crc);
                let mut page_data = logical_data;
                page_data.extend_from_slice(&record.to_bytes());
                blob.write_at(i * physical_page_size, page_data)
                    .await
                    .unwrap();
            }

            // Fill the buffer pool with the blob's data via PoolRef::read.
            let pool_ref = PoolRef::new(PAGE_SIZE, NZUsize!(10));
            assert_eq!(pool_ref.next_id().await, 0);
            assert_eq!(pool_ref.next_id().await, 1);
            for i in 0..11 {
                // Read expects logical bytes only (CRCs are stripped).
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                pool_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }

            // Repeat the read to exercise reading from the buffer pool. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                pool_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }

            // Cleanup.
            blob.sync().await.unwrap();
        });
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
            let bytes_read = pool.read_at(0, &mut buf, aligned_max_offset);
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
                pool.read_at(0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));

            // Verify the second page was cached correctly.
            assert_eq!(
                pool.read_at(0, &mut buf, high_offset + MIN_PAGE_SIZE),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
        });
    }
}

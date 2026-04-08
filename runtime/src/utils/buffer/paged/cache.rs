//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.

use super::get_page_from_blob;
use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufMut};
use commonware_utils::sync::RwLock;
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

/// Shared future for one logical page fetch. The output uses `Arc<Error>` because `Shared`
/// requires cloneable results. The `IoBuf` contains only the logical, validated page bytes.
type PageFetchFuture = Shared<Pin<Box<dyn Future<Output = Result<IoBuf, Arc<Error>>> + Send>>>;

/// Shared handle to one in-flight fetch generation. The cache keeps one copy in `page_fetches`,
/// and each waiter clones the `Arc` while it is still interested in the result.
type PageFetch = Arc<PageFetchFuture>;

/// One in-flight fetch generation for a single `(blob_id, page_num)`.
///
/// `fetch` is shared by every waiter that joined this generation. `waiters` counts the still
/// armed waiters whose drop path may need to remove this entry if they become the last
/// unresolved waiter. If `page_fetches[key]` is later replaced by a newer generation, stale
/// waiters from the old generation must ignore it and rely on `Arc::ptr_eq` against their saved
/// `fetch`.
struct PageFetchEntry {
    /// Shared page fetch future that reads and validates the logical page exactly once.
    fetch: PageFetch,
    /// Count of waiters that still need cancellation cleanup for this fetch generation.
    waiters: usize,
}

/// Removes a stale in-flight page fetch when the last unresolved waiter is dropped.
struct PageFetchGuard {
    cache: Arc<RwLock<Cache>>,
    key: (u64, u64),
    fetch: PageFetch,
    armed: bool,
}

impl PageFetchGuard {
    const fn new(cache: Arc<RwLock<Cache>>, key: (u64, u64), fetch: PageFetch) -> Self {
        Self {
            cache,
            key,
            fetch,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PageFetchGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // A resolved fetch removes `page_fetches[key]` before waiters resume and disarm their
        // guards. If that fetch failed, the page remains uncached, so a new reader can install a
        // new fetch for the same key before an old waiter is cancelled. Ignore drops from stale
        // waiters so they cannot decrement or remove a newer generation. A surviving waiter keeps
        // the current generation installed, which lets the shared future finish and cache the page
        // on success.
        let mut cache = self.cache.write();
        let Entry::Occupied(mut current) = cache.page_fetches.entry(self.key) else {
            return;
        };
        if !Arc::ptr_eq(&current.get().fetch, &self.fetch) {
            return;
        }
        if current.get().waiters == 1 {
            current.remove();
        } else {
            current.get_mut().waiters -= 1;
        }
    }
}

/// A [Cache] caches pages of [Blob] data in memory after verifying the integrity of each.
///
/// A single page cache can be used to cache data from multiple blobs by assigning a unique id to
/// each.
///
/// Implements the [Clock](https://en.wikipedia.org/wiki/Page_replacement_algorithm#Clock)
/// replacement policy, which is a lightweight approximation of LRU. The page `cache` is a circular
/// list of recently accessed pages, and `clock` is the index of the next page within it to examine
/// for replacement. When a page needs to be evicted, we start the search at `clock` within `cache`,
/// searching for the first page with a false reference bit, and setting any skipped page's
/// reference bit to false along the way.
struct Cache {
    /// The page cache index, with a key composed of (blob id, page number), that maps each cached
    /// page to the index of its slot in `entries` and `slots`.
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

    /// Per-slot page buffers allocated from the pool.
    ///
    /// `slots[i]` stores one logical page for `entries[i]`.
    slots: Vec<IoBufMut>,

    /// Size of each page in bytes.
    page_size: usize,

    /// The Clock replacement policy's clock hand index into `entries`.
    clock: usize,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: HashMap<(u64, u64), PageFetchEntry>,
}

/// Metadata for a single cache entry (page data stored in per-slot buffers).
struct CacheEntry {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u64, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,
}

/// A reference to a page cache that can be shared across threads via cloning, along with the page
/// size that will be used with it. Provides the API for interacting with the page cache in a
/// thread-safe manner.
#[derive(Clone)]
pub struct CacheRef {
    /// The size of each page in the underlying blobs managed by this page cache.
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. (Reads
    /// on blobs that were written with a different page size will fail their integrity check.)
    page_size: u64,

    /// The next id to assign to a blob that will be managed by this cache.
    next_id: Arc<AtomicU64>,

    /// Shareable reference to the page cache.
    cache: Arc<RwLock<Cache>>,

    /// Pool used for page-cache and associated buffer allocations.
    pool: BufferPool,
}

impl CacheRef {
    /// Create a shared page-cache handle backed by `pool`.
    ///
    /// The cache stores at most `capacity` pages, each exactly `page_size` bytes.
    /// Initialization eagerly allocates and zeroes all cache slots from `pool`.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size_u64 = page_size.get() as u64;

        Self {
            page_size: page_size_u64,
            next_id: Arc::new(AtomicU64::new(0)),
            cache: Arc::new(RwLock::new(Cache::new(pool.clone(), page_size, capacity))),
            pool,
        }
    }

    /// Create a shared page-cache handle, extracting the storage [BufferPool] from a
    /// [BufferPooler].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        page_size: NonZeroU16,
        capacity: NonZeroUsize,
    ) -> Self {
        Self::new(pooler.storage_buffer_pool().clone(), page_size, capacity)
    }

    /// The page size used by this page cache.
    #[inline]
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }

    /// Returns the storage buffer pool associated with this cache.
    #[inline]
    pub const fn pool(&self) -> &BufferPool {
        &self.pool
    }

    /// Returns a unique id for the next blob that will use this page cache.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Convert a logical offset into the number of the page it belongs to and the offset within
    /// that page.
    pub const fn offset_to_page(&self, offset: u64) -> (u64, u64) {
        Cache::offset_to_page(self.page_size, offset)
    }

    /// Try to read the specified bytes from the page cache only. Returns the number of bytes
    /// successfully read from cache and copied to `buf` before a page fault, if any.
    pub(super) fn read_cached(
        &self,
        blob_id: u64,
        mut buf: &mut [u8],
        mut logical_offset: u64,
    ) -> usize {
        let original_len = buf.len();
        let page_cache = self.cache.read();
        while !buf.is_empty() {
            let count = page_cache.read_at(blob_id, buf, logical_offset);
            if count == 0 {
                // Cache miss - return how many bytes we successfully read
                break;
            }
            logical_offset += count as u64;
            buf = &mut buf[count..];
        }
        original_len - buf.len()
    }

    /// Read multiple disjoint byte ranges from the page cache in a single lock acquisition.
    ///
    /// Each element of `ranges` is `(logical_offset, dest_slice)`. Returns the number of
    /// ranges that were *fully* read from cache before encountering a miss. Ranges must be
    /// sorted by offset and non-overlapping.
    pub(super) fn read_cached_many(&self, blob_id: u64, ranges: &mut [(&mut [u8], u64)]) -> usize {
        let page_cache = self.cache.read();
        let mut fully_read = 0;
        for (buf, logical_offset) in ranges.iter_mut() {
            let mut remaining = buf.len();
            let mut offset = *logical_offset;
            let mut dst = 0;
            while remaining > 0 {
                let count = page_cache.read_at(blob_id, &mut buf[dst..], offset);
                if count == 0 {
                    return fully_read;
                }
                offset += count as u64;
                dst += count;
                remaining -= count;
            }
            fully_read += 1;
        }
        fully_read
    }

    /// Read the specified bytes, preferentially from the page cache. Bytes not found in the cache
    /// will be read from the provided `blob` and cached for future reads.
    pub(super) async fn read<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        // Read up to a page worth of data at a time from either the page cache or the `blob`,
        // until the requested data is fully read.
        while !buf.is_empty() {
            // Read lock the page cache and see if we can get (some of) the data from it.
            {
                let page_cache = self.cache.read();
                let count = page_cache.read_at(blob_id, buf, offset);
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
    /// from `blob` & caching the result in the page cache. Returns the number of bytes read, which
    /// should always be non-zero.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        assert!(!buf.is_empty());

        let (page_num, offset_in_page) = Cache::offset_to_page(self.page_size, offset);
        let offset_in_page = offset_in_page as usize;
        trace!(page_num, blob_id, "page fault");

        // Create or clone a future that retrieves the desired page from the underlying blob. This
        // requires a write lock on the page cache since we may need to modify `page_fetches` if
        // this task is the first fetcher.
        let (fetch_future, mut fetch_guard) = {
            let mut cache = self.cache.write();

            // There's a (small) chance the page was fetched & buffered by another task before we
            // were able to acquire the write lock, so check the cache before doing anything else.
            let count = cache.read_at(blob_id, buf, offset);
            if count != 0 {
                return Ok(count);
            }

            let key = (blob_id, page_num);
            match cache.page_fetches.entry(key) {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page, so clone its existing future.
                    let entry = o.into_mut();
                    entry.waiters += 1;
                    let fetch_future = entry.fetch.as_ref().clone();
                    let fetch = Arc::clone(&entry.fetch);
                    (
                        fetch_future,
                        PageFetchGuard::new(Arc::clone(&self.cache), key, fetch),
                    )
                }
                Entry::Vacant(v) => {
                    // Nobody is currently fetching this page, so create a future that will do the
                    // work. get_page_from_blob handles CRC validation and returns only logical bytes.
                    let blob = blob.clone();
                    let cache = Arc::clone(&self.cache);
                    let page_size = self.page_size;
                    let future = async move {
                        let result = fetch_cacheable_page(&blob, page_num, page_size).await;
                        if let Err(err) = &result {
                            error!(page_num, ?err, "Page fetch failed");
                        }

                        // This shared future still owns `page_fetches[key]`. As long as at least
                        // one waiter remains armed, that entry pins this generation in place, so a
                        // replacement fetch for the same page cannot be inserted before we cache
                        // the successful result below. Only when every waiter cancels can the last
                        // guard remove the entry and let a later reader start a new generation.
                        let mut cache = cache.write();
                        if let Ok(page) = &result {
                            cache.cache(blob_id, page.as_ref(), page_num);
                        }
                        let _ = cache.page_fetches.remove(&key);
                        result
                    };

                    // Make the future shareable and insert it into the map.
                    let fetch_future = future.boxed().shared();
                    let fetch = Arc::new(fetch_future.clone());
                    v.insert(PageFetchEntry {
                        fetch: Arc::clone(&fetch),
                        waiters: 1,
                    });

                    (
                        fetch_future,
                        PageFetchGuard::new(Arc::clone(&self.cache), key, fetch),
                    )
                }
            }
        };

        // Await the shared fetch. The future itself logs failures, caches the resolved page, and
        // removes the in-flight marker before it returns, so waiters only need cancellation
        // cleanup while the fetch is still unresolved.
        let fetch_result = fetch_future.await;
        fetch_guard.disarm();
        let page_buf = match fetch_result {
            Ok(page_buf) => page_buf,
            Err(_) => return Err(Error::ReadFailed),
        };

        // Copy the requested portion of the page into the buffer.
        let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf.as_ref()[offset_in_page..offset_in_page + bytes_to_copy]);

        Ok(bytes_to_copy)
    }

    /// Cache the provided pages of data in the page cache, returning the remaining bytes that
    /// didn't fill a whole page. `offset` must be page aligned.
    ///
    /// # Panics
    ///
    /// - Panics if `offset` is not page aligned.
    /// - If the buffer is not the size of a page.
    pub fn cache(&self, blob_id: u64, mut buf: &[u8], offset: u64) -> usize {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        {
            // Write lock the page cache.
            let page_size = self.page_size as usize;
            let mut page_cache = self.cache.write();
            while buf.len() >= page_size {
                page_cache.cache(blob_id, &buf[..page_size], page_num);
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

impl Cache {
    /// Return a new empty page cache with an initial next-blob id of 0, and a max cache capacity
    /// of `capacity` pages, each of size `page_size` bytes.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size = page_size.get() as usize;
        let capacity = capacity.get();
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let slot = pool.alloc_zeroed(page_size);
            slots.push(slot);
        }
        Self {
            index: HashMap::new(),
            entries: Vec::with_capacity(capacity),
            slots,
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
        self.slots[slot].as_ref()
    }

    /// Returns a mutable slice to the page data for the given slot index.
    #[inline]
    fn page_slice_mut(&mut self, slot: usize) -> &mut [u8] {
        assert!(slot < self.capacity);
        self.slots[slot].as_mut()
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    const fn offset_to_page(page_size: u64, offset: u64) -> (u64, u64) {
        (offset / page_size, offset % page_size)
    }

    /// Attempt to fetch blob data starting at `offset` from the page cache. Returns the number of
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

    /// Put the given `page` into the page cache.
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

/// Fetch one logical page for insertion into the page cache, rejecting partial pages because cache
/// entries must always contain a full logical page.
async fn fetch_cacheable_page(
    blob: &impl Blob,
    page_num: u64,
    page_size: u64,
) -> Result<IoBuf, Arc<Error>> {
    let page = get_page_from_blob(blob, page_num, page_size)
        .await
        .map_err(Arc::new)?;

    // We should never be fetching partial pages through the page cache. This can happen if a
    // non-last page is corrupted and falls back to a partial CRC.
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
}

#[cfg(test)]
mod tests {
    use super::{super::Checksum, *};
    use crate::{
        buffer::paged::CHECKSUM_SIZE, deterministic, BufferPool, BufferPoolConfig, Clock as _,
        IoBufsMut, Runner as _, Spawner as _, Storage as _,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize, NZU16};
    use futures::future::pending;
    use prometheus_client::registry::Registry;
    use std::{
        num::NonZeroU16,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    // Logical page size (what CacheRef uses and what gets cached).
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    /// A blob that signals once a read starts and then never returns.
    #[derive(Clone)]
    struct BlockingBlob {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl Blob for BlockingBlob {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.read_at_buf(offset, len, IoBufsMut::default()).await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            let sender = self
                .started
                .lock()
                .take()
                .expect("blocking blob read started more than once");
            let _ = sender.send(());
            pending::<()>().await;
            unreachable!()
        }

        async fn write_at(
            &self,
            _offset: u64,
            _bufs: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    enum ControlledBlobResult {
        Success(Arc<Vec<u8>>),
        Error,
    }

    /// A blob that blocks its first physical page read until released and counts total reads.
    #[derive(Clone)]
    struct ControlledBlob {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
        reads: Arc<AtomicUsize>,
        result: ControlledBlobResult,
    }

    impl Blob for ControlledBlob {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.read_at_buf(offset, len, IoBufsMut::default()).await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            if self.reads.fetch_add(1, Ordering::Relaxed) == 0 {
                let sender = self
                    .started
                    .lock()
                    .take()
                    .expect("controlled blob start signal consumed more than once");
                let _ = sender.send(());

                let release = self
                    .release
                    .lock()
                    .take()
                    .expect("controlled blob release receiver consumed more than once");
                release.await.expect("release signal dropped");
            }

            match &self.result {
                ControlledBlobResult::Success(page) => Ok(IoBufsMut::from(page.as_ref().clone())),
                ControlledBlobResult::Error => Err(Error::ReadFailed),
            }
        }

        async fn write_at(
            &self,
            _offset: u64,
            _bufs: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test_traced]
    fn test_cache_basic() {
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(10));

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        cache.cache(0, &[1; PAGE_SIZE.get() as usize], 0);
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- should log a duplicate page warning but still work.
        cache.cache(0, &[2; PAGE_SIZE.get() as usize], 0);
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            cache.cache(0, &[i as u8; PAGE_SIZE.get() as usize], i);
        }
        // Page 0 should have been evicted.
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = cache.read_at(0, &mut buf, i * PAGE_SIZE_U64);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full logical page.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = cache.read_at(0, &mut buf, PAGE_SIZE_U64 + 2);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize - 2);
        assert_eq!(
            &buf[..PAGE_SIZE.get() as usize - 2],
            [1; PAGE_SIZE.get() as usize - 2]
        );
    }

    #[test_traced]
    fn test_cache_read_with_blob() {
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

            // Fill the page cache with the blob's data via CacheRef::read.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));
            assert_eq!(cache_ref.next_id(), 0);
            assert_eq!(cache_ref.next_id(), 1);
            for i in 0..11 {
                // Read expects logical bytes only (CRCs are stripped).
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                cache_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }

            // Repeat the read to exercise reading from the page cache. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                cache_ref
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
    fn test_cache_max_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));

            // Use the largest page-aligned offset representable for the configured PAGE_SIZE.
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE_U64);

            // CacheRef::cache expects only logical bytes (no CRC).
            let logical_data = vec![42u8; PAGE_SIZE.get() as usize];

            // Caching exactly one page at the maximum offset should succeed.
            let remaining = cache_ref.cache(0, logical_data.as_slice(), aligned_max_offset);
            assert_eq!(remaining, 0);

            // Reading from the cache should return the logical bytes.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let page_cache = cache_ref.cache.read();
            let bytes_read = page_cache.read_at(0, &mut buf, aligned_max_offset);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert!(buf.iter().all(|b| *b == 42));
        });
    }

    #[test_traced]
    fn test_cache_at_high_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use the minimum page size (CHECKSUM_SIZE + 1 = 13) with high offset.
            const MIN_PAGE_SIZE: u64 = CHECKSUM_SIZE + 1;
            let cache_ref =
                CacheRef::from_pooler(&context, NZU16!(MIN_PAGE_SIZE as u16), NZUsize!(2));

            // Create two pages worth of logical data (no CRCs - CacheRef::cache expects logical
            // only).
            let data = vec![1u8; MIN_PAGE_SIZE as usize * 2];

            // Cache pages at a high (but not max) aligned offset so we can verify both pages.
            // Use an offset that's a few pages below max to avoid overflow when verifying.
            let aligned_max_offset = u64::MAX - (u64::MAX % MIN_PAGE_SIZE);
            let high_offset = aligned_max_offset - (MIN_PAGE_SIZE * 2);
            let remaining = cache_ref.cache(0, &data, high_offset);
            // Both pages should be cached.
            assert_eq!(remaining, 0);

            // Verify the first page was cached correctly.
            let mut buf = vec![0u8; MIN_PAGE_SIZE as usize];
            let page_cache = cache_ref.cache.read();
            assert_eq!(
                page_cache.read_at(0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));

            // Verify the second page was cached correctly.
            assert_eq!(
                page_cache.read_at(0, &mut buf, high_offset + MIN_PAGE_SIZE),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
        });
    }

    #[test_traced]
    fn test_page_fetches_entry_removed_when_first_fetcher_cancelled() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Set up a small cache and a blob whose read never completes once started.
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));
            let (started_tx, started_rx) = oneshot::channel();
            let blob = BlockingBlob {
                started: Arc::new(Mutex::new(Some(started_tx))),
            };
            let mut read_buf = vec![0u8; PAGE_SIZE.get() as usize];

            // Spawn the first fetcher. It will insert into `page_fetches` and then block forever.
            let cache_ref_for_task = cache_ref.clone();
            let blob_for_task = blob.clone();
            let handle = context.spawn(move |_| async move {
                let _ = cache_ref_for_task
                    .read(&blob_for_task, blob_id, &mut read_buf, 0)
                    .await;
            });

            // Wait until the underlying read has started, ensuring the in-flight marker exists.
            started_rx.await.expect("blocking read never started");
            {
                let page_cache = cache_ref.cache.read();
                assert!(page_cache.page_fetches.contains_key(&(blob_id, 0)));
            }

            // Cancel the first fetcher before it reaches explicit cleanup.
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // The guard drop path should have removed the stale in-flight entry.
            let page_cache = cache_ref.cache.read();
            assert!(
                !page_cache.page_fetches.contains_key(&(blob_id, 0)),
                "cancelled first fetcher should not leave stale page_fetches entry"
            );
        });
    }

    #[test_traced]
    fn test_followers_keep_single_flight_after_first_fetcher_cancellation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));

            // Return one valid full page, but hold the underlying read until the test releases it.
            let logical_page = vec![7u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_page);
            let mut physical_page = logical_page.clone();
            physical_page.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc).to_bytes());
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = ControlledBlob {
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                reads: reads.clone(),
                result: ControlledBlobResult::Success(Arc::new(physical_page)),
            };

            // Start the fetch that installs the shared in-flight entry.
            let mut first_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.clone().spawn(move |_| async move {
                let _ = cache_ref_for_first
                    .read(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await;
            });
            started_rx.await.expect("first read never started");

            // Join as a follower while the first fetch is still blocked in the blob.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.clone().spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
                    .expect("second read failed");
                second_buf
            });

            // Wait until both tasks are registered against the same in-flight fetch.
            loop {
                let joined = {
                    let page_cache = cache_ref.cache.read();
                    page_cache
                        .page_fetches
                        .get(&(blob_id, 0))
                        .map(|fetch| fetch.waiters == 2)
                        .unwrap_or(false)
                };
                if joined {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            // Cancel the original fetcher; the follower should keep the generation alive.
            first.abort();
            assert!(matches!(first.await, Err(Error::Closed)));

            // A later reader should still join the existing in-flight fetch instead of starting a
            // second blob read.
            let mut third_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_third = cache_ref.clone();
            let blob_for_third = blob.clone();
            let third = context.clone().spawn(move |_| async move {
                cache_ref_for_third
                    .read(&blob_for_third, blob_id, &mut third_buf, 0)
                    .await
                    .expect("third read failed");
                third_buf
            });

            // Either the third reader bumps the waiter count back to 2, or a bug starts a second
            // blob read.
            loop {
                let third_entered = {
                    let page_cache = cache_ref.cache.read();
                    reads.load(Ordering::Relaxed) > 1
                        || page_cache
                            .page_fetches
                            .get(&(blob_id, 0))
                            .map(|fetch| fetch.waiters == 2)
                            .unwrap_or(false)
                };
                if third_entered {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            // Let the single underlying fetch complete and satisfy both surviving waiters.
            let _ = release_tx.send(());
            let second_buf = second.await.expect("second task failed");
            let third_buf = third.await.expect("third task failed");
            assert_eq!(second_buf, logical_page);
            assert_eq!(third_buf, logical_page);

            // All waiters should have shared the same blob read.
            assert_eq!(reads.load(Ordering::Relaxed), 1);

            // The successful fetch should populate the cache for later readers.
            let mut cached = vec![0u8; PAGE_SIZE.get() as usize];
            assert_eq!(
                cache_ref.read_cached(blob_id, &mut cached, 0),
                PAGE_SIZE.get() as usize
            );
            assert_eq!(cached, logical_page);

            // A later read should hit the cached page and avoid touching the blob again.
            let mut fourth_buf = vec![0u8; PAGE_SIZE.get() as usize];
            cache_ref
                .read(&blob, blob_id, &mut fourth_buf, 0)
                .await
                .unwrap();
            assert_eq!(fourth_buf, logical_page);
            assert_eq!(reads.load(Ordering::Relaxed), 1);

            let page_cache = cache_ref.cache.read();
            assert!(
                !page_cache.page_fetches.contains_key(&(blob_id, 0)),
                "completed fetch should leave no stale page_fetches entry"
            );
        });
    }

    #[test_traced]
    fn test_page_fetch_error_removes_entry_for_all_waiters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));

            // Hold one shared fetch in flight, then make the underlying read fail.
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = ControlledBlob {
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                reads: reads.clone(),
                result: ControlledBlobResult::Error,
            };

            // Start the fetch that creates the in-flight entry.
            let mut first_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.clone().spawn(move |_| async move {
                cache_ref_for_first
                    .read(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await
            });
            started_rx.await.expect("first erroring read never started");

            // Join with a second waiter that should observe the same failure.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.clone().spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
            });

            // Wait until both tasks share the same in-flight fetch entry.
            loop {
                let joined = {
                    let page_cache = cache_ref.cache.read();
                    page_cache
                        .page_fetches
                        .get(&(blob_id, 0))
                        .map(|fetch| fetch.waiters == 2)
                        .unwrap_or(false)
                };
                if joined {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            // Release the blocked read so the shared fetch resolves with an error.
            let _ = release_tx.send(());

            assert!(matches!(first.await, Ok(Err(Error::ReadFailed))));
            assert!(matches!(second.await, Ok(Err(Error::ReadFailed))));
            // Both waiters should still have shared a single blob read.
            assert_eq!(reads.load(Ordering::Relaxed), 1);

            // The failed generation must remove its in-flight entry and avoid caching data.
            {
                let page_cache = cache_ref.cache.read();
                assert!(
                    !page_cache.page_fetches.contains_key(&(blob_id, 0)),
                    "erroring fetch should leave no stale page_fetches entry"
                );
            }
            let mut cached = vec![0u8; PAGE_SIZE.get() as usize];
            assert_eq!(cache_ref.read_cached(blob_id, &mut cached, 0), 0);

            // A later read should start a fresh fetch rather than reusing stale error state.
            let mut third_buf = vec![0u8; PAGE_SIZE.get() as usize];
            assert!(matches!(
                cache_ref.read(&blob, blob_id, &mut third_buf, 0).await,
                Err(Error::ReadFailed)
            ));
            assert_eq!(reads.load(Ordering::Relaxed), 2);
        });
    }
}

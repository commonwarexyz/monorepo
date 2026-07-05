//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.

use super::get_page_from_blob;
use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufMut};
use ahash::AHashMap;
use commonware_utils::{
    cache::Clock,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use futures::{future::Shared, FutureExt};
use std::{
    collections::hash_map::Entry,
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{error, trace};

/// Shared future for one logical page fetch. The output uses `Arc<Error>` because `Shared`
/// requires cloneable results. The `IoBuf` contains only the logical, validated page bytes.
///
/// `Shared` also makes the future `Sync` and cloneable, so a caching implementation can hand one
/// fetch generation to every concurrent reader of the same page.
pub type PageFetchFuture = Shared<Pin<Box<dyn Future<Output = Result<IoBuf, Arc<Error>>> + Send>>>;

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

/// Maximum number of lock-protected shards a [ClockCache] partitions its pages across.
///
/// Must be a power of two. The actual shard count is reduced for small caches so every shard
/// holds at least one page.
const MAX_SHARDS: usize = 16;

/// Number of consecutive pages that map to the same shard.
///
/// Must be a power of two. Sequential multi-page operations re-acquire a shard lock only at
/// block boundaries, while operations spanning many blocks still spread across every shard.
const SHARD_BLOCK_PAGES: u64 = 8;

/// Returns the index of the shard owning `(blob_id, page_num)` among `shard_count` shards.
const fn shard_index(shard_count: usize, blob_id: u64, page_num: u64) -> usize {
    let mixed =
        (page_num / SHARD_BLOCK_PAGES).wrapping_add(blob_id.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    (mixed as usize) & (shard_count - 1)
}

/// Returns the shard owning `(blob_id, page_num)`.
fn shard_for(shards: &[RwLock<Cache>], blob_id: u64, page_num: u64) -> &RwLock<Cache> {
    &shards[shard_index(shards.len(), blob_id, page_num)]
}

/// Removes a stale in-flight page fetch when the last unresolved waiter is dropped.
struct PageFetchGuard {
    shards: Arc<[RwLock<Cache>]>,
    key: (u64, u64),
    fetch: PageFetch,
    armed: bool,
}

impl PageFetchGuard {
    const fn new(shards: Arc<[RwLock<Cache>]>, key: (u64, u64), fetch: PageFetch) -> Self {
        Self {
            shards,
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
        let mut cache = shard_for(&self.shards, self.key.0, self.key.1).write();
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
/// Eviction is delegated to a [Clock], which uses the Clock (second-chance) replacement
/// policy, a lightweight approximation of LRU. All page buffers are pre-allocated from `pool` at
/// construction (via [Clock::prefill]) and reused in place, so caching never allocates after
/// construction.
struct Cache {
    /// Maps each (blob id, page number) to its logical page buffer.
    cache: Clock<(u64, u64), IoBufMut>,

    /// Size of each page in bytes.
    page_size: usize,

    /// Pool the page buffers were allocated from.
    pool: BufferPool,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: AHashMap<(u64, u64), PageFetchEntry>,
}

/// A cache of logical [Blob] pages, shared by every blob registered with a [CacheRef].
/// Implementations decide what (if anything) to retain; [CacheRef] drives all reads, insertions,
/// and invalidations through this trait.
pub trait PageCache: Clone + Send + Sync + 'static {
    /// Copy cached bytes starting at `offset` into `buf`, returning the number of bytes copied.
    /// May stop early at any page boundary; `0` means the first page was not cached.
    fn read_at(&self, blob_id: u64, buf: &mut [u8], offset: u64) -> usize;

    /// Read multiple disjoint byte ranges. Fully cached ranges are filled and removed from
    /// `ranges`; entries left behind are (at least partially) uncached.
    fn read_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>);

    /// Store the whole `page_size`-sized pages of `buf` as consecutive pages starting at
    /// `first_page`, ignoring any trailing partial page.
    fn cache(&self, blob_id: u64, page_size: usize, buf: &[u8], first_page: u64);

    /// Drop any cached pages for `blob_id` at `page_num >= start_page`.
    fn invalidate_from(&self, blob_id: u64, start_page: u64);

    /// Resolve a page fault for `(blob_id, page_num)`: `fetch` reads and validates the logical
    /// page from the underlying blob. Copies the requested bytes (from `offset` onward, to the
    /// end of the page at most) into `buf`, returning the number of bytes copied.
    /// Implementations may join concurrent fetches of the same page and may retain the fetched
    /// page for future reads.
    fn fault<'a>(
        &'a self,
        blob_id: u64,
        page_num: u64,
        offset: u64,
        buf: &'a mut [u8],
        fetch: PageFetchFuture,
    ) -> impl Future<Output = Result<usize, Error>> + Send + Sync + 'a;
}

/// A [PageCache] with bounded capacity and Clock (second-chance) eviction that deduplicates
/// concurrent fetches of the same page.
///
/// Pages are partitioned across independent lock-protected shards, so concurrent readers and
/// writers of different pages contend only when their pages share a shard. Eviction is
/// per-shard.
#[derive(Clone)]
pub struct ClockCache {
    /// Page-cache shards. Each `(blob_id, page_num)` is owned by exactly one shard (see
    /// [shard_for]). The shard count is a power of two.
    shards: Arc<[RwLock<Cache>]>,

    /// Size of each page in bytes.
    page_size: u64,
}

impl ClockCache {
    /// Create a cache storing at most `capacity` pages, each exactly `page_size` bytes, eagerly
    /// allocated from `pool` and partitioned across shards.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();

        // Largest power of two <= min(MAX_SHARDS, capacity), so every shard gets at least one
        // page and the shard index is a mask.
        let shard_count = 1usize << MAX_SHARDS.min(capacity).ilog2();
        let base = capacity / shard_count;
        let rem = capacity % shard_count;
        let shards: Arc<[RwLock<Cache>]> = (0..shard_count)
            .map(|i| {
                let cap = NonZeroUsize::new(base + usize::from(i < rem))
                    .expect("shard capacity is nonzero");
                RwLock::new(Cache::new(pool.clone(), page_size, cap))
            })
            .collect();

        Self {
            shards,
            page_size: page_size.get() as u64,
        }
    }

    /// Returns the shard owning `(blob_id, page_num)`.
    fn shard(&self, blob_id: u64, page_num: u64) -> &RwLock<Cache> {
        shard_for(&self.shards, blob_id, page_num)
    }
}

impl PageCache for ClockCache {
    fn read_at(&self, blob_id: u64, mut buf: &mut [u8], mut offset: u64) -> usize {
        let original_len = buf.len();

        // Hold one shard's read lock at a time, re-acquiring only when the next page belongs
        // to a different shard.
        let mut held: Option<(usize, RwLockReadGuard<'_, Cache>)> = None;
        while !buf.is_empty() {
            let s = shard_index(self.shards.len(), blob_id, offset / self.page_size);
            if held.as_ref().map(|(held_s, _)| *held_s) != Some(s) {
                held = Some((s, self.shards[s].read()));
            }
            let cache = &held.as_ref().expect("guard held").1;
            let count = cache.read_at(blob_id, buf, offset);
            if count == 0 {
                break;
            }
            offset += count as u64;
            buf = &mut buf[count..];
        }
        original_len - buf.len()
    }

    fn read_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>) {
        // A single range needs no grouping.
        if let [(buf, logical_offset)] = ranges.as_mut_slice() {
            if self.read_at(blob_id, buf, *logical_offset) == buf.len() {
                ranges.clear();
            }
            return;
        }

        // Counting-sort range indices by the shard owning each range's first page so each
        // shard is read-locked at most once per call for ranges contained in a single shard
        // block (the common case).
        let shard_count = self.shards.len();
        let range_shard = |offset: u64| shard_index(shard_count, blob_id, offset / self.page_size);
        let mut counts = [0usize; MAX_SHARDS];
        for (_, offset) in ranges.iter() {
            counts[range_shard(*offset)] += 1;
        }
        let mut next = [0usize; MAX_SHARDS];
        let mut sum = 0;
        for s in 0..shard_count {
            next[s] = sum;
            sum += counts[s];
        }
        let mut order = vec![0u32; ranges.len()];
        for (i, (_, offset)) in ranges.iter().enumerate() {
            let s = range_shard(*offset);
            order[next[s]] = i as u32;
            next[s] += 1;
        }

        let mut complete = vec![false; ranges.len()];
        let mut pos = 0;
        for (s, count) in counts.iter().enumerate().take(shard_count) {
            let end = pos + count;
            if pos == end {
                continue;
            }
            let cache = self.shards[s].read();
            for &i in &order[pos..end] {
                let (buf, logical_offset) = &mut ranges[i as usize];
                let mut remaining = buf.len();
                let mut offset = *logical_offset;
                let mut dst = 0;
                while remaining > 0 {
                    // A range that crosses a block boundary continues in another shard; take
                    // that shard's lock just for the pages that live there.
                    let idx = shard_index(shard_count, blob_id, offset / self.page_size);
                    let read = if idx == s {
                        cache.read_at(blob_id, &mut buf[dst..], offset)
                    } else {
                        self.shards[idx]
                            .read()
                            .read_at(blob_id, &mut buf[dst..], offset)
                    };
                    if read == 0 {
                        break;
                    }
                    offset += read as u64;
                    dst += read;
                    remaining -= read;
                }
                complete[i as usize] = remaining == 0;
            }
            pos = end;
        }

        // Keep cache misses in `ranges`; drop fully-cached entries.
        let mut idx = 0;
        ranges.retain(|_| {
            let keep = !complete[idx];
            idx += 1;
            keep
        });
    }

    fn cache(&self, blob_id: u64, page_size: usize, mut buf: &[u8], mut first_page: u64) {
        // Hold one shard's write lock at a time, re-acquiring at block boundaries, so a
        // multi-page insert never blocks readers of other shards for the whole batch.
        let mut held: Option<(usize, RwLockWriteGuard<'_, Cache>)> = None;
        while buf.len() >= page_size {
            let s = shard_index(self.shards.len(), blob_id, first_page);
            if held.as_ref().map(|(held_s, _)| *held_s) != Some(s) {
                held = Some((s, self.shards[s].write()));
            }
            let cache = &mut held.as_mut().expect("guard held").1;
            cache.cache(blob_id, &buf[..page_size], first_page);
            buf = &buf[page_size..];
            first_page = match first_page.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
    }

    fn invalidate_from(&self, blob_id: u64, start_page: u64) {
        for shard in self.shards.iter() {
            shard.write().invalidate_from(blob_id, start_page);
        }
    }

    async fn fault(
        &self,
        blob_id: u64,
        page_num: u64,
        offset: u64,
        buf: &mut [u8],
        fetch: PageFetchFuture,
    ) -> Result<usize, Error> {
        // Create or clone a future that resolves the fetch. This requires a write lock on the
        // owning shard since we may need to modify `page_fetches` if this task is the first
        // fetcher.
        let (fetch_future, mut fetch_guard) = {
            let mut cache = self.shard(blob_id, page_num).write();

            // There's a (small) chance the page was fetched & buffered by another task before
            // we were able to acquire the write lock, so check the cache before anything else.
            let count = cache.read_at(blob_id, buf, offset);
            if count != 0 {
                return Ok(count);
            }

            let key = (blob_id, page_num);
            match cache.page_fetches.entry(key) {
                Entry::Occupied(o) => {
                    // Another task is already fetching this page, so clone its existing
                    // future.
                    let entry = o.into_mut();
                    entry.waiters += 1;
                    let fetch_future = entry.fetch.as_ref().clone();
                    let fetch = Arc::clone(&entry.fetch);
                    (
                        fetch_future,
                        PageFetchGuard::new(Arc::clone(&self.shards), key, fetch),
                    )
                }
                Entry::Vacant(v) => {
                    // Nobody is currently fetching this page, so wrap the provided fetch in a
                    // future that also caches the result and clears the in-flight marker.
                    let shards = Arc::clone(&self.shards);
                    let future = async move {
                        let result = fetch.await;
                        if let Err(err) = &result {
                            error!(page_num, ?err, "Page fetch failed");
                        }

                        // This shared future still owns `page_fetches[key]`. As long as at
                        // least one waiter remains armed, that entry pins this generation in
                        // place, so a replacement fetch for the same page cannot be inserted
                        // before we cache the successful result below. Only when every waiter
                        // cancels can the last guard remove the entry and let a later reader
                        // start a new generation.
                        let mut cache = shard_for(&shards, blob_id, page_num).write();
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
                        PageFetchGuard::new(Arc::clone(&self.shards), key, fetch),
                    )
                }
            }
        };

        // Await the shared fetch. The future itself logs failures, caches the resolved page,
        // and removes the in-flight marker before it returns, so waiters only need
        // cancellation cleanup while the fetch is still unresolved.
        let fetch_result = fetch_future.await;
        fetch_guard.disarm();
        let page_buf = match fetch_result {
            Ok(page_buf) => page_buf,
            Err(_) => return Err(Error::ReadFailed),
        };

        // Copy the requested portion of the page into the buffer.
        let offset_in_page = (offset % page_buf.len() as u64) as usize;
        let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf.as_ref()[offset_in_page..offset_in_page + bytes_to_copy]);

        Ok(bytes_to_copy)
    }
}

/// A [PageCache] that retains nothing: every read is a fault, and every fault fetches directly
/// from the blob (with the same integrity validation as a caching implementation).
///
/// Useful when an external cache (e.g. the OS page cache under buffered I/O) already holds hot
/// pages and in-process caching would duplicate it, or to measure uncached read cost. Unlike a
/// caching implementation, concurrent readers of the same page each perform their own fetch.
#[derive(Clone, Copy)]
pub struct NoCache;

impl PageCache for NoCache {
    fn read_at(&self, _blob_id: u64, _buf: &mut [u8], _offset: u64) -> usize {
        0
    }

    fn read_many(&self, _blob_id: u64, _ranges: &mut Vec<(&mut [u8], u64)>) {}

    fn cache(&self, _blob_id: u64, _page_size: usize, _buf: &[u8], _first_page: u64) {}

    fn invalidate_from(&self, _blob_id: u64, _start_page: u64) {}

    async fn fault(
        &self,
        _blob_id: u64,
        page_num: u64,
        offset: u64,
        buf: &mut [u8],
        fetch: PageFetchFuture,
    ) -> Result<usize, Error> {
        let page_buf = match fetch.await {
            Ok(page_buf) => page_buf,
            Err(err) => {
                error!(page_num, ?err, "Page fetch failed");
                return Err(Error::ReadFailed);
            }
        };
        let offset_in_page = (offset % page_buf.len() as u64) as usize;
        let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf.as_ref()[offset_in_page..offset_in_page + bytes_to_copy]);
        Ok(bytes_to_copy)
    }
}

/// A reference to a page cache that can be shared across threads via cloning, along with the page
/// size that will be used with it. Provides the API for interacting with the page cache in a
/// thread-safe manner.
#[derive(Clone)]
pub struct CacheRef<P: PageCache = ClockCache> {
    /// The size of each page in the underlying blobs managed by this page cache.
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. (Reads
    /// on blobs that were written with a different page size will fail their integrity check.)
    page_size: u64,

    /// The next id to assign to a blob that will be managed by this cache.
    next_id: Arc<AtomicU64>,

    /// The [PageCache] implementation backing this handle.
    cache: P,

    /// Pool used for page-cache and associated buffer allocations.
    pool: BufferPool,
}

impl CacheRef<ClockCache> {
    /// Create a shared page-cache handle backed by a [ClockCache] allocated from `pool`.
    ///
    /// The cache stores at most `capacity` pages, each exactly `page_size` bytes.
    /// Initialization eagerly allocates and zeroes all cache slots from `pool`.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let cache = ClockCache::new(pool.clone(), page_size, capacity);
        Self::with_cache(pool, page_size, cache)
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
}

impl CacheRef<NoCache> {
    /// Create a handle backed by [NoCache], performing no in-process caching.
    pub fn no_cache(pool: BufferPool, page_size: NonZeroU16) -> Self {
        Self::with_cache(pool, page_size, NoCache)
    }

    /// Create a handle backed by [NoCache], extracting the storage [BufferPool] from a
    /// [BufferPooler].
    pub fn no_cache_from_pooler(pooler: &impl BufferPooler, page_size: NonZeroU16) -> Self {
        Self::no_cache(pooler.storage_buffer_pool().clone(), page_size)
    }
}

impl<P: PageCache> CacheRef<P> {
    /// Create a handle backed by the given [PageCache] implementation.
    pub fn with_cache(pool: BufferPool, page_size: NonZeroU16, cache: P) -> Self {
        Self {
            page_size: page_size.get() as u64,
            next_id: Arc::new(AtomicU64::new(0)),
            cache,
            pool,
        }
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
    pub(super) fn read_cached(&self, blob_id: u64, buf: &mut [u8], logical_offset: u64) -> usize {
        self.cache.read_at(blob_id, buf, logical_offset)
    }

    /// Read multiple disjoint byte ranges from the page cache.
    ///
    /// Each element of `ranges` is `(dest_slice, logical_offset)`. Fully-cached ranges have
    /// their data written to the destination slice and are removed from `ranges`. Entries left
    /// in `ranges` correspond to cache misses that the caller must read from the underlying
    /// blob.
    pub(super) fn read_cached_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>) {
        self.cache.read_many(blob_id, ranges);
    }

    /// Read the specified bytes, preferentially from the page cache. Bytes not found in the cache
    /// will be read from the provided `blob` and (depending on the [PageCache] implementation)
    /// cached for future reads.
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
            let count = self.read_cached(blob_id, buf, offset);
            if count != 0 {
                offset += count as u64;
                buf = &mut buf[count..];
                continue;
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

    /// Fetch the requested page after encountering a page fault, delegating dedup and retention
    /// to the [PageCache] implementation. Returns the number of bytes read, which should always
    /// be non-zero.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        assert!(!buf.is_empty());

        let (page_num, _) = Cache::offset_to_page(self.page_size, offset);
        trace!(page_num, blob_id, "page fault");

        // Build a type-erased fetch of the page. get_page_from_blob handles CRC validation and
        // returns only logical bytes.
        let blob = blob.clone();
        let page_size = self.page_size;
        let fetch: PageFetchFuture =
            async move { fetch_cacheable_page(&blob, page_num, page_size).await }
                .boxed()
                .shared();

        self.cache
            .fault(blob_id, page_num, offset, buf, fetch)
            .await
    }

    /// Cache the provided pages of data in the page cache, returning the remaining bytes that
    /// didn't fill a whole page. `offset` must be page aligned.
    ///
    /// # Panics
    ///
    /// Panics if `offset` is not page aligned.
    pub fn cache(&self, blob_id: u64, buf: &[u8], offset: u64) -> usize {
        let (page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        let page_size = self.page_size as usize;
        self.cache.cache(blob_id, page_size, buf, page_num);
        buf.len() % page_size
    }

    /// Drop any cached pages for `blob_id` at `page_num >= start_page`. Used after a blob is
    /// truncated so subsequent reads can't observe pre-truncation bytes in a page that the tip
    /// buffer (or future writes) now owns.
    pub(super) fn invalidate_from(&self, blob_id: u64, start_page: u64) {
        self.cache.invalidate_from(blob_id, start_page);
    }
}

impl Cache {
    /// Return a new empty page cache with a max cache capacity of `capacity` pages, each of size
    /// `page_size` bytes.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size = page_size.get() as usize;
        let mut cache = Clock::new(capacity);
        cache.prefill(|| pool.alloc_zeroed(page_size));
        Self {
            cache,
            page_size,
            pool,
            page_fetches: AHashMap::new(),
        }
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
        let Some(page) = self.cache.get(&(blob_id, page_num)) else {
            return 0;
        };
        let page = page.as_ref();

        let offset_in_page = offset_in_page as usize;
        let bytes_to_copy = std::cmp::min(buf.len(), self.page_size - offset_in_page);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Put the given `page` into the page cache.
    fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), self.page_size);
        let pool = &self.pool;
        let page_size = self.page_size;
        let buf = self
            .cache
            .get_or_insert_mut((blob_id, page_num), || pool.alloc_zeroed(page_size));
        buf.as_mut().copy_from_slice(page);
    }

    /// Drop any cached pages for `blob_id` at `page_num >= start_page`.
    fn invalidate_from(&mut self, blob_id: u64, start_page: u64) {
        self.cache
            .retain(|&(bid, page_num), _| bid != blob_id || page_num < start_page);
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
        buffer::paged::CHECKSUM_SIZE, deterministic, telemetry::metrics::Registry, Buf, BufferPool,
        BufferPoolConfig, Clock as _, Handle, IoBufsMut, Runner as _, Spawner as _, Storage as _,
        Supervisor as _,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize, NZU16};
    use futures::future::pending;
    use rstest::rstest;
    use std::{
        num::NonZeroU16,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    /// Build a [CacheRef] backed by a [ClockCache], returning both so tests can probe the
    /// concrete cache state behind the trait.
    fn clocked(
        pooler: &impl BufferPooler,
        page_size: NonZeroU16,
        capacity: NonZeroUsize,
    ) -> (CacheRef, Arc<ClockCache>) {
        let pool = pooler.storage_buffer_pool().clone();
        let clock = Arc::new(ClockCache::new(pool.clone(), page_size, capacity));
        (
            CacheRef::with_cache(pool, page_size, clock.as_ref().clone()),
            clock,
        )
    }

    // Logical page size (what CacheRef uses and what gets cached).
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    fn expected_cached_bytes(logical_offset: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let page = (logical_offset + i as u64) / PAGE_SIZE_U64;
                page as u8 + 1
            })
            .collect()
    }

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

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            if !bufs.has_remaining() {
                return Ok(());
            }

            self.write_at(offset, bufs).await?;
            self.sync().await
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            Handle::ready(self.sync().await)
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

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            if !bufs.has_remaining() {
                return Ok(());
            }

            self.write_at(offset, bufs).await?;
            self.sync().await
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            Handle::ready(self.sync().await)
        }
    }

    #[test_traced]
    fn test_cache_basic() {
        let pool = test_pool();
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(10));

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        cache.cache(0, &[1; PAGE_SIZE.get() as usize], 0);
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- re-caching the same page overwrites it in place.
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
    fn test_invalidate_from_does_not_orphan_re_cached_page() {
        // Invalidating pages, re-caching one, then forcing an eviction must keep every live page
        // readable. Freed slots are reused cleanly, so an invalidated-then-re-cached page is never
        // orphaned by a later eviction.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(2));
        let blob_id = 0u64;
        let page_size = PAGE_SIZE.get() as usize;

        // Fill both slots, then invalidate them so both slots are freed for reuse.
        cache.cache(blob_id, &vec![0xAA; page_size], 0);
        cache.cache(blob_id, &vec![0xBB; page_size], 1);
        cache.invalidate_from(blob_id, 0);

        // Re-cache page 1 into a reused slot.
        cache.cache(blob_id, &vec![0xCC; page_size], 1);
        let mut buf = vec![0u8; page_size];
        assert_eq!(
            cache.read_at(blob_id, &mut buf, PAGE_SIZE_U64),
            page_size,
            "page 1 should be readable after re-cache"
        );
        assert_eq!(buf, vec![0xCC; page_size]);

        // Cache a new page, which reuses the other freed slot rather than evicting live page 1.
        cache.cache(blob_id, &vec![0xDD; page_size], 2);

        // Slot 0 must still be reachable via its live index entry.
        let mut buf = vec![0u8; page_size];
        assert_eq!(
            cache.read_at(blob_id, &mut buf, PAGE_SIZE_U64),
            page_size,
            "live page 1 was orphaned by stale-slot eviction"
        );
        assert_eq!(buf, vec![0xCC; page_size]);

        // And the newly cached page 2 is also reachable.
        let mut buf = vec![0u8; page_size];
        assert_eq!(
            cache.read_at(blob_id, &mut buf, PAGE_SIZE_U64 * 2),
            page_size
        );
        assert_eq!(buf, vec![0xDD; page_size]);
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
    fn test_no_cache_reads_without_caching() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let physical_page_size = PAGE_SIZE_U64 + CHECKSUM_SIZE;

            // Populate a blob with 3 consecutive pages of CRC-protected data.
            let (blob, _) = context
                .open("test", "passthrough_blob".as_bytes())
                .await
                .expect("Failed to open blob");
            for i in 0..3 {
                let logical_data = vec![i as u8; PAGE_SIZE.get() as usize];
                let crc = Crc32::checksum(&logical_data);
                let record = Checksum::new(PAGE_SIZE.get(), crc);
                let mut page_data = logical_data;
                page_data.extend_from_slice(&record.to_bytes());
                blob.write_at(i * physical_page_size, page_data)
                    .await
                    .unwrap();
            }

            let cache_ref = CacheRef::no_cache_from_pooler(&context, PAGE_SIZE);

            // Every read fetches directly from the blob (with CRC validation), including reads
            // that span a page boundary.
            for i in 0..3 {
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                cache_ref
                    .read(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }
            let mut buf = vec![0; PAGE_SIZE.get() as usize];
            cache_ref
                .read(&blob, 0, &mut buf, PAGE_SIZE_U64 / 2)
                .await
                .unwrap();
            assert_eq!(
                &buf[..(PAGE_SIZE.get() / 2) as usize],
                &[0u8; PAGE_SIZE.get() as usize][..(PAGE_SIZE.get() / 2) as usize]
            );
            assert_eq!(
                &buf[(PAGE_SIZE.get() / 2) as usize..],
                &[1u8; PAGE_SIZE.get() as usize][..(PAGE_SIZE.get() / 2) as usize]
            );

            // Nothing is retained: cached probes always miss, and insertion is a no-op that
            // still reports the leftover partial-page bytes.
            let mut buf = vec![0; PAGE_SIZE.get() as usize];
            assert_eq!(cache_ref.read_cached(0, &mut buf, 0), 0);
            let mut ranges = vec![(&mut buf[..], 0u64)];
            cache_ref.read_cached_many(0, &mut ranges);
            assert_eq!(ranges.len(), 1);
            let logical = vec![7u8; PAGE_SIZE.get() as usize + 3];
            assert_eq!(cache_ref.cache(0, &logical, 0), 3);
            let mut buf = vec![0; PAGE_SIZE.get() as usize];
            assert_eq!(cache_ref.read_cached(0, &mut buf, 0), 0);

            // Invalidation is a no-op rather than a panic.
            cache_ref.invalidate_from(0, 0);
        });
    }

    #[test_traced]
    fn test_cache_max_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cache_ref, clock) = clocked(&context, PAGE_SIZE, NZUsize!(2));

            // Use the largest page-aligned offset representable for the configured PAGE_SIZE.
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE_U64);

            // CacheRef::cache expects only logical bytes (no CRC).
            let logical_data = vec![42u8; PAGE_SIZE.get() as usize];

            // Caching exactly one page at the maximum offset should succeed.
            let remaining = cache_ref.cache(0, logical_data.as_slice(), aligned_max_offset);
            assert_eq!(remaining, 0);

            // Reading from the cache should return the logical bytes.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let max_page = aligned_max_offset / PAGE_SIZE_U64;
            let page_cache = clock.shard(0, max_page).read();
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
            let (cache_ref, clock) = clocked(&context, NZU16!(MIN_PAGE_SIZE as u16), NZUsize!(32));

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
            let first_page = high_offset / MIN_PAGE_SIZE;
            assert_eq!(
                clock
                    .shard(0, first_page)
                    .read()
                    .read_at(0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));

            // Verify the second page was cached correctly.
            assert_eq!(
                clock.shard(0, first_page + 1).read().read_at(
                    0,
                    &mut buf,
                    high_offset + MIN_PAGE_SIZE
                ),
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
            let (cache_ref, clock) = clocked(&context, PAGE_SIZE, NZUsize!(10));
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
                let page_cache = clock.shard(blob_id, 0).read();
                assert!(page_cache.page_fetches.contains_key(&(blob_id, 0)));
            }

            // Cancel the first fetcher before it reaches explicit cleanup.
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // The guard drop path should have removed the stale in-flight entry.
            let page_cache = clock.shard(blob_id, 0).read();
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
            let (cache_ref, clock) = clocked(&context, PAGE_SIZE, NZUsize!(10));

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
            let first = context.child("first").spawn(move |_| async move {
                let _ = cache_ref_for_first
                    .read(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await;
            });
            started_rx.await.expect("first read never started");

            // Join as a follower while the first fetch is still blocked in the blob.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.child("second").spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
                    .expect("second read failed");
                second_buf
            });

            // Wait until both tasks are registered against the same in-flight fetch.
            loop {
                let joined = {
                    let page_cache = clock.shard(blob_id, 0).read();
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
            let third = context.child("third").spawn(move |_| async move {
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
                    let page_cache = clock.shard(blob_id, 0).read();
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

            let page_cache = clock.shard(blob_id, 0).read();
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
            let (cache_ref, clock) = clocked(&context, PAGE_SIZE, NZUsize!(10));

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
            let first = context.child("first").spawn(move |_| async move {
                cache_ref_for_first
                    .read(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await
            });
            started_rx.await.expect("first erroring read never started");

            // Join with a second waiter that should observe the same failure.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.child("second").spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
            });

            // Wait until both tasks share the same in-flight fetch entry.
            loop {
                let joined = {
                    let page_cache = clock.shard(blob_id, 0).read();
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
                let page_cache = clock.shard(blob_id, 0).read();
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

    #[test_traced]
    fn test_read_cached_many_all_cached() {
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        let page0 = vec![0xAA; PAGE_SIZE.get() as usize];
        let page1 = vec![0xBB; PAGE_SIZE.get() as usize];

        // Populate two pages with distinct data.
        assert_eq!(cache_ref.cache(blob_id, &page0, 0), 0);
        assert_eq!(cache_ref.cache(blob_id, &page1, PAGE_SIZE_U64), 0);

        let mut buf0 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut buf1 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf0, 0), (&mut buf1, PAGE_SIZE_U64)];

        cache_ref.read_cached_many(blob_id, &mut ranges);

        // All ranges served from cache, so the vec is now empty.
        assert!(ranges.is_empty());
        drop(ranges);

        // Buffers should contain the cached page data.
        assert!(buf0 == page0);
        assert!(buf1 == page1);
    }

    #[test_traced]
    fn test_read_cached_many_none_cached() {
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();

        let mut buf0 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut buf1 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf0, 0), (&mut buf1, PAGE_SIZE_U64)];

        // Empty cache: both ranges should miss and remain in the vec unchanged.
        cache_ref.read_cached_many(blob_id, &mut ranges);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].1, 0);
        assert_eq!(ranges[1].1, PAGE_SIZE_U64);
    }

    #[test_traced]
    fn test_read_cached_many_scattered_misses() {
        // Verify that read_cached_many checks ALL ranges, not just up to the
        // first miss. Pages 0 and 2 are cached, page 1 is not.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();

        let page0 = vec![0x11; PAGE_SIZE.get() as usize];
        let page2 = vec![0x33; PAGE_SIZE.get() as usize];
        assert_eq!(cache_ref.cache(blob_id, &page0, 0), 0);
        // page 1 deliberately not cached
        assert_eq!(cache_ref.cache(blob_id, &page2, PAGE_SIZE_U64 * 2), 0);

        let mut buf0 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut buf1 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut buf2 = vec![0u8; PAGE_SIZE_U64 as usize];
        let mut ranges: Vec<(&mut [u8], u64)> = vec![
            (&mut buf0, 0),
            (&mut buf1, PAGE_SIZE_U64),
            (&mut buf2, PAGE_SIZE_U64 * 2),
        ];

        cache_ref.read_cached_many(blob_id, &mut ranges);

        // Only the page 1 miss should remain (page 2 is still processed despite
        // the earlier miss).
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, PAGE_SIZE_U64);
        drop(ranges);

        // Cached pages should have their data written to the buffers.
        assert!(buf0 == page0);
        assert!(buf2 == page2);
        // Missed page's buffer should be untouched (still zeroed).
        assert!(buf1.iter().all(|b| *b == 0));
    }

    #[rstest]
    #[case::empty_read(vec![], 0, 0, 0)]
    #[case::single_cached_page(vec![0], 3, 5, 5)]
    #[case::cached_range_can_cross_pages(vec![0, 1], PAGE_SIZE_U64 - 2, 4, 4)]
    #[case::missing_first_page_reads_nothing(vec![1], 0, 4, 0)]
    #[case::missing_later_page_truncates_read(vec![0], PAGE_SIZE_U64 - 2, 4, 2)]
    fn test_read_cached(
        #[case] cached_pages: Vec<u64>,
        #[case] logical_offset: u64,
        #[case] len: usize,
        #[case] expected_count: usize,
    ) {
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        let sentinel = 0xEE;
        let page_size = PAGE_SIZE.get() as usize;

        for page in cached_pages {
            // Use a distinct byte per page so cross-page reads prove both halves were copied.
            let data = vec![page as u8 + 1; page_size];
            assert_eq!(cache_ref.cache(blob_id, &data, page * PAGE_SIZE_U64), 0);
        }

        let mut buf = vec![sentinel; len];
        let count = cache_ref.read_cached(blob_id, &mut buf, logical_offset);
        assert_eq!(count, expected_count);

        // The satisfied prefix holds cached bytes; everything past the first fault is untouched.
        assert_eq!(buf[..count], expected_cached_bytes(logical_offset, count));
        assert!(buf[count..].iter().all(|b| *b == sentinel));
    }
}

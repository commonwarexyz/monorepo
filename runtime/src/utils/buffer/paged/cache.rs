//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.

use super::{CHECKSUM_SIZE, STORAGE_PAGE_SIZE, get_page_from_blob};
use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufMut, ReadOptions};
use ahash::AHashMap;
use commonware_utils::{Widen, cache, sync::RwLock};
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use std::{
    collections::hash_map::Entry,
    num::{NonZeroU16, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{debug, error, trace};

/// Shared future for one logical page fetch. The cache keeps one clone in `page_fetches` and
/// each waiter holds another while it is still interested in the result. The `IoBuf` contains
/// only the logical, validated page bytes.
type PageFetch = Shared<BoxFuture<'static, Result<IoBuf, Error>>>;

/// One in-flight fetch generation for a single `(blob_id, page_num)`.
///
/// `fetch` is shared by every waiter that joined this generation. `waiters` counts the still
/// armed waiters whose drop path may need to remove this entry if they become the last
/// unresolved waiter. If `page_fetches[key]` is later replaced by a newer generation, stale
/// waiters from the old generation must ignore it and rely on `Shared::ptr_eq` against their saved
/// `fetch`.
struct PageFetchEntry {
    /// Shared page fetch future that reads and validates the logical page exactly once.
    fetch: PageFetch,
    /// Count of waiters that still need cancellation cleanup for this fetch generation.
    waiters: usize,
}

/// Removes a stale in-flight page fetch when the last unresolved waiter is dropped.
struct PageFetchGuard<'a> {
    cache: &'a RwLock<Cache>,
    key: (u64, u64),
    fetch: PageFetch,
    armed: bool,
}

impl<'a> PageFetchGuard<'a> {
    const fn new(cache: &'a RwLock<Cache>, key: (u64, u64), fetch: PageFetch) -> Self {
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

impl Drop for PageFetchGuard<'_> {
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
        // Neither stored clone is ever polled, so `ptr_eq` never sees a terminated future.
        if !current.get().fetch.ptr_eq(&self.fetch) {
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
/// Eviction uses the Clock2Q+ replacement algorithm. All page buffers are pre-allocated from
/// `pool` at construction and reused in place, so caching never allocates page buffers after
/// construction.
///
/// Reads first resolve pages through `hints`, a fixed-size direct-mapped array from
/// [Self::hint_index] to the [cache::Cache] slot the page was last cached in: a lookup is one array
/// load instead of a hash-table probe chain, which the out-of-order core cannot overlap across
/// items. Hints are best-effort, never truth: [cache::Cache::get_at] only resolves a slot that
/// still holds the page's key live, so entries staled by eviction, invalidation, or hint collisions
/// read as misses and fall back to the [cache::Cache]'s own lookup. Hints need no maintenance on
/// eviction or invalidation, and their memory is fixed at construction, so no blob offset can grow
/// them.
struct Cache {
    /// Maps each (blob id, page number) to its logical page buffer.
    cache: cache::Cache<(u64, u64), IoBufMut>,

    /// Direct-mapped [cache::Cache] slot hints, indexed by [Self::hint_index]. Initialized
    /// out-of-range so untouched entries read as misses. The length is a power of two so
    /// [Self::hint_index] can wrap with a mask instead of a division, and at least twice the
    /// cache capacity: a full cache has one live page per `capacity`, so sizing at capacity
    /// makes hint collisions (and their slower fallback lookups) common.
    hints: Vec<usize>,

    /// Logical size of each page in bytes (the payload stored per page, excluding the CRC
    /// record appended on disk).
    page_size: NonZeroU16,

    /// Pool the page buffers were allocated from.
    pool: BufferPool,

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: AHashMap<(u64, u64), PageFetchEntry>,
}

/// A reference to a page cache that can be shared across threads via cloning, along with the page
/// size that will be used with it. Provides the API for interacting with the page cache in a
/// thread-safe manner.
#[derive(Clone)]
pub struct CacheRef {
    /// The logical size of each page in the underlying blobs managed by this page cache. A page
    /// occupies `page_size + CHECKSUM_SIZE` bytes on disk (its physical size).
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. Reads on
    /// blobs written with a different page size fail their integrity check, and reopening such a
    /// blob for writing treats the mismatched pages as invalid trailing data and silently truncates
    /// the blob (potentially to empty). Changing an existing store's page size is a destructive
    /// format migration, not a configuration change.
    page_size: NonZeroU16,

    /// The next id to assign to a blob that will be managed by this cache.
    next_id: Arc<AtomicU64>,

    /// The page-cache shards. Pages map to shards in 8-page blocks (see [Self::shard]) so
    /// concurrent readers of unrelated pages take different locks while short sequential
    /// runs stay on one shard. A capacity below one block per shard collapses to a single
    /// shard, preserving the unsharded behavior for tiny caches.
    shards: Arc<[RwLock<Cache>]>,

    /// `shards.len() - 1`; the shard count is a power of two so routing can mask.
    shard_mask: u64,

    /// Pool used for page-cache and associated buffer allocations.
    pool: BufferPool,
}

/// Maximum number of page-cache shards (power of two).
const MAX_SHARDS: usize = 16;

/// Consecutive pages that map to one shard, as a power-of-two exponent (8-page blocks):
/// large enough that short sequential runs reuse one lock, small enough to spread load.
const PAGES_PER_SHARD_BLOCK_BITS: u32 = 3;

impl CacheRef {
    /// Create a shared page-cache handle backed by `pool`.
    ///
    /// The cache stores at most `capacity` pages, each exactly `page_size` bytes (see
    /// [Self::page_size] for how this relates to a page's physical size on disk).
    /// Initialization eagerly allocates and zeroes all cache slots from `pool`. Eviction follows
    /// the cache's Clock2Q+ replacement algorithm.
    ///
    /// Any `page_size` is accepted, but physical pages that do not align with storage pages (see
    /// the module docs) amplify cold random reads. Use [super::page_size] to pick an aligned value.
    /// Cache misses request [ReadOptions::DONT_CACHE] because the fetched page is retained here.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size_u64: u64 = page_size.widen();
        let physical_page_size = page_size_u64 + CHECKSUM_SIZE;
        if !physical_page_size.is_multiple_of(STORAGE_PAGE_SIZE)
            && !STORAGE_PAGE_SIZE.is_multiple_of(physical_page_size)
        {
            debug!(
                page_size = page_size.get(),
                physical_page_size, "physical pages do not align with storage pages"
            );
        }

        // One shard per 8-page block up to [MAX_SHARDS], rounded down to a power of two.
        let shards = MAX_SHARDS.min((capacity.get() >> PAGES_PER_SHARD_BLOCK_BITS).max(1));
        let shards = if shards.is_power_of_two() {
            shards
        } else {
            shards.next_power_of_two() >> 1
        };
        let per_shard = capacity.get().div_ceil(shards);
        let shards: Arc<[RwLock<Cache>]> = (0..shards)
            .map(|_| {
                RwLock::new(Cache::new(
                    pool.clone(),
                    page_size,
                    NonZeroUsize::new(per_shard).expect("per-shard capacity is non-zero"),
                ))
            })
            .collect::<Vec<_>>()
            .into();

        Self {
            page_size,
            next_id: Arc::new(AtomicU64::new(0)),
            shard_mask: (shards.len() - 1) as u64,
            shards,
            pool,
        }
    }

    /// The shard lock holding `page_num` of blob `blob_id` (test inspection only).
    #[cfg(test)]
    fn test_shard(&self, blob_id: u64, page_num: u64) -> &RwLock<Cache> {
        &self.shards[self.shard(blob_id, page_num)]
    }

    /// The shard holding `page_num` of blob `blob_id`.
    #[inline]
    const fn shard(&self, blob_id: u64, page_num: u64) -> usize {
        let block = page_num >> PAGES_PER_SHARD_BLOCK_BITS;
        (block.wrapping_add(blob_id.wrapping_mul(commonware_utils::GOLDEN_RATIO)) & self.shard_mask)
            as usize
    }

    /// Create a shared page-cache handle, extracting the storage [BufferPool] from a
    /// [BufferPooler]. Cache misses request [ReadOptions::DONT_CACHE].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        page_size: NonZeroU16,
        capacity: NonZeroUsize,
    ) -> Self {
        Self::new(pooler.storage_buffer_pool().clone(), page_size, capacity)
    }

    /// The page size used by this page cache: the logical payload bytes stored per page. Each
    /// page occupies `page_size() + CHECKSUM_SIZE` bytes on disk (its physical size).
    #[inline]
    pub const fn page_size(&self) -> NonZeroU16 {
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
    pub fn offset_to_page(&self, offset: u64) -> (u64, u64) {
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
        let mut held: Option<(usize, _)> = None;
        while !buf.is_empty() {
            let (page_num, _) = self.offset_to_page(logical_offset);
            let shard = self.shard(blob_id, page_num);
            // Reuse the held guard within a shard; drop it before acquiring the next
            // (never wait on one shard while holding another).
            if held.as_ref().map(|(s, _)| *s) != Some(shard) {
                drop(held.take());
                held = Some((shard, self.shards[shard].read()));
            }
            let (_, page_cache) = held.as_ref().expect("guard held");
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

    /// Read multiple disjoint byte ranges from the page cache, taking each shard's lock once.
    ///
    /// Each element of `ranges` is `(dest_slice, logical_offset)`. Fully-cached ranges have
    /// their data written to the destination slice and are removed from `ranges`. Entries left
    /// in `ranges` start at the first missing byte, with any cached prefix already copied into
    /// the destination and excluded from the remaining slice.
    pub(super) fn read_cached_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>) {
        // One pass computes each range's first page, in-page offset, and shard; the per-shard
        // passes below reuse them instead of re-deriving (offset math is a division).
        let mut tags: Vec<(u32, u64, usize, usize)> = Vec::with_capacity(ranges.len());
        let mut present: u32 = 0;
        for (_, offset) in ranges.iter() {
            let (page_num, offset_in_page, remaining) = Cache::locate(self.page_size, *offset);
            let shard = self.shard(blob_id, page_num);
            present |= 1 << shard;
            tags.push((shard as u32, page_num, offset_in_page, remaining));
        }

        // Bytes copied into each range, and whether it stopped at a shard boundary rather than
        // a miss.
        let mut progress: Vec<(usize, bool)> = vec![(0, false); ranges.len()];

        // Serve each non-empty shard with one lock acquisition, scanning the tag vector for its
        // ranges (at most shards x ranges comparisons, allocation-free).
        let mut shard_iter = present;
        while shard_iter != 0 {
            let shard = shard_iter.trailing_zeros() as usize;
            shard_iter &= shard_iter - 1;
            let page_cache = self.shards[shard].read();
            for idx in 0..ranges.len() {
                let (tag, first_page, offset_in_page, remaining) = tags[idx];
                if tag as usize != shard {
                    continue;
                }
                let (buf, offset) = &mut ranges[idx];
                if buf.is_empty() {
                    continue;
                }
                let seg = std::cmp::min(buf.len(), remaining);
                let Some(page) = page_cache.get_page(blob_id, first_page) else {
                    continue;
                };
                buf[..seg].copy_from_slice(&page.as_ref()[offset_in_page..offset_in_page + seg]);
                let mut done = seg;

                // A continuation past the first page stays on this shard's guard while its pages
                // remain here. Crossing into another shard defers to the post-pass (never wait on
                // one shard while holding another).
                let mut page_num = first_page;
                let mut crossed = false;
                while done < buf.len() {
                    page_num += 1;
                    if self.shard(blob_id, page_num) != shard {
                        crossed = true;
                        break;
                    }
                    let count =
                        page_cache.read_at(blob_id, &mut buf[done..], *offset + done as u64);
                    if count == 0 {
                        break;
                    }
                    done += count;
                }
                progress[idx] = (done, crossed);
            }
        }

        // Post-pass: ranges that crossed a shard boundary continue through the guard-reusing
        // single-read path with no shard lock held. Drop fully-cached ranges and retain only
        // unread suffixes.
        let mut next = 0;
        ranges.retain_mut(|(buf, offset)| {
            let (mut done, crossed) = progress[next];
            next += 1;
            if crossed {
                done += self.read_cached(blob_id, &mut buf[done..], *offset + done as u64);
            }
            if done == buf.len() {
                return false;
            }
            *offset += done as u64;
            *buf = std::mem::take(buf).split_at_mut(done).1;
            true
        });
    }

    /// Complete the unread suffix of a cache probe. The first page is rechecked under the write
    /// lock before starting or joining a fetch. Subsequent cached pages are read together until
    /// the next miss.
    pub(super) async fn read_after_miss<B: Blob>(
        &self,
        blob: &Arc<B>,
        blob_id: u64,
        mut buf: &mut [u8],
        mut offset: u64,
    ) -> Result<(), Error> {
        // Read from the page cache or `blob` until the requested data is fully read.
        // Fetch missing pages one at a time and copy consecutive cached pages together.
        while !buf.is_empty() {
            // Resolve the missing page, rechecking for a concurrent fill before fetching.
            let count = self
                .read_after_page_fault(blob, blob_id, buf, offset)
                .await?;
            offset += count as u64;
            buf = &mut buf[count..];
            if buf.is_empty() {
                break;
            }

            // Copy the following cached pages under one read lock, stopping at the next miss.
            let cached = self.read_cached(blob_id, buf, offset);
            offset += cached as u64;
            buf = &mut buf[cached..];
        }

        Ok(())
    }

    /// Fetch the requested page after encountering a page fault, which may involve retrieving it
    /// from `blob` & caching the result in the page cache. Returns the number of bytes read, which
    /// should always be non-zero.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &Arc<B>,
        blob_id: u64,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        assert!(!buf.is_empty());

        let (page_num, offset_in_page, _) = Cache::locate(self.page_size, offset);
        trace!(page_num, blob_id, "page fault");

        // Create or clone a future that retrieves the desired page from the underlying blob. This
        // requires a write lock on the page cache since we may need to modify `page_fetches` if
        // this task is the first fetcher.
        let key = (blob_id, page_num);
        let shard = self.shard(blob_id, page_num);
        let fetch = {
            let mut cache = self.shards[shard].write();

            // There's a (small) chance the page was fetched & buffered by another task before we
            // were able to acquire the write lock, so check the cache before doing anything else.
            let count = cache.read_at(blob_id, buf, offset);
            if count != 0 {
                return Ok(count);
            }

            match cache.page_fetches.entry(key) {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page, so clone its existing future.
                    let entry = o.into_mut();
                    entry.waiters += 1;
                    entry.fetch.clone()
                }
                Entry::Vacant(v) => {
                    // Nobody is currently fetching this page, so create a future that will do the
                    // work. get_page_from_blob handles CRC validation and returns only logical bytes.
                    let blob = blob.clone();
                    let shards = Arc::clone(&self.shards);
                    let page_size = self.page_size;
                    let future = async move {
                        let result = fetch_cacheable_page(blob.as_ref(), page_num, page_size).await;
                        if let Err(err) = &result {
                            error!(page_num, ?err, "Page fetch failed");
                        }

                        // This shared future still owns `page_fetches[key]`. As long as at least
                        // one waiter remains armed, that entry pins this generation in place, so a
                        // replacement fetch for the same page cannot be inserted before we cache
                        // the successful result below. Only when every waiter cancels can the last
                        // guard remove the entry and let a later reader start a new generation.
                        let mut cache = shards[shard].write();
                        if let Ok(page) = &result {
                            cache.cache(blob_id, page.as_ref(), page_num);
                        }
                        let _ = cache.page_fetches.remove(&key);
                        result
                    };

                    // Make the future shareable and insert it into the map.
                    let fetch = future.boxed().shared();
                    v.insert(PageFetchEntry {
                        fetch: fetch.clone(),
                        waiters: 1,
                    });
                    fetch
                }
            }
        };
        let mut fetch_guard = PageFetchGuard::new(&self.shards[shard], key, fetch.clone());

        // Await the shared fetch. The future itself logs failures, caches the resolved page, and
        // removes the in-flight marker before it returns, so waiters only need cancellation
        // cleanup while the fetch is still unresolved.
        let fetch_result = fetch.await;
        fetch_guard.disarm();
        let page_buf = fetch_result?;

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
    /// Panics if `offset` is not page aligned.
    pub fn cache(&self, blob_id: u64, buf: &[u8], offset: u64) -> usize {
        let page_size: usize = self.page_size.widen();
        buf.len() - self.cache_pages(blob_id, buf.chunks_exact(page_size), offset)
    }

    /// Insert whole logical pages, taking each shard's lock once per run of its pages, and return
    /// the number of bytes cached.
    pub(super) fn cache_pages<'a>(
        &self,
        blob_id: u64,
        pages: impl Iterator<Item = &'a [u8]>,
        offset: u64,
    ) -> usize {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        let mut cached = 0;
        let mut held: Option<(usize, _)> = None;
        for page in pages {
            // Reuse the guard across a block's pages; drop it before acquiring the next shard.
            let shard = self.shard(blob_id, page_num);
            if held.as_ref().map(|(s, _)| *s) != Some(shard) {
                drop(held.take());
                held = Some((shard, self.shards[shard].write()));
            }
            let (_, page_cache) = held.as_mut().expect("guard held");
            page_cache.cache(blob_id, page, page_num);
            cached += page.len();
            page_num = match page_num.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        cached
    }

    /// Drop all cached pages while retaining the backing page buffers for reuse.
    ///
    /// Call only when no reads are in flight for this cache.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            shard.write().clear();
        }
    }
}

impl Cache {
    /// Return a new empty page cache with a max cache capacity of `capacity` pages, each of size
    /// `page_size` bytes.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let slot_size: usize = page_size.widen();
        let mut cache = cache::Cache::new(capacity);
        cache.prefill(|| pool.alloc_zeroed(slot_size));
        let hints = capacity.get().saturating_mul(2).next_power_of_two();
        Self {
            cache,
            hints: vec![usize::MAX; hints],
            page_size,
            pool,
            page_fetches: AHashMap::new(),
        }
    }

    /// Convert a logical offset into the number of the page it belongs to and the offset within
    /// that page.
    fn offset_to_page(page_size: NonZeroU16, offset: u64) -> (u64, u64) {
        let page_size: u64 = page_size.widen();
        (offset / page_size, offset % page_size)
    }

    /// Locate `offset` within its page: the page number, the offset inside that page, and the
    /// bytes remaining in the page at that offset.
    fn locate(page_size: NonZeroU16, offset: u64) -> (u64, usize, usize) {
        let (page_num, offset_in_page) = Self::offset_to_page(page_size, offset);
        let offset_in_page = offset_in_page as usize;
        let width: usize = page_size.widen();
        let remaining = width - offset_in_page;
        (page_num, offset_in_page, remaining)
    }

    /// Attempt to fetch blob data starting at `offset` from the page cache. Returns the number of
    /// bytes read, which could be 0 if the first page in the requested range isn't buffered, and is
    /// never more than `self.page_size` or the length of `buf`. The returned bytes won't cross a
    /// page boundary, so multiple reads may be required even if all data in the desired range is
    /// buffered.
    fn read_at(&self, blob_id: u64, buf: &mut [u8], logical_offset: u64) -> usize {
        let (page_num, offset_in_page, remaining) = Self::locate(self.page_size, logical_offset);
        let Some(page) = self.get_page(blob_id, page_num) else {
            return 0;
        };
        let page = page.as_ref();

        let bytes_to_copy = std::cmp::min(buf.len(), remaining);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Put the given `page` into the page cache and record its slot hint.
    fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        let page_size: usize = self.page_size.widen();
        assert_eq!(page.len(), page_size);
        let pool = &self.pool;
        let (slot, buf) = self
            .cache
            .get_or_insert_mut((blob_id, page_num), || pool.alloc_zeroed(page_size));
        buf.as_mut().copy_from_slice(page);
        let hint = self.hint_index(blob_id, page_num);
        self.hints[hint] = slot;
    }

    /// The hint slot for `(blob_id, page_num)`: the page number offset by a per-blob salt,
    /// wrapped to the array.
    ///
    /// Adding (rather than hashing in) the page number keeps consecutive pages in consecutive
    /// hint entries, so the sorted batches issued by [CacheRef::read_cached_many] walk the
    /// array sequentially instead of taking a cache miss per lookup. The salt spreads blobs'
    /// ranges apart; two blobs whose ranges still overlap only evict each other's hints, which
    /// [Self::get_page] repairs through the fallback lookup.
    #[inline]
    const fn hint_index(&self, blob_id: u64, page_num: u64) -> usize {
        let salted = page_num.wrapping_add(blob_id.wrapping_mul(commonware_utils::GOLDEN_RATIO));
        (salted & (self.hints.len() as u64 - 1)) as usize
    }

    /// Look up a page, preferring its direct-mapped slot hint over the [cache::Cache]'s own lookup.
    #[inline]
    fn get_page(&self, blob_id: u64, page_num: u64) -> Option<&IoBufMut> {
        let key = (blob_id, page_num);
        let slot = self.hints[self.hint_index(blob_id, page_num)];
        if let Some(page) = self.cache.get_at(slot, &key) {
            return Some(page);
        }
        self.cache.get(&key)
    }

    /// Drop all cached pages while retaining backing page buffers for reuse.
    #[cfg(any(test, feature = "test-utils"))]
    fn clear(&mut self) {
        self.cache.retain(|_, _| false);
        self.page_fetches.clear();
    }
}

/// Fetch one logical page for insertion into the page cache, rejecting partial pages because cache
/// entries must always contain a full logical page.
async fn fetch_cacheable_page(
    blob: &impl Blob,
    page_num: u64,
    page_size: NonZeroU16,
) -> Result<IoBuf, Error> {
    // CacheRef retains the page, so the source page need not remain in the OS page cache.
    let width: u64 = page_size.widen();
    let page = get_page_from_blob(blob, page_num, width, ReadOptions::DONT_CACHE).await?;

    // We should never be fetching partial pages through the page cache. This can happen if a
    // non-last page is corrupted and falls back to a partial CRC.
    let len = page.len();
    let expected: usize = page_size.widen();
    if len != expected {
        error!(
            page_num,
            expected = page_size,
            actual = len,
            "attempted to fetch partial page from blob"
        );
        return Err(Error::InvalidChecksum);
    }

    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::{super::Checksum, *};
    use crate::{
        BufferPool, BufferPoolConfig, Clock as _, Handle, IoBufMut, IoBufs, IoBufsMut, Runner as _,
        Spawner as _, Storage as _, Supervisor as _, WriteOptions, buffer::paged::CHECKSUM_SIZE,
        deterministic, mocks::MigratingReadBlob, telemetry::metrics::Registry,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::{select, test_traced};
    use commonware_utils::{NZU16, NZUsize, channel::oneshot, sync::Mutex};
    use futures::{future::pending, poll};
    use rstest::rstest;
    use std::{
        num::NonZeroU16,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
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
    struct BlockingBlob {
        started: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl Blob for BlockingBlob {
        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.read_at_buf(offset, len, IoBufMut::with_capacity(len), options)
                .await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
            _options: ReadOptions,
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
            _options: WriteOptions,
        ) -> Result<(), Error> {
            Ok(())
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

    enum ControlledBlobResult {
        Success(Vec<u8>),
        Error,
    }

    /// A blob that counts physical reads and can pause a read until released.
    struct ControlledBlob {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        reads: Arc<AtomicUsize>,
        result: ControlledBlobResult,
    }

    impl Blob for ControlledBlob {
        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.read_at_buf(offset, len, IoBufMut::with_capacity(len), options)
                .await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let release = self.release.lock().take();
            if let Some(release) = release {
                let sender = self
                    .started
                    .lock()
                    .take()
                    .expect("controlled blob start signal missing");
                let _ = sender.send(());
                release.await.expect("release signal dropped");
            }

            match &self.result {
                ControlledBlobResult::Success(page) => Ok(IoBufsMut::from(page.clone())),
                ControlledBlobResult::Error => Err(Error::ReadFailed),
            }
        }

        async fn write_at(
            &self,
            _offset: u64,
            _bufs: impl Into<crate::IoBufs> + Send,
            _options: WriteOptions,
        ) -> Result<(), Error> {
            Ok(())
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
    fn test_clear_does_not_orphan_recached_page() {
        // Clearing the cache and reusing its slots must keep each newly cached page readable.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(2));
        let blob_id = 0u64;
        let page_size = PAGE_SIZE.get() as usize;

        // Fill both slots, then clear the cache so both slots are available for reuse.
        cache.cache(blob_id, &vec![0xAA; page_size], 0);
        cache.cache(blob_id, &vec![0xBB; page_size], 1);
        cache.clear();

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
            let blob = Arc::new(blob);
            for i in 0..11 {
                // Write logical data followed by Checksum.
                let logical_data = vec![i as u8; PAGE_SIZE.get() as usize];
                let crc = Crc32::checksum(&logical_data);
                let record = Checksum::new(PAGE_SIZE.get(), crc);
                let mut page_data = logical_data;
                page_data.extend_from_slice(&record.to_bytes());
                blob.write_at(i * physical_page_size, page_data, WriteOptions::default())
                    .await
                    .unwrap();
            }

            // Fill the page cache with the blob's data through miss completion.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));
            assert_eq!(cache_ref.next_id(), 0);
            assert_eq!(cache_ref.next_id(), 1);
            for i in 0..11 {
                // Read expects logical bytes only (CRCs are stripped).
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                cache_ref
                    .read_after_miss(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }

            // Repeat the read to exercise reading from the page cache. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let mut buf = vec![0; PAGE_SIZE.get() as usize];
                cache_ref
                    .read_after_miss(&blob, 0, &mut buf, i * PAGE_SIZE_U64)
                    .await
                    .unwrap();
                assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
            }

            // Cleanup.
            blob.sync().await.unwrap();
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default(), false)]
    #[case::tokio(crate::tokio::Runner::default(), false)]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default(), true)
    )]
    fn test_page_fetch_migrates_between_dedicated_workers<R: crate::Runner>(
        #[case] runner: R,
        #[case] require_pending: bool,
    ) where
        R::Context: crate::BufferPooler + crate::Clock + crate::Spawner + crate::Storage,
    {
        runner.start(|context| async move {
            // Build a valid checksummed page in the runtime's real storage backend.
            let logical_page = vec![7u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_page);
            let mut physical_page = logical_page.clone();
            physical_page.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc).to_bytes());

            let partition = "cache_page_fetch_migration";
            let (blob, size) = context.open(partition, b"blob").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, physical_page, WriteOptions::default())
                .await
                .unwrap();

            // Count reads beneath an empty cache so duplicate physical misses remain observable.
            let blob = Arc::new(MigratingReadBlob::new(blob, require_pending));
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let blob_id = cache_ref.next_id();

            // The source polls its cache read once and then stays alive without repolling it. Once
            // that poll has fully unwound, the destination joins and solely drives the shared fetch
            // to completion before the source is released.
            let concurrent_reads = async {
                let (source_polled_tx, source_polled_rx) = oneshot::channel();
                let (source_release_tx, source_release_rx) = oneshot::channel();
                let first_cache = cache_ref.clone();
                let first_blob = blob.clone();
                let first = context.child("first").dedicated().spawn(move |_| async move {
                    let mut buf = vec![0; PAGE_SIZE.get() as usize];
                    let mut read = Box::pin(first_cache.read_after_miss(
                        &first_blob,
                        blob_id,
                        &mut buf,
                        0,
                    ));

                    // Publish the handoff only after Shared has released its polling lock, then
                    // park on an unrelated signal so source wakeups cannot repoll the cache read.
                    assert!(poll!(&mut read).is_pending());
                    source_polled_tx
                        .send(())
                        .expect("source poll receiver dropped");
                    source_release_rx
                        .await
                        .expect("source release signal dropped");
                    read.await.unwrap();
                    buf
                });
                source_polled_rx
                    .await
                    .expect("source cache poll never completed");

                // Join the installed PageFetch from a second worker, which becomes its only active
                // poller while the source remains parked.
                let second_cache = cache_ref.clone();
                let second_blob = blob.clone();
                let second = context
                    .child("second")
                    .dedicated()
                    .spawn(move |_| async move {
                        let mut buf = vec![0; PAGE_SIZE.get() as usize];
                        second_cache
                            .read_after_miss(&second_blob, blob_id, &mut buf, 0)
                            .await
                            .unwrap();
                        buf
                    });

                // Release the source only after the destination completes the shared fetch.
                let second_buf = second.await.unwrap();
                source_release_tx
                    .send(())
                    .expect("source worker exited before release");
                (first.await.unwrap(), second_buf)
            };

            // Bound the coordination independently of either worker so a lost migration wakeup
            // fails instead of leaving the runtime parked indefinitely.
            let (first_buf, second_buf) = select! {
                result = concurrent_reads => result,
                _ = context.sleep(Duration::from_secs(10)) => panic!("concurrent page fetch timed out"),
            };

            // Both waiters must receive the validated logical page from one physical backend read.
            assert_eq!(first_buf, logical_page);
            assert_eq!(second_buf, logical_page);
            assert_eq!(blob.reads(), 1);
            context.remove(partition, None).await.unwrap();
        });
    }

    #[test_traced]
    fn test_cache_clear_forces_uncached_blob_read() {
        struct CountingBlob {
            reads: AtomicUsize,
            read_options: Mutex<Vec<ReadOptions>>,
            page: Vec<u8>,
        }

        impl Blob for CountingBlob {
            async fn read_at(
                &self,
                offset: u64,
                len: usize,
                options: ReadOptions,
            ) -> Result<IoBufsMut, Error> {
                self.read_at_buf(offset, len, IoBufsMut::default(), options)
                    .await
            }

            async fn read_at_buf(
                &self,
                _offset: u64,
                _len: usize,
                _bufs: impl Into<IoBufsMut> + Send,
                options: ReadOptions,
            ) -> Result<IoBufsMut, Error> {
                self.reads.fetch_add(1, Ordering::Relaxed);
                self.read_options.lock().push(options);
                Ok(IoBufsMut::from(self.page.clone()))
            }

            async fn write_at(
                &self,
                _offset: u64,
                _bufs: impl Into<IoBufs> + Send,
                _options: WriteOptions,
            ) -> Result<(), Error> {
                Ok(())
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

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let page = vec![7u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&page);
            let record = Checksum::new(PAGE_SIZE.get(), crc);
            let mut physical_page = page.clone();
            physical_page.extend_from_slice(&record.to_bytes());
            let blob = Arc::new(CountingBlob {
                reads: AtomicUsize::new(0),
                read_options: Mutex::new(Vec::new()),
                page: physical_page,
            });
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));

            let mut buf = vec![0u8; page.len()];
            cache_ref
                .read_after_miss(&blob, 0, &mut buf, 0)
                .await
                .unwrap();
            assert_eq!(buf, page);
            assert_eq!(blob.reads.load(Ordering::Relaxed), 1);

            let mut buf = vec![0u8; page.len()];
            cache_ref
                .read_after_miss(&blob, 0, &mut buf, 0)
                .await
                .unwrap();
            assert_eq!(buf, page);
            assert_eq!(blob.reads.load(Ordering::Relaxed), 1);

            cache_ref.clear();

            let mut buf = vec![0u8; page.len()];
            cache_ref
                .read_after_miss(&blob, 0, &mut buf, 0)
                .await
                .unwrap();
            assert_eq!(buf, page);
            assert_eq!(blob.reads.load(Ordering::Relaxed), 2);
            assert_eq!(
                *blob.read_options.lock(),
                vec![ReadOptions::DONT_CACHE, ReadOptions::DONT_CACHE]
            );
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
            let (page_num, _) = cache_ref.offset_to_page(aligned_max_offset);
            let page_cache = cache_ref.test_shard(0, page_num).read();
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
            let (page_num, _) = cache_ref.offset_to_page(high_offset);
            let page_cache = cache_ref.test_shard(0, page_num).read();
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
            let blob = Arc::new(BlockingBlob {
                started: Mutex::new(Some(started_tx)),
            });
            let mut read_buf = vec![0u8; PAGE_SIZE.get() as usize];

            // Spawn the first fetcher. It will insert into `page_fetches` and then block forever.
            let cache_ref_for_task = cache_ref.clone();
            let blob_for_task = blob.clone();
            let handle = context.spawn(move |_| async move {
                let _ = cache_ref_for_task
                    .read_after_miss(&blob_for_task, blob_id, &mut read_buf, 0)
                    .await;
            });

            // Wait until the underlying read has started, ensuring the in-flight marker exists.
            started_rx.await.expect("blocking read never started");
            {
                let page_cache = cache_ref.test_shard(blob_id, 0).read();
                assert!(page_cache.page_fetches.contains_key(&(blob_id, 0)));
            }

            // Cancel the first fetcher before it reaches explicit cleanup.
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));

            // The guard drop path should have removed the stale in-flight entry.
            let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
            let blob = Arc::new(ControlledBlob {
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(Some(release_rx)),
                reads: reads.clone(),
                result: ControlledBlobResult::Success(physical_page),
            });

            // Start the fetch that installs the shared in-flight entry.
            let mut first_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.child("first").spawn(move |_| async move {
                let _ = cache_ref_for_first
                    .read_after_miss(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await;
            });
            started_rx.await.expect("first read never started");

            // Join as a follower while the first fetch is still blocked in the blob.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.child("second").spawn(move |_| async move {
                cache_ref_for_second
                    .read_after_miss(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
                    .expect("second read failed");
                second_buf
            });

            // Wait until both tasks are registered against the same in-flight fetch.
            loop {
                let joined = {
                    let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
                    .read_after_miss(&blob_for_third, blob_id, &mut third_buf, 0)
                    .await
                    .expect("third read failed");
                third_buf
            });

            // Either the third reader bumps the waiter count back to 2, or a bug starts a second
            // blob read.
            loop {
                let third_entered = {
                    let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
                .read_after_miss(&blob, blob_id, &mut fourth_buf, 0)
                .await
                .unwrap();
            assert_eq!(fourth_buf, logical_page);
            assert_eq!(reads.load(Ordering::Relaxed), 1);

            let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
            let blob = Arc::new(ControlledBlob {
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(Some(release_rx)),
                reads: reads.clone(),
                result: ControlledBlobResult::Error,
            });

            // Start the fetch that creates the in-flight entry.
            let mut first_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.child("first").spawn(move |_| async move {
                cache_ref_for_first
                    .read_after_miss(&blob_for_first, blob_id, &mut first_buf, 0)
                    .await
            });
            started_rx.await.expect("first erroring read never started");

            // Join with a second waiter that should observe the same failure.
            let mut second_buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.child("second").spawn(move |_| async move {
                cache_ref_for_second
                    .read_after_miss(&blob_for_second, blob_id, &mut second_buf, 0)
                    .await
            });

            // Wait until both tasks share the same in-flight fetch entry.
            loop {
                let joined = {
                    let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
                let page_cache = cache_ref.test_shard(blob_id, 0).read();
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
                cache_ref
                    .read_after_miss(&blob, blob_id, &mut third_buf, 0)
                    .await,
                Err(Error::ReadFailed)
            ));
            assert_eq!(reads.load(Ordering::Relaxed), 2);
        });
    }

    #[test_traced]
    fn test_cancelled_stale_waiter_preserves_new_fetch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = Arc::new(ControlledBlob {
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(Some(release_rx)),
                reads: reads.clone(),
                result: ControlledBlobResult::Error,
            });

            // Keep the follower suspended while another waiter completes the failed fetch.
            let mut first_buf = vec![0; PAGE_SIZE.get() as usize];
            let mut first = Box::pin(cache_ref.read_after_miss(&blob, blob_id, &mut first_buf, 0));
            assert!(poll!(&mut first).is_pending());
            started_rx.await.unwrap();
            let mut stale_buf = vec![0; PAGE_SIZE.get() as usize];
            let mut stale = Box::pin(cache_ref.read_after_miss(&blob, blob_id, &mut stale_buf, 0));
            assert!(poll!(&mut stale).is_pending());
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            release_tx.send(()).unwrap();
            assert!(matches!(first.await, Err(Error::ReadFailed)));

            // A retry may start before the suspended follower consumes the old result.
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            *blob.started.lock() = Some(started_tx);
            *blob.release.lock() = Some(release_rx);
            let mut retry_buf = vec![0; PAGE_SIZE.get() as usize];
            let mut retry = Box::pin(cache_ref.read_after_miss(&blob, blob_id, &mut retry_buf, 0));
            assert!(poll!(&mut retry).is_pending());
            started_rx.await.unwrap();
            assert_eq!(reads.load(Ordering::Relaxed), 2);

            // Cancelling the old follower must leave the retry available for new readers to join.
            drop(stale);
            let mut joined_buf = vec![0; PAGE_SIZE.get() as usize];
            let mut joined =
                Box::pin(cache_ref.read_after_miss(&blob, blob_id, &mut joined_buf, 0));
            assert!(poll!(&mut joined).is_pending());
            assert_eq!(reads.load(Ordering::Relaxed), 2);
            release_tx.send(()).unwrap();
            assert!(matches!(retry.await, Err(Error::ReadFailed)));
            assert!(matches!(joined.await, Err(Error::ReadFailed)));
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
        {
            let mut cache = cache_ref.test_shard(blob_id, 0).write();
            cache.cache(blob_id, &page0, 0);
            cache.cache(blob_id, &page1, 1);
        }

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
    fn test_read_cached_many_resumes_after_evicted_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(3));
            let blob_id = cache_ref.next_id();
            let page_size = PAGE_SIZE.get() as usize;
            cache_ref.cache(blob_id, &vec![0x11; page_size], 0);
            cache_ref.cache(blob_id, &vec![0x22; page_size], PAGE_SIZE_U64);

            let mut buf = vec![0; page_size + 8];
            let mut ranges = vec![(buf.as_mut_slice(), PAGE_SIZE_U64 - 3)];
            cache_ref.read_cached_many(blob_id, &mut ranges);
            assert_eq!(ranges.len(), 1);
            assert_eq!(ranges[0].1, PAGE_SIZE_U64 * 2);
            assert_eq!(ranges[0].0.len(), 5);

            // The destination owns copied bytes even after their source pages are evicted.
            cache_ref.clear();
            let mut physical_page = vec![0x33; page_size];
            let crc = Crc32::checksum(&physical_page);
            physical_page.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc).to_bytes());
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = Arc::new(ControlledBlob {
                started: Mutex::new(None),
                release: Mutex::new(None),
                reads: reads.clone(),
                result: ControlledBlobResult::Success(physical_page),
            });
            for (remaining, offset) in ranges {
                cache_ref
                    .read_after_miss(&blob, blob_id, remaining, offset)
                    .await
                    .unwrap();
            }
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            assert_eq!(&buf[..3], &[0x11; 3]);
            assert!(buf[3..3 + page_size].iter().all(|&byte| byte == 0x22));
            assert_eq!(&buf[3 + page_size..], &[0x33; 5]);
        });
    }

    #[test_traced]
    fn test_observed_miss_filled_before_completion() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let blob_id = cache_ref.next_id();
            let mut buf = [0; 8];
            assert_eq!(cache_ref.read_cached(blob_id, &mut buf, 3), 0);
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = Arc::new(ControlledBlob {
                started: Mutex::new(None),
                release: Mutex::new(None),
                reads: reads.clone(),
                result: ControlledBlobResult::Error,
            });

            // Another reader may populate the page before the completion future is polled.
            let completion = cache_ref.read_after_miss(&blob, blob_id, &mut buf, 3);
            cache_ref.cache(blob_id, &vec![0x44; PAGE_SIZE.get() as usize], 0);
            completion.await.unwrap();
            assert_eq!(reads.load(Ordering::Relaxed), 0);
            assert_eq!(buf, [0x44; 8]);
        });
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
        {
            let mut cache = cache_ref.test_shard(blob_id, 0).write();
            cache.cache(blob_id, &page0, 0);
            // page 1 deliberately not cached
            cache.cache(blob_id, &page2, 2);
        }

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

    #[test_traced]
    fn test_read_cached_many_stale_hint_after_eviction() {
        // Insert one page past capacity so page 0 is evicted and its slot is reused for page 2.
        // Page 0's hint now points at a slot holding page 2's key, so the batched read must report
        // page 0 as a miss (never page 2's bytes) while still serving the live pages.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(2));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        {
            let mut cache = cache_ref.test_shard(blob_id, 0).write();
            for page in 0u64..3 {
                cache.cache(blob_id, &vec![page as u8 + 1; page_size], page);
            }
        }

        let mut bufs: Vec<Vec<u8>> = (0..3).map(|_| vec![0u8; page_size]).collect();
        let mut iter = bufs.iter_mut();
        let mut ranges: Vec<(&mut [u8], u64)> = (0..3u64)
            .map(|page| (iter.next().unwrap().as_mut_slice(), page * PAGE_SIZE_U64))
            .collect();
        cache_ref.read_cached_many(blob_id, &mut ranges);

        // Page 0 was evicted: it must be the one remaining miss, untouched.
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, 0);
        drop(ranges);
        assert!(bufs[0].iter().all(|b| *b == 0));
        assert_eq!(bufs[1], vec![2u8; page_size]);
        assert_eq!(bufs[2], vec![3u8; page_size]);
    }

    #[test_traced]
    fn test_read_cached_many_cross_blob_hint_collision() {
        // Two blobs whose salted ranges overlap share a hint entry, and the later insert
        // overwrites the earlier blob's hint. The hint only proposes a [cache::Cache] slot.
        // [cache::Cache::get_at] validates the full (blob, page) key, so each blob reads back its
        // own bytes (the clobbered one through the fallback lookup), never the other's.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(4));
        let blob_a = cache_ref.next_id();
        let blob_b = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        let page_a = 5u64;
        let page_b = {
            // Capacity 4 collapses to one shard, so any (blob, page) resolves to it.
            let mut cache = cache_ref.test_shard(blob_a, page_a).write();

            // Solve hint_index(blob_b, page_b) == hint_index(blob_a, page_a) for page_b.
            let mask = cache.hints.len() as u64 - 1;
            let page_b = page_a
                .wrapping_add(blob_a.wrapping_mul(commonware_utils::GOLDEN_RATIO))
                .wrapping_sub(blob_b.wrapping_mul(commonware_utils::GOLDEN_RATIO))
                & mask;
            assert_eq!(
                cache.hint_index(blob_a, page_a),
                cache.hint_index(blob_b, page_b)
            );
            cache.cache(blob_a, &vec![0xAA; page_size], page_a);
            cache.cache(blob_b, &vec![0xBB; page_size], page_b);
            page_b
        };

        for (blob, page, byte) in [(blob_a, page_a, 0xAAu8), (blob_b, page_b, 0xBB)] {
            let mut buf = vec![0u8; page_size];
            let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf, page * PAGE_SIZE_U64)];
            cache_ref.read_cached_many(blob, &mut ranges);
            assert!(
                ranges.is_empty(),
                "blob {blob} page {page} should be cached"
            );
            drop(ranges);
            assert_eq!(buf, vec![byte; page_size]);
        }
    }

    #[test_traced]
    fn test_read_cached_many_sparse_page_number_keeps_hints_fixed() {
        // Hint memory is fixed at construction: caching at an extreme page number must not
        // grow any structure, and the page is still served through the hint path.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(2));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        let page_num = u64::MAX / PAGE_SIZE_U64 - 1;
        {
            let mut cache = cache_ref.test_shard(blob_id, 0).write();
            let hints = cache.hints.len();
            cache.cache(blob_id, &vec![0x5A; page_size], page_num);
            assert_eq!(cache.hints.len(), hints);
        }

        let mut buf = vec![0u8; page_size];
        let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf, page_num * PAGE_SIZE_U64)];
        cache_ref.read_cached_many(blob_id, &mut ranges);
        assert!(ranges.is_empty());
        drop(ranges);
        assert_eq!(buf, vec![0x5A; page_size]);
    }

    #[test_traced]
    fn test_read_cached_many_evicted_page_is_a_miss() {
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(1));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        let read_page = |page: u64| {
            let mut buf = vec![0u8; page_size];
            let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf, page * PAGE_SIZE_U64)];
            cache_ref.read_cached_many(blob_id, &mut ranges);
            let hit = ranges.is_empty();
            drop(ranges);
            hit.then_some(buf)
        };

        cache_ref.cache(blob_id, &vec![1; page_size], 0);
        assert_eq!(read_page(0), Some(vec![1; page_size]));

        // The one-page cache must evict page zero when page one arrives.
        cache_ref.cache(blob_id, &vec![2; page_size], PAGE_SIZE_U64);
        assert_eq!(read_page(0), None);
        assert_eq!(read_page(1), Some(vec![2; page_size]));

        // A reused slot must expose the replacement bytes through the hint path.
        cache_ref.cache(blob_id, &vec![0xCC; page_size], 0);
        assert_eq!(read_page(0), Some(vec![0xCC; page_size]));
        assert_eq!(read_page(1), None);
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

        {
            let mut cache = cache_ref.test_shard(blob_id, 0).write();
            for page in cached_pages {
                // Use a distinct byte per page so cross-page reads prove both halves were copied.
                cache.cache(blob_id, &vec![page as u8 + 1; page_size], page);
            }
        }

        let mut buf = vec![sentinel; len];
        let count = cache_ref.read_cached(blob_id, &mut buf, logical_offset);
        assert_eq!(count, expected_count);

        // The satisfied prefix holds cached bytes; everything past the first fault is untouched.
        assert_eq!(buf[..count], expected_cached_bytes(logical_offset, count));
        assert!(buf[count..].iter().all(|b| *b == sentinel));
    }
    #[test_traced]
    fn test_multi_shard_block_boundary_reads() {
        // Capacity 256 yields 16 shards (8-page blocks). Cache a contiguous run of pages
        // spanning several shard blocks through the write-through path, then read ranges
        // that cross block boundaries through both read paths: the guard hand-off and the
        // per-shard batch pass with its crossing-range post-pass.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(256));
        assert_eq!(cache_ref.shards.len(), 16);
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;

        // 32 pages = 4 shard blocks, distinct fill per page.
        let mut data = Vec::with_capacity(32 * page_size);
        for page in 0u8..32 {
            data.extend(std::iter::repeat_n(page + 1, page_size));
        }
        assert_eq!(cache_ref.cache(blob_id, &data, 0), 0);

        // Single read spanning all four blocks (three shard hand-offs).
        let mut buf = vec![0u8; 32 * page_size];
        assert_eq!(cache_ref.read_cached(blob_id, &mut buf, 0), buf.len());
        assert_eq!(buf, data);

        // Batched ranges, each crossing a block boundary (pages 7..9, 15..17, 23..25).
        let mut bufs = vec![vec![0u8; 2 * page_size]; 3];
        let mut iter = bufs.iter_mut();
        let mut ranges: Vec<(&mut [u8], u64)> = [7u64, 15, 23]
            .iter()
            .map(|&page| {
                (
                    iter.next().expect("buffer per range").as_mut_slice(),
                    page * PAGE_SIZE_U64,
                )
            })
            .collect();
        cache_ref.read_cached_many(blob_id, &mut ranges);
        assert!(ranges.is_empty(), "all crossing ranges should be cached");
        for (i, &page) in [7usize, 15, 23].iter().enumerate() {
            assert_eq!(
                &bufs[i][..page_size],
                &data[page * page_size..][..page_size]
            );
            assert_eq!(
                &bufs[i][page_size..],
                &data[(page + 1) * page_size..][..page_size]
            );
        }
    }

    #[test_traced]
    fn test_multi_shard_crossing_range_keeps_unread_suffix() {
        // A batched range that crosses into another shard and then misses keeps only its
        // unread suffix, with the prefix from both shards already copied.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(256));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;

        // Cache pages 7 and 8 (different shard blocks) but not page 9.
        let mut data = Vec::with_capacity(2 * page_size);
        for page in 7u8..9 {
            data.extend(std::iter::repeat_n(page + 1, page_size));
        }
        let aligned = 7 * PAGE_SIZE_U64;
        assert_eq!(cache_ref.cache(blob_id, &data, aligned), 0);
        assert_ne!(
            cache_ref.shard(blob_id, 7),
            cache_ref.shard(blob_id, 8),
            "pages 7 and 8 must be in different shards"
        );

        let mut buf = vec![0u8; 3 * page_size];
        let mut ranges: Vec<(&mut [u8], u64)> = vec![(buf.as_mut_slice(), aligned)];
        cache_ref.read_cached_many(blob_id, &mut ranges);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].1, 9 * PAGE_SIZE_U64);
        assert_eq!(ranges[0].0.len(), page_size);
        drop(ranges);
        assert_eq!(&buf[..2 * page_size], data.as_slice());
    }
}

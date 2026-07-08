//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.

use super::{buf::PagedBuf, get_page_from_blob};
use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufMut};
use ahash::AHashMap;
use commonware_codec::Read as CodecRead;
use commonware_utils::{cache::Clock, sync::RwLock};
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

/// Target number of bytes decoded per page-cache read-lock acquisition in
/// [CacheRef::decode_cached_exact_many]. Each acquisition covers at least one item, so a single
/// item larger than this still decodes under one acquisition. Bounding hold time by bytes
/// rather than item count keeps writers from being held off for long stretches when items are
/// large.
const DECODE_BATCH_BYTES: usize = 8192;

/// Result of attempting to decode a value from cached pages.
pub(super) enum CachedDecode<T> {
    /// Decoded successfully from resident bytes. The second field is the number of bytes
    /// consumed.
    Decoded(T, usize),
    /// The required bytes were fully resident but malformed.
    Invalid(commonware_codec::Error),
    /// Not enough resident bytes to attempt or finish the decode.
    Missing,
}

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
/// Eviction is delegated to a [Clock], which uses the Clock (second-chance) replacement
/// policy, a lightweight approximation of LRU. All page buffers are pre-allocated from `pool` at
/// construction (via [Clock::prefill]) and reused in place, so caching never allocates after
/// construction.
///
/// Reads first resolve pages through `hints`, a fixed-size direct-mapped array from
/// [Self::hint_index] to the [Clock] slot the page was last cached in: a lookup is one array
/// load instead of a hash-table probe chain, which the out-of-order core cannot overlap across
/// items. Hints are best-effort, never truth: [Clock::get_at] only resolves a slot that still
/// holds the page's key live, so entries staled by eviction, invalidation, or hint collisions
/// read as misses and fall back to the [Clock]'s own lookup. Hints need no maintenance on
/// eviction or invalidation, and their memory is fixed at construction, so no blob offset can
/// grow them.
struct Cache {
    /// Maps each (blob id, page number) to its logical page buffer.
    cache: Clock<(u64, u64), IoBufMut>,

    /// Direct-mapped [Clock] slot hints, indexed by [Self::hint_index]. Initialized
    /// out-of-range so untouched entries read as misses. The length is a power of two so
    /// [Self::hint_index] can wrap with a mask instead of a division, and at least twice the
    /// cache capacity: a full cache has one live page per `capacity`, so sizing at capacity
    /// makes hint collisions (and their slower fallback lookups) common.
    hints: Vec<usize>,

    /// Size of each page in bytes.
    page_size: usize,

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
    /// Each element of `ranges` is `(dest_slice, logical_offset)`. Fully-cached ranges have
    /// their data written to the destination slice and are removed from `ranges`. Entries left
    /// in `ranges` correspond to cache misses that the caller must read from the underlying
    /// blob.
    pub(super) fn read_cached_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>) {
        let page_cache = self.cache.read();
        let page_size = page_cache.page_size;

        // Resolve every range's first page before copying any data. The lookups are
        // independent, so batching them lets the core overlap their memory latency instead of
        // stalling each lookup behind the previous range's copy.
        let mut srcs: Vec<Option<&[u8]>> = Vec::with_capacity(ranges.len());
        for (buf, offset) in ranges.iter() {
            let (page_num, offset_in_page) = Cache::offset_to_page(page_size as u64, *offset);
            let offset_in_page = offset_in_page as usize;
            let seg = std::cmp::min(buf.len(), page_size - offset_in_page);
            srcs.push(
                page_cache
                    .get_page(blob_id, page_num)
                    .map(|page| &page.as_ref()[offset_in_page..offset_in_page + seg]),
            );
        }

        // Copy resolved pages, dropping fully-cached ranges and keeping misses. A range whose
        // first page missed is kept untouched, and one that continues past its first page reads
        // the rest page by page, staying a miss if any later page faults.
        let mut next = 0;
        ranges.retain_mut(|(buf, offset)| {
            let src = srcs[next];
            next += 1;
            if buf.is_empty() {
                return false;
            }
            let Some(src) = src else {
                return true;
            };
            buf[..src.len()].copy_from_slice(src);
            let mut done = src.len();
            while done < buf.len() {
                let count = page_cache.read_at(blob_id, &mut buf[done..], *offset + done as u64);
                if count == 0 {
                    return true;
                }
                done += count;
            }
            false
        });
    }

    /// Decode a `T` from the resident prefix of the window starting at `offset`, letting the
    /// decoder consume at most `max_len` bytes. The window's first `cached_len` bytes come from
    /// cached pages and the following `tail.len()` bytes are supplied by the caller (the
    /// in-memory bytes immediately after the cached region). Callers must ensure
    /// `cached_len + tail.len()` does not exceed `max_len` (smaller only when the window was
    /// clamped to the blob's logical size). The decode runs under the page-cache read lock with
    /// zero copies, so `T::read_cfg` must be cheap and parse-only.
    #[inline]
    pub(super) fn decode_cached_prefix<T: CodecRead>(
        &self,
        blob_id: u64,
        offset: u64,
        cached_len: usize,
        tail: &[u8],
        max_len: usize,
        cfg: &T::Cfg,
    ) -> CachedDecode<T> {
        self.cache
            .read()
            .decode_prefix(blob_id, offset, cached_len, tail, max_len, cfg)
    }

    /// Like [Self::decode_cached_prefix] but requires the encoding to occupy exactly
    /// `cached_len + tail.len()` bytes.
    #[inline]
    pub(super) fn decode_cached_exact<T: CodecRead>(
        &self,
        blob_id: u64,
        offset: u64,
        cached_len: usize,
        tail: &[u8],
        cfg: &T::Cfg,
    ) -> CachedDecode<T> {
        self.cache
            .read()
            .decode_exact(blob_id, offset, cached_len, tail, cfg)
    }

    /// Decode multiple items of exactly `len` bytes each at the given offsets for `blob_id`,
    /// without performing I/O. For each offset, pushes `Some(item)` on success or `None` when the
    /// item's bytes are not fully resident. Returns an error only when resident bytes are
    /// malformed. In that case `out` may contain fewer than `offsets.len()` new entries and must
    /// be discarded.
    ///
    /// The page-cache read lock is taken once per chunk of offsets rather than once per item,
    /// amortizing lock acquisition while bounding hold time.
    pub(super) fn decode_cached_exact_many<T: CodecRead>(
        &self,
        blob_id: u64,
        offsets: &[u64],
        len: usize,
        cfg: &T::Cfg,
        out: &mut Vec<Option<T>>,
    ) -> Result<(), commonware_codec::Error> {
        let chunk_size = (DECODE_BATCH_BYTES / len.max(1)).max(1);
        for chunk in offsets.chunks(chunk_size) {
            let cache = self.cache.read();

            // Resolve every item's page slice before decoding any of them. The lookups are
            // independent, so batching them lets the core overlap their memory latency
            // instead of stalling each lookup behind the previous item's decode.
            let mut srcs: Vec<Option<&[u8]>> = Vec::with_capacity(chunk.len());
            for &offset in chunk {
                srcs.push(cache.resident_in_page(blob_id, offset, len));
            }

            for (src, &offset) in srcs.iter().zip(chunk) {
                match src {
                    // The entire encoding lies within the resolved page, so it decodes from
                    // the contiguous slice and every outcome is authoritative (mirroring
                    // [Cache::decode_exact]'s fast path).
                    Some(slice) if slice.len() == len => {
                        let mut buf = *slice;
                        match T::read_cfg(&mut buf, cfg) {
                            Ok(value) if buf.is_empty() => out.push(Some(value)),
                            Ok(_) => {
                                return Err(commonware_codec::Error::ExtraData(buf.len()));
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    // The item continues past the resolved page, so assemble the full
                    // multi-page window.
                    Some(_) => match cache.decode_exact::<T>(blob_id, offset, len, &[], cfg) {
                        CachedDecode::Decoded(value, _) => out.push(Some(value)),
                        CachedDecode::Missing => out.push(None),
                        CachedDecode::Invalid(err) => return Err(err),
                    },
                    None => out.push(None),
                }
            }
        }
        Ok(())
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

    /// Drop any cached pages for `blob_id` at `page_num >= start_page`. Used after a blob is
    /// truncated so subsequent reads can't observe pre-truncation bytes in a page that the tip
    /// buffer (or future writes) now owns.
    pub(super) fn invalidate_from(&self, blob_id: u64, start_page: u64) {
        self.cache.write().invalidate_from(blob_id, start_page);
    }
}

impl Cache {
    /// Return a new empty page cache with a max cache capacity of `capacity` pages, each of size
    /// `page_size` bytes.
    pub fn new(pool: BufferPool, page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size = page_size.get() as usize;
        let mut cache = Clock::new(capacity);
        cache.prefill(|| pool.alloc_zeroed(page_size));
        let hints = capacity.get().saturating_mul(2).next_power_of_two();
        Self {
            cache,
            hints: vec![usize::MAX; hints],
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
        let Some(page) = self.get_page(blob_id, page_num) else {
            return 0;
        };
        let page = page.as_ref();

        let offset_in_page = offset_in_page as usize;
        let bytes_to_copy = std::cmp::min(buf.len(), self.page_size - offset_in_page);
        buf[..bytes_to_copy].copy_from_slice(&page[offset_in_page..offset_in_page + bytes_to_copy]);

        bytes_to_copy
    }

    /// Gather the resident contiguous prefix of `[offset, offset + max_len)` for `blob_id` as
    /// borrowed slices, marking every touched page as referenced. Stops at `max_len`, at the
    /// first non-resident page, at the [super::buf::MAX_GATHER_PAGES] cap, or at a page-number
    /// overflow. The returned buffer's `truncated` flag is set in all but the first case.
    ///
    /// The returned buffer borrows the cache's slot buffers, so the caller must hold its read
    /// guard for the lifetime of the buffer. Slots are only mutated under the cache write lock,
    /// which keeps the borrowed bytes stable.
    fn gather(&self, blob_id: u64, offset: u64, max_len: usize) -> PagedBuf<'_> {
        let mut buf = PagedBuf::new();
        if max_len == 0 {
            return buf;
        }
        let (mut page_num, offset_in_page) = Self::offset_to_page(self.page_size as u64, offset);
        let mut start = offset_in_page as usize;
        let mut gathered = 0;
        loop {
            let Some(page) = self.get_page(blob_id, page_num) else {
                buf.set_truncated();
                return buf;
            };
            let page = page.as_ref();

            let end = self.page_size.min(start.saturating_add(max_len - gathered));
            if !buf.push(&page[start..end]) {
                buf.set_truncated();
                return buf;
            }
            gathered += end - start;
            if gathered == max_len {
                return buf;
            }
            start = 0;
            page_num = match page_num.checked_add(1) {
                Some(next) => next,
                None => {
                    buf.set_truncated();
                    return buf;
                }
            };
        }
    }

    /// Returns the resident page slice for `[offset, offset + want)` clamped to the page end,
    /// marking the page as referenced. Returns `None` if the page is not resident.
    #[inline]
    fn resident_in_page(&self, blob_id: u64, offset: u64, want: usize) -> Option<&[u8]> {
        let (page_num, offset_in_page) = Self::offset_to_page(self.page_size as u64, offset);
        let page = self.get_page(blob_id, page_num)?.as_ref();
        let start = offset_in_page as usize;
        let end = self.page_size.min(start.saturating_add(want));
        Some(&page[start..end])
    }

    /// Gather the resident prefix of the window starting at `offset` whose first `cached_len`
    /// bytes live in pages and whose following `tail.len()` bytes are supplied by the caller.
    /// The tail is appended only when every cached byte was gathered, preserving contiguity.
    fn gather_with_tail<'a>(
        &'a self,
        blob_id: u64,
        offset: u64,
        cached_len: usize,
        tail: &'a [u8],
    ) -> PagedBuf<'a> {
        let mut buf = self.gather(blob_id, offset, cached_len);
        if !buf.truncated() && !tail.is_empty() && !buf.push(tail) {
            buf.set_truncated();
        }
        buf
    }

    /// Decode a `T` from the resident prefix of the window starting at `offset`, letting the
    /// decoder consume at most `max_len` bytes. The window's first `cached_len` bytes come from
    /// cached pages and the following `tail.len()` bytes are supplied by the caller;
    /// `cached_len + tail.len()` is at most `max_len` (smaller only when the caller clamped the
    /// window to the blob's logical size).
    ///
    /// Soundness of decoding from a possibly-truncated gather: the cache only ever stores full
    /// logical pages ([Self::cache] asserts `page.len() == page_size`, `fetch_cacheable_page`
    /// rejects partial pages, and [Self::invalidate_from] drops pages at and beyond a truncation
    /// point on resize). Every byte reachable through [Self::gather] is therefore a committed
    /// logical byte of the blob, and the page overlapping the in-memory tail is never resident,
    /// so gathering naturally stops at the cached/tail boundary (where the caller-provided
    /// `tail` bytes resume, appended only after a complete gather). A successful decode within
    /// the gathered prefix is thus valid even if gathering was truncated, PROVIDED two caller
    /// obligations hold. First, the decoder must be driven solely by the bytes it consumes: one
    /// whose result depends on `remaining()` would observe a residency-dependent window rather
    /// than the requested range (documented on the public prefix API). Second, resizes must be
    /// serialized against synchronous decodes, since a decode between a blob truncation and the
    /// cache invalidation could otherwise serve pre-resize bytes (the exclusive borrow on
    /// `Writer::resize` enforces this at compile time).
    #[inline]
    fn decode_prefix<T: CodecRead>(
        &self,
        blob_id: u64,
        offset: u64,
        cached_len: usize,
        tail: &[u8],
        max_len: usize,
        cfg: &T::Cfg,
    ) -> CachedDecode<T> {
        if max_len == 0 || cached_len + tail.len() == 0 {
            return CachedDecode::Missing;
        }

        // Fast path: most items lie within a single page, where decoding from the contiguous
        // slice avoids assembling a multi-slice view. This runs even when a tail is pending
        // (the in-page slice is a prefix of the window either way, so a success over it is
        // authoritative for consume-driven decoders), keeping items that parse within their
        // first page from paying a full multi-page gather.
        let mut in_page = 0;
        if cached_len > 0 {
            let Some(slice) = self.resident_in_page(blob_id, offset, cached_len) else {
                return CachedDecode::Missing;
            };
            in_page = slice.len();
            let mut buf = slice;
            match T::read_cfg(&mut buf, cfg) {
                Ok(value) => return CachedDecode::Decoded(value, in_page - buf.len()),
                // The whole requested range was available, so the failure is authoritative.
                Err(err) if in_page == max_len => return CachedDecode::Invalid(err),
                // The decode may have needed bytes from a following page or the tail, so
                // retry below with the gathered multi-slice view.
                Err(_) => {}
            }
        }

        let mut buf = self.gather_with_tail(blob_id, offset, cached_len, tail);
        assert!(
            buf.len() >= in_page,
            "gather must cover at least the fast-path page slice"
        );
        if buf.len() == in_page {
            // Nothing beyond the bytes the fast path already tried (or none at all) is
            // resident, so the failure above was (possibly) an artifact of missing data.
            return CachedDecode::Missing;
        }
        let total = buf.len();
        match T::read_cfg(&mut buf, cfg) {
            Ok(value) => CachedDecode::Decoded(value, buf.consumed()),
            // Any failure against a window shorter than `max_len` (a truncated gather or a
            // window clamped by the logical size) may be an artifact of missing data. The
            // caller's async fallback re-reads authoritative bytes and surfaces real
            // corruption.
            Err(_) if buf.truncated() || total < max_len => CachedDecode::Missing,
            Err(err) => CachedDecode::Invalid(err),
        }
    }

    /// Like [Self::decode_prefix] but requires the encoding to occupy exactly
    /// `cached_len + tail.len()` bytes, matching `Decode::decode_cfg` semantics.
    #[inline]
    fn decode_exact<T: CodecRead>(
        &self,
        blob_id: u64,
        offset: u64,
        cached_len: usize,
        tail: &[u8],
        cfg: &T::Cfg,
    ) -> CachedDecode<T> {
        let len = cached_len + tail.len();
        if len == 0 {
            return CachedDecode::Missing;
        }

        // Fast path: the entire encoding lies within a single page, so it can be decoded from
        // the contiguous slice and every outcome is authoritative.
        if tail.is_empty() {
            let Some(slice) = self.resident_in_page(blob_id, offset, len) else {
                return CachedDecode::Missing;
            };
            if slice.len() == len {
                let mut buf = slice;
                return match T::read_cfg(&mut buf, cfg) {
                    Ok(value) if buf.is_empty() => CachedDecode::Decoded(value, len),
                    // All `len` bytes were resident, so under-consumption means the encoding
                    // does not occupy exactly `len` bytes. Report the same error as
                    // `Decode::decode_cfg`.
                    Ok(_) => CachedDecode::Invalid(commonware_codec::Error::ExtraData(buf.len())),
                    Err(err) => CachedDecode::Invalid(err),
                };
            }
        }

        let mut buf = self.gather_with_tail(blob_id, offset, cached_len, tail);
        let truncated = buf.truncated();
        match T::read_cfg(&mut buf, cfg) {
            Ok(value) if buf.consumed() == len => CachedDecode::Decoded(value, len),
            // A short decode against a truncated gather may be an artifact of missing data
            // (the decoder may have consumed a prefix that happens to parse standalone).
            Ok(_) if truncated => CachedDecode::Missing,
            Ok(_) => {
                CachedDecode::Invalid(commonware_codec::Error::ExtraData(len - buf.consumed()))
            }
            Err(_) if truncated => CachedDecode::Missing,
            Err(err) => CachedDecode::Invalid(err),
        }
    }

    /// Put the given `page` into the page cache and record its slot hint.
    fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        assert_eq!(page.len(), self.page_size);
        let pool = &self.pool;
        let page_size = self.page_size;
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

    /// Look up a page, preferring its direct-mapped slot hint over the [Clock]'s own lookup.
    #[inline]
    fn get_page(&self, blob_id: u64, page_num: u64) -> Option<&IoBufMut> {
        let key = (blob_id, page_num);
        let slot = self.hints[self.hint_index(blob_id, page_num)];
        if let Some(page) = self.cache.get_at(slot, &key) {
            return Some(page);
        }
        self.cache.get(&key)
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
    use super::{
        super::{buf::MAX_GATHER_PAGES, Checksum},
        *,
    };
    use crate::{
        buffer::paged::CHECKSUM_SIZE, deterministic, telemetry::metrics::Registry, Buf, BufferPool,
        BufferPoolConfig, Clock as _, Handle, IoBufsMut, Runner as _, Spawner as _, Storage as _,
        Supervisor as _,
    };
    use commonware_codec::ReadExt as _;
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

    #[test_traced]
    fn test_read_cached_many_all_cached() {
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        let page0 = vec![0xAA; PAGE_SIZE.get() as usize];
        let page1 = vec![0xBB; PAGE_SIZE.get() as usize];

        // Populate two pages with distinct data.
        {
            let mut cache = cache_ref.cache.write();
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

    /// Build a page of `PAGE_SIZE` bytes where byte `i` is `(seed + i) as u8`.
    fn patterned_page(seed: usize) -> Vec<u8> {
        (0..PAGE_SIZE.get() as usize)
            .map(|i| (seed + i) as u8)
            .collect()
    }

    /// The `u64` stored at `offset` in the logical byte stream of patterned pages.
    fn patterned_u64(offset: usize) -> u64 {
        let bytes: Vec<u8> = (offset..offset + 8).map(|i| i as u8).collect();
        u64::from_be_bytes(bytes.try_into().unwrap())
    }

    #[test_traced]
    fn test_decode_cached_within_one_page() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        let offset = 16u64;
        match cache_ref.decode_cached_exact::<u64>(blob_id, offset, 8, &[], &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value, patterned_u64(offset as usize));
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected decode to succeed"),
        }

        // The prefix variant reports actual consumption when given extra room.
        match cache_ref.decode_cached_prefix::<u64>(blob_id, offset, 64, &[], 64, &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value, patterned_u64(offset as usize));
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected decode to succeed"),
        }
    }

    #[test_traced]
    fn test_decode_cached_spanning_two_pages() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);
        cache_ref.cache(
            blob_id,
            &patterned_page(PAGE_SIZE.get() as usize),
            PAGE_SIZE_U64,
        );

        let offset = PAGE_SIZE_U64 - 4;
        match cache_ref.decode_cached_exact::<u64>(blob_id, offset, 8, &[], &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value, patterned_u64(offset as usize));
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected decode spanning pages to succeed"),
        }
    }

    #[test_traced]
    fn test_decode_cached_missing_second_page() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        // The first page is resident but the second is not, so a decode spanning the
        // boundary cannot complete.
        let offset = PAGE_SIZE_U64 - 4;
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, offset, 8, &[], &()),
            CachedDecode::Missing
        ));

        // A fully absent range is also missing.
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, PAGE_SIZE_U64 * 5, 8, &[], &()),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_invalid_resident_bytes() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &vec![0xFF; PAGE_SIZE.get() as usize], 0);

        // 0xFF is not a valid bool encoding and the byte is resident, so the decode is
        // authoritatively invalid.
        assert!(matches!(
            cache_ref.decode_cached_exact::<bool>(blob_id, 0, 1, &[], &()),
            CachedDecode::Invalid(_)
        ));
    }

    #[test_traced]
    fn test_decode_cached_truncated_error_is_missing() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &vec![0xFF; PAGE_SIZE.get() as usize], 0);

        // The first bool (0xFF) is malformed, but the gather is truncated (the second
        // page holding the second bool is absent), so ANY decode failure must be treated
        // as missing data rather than corruption.
        let offset = PAGE_SIZE_U64 - 1;
        assert!(matches!(
            cache_ref.decode_cached_exact::<[bool; 2]>(blob_id, offset, 2, &[], &()),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_short_ok_truncated_is_missing() {
        // A decoder that succeeds on the truncated gather while consuming fewer than `len`
        // bytes must be classified as Missing (partial residency), not Invalid(ExtraData):
        // the absent tail page may hold the rest of the encoding, and the async fallback is
        // the authority.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        // u32 needs 4 bytes and exactly 4 bytes are resident before the absent page 1, but the
        // caller claims the encoding occupies 8 bytes.
        let offset = PAGE_SIZE_U64 - 4;
        assert!(matches!(
            cache_ref.decode_cached_exact::<u32>(blob_id, offset, 8, &[], &()),
            CachedDecode::Missing
        ));

        // Same shape through the prefix variant: a successful decode within the resident
        // prefix is a valid result there.
        assert!(matches!(
            cache_ref.decode_cached_prefix::<u32>(blob_id, offset, 8, &[], 8, &()),
            CachedDecode::Decoded(_, 4)
        ));
    }

    #[test_traced]
    fn test_decode_cached_gather_cap() {
        const ITEM_SIZE: usize = MAX_GATHER_PAGES * PAGE_SIZE.get() as usize + 8;
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(MAX_GATHER_PAGES + 2));
        let blob_id = cache_ref.next_id();
        for page in 0..=MAX_GATHER_PAGES as u64 {
            cache_ref.cache(blob_id, &patterned_page(0), page * PAGE_SIZE_U64);
        }

        // Every page of the item is resident, but it spans more than MAX_GATHER_PAGES
        // pages, so the gather is capped and the decode reports missing data.
        assert!(matches!(
            cache_ref.decode_cached_exact::<[u8; ITEM_SIZE]>(blob_id, 0, ITEM_SIZE, &[], &()),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_sets_referenced_bits() {
        // Fill a capacity-3 cache with pages 0..3, then insert page 3 to clear all
        // referenced bits and evict page 0 (Clock sweep), leaving pages 1 and 2
        // unreferenced.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(3));
        let blob_id = cache_ref.next_id();
        let page = patterned_page(0);
        for num in 0u64..4 {
            cache_ref.cache(blob_id, &page, num * PAGE_SIZE_U64);
        }

        // Touch page 1 via a cached decode, marking it referenced.
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, PAGE_SIZE_U64, 8, &[], &()),
            CachedDecode::Decoded(..)
        ));

        // Inserting another page must now evict unreferenced page 2 rather than the
        // just-referenced page 1.
        cache_ref.cache(blob_id, &page, 4 * PAGE_SIZE_U64);
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, PAGE_SIZE_U64, 8, &[], &()),
            CachedDecode::Decoded(..)
        ));
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, 2 * PAGE_SIZE_U64, 8, &[], &()),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_exact_many_chunked() {
        // Use more bytes than DECODE_BATCH_BYTES covers in one chunk to exercise multiple
        // lock acquisitions, with a missing page in the middle.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        let items_per_page = PAGE_SIZE.get() as usize / 8;
        cache_ref.cache(blob_id, &patterned_page(0), 0);
        // Page 1 deliberately absent.
        cache_ref.cache(
            blob_id,
            &patterned_page(2 * PAGE_SIZE.get() as usize),
            2 * PAGE_SIZE_U64,
        );

        // Offsets covering pages 0 and 2 (resident) and pages 1 and 3..9 (absent), spanning
        // enough total bytes to require multiple lock acquisitions.
        let offsets: Vec<u64> = (0..9 * items_per_page as u64).map(|i| i * 8).collect();
        assert!(offsets.len() * 8 > DECODE_BATCH_BYTES);
        let mut out = Vec::with_capacity(offsets.len());
        cache_ref
            .decode_cached_exact_many::<u64>(blob_id, &offsets, 8, &(), &mut out)
            .unwrap();

        assert_eq!(out.len(), offsets.len());
        for (i, (item, &offset)) in out.iter().zip(&offsets).enumerate() {
            if matches!(i / items_per_page, 0 | 2) {
                assert_eq!(
                    item.as_ref().copied(),
                    Some(patterned_u64(offset as usize % PAGE_SIZE.get() as usize)),
                    "offset {offset} should hit"
                );
            } else {
                assert!(item.is_none(), "offset {offset} should miss");
            }
        }
    }

    /// A varint length prefix followed by exactly that many payload bytes, mirroring the
    /// journal frame decoder used with the prefix decode path.
    struct VarPrefixed(Vec<u8>);

    impl commonware_codec::Read for VarPrefixed {
        type Cfg = ();

        fn read_cfg(
            buf: &mut impl crate::Buf,
            _: &Self::Cfg,
        ) -> Result<Self, commonware_codec::Error> {
            let len = commonware_codec::varint::UInt::<u32>::read(buf)?.0 as usize;
            commonware_codec::util::at_least(buf, len)?;
            let mut data = vec![0u8; len];
            buf.copy_to_slice(&mut data);
            Ok(Self(data))
        }
    }

    #[test_traced]
    fn test_decode_cached_with_tail_spanning_boundary() {
        // A window whose first bytes come from a resident page and whose suffix is supplied
        // by the caller as an in-memory tail slice decodes as one contiguous view.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        let offset = PAGE_SIZE_U64 - 4;
        let tail: Vec<u8> = (0..4)
            .map(|i| (PAGE_SIZE.get() as usize + i) as u8)
            .collect();
        let expected = patterned_u64(offset as usize);
        match cache_ref.decode_cached_exact::<u64>(blob_id, offset, 4, &tail, &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value, expected);
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected tail-assembled decode to succeed"),
        }

        // The prefix variant assembles the same window.
        match cache_ref.decode_cached_prefix::<u64>(blob_id, offset, 4, &tail, 8, &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value, expected);
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected tail-assembled prefix decode to succeed"),
        }
    }

    #[test_traced]
    fn test_decode_cached_tail_requires_complete_gather() {
        // The tail may only extend a COMPLETE gather. Here the cached region spans pages 0
        // and 1 but page 1 is absent, so the tail must not be appended: a varint frame whose
        // header is resident but whose payload continues through the hole must classify as
        // Missing. If the tail were spliced onto the truncated gather, the frame would parse
        // successfully out of discontiguous bytes and return a wrong value as authoritative.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        let mut page = patterned_page(0);
        let header_at = PAGE_SIZE.get() as usize - 4;
        page[header_at..].copy_from_slice(&[0x07, 1, 2, 3]);
        cache_ref.cache(blob_id, &page, 0);

        let offset = header_at as u64;
        let tail = [4u8, 5, 6, 7];
        assert!(matches!(
            cache_ref.decode_cached_prefix::<VarPrefixed>(blob_id, offset, 8, &tail, 12, &()),
            CachedDecode::Missing
        ));

        // Once page 1 is resident the same window decodes, proving the setup is otherwise
        // servable.
        cache_ref.cache(blob_id, &patterned_page(64), PAGE_SIZE_U64);
        match cache_ref.decode_cached_prefix::<VarPrefixed>(blob_id, offset, 8, &tail, 12, &()) {
            CachedDecode::Decoded(value, consumed) => {
                assert_eq!(value.0.len(), 7);
                assert_eq!(consumed, 8);
            }
            _ => panic!("expected decode with resident page 1 to succeed"),
        }
    }

    #[test_traced]
    fn test_decode_cached_edge_windows() {
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(MAX_GATHER_PAGES + 2));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        // Zero-length windows are misses for both variants.
        assert!(matches!(
            cache_ref.decode_cached_prefix::<u64>(blob_id, 0, 0, &[], 0, &()),
            CachedDecode::Missing
        ));
        assert!(matches!(
            cache_ref.decode_cached_exact::<u64>(blob_id, 0, 0, &[], &()),
            CachedDecode::Missing
        ));

        // A window supplied entirely by the tail decodes without touching any page.
        let tail: Vec<u8> = (0..8u8).collect();
        match cache_ref.decode_cached_exact::<u64>(blob_id, 0, 0, &tail, &()) {
            CachedDecode::Decoded(value, _) => {
                assert_eq!(value, u64::from_be_bytes([0, 1, 2, 3, 4, 5, 6, 7]))
            }
            _ => panic!("expected tail-only decode to succeed"),
        }

        // A fully resident multi-slice window whose bytes are malformed is authoritative
        // corruption: byte 1 of the patterned page is 0x01 (a valid bool) and the tail byte
        // is not.
        assert!(matches!(
            cache_ref.decode_cached_exact::<[bool; 2]>(blob_id, 1, 1, &[0xFF], &()),
            CachedDecode::Invalid(_)
        ));

        // A cached region occupying every gather slot leaves no room to append the tail, so
        // the window is truncated and classifies as missing.
        const CAP_LEN: usize = MAX_GATHER_PAGES * PAGE_SIZE.get() as usize;
        for page in 0..MAX_GATHER_PAGES as u64 {
            cache_ref.cache(blob_id, &patterned_page(0), page * PAGE_SIZE_U64);
        }
        assert!(matches!(
            cache_ref.decode_cached_exact::<[u8; CAP_LEN + 4]>(
                blob_id,
                0,
                CAP_LEN,
                &[1, 2, 3, 4],
                &()
            ),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_page_number_overflow() {
        // A window starting in the last addressable page cannot gather past it: the page
        // number overflow truncates the gather and the decode classifies as missing. Only a
        // one-byte page size can address page u64::MAX.
        let cache_ref = CacheRef::new(test_pool(), NZU16!(1), NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &[0x01], u64::MAX);

        assert!(matches!(
            cache_ref.decode_cached_exact::<u16>(blob_id, u64::MAX, 2, &[], &()),
            CachedDecode::Missing
        ));
    }

    #[test_traced]
    fn test_decode_cached_exact_under_consumption_is_invalid() {
        // A decoder that consumes fewer than the exact window's bytes must be reported as
        // ExtraData corruption when every byte was authoritatively available, both on the
        // single-page fast path and on the gathered tail path.
        let cache_ref = CacheRef::new(test_pool(), PAGE_SIZE, NZUsize!(10));
        let blob_id = cache_ref.next_id();
        cache_ref.cache(blob_id, &patterned_page(0), 0);

        // Fast path: all 8 bytes resident in one page, u32 consumes 4.
        assert!(matches!(
            cache_ref.decode_cached_exact::<u32>(blob_id, 16, 8, &[], &()),
            CachedDecode::Invalid(commonware_codec::Error::ExtraData(4))
        ));

        // Gather path: 4 cached bytes plus a 4-byte tail, u32 consumes 4.
        let offset = PAGE_SIZE_U64 - 4;
        assert!(matches!(
            cache_ref.decode_cached_exact::<u32>(blob_id, offset, 4, &[9, 9, 9, 9], &()),
            CachedDecode::Invalid(commonware_codec::Error::ExtraData(4))
        ));
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
            let mut cache = cache_ref.cache.write();
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
        // Insert one page past capacity so the CLOCK evicts page 0 and reuses its slot for
        // page 2. Page 0's hint now points at a slot holding page 2's key, so the batched
        // read must report page 0 as a miss (never page 2's bytes) while still serving the
        // live pages.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(2));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        {
            let mut cache = cache_ref.cache.write();
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
        // overwrites the earlier blob's hint. The hint only proposes a slot: [Clock::get_at]
        // validates the full (blob, page) key, so each blob reads back its own bytes (the
        // clobbered one through the fallback lookup), never the other's.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(4));
        let blob_a = cache_ref.next_id();
        let blob_b = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        let page_a = 5u64;
        let page_b = {
            let mut cache = cache_ref.cache.write();

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
            let mut cache = cache_ref.cache.write();
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
    fn test_read_cached_many_invalidated_page_is_a_miss() {
        // Invalidated pages free their slots but keep their keys. Their hints need no
        // cleanup: a freed slot is not live, so the dropped page reads as a miss until
        // re-cached.
        let pool = test_pool();
        let cache_ref = CacheRef::new(pool, PAGE_SIZE, NZUsize!(4));
        let blob_id = cache_ref.next_id();
        let page_size = PAGE_SIZE.get() as usize;
        {
            let mut cache = cache_ref.cache.write();
            for page in 0u64..4 {
                cache.cache(blob_id, &vec![page as u8 + 1; page_size], page);
            }
        }
        cache_ref.invalidate_from(blob_id, 2);

        let read_page = |page: u64| {
            let mut buf = vec![0u8; page_size];
            let mut ranges: Vec<(&mut [u8], u64)> = vec![(&mut buf, page * PAGE_SIZE_U64)];
            cache_ref.read_cached_many(blob_id, &mut ranges);
            let hit = ranges.is_empty();
            drop(ranges);
            hit.then_some(buf)
        };
        assert_eq!(read_page(0), Some(vec![1u8; page_size]));
        assert_eq!(read_page(1), Some(vec![2u8; page_size]));
        assert_eq!(read_page(2), None);
        assert_eq!(read_page(3), None);

        // Re-caching a dropped page restores it through the hint path.
        {
            let mut cache = cache_ref.cache.write();
            cache.cache(blob_id, &vec![0xCC; page_size], 2);
        }
        assert_eq!(read_page(2), Some(vec![0xCC; page_size]));
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
            let mut cache = cache_ref.cache.write();
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
}

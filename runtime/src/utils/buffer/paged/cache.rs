//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.
//!
//! # Memory Bound Semantics
//!
//! Cache capacity bounds resident cache slots, not total process memory retained by read results.
//! Returned [IoBuf] slices are reference-counted and can outlive eviction, so memory for evicted
//! pages can remain live until all readers drop their references.

use super::{read_page_from_blob_into, CHECKSUM_SIZE};
use crate::{Blob, BufferPool, BufferPooler, Error, IoBuf, IoBufMut, IoBufs};
use commonware_utils::sync::AsyncRwLock;
use futures::{future::Shared, FutureExt};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Weak,
    },
};
use tracing::{debug, error, trace};

// Type alias for the future we'll be storing for each in-flight page fetch.
//
// We wrap [Error] in an Arc so it will be cloneable, which is required for the future to be
// [Shared]. The IoBuf contains only the logical (validated) bytes of the page.
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<IoBuf, Arc<Error>>> + Send>>>;
type ResolvedFetch = ((u64, u64), Result<IoBuf, Arc<Error>>);

/// Shared state for one in-flight page fetch.
struct PageFetchState {
    future: PageFetchFut,
}

impl PageFetchState {
    fn is_unresolved(&self) -> bool {
        self.future.peek().is_none()
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
    slots: Vec<IoBuf>,

    /// Pool used for slot recycling and fallback replacement allocations.
    pool: BufferPool,

    /// Logical size of each cached page in bytes.
    page_size: usize,

    /// The Clock replacement policy's clock hand index into `entries`.
    clock: usize,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// Weak references to in-flight page fetches keyed by `(blob id, page number)`.
    ///
    /// Dead weak tombstones may remain until scavenged.
    page_fetches: HashMap<(u64, u64), Weak<PageFetchState>>,
}

/// Metadata for a single cache entry (page data stored in per-slot buffers).
struct CacheEntry {
    /// The cache key which is composed of the blob id and page number of the page.
    key: (u64, u64),

    /// A bit indicating whether this page was recently referenced.
    referenced: AtomicBool,

    /// Whether the slot currently contains validated data for `key`.
    ready: AtomicBool,
}

/// A reference to a page cache that can be shared across threads via cloning, along with the page
/// size that will be used with it. Provides the API for interacting with the page cache in a
/// thread-safe manner.
#[derive(Clone)]
pub struct CacheRef {
    /// The logical size of each page in the underlying blobs managed by this page cache.
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. (Reads
    /// on blobs that were written with a different page size will fail their integrity check.)
    logical_page_size: u64,

    /// The physical on-disk page size in bytes, including checksum record bytes.
    physical_page_size: u64,

    /// The next id to assign to a blob that will be managed by this cache.
    next_id: Arc<AtomicU64>,

    /// Shareable reference to the page cache.
    cache: Arc<AsyncRwLock<Cache>>,

    /// Pool used for page-cache and associated buffer allocations.
    pool: BufferPool,
}

impl CacheRef {
    /// Consume stale fetch-map entries and apply their outcomes.
    ///
    /// This handles both already-resolved entries and dead weak tombstones whose strong state was
    /// dropped (e.g. after waiter cancellation).
    fn scavenge_fetch_entries(&self, cache: &mut Cache) {
        for key in cache.take_dead_fetch_tombstones() {
            debug!(
                blob_id = key.0,
                page_num = key.1,
                "dropping dead fetch weak entry"
            );
            cache.mark_fetch_failed(key);
        }

        for (key, result) in cache.take_resolved_fetches() {
            match result {
                Ok(page) => {
                    if !cache.should_accept_resolved_fetch(key) {
                        debug!(
                            blob_id = key.0,
                            page_num = key.1,
                            "dropping stale resolved fetch because key already has ready data"
                        );
                        continue;
                    }
                    if cache.insert_page(key, page).is_err() {
                        error!(
                            blob_id = key.0,
                            page_num = key.1,
                            "failed to insert stale fetched page"
                        );
                    }
                }
                Err(_) => cache.mark_fetch_failed(key),
            }
        }
    }

    /// Create a shared page-cache handle backed by `pool`.
    ///
    /// `physical_page_size` is the on-disk page size, including checksum record bytes.
    ///
    /// The cache stores at most `capacity` pages, each exactly one logical page worth of bytes
    /// (`physical_page_size - CHECKSUM_SIZE`).
    /// Initialization eagerly allocates and zeroes all cache slots from `pool`.
    ///
    /// Capacity bounds the number of resident slots in this cache. Read results may outlive
    /// eviction and retain memory until dropped by readers.
    pub fn new(pool: BufferPool, physical_page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let physical_page_size_u64 = physical_page_size.get() as u64;
        assert!(
            physical_page_size_u64 > CHECKSUM_SIZE,
            "physical page size must be larger than checksum record"
        );
        let logical_page_size_u64 = physical_page_size_u64 - CHECKSUM_SIZE;
        let logical_page_size_u16 =
            u16::try_from(logical_page_size_u64).expect("logical page size must fit in u16");
        let logical_page_size =
            NonZeroU16::new(logical_page_size_u16).expect("logical page size must be non-zero");

        Self {
            logical_page_size: logical_page_size_u64,
            physical_page_size: physical_page_size_u64,
            next_id: Arc::new(AtomicU64::new(0)),
            cache: Arc::new(AsyncRwLock::new(Cache::new(
                pool.clone(),
                logical_page_size,
                capacity,
            ))),
            pool,
        }
    }

    /// Create a shared page-cache handle, extracting the storage [BufferPool] from a
    /// [BufferPooler].
    pub fn from_pooler(
        pooler: &impl BufferPooler,
        physical_page_size: NonZeroU16,
        capacity: NonZeroUsize,
    ) -> Self {
        Self::new(
            pooler.storage_buffer_pool().clone(),
            physical_page_size,
            capacity,
        )
    }

    /// The logical page size used by this page cache.
    #[inline]
    pub const fn page_size(&self) -> u64 {
        self.logical_page_size
    }

    /// The physical page size used by the underlying blob format.
    #[inline]
    pub const fn physical_page_size(&self) -> u64 {
        self.physical_page_size
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
        Cache::offset_to_page(self.logical_page_size, offset)
    }

    /// Attempt to read bytes from cache only, stopping at the first miss.
    ///
    /// Returns the buffers read from cache and the number of bytes read.
    pub(super) async fn read_cached(
        &self,
        blob_id: u64,
        mut logical_offset: u64,
        len: usize,
    ) -> (IoBufs, usize) {
        let mut remaining = len;
        let mut out = IoBufs::default();
        let page_cache = self.cache.read().await;
        while remaining > 0 {
            let Some(page) = page_cache.read_at(blob_id, logical_offset, remaining) else {
                break;
            };
            remaining -= page.len();
            logical_offset = match logical_offset.checked_add(page.len() as u64) {
                Some(next) => next,
                None => break,
            };
            out.append(page);
        }
        (out, len - remaining)
    }

    /// Read the specified bytes, preferentially from the page cache. Bytes not found in the cache
    /// will be read from the provided `blob` and cached for future reads.
    pub(super) async fn read<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        logical_offset: u64,
        len: usize,
    ) -> Result<IoBufs, Error> {
        self.read_with_prefix(blob, blob_id, logical_offset, len, IoBufs::default(), 0)
            .await
    }

    /// Continue reading `len` bytes, appending newly read data after `prefix_len` bytes already in
    /// `result`.
    pub(super) async fn read_with_prefix<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        logical_offset: u64,
        len: usize,
        mut result: IoBufs,
        prefix_len: usize,
    ) -> Result<IoBufs, Error> {
        let mut remaining = len
            .checked_sub(prefix_len)
            .expect("prefix length must not exceed requested length");
        let mut logical_offset = logical_offset
            .checked_add(prefix_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        while remaining > 0 {
            // Read lock the page cache and see if we can get (some of) the data from it.
            if let Some(page) = {
                let page_cache = self.cache.read().await;
                page_cache.read_at(blob_id, logical_offset, remaining)
            } {
                remaining -= page.len();
                logical_offset = logical_offset
                    .checked_add(page.len() as u64)
                    .ok_or(Error::OffsetOverflow)?;
                result.append(page);
                continue;
            }

            // Handle page fault.
            let page = self
                .read_after_page_fault(blob, blob_id, logical_offset, remaining)
                .await?;
            remaining -= page.len();
            logical_offset = logical_offset
                .checked_add(page.len() as u64)
                .ok_or(Error::OffsetOverflow)?;
            result.append(page);
        }

        Ok(result)
    }

    /// Fetch the requested page after encountering a page fault, which may involve retrieving it
    /// from `blob` & caching the result in the page cache.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        offset: u64,
        max_len: usize,
    ) -> Result<IoBuf, Error> {
        assert!(max_len > 0);

        let (page_num, offset_in_page) = Cache::offset_to_page(self.logical_page_size, offset);
        let offset_in_page = offset_in_page as usize;
        trace!(page_num, blob_id, "page fault");

        enum Acquisition {
            Fetch(Arc<PageFetchState>),
            WaitForCapacity(PageFetchFut),
        }
        let fetch_state = loop {
            // Create or clone a future that retrieves the desired page from the underlying blob.
            // This requires a write lock on the page cache since we may need to modify
            // `page_fetches`.
            let acquisition = {
                let mut cache = self.cache.write().await;

                // There's a (small) chance the page was fetched & buffered by another task before we
                // were able to acquire the write lock, so check the cache before doing anything else.
                if let Some(page) = cache.read_at(blob_id, offset, max_len) {
                    return Ok(page);
                }

                // Reap any resolved stale fetch entries so they cannot block eviction/retries.
                self.scavenge_fetch_entries(&mut cache);
                if let Some(page) = cache.read_at(blob_id, offset, max_len) {
                    return Ok(page);
                }

                let key = (blob_id, page_num);
                let logical_page_size = self.logical_page_size;
                let physical_page_size = logical_page_size + CHECKSUM_SIZE;
                let create_fetch = |cache: &mut Cache| -> Result<Acquisition, Error> {
                    match cache.try_reserve_fetch_buffer(key, physical_page_size as usize) {
                        Some(buf) => {
                            let blob = blob.clone();
                            let future = async move {
                                let page = read_page_from_blob_into(
                                    &blob,
                                    page_num,
                                    logical_page_size,
                                    buf,
                                )
                                .await
                                .map_err(Arc::new)?;
                                // We should never be fetching partial pages through the page cache. This
                                // can happen if a non-last page is corrupted and falls back to a partial
                                // CRC.
                                let len = page.len();
                                if len != logical_page_size as usize {
                                    error!(
                                        page_num,
                                        expected = logical_page_size,
                                        actual = len,
                                        "attempted to fetch partial page from blob"
                                    );
                                    return Err(Arc::new(Error::InvalidChecksum));
                                }
                                Ok(page)
                            };

                            let state = Arc::new(PageFetchState {
                                future: future.boxed().shared(),
                            });
                            cache.page_fetches.insert(key, Arc::downgrade(&state));
                            Ok(Acquisition::Fetch(state))
                        }
                        None => {
                            // All slots are currently in-flight. Wait for any in-flight fetch to
                            // complete, then retry acquisition.
                            let Some(wait_on) = cache.unresolved_fetch_to_wait_on() else {
                                error!(
                                    blob_id,
                                    page_num,
                                    "no evictable slot and no in-flight fetches to wait on"
                                );
                                return Err(Error::ReadFailed);
                            };
                            Ok(Acquisition::WaitForCapacity(wait_on))
                        }
                    }
                };

                if let Some(existing) = cache.page_fetches.get(&key).cloned() {
                    if let Some(state) = existing.upgrade() {
                        Acquisition::Fetch(state)
                    } else {
                        let _ = cache.page_fetches.remove(&key);
                        create_fetch(&mut cache)?
                    }
                } else {
                    create_fetch(&mut cache)?
                }
            };

            match acquisition {
                Acquisition::Fetch(fetch_state) => break fetch_state,
                Acquisition::WaitForCapacity(wait_on) => {
                    let _ = wait_on.await;
                    continue;
                }
            }
        };

        // Await the shared future result.
        let fetch_result = fetch_state.future.clone().await;

        let page_for_return = match fetch_result {
            Ok(page_buf) => {
                let key = (blob_id, page_num);
                let mut cache = self.cache.write().await;
                cache.remove_fetch_if_matches(key, &fetch_state);
                if cache.should_accept_resolved_fetch(key) {
                    if cache.insert_page(key, page_buf.clone()).is_err() {
                        error!(blob_id, page_num, "failed to insert fetched page");
                    }
                } else {
                    debug!(
                        blob_id,
                        page_num, "dropping stale fetched page because key already has ready data"
                    );
                }
                page_buf
            }
            Err(err) => {
                let key = (blob_id, page_num);
                let mut cache = self.cache.write().await;
                cache.remove_fetch_if_matches(key, &fetch_state);
                cache.mark_fetch_failed(key);
                error!(page_num, ?err, "Page fetch failed");
                return Err(Error::ReadFailed);
            }
        };

        // Return directly from the fetched page to preserve correctness regardless of insertion.
        let bytes = std::cmp::min(max_len, page_for_return.len() - offset_in_page);
        Ok(page_for_return.slice(offset_in_page..offset_in_page + bytes))
    }

    /// Cache full logical pages in the page cache. `offset` must be page aligned.
    ///
    /// # Panics
    ///
    /// - Panics if `offset` is not page aligned.
    /// - If any page is not exactly one logical page in size.
    /// - If `offset` is near `u64::MAX` and `pages` spans past the last representable page
    ///   number.
    ///
    /// # Best Effort Behavior
    ///
    /// This method is best effort. If the cache cannot make capacity progress (for example, no
    /// evictable slots and no unresolved in-flight fetches to await), remaining pages are dropped
    /// after logging an error.
    pub async fn cache(&self, blob_id: u64, pages: Vec<IoBuf>, offset: u64) {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);

        let total_pages = pages.len();
        let mut pending: VecDeque<(u64, IoBuf)> = VecDeque::with_capacity(total_pages);
        for (idx, page) in pages.into_iter().enumerate() {
            pending.push_back((page_num, page));
            if idx + 1 < total_pages {
                page_num = page_num
                    .checked_add(1)
                    .expect("page number overflow while caching");
            }
        }

        while !pending.is_empty() {
            let wait_for = {
                let mut cache = self.cache.write().await;
                self.scavenge_fetch_entries(&mut cache);

                while let Some((page_num, page)) = pending.pop_front() {
                    match cache.insert_page((blob_id, page_num), page) {
                        Ok(()) => continue,
                        Err(returned_page) => {
                            pending.push_front((page_num, returned_page));
                            break;
                        }
                    }
                }

                if pending.is_empty() {
                    None
                } else {
                    cache.unresolved_fetch_to_wait_on()
                }
            };

            if pending.is_empty() {
                break;
            }

            let Some(wait_for) = wait_for else {
                let (failed_page, _) = pending.pop_front().expect("pending non-empty");
                error!(
                    blob_id,
                    page_num = failed_page,
                    "failed to cache page: no capacity and no in-flight fetches to wait on"
                );
                continue;
            };
            let _ = wait_for.await;
        }
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
            let slot = pool.alloc_zeroed(page_size).freeze();
            slots.push(slot);
        }
        Self {
            index: HashMap::new(),
            entries: Vec::with_capacity(capacity),
            slots,
            pool,
            page_size,
            clock: 0,
            capacity,
            page_fetches: HashMap::new(),
        }
    }

    /// Returns the cached page for the given slot index.
    #[inline]
    fn page(&self, slot: usize) -> &IoBuf {
        assert!(slot < self.capacity);
        &self.slots[slot]
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    const fn offset_to_page(page_size: u64, offset: u64) -> (u64, u64) {
        (offset / page_size, offset % page_size)
    }

    /// Attempt to fetch blob data starting at `logical_offset` from the page cache.
    ///
    /// Returns `None` if the first page in the requested range isn't buffered.
    /// Returned bytes never cross a page boundary.
    fn read_at(&self, blob_id: u64, logical_offset: u64, max_len: usize) -> Option<IoBuf> {
        let (page_num, offset_in_page) =
            Self::offset_to_page(self.page_size as u64, logical_offset);
        let slot = *self.index.get(&(blob_id, page_num))?;
        let entry = &self.entries[slot];
        assert_eq!(entry.key, (blob_id, page_num));
        if !entry.ready.load(Ordering::Relaxed) {
            return None;
        }
        entry.referenced.store(true, Ordering::Relaxed);

        let page = self.page(slot);
        let bytes = std::cmp::min(max_len, self.page_size - offset_in_page as usize);
        Some(page.slice(offset_in_page as usize..offset_in_page as usize + bytes))
    }

    /// Put a page into the cache.
    fn insert_page(&mut self, key: (u64, u64), page: IoBuf) -> Result<(), IoBuf> {
        let Some(slot) = self.prepare_slot(key, true) else {
            return Err(page);
        };
        assert_eq!(page.len(), self.page_size);
        self.slots[slot] = page;
        Ok(())
    }

    /// Reserve/initialize a slot for `key`, setting its ready state to `ready`.
    fn prepare_slot(&mut self, key: (u64, u64), ready: bool) -> Option<usize> {
        let (blob_id, page_num) = key;
        // Check for existing entry (update case)
        if let Some(&slot) = self.index.get(&key) {
            // This case can result when a blob is truncated across a page boundary, and later grows
            // back to (beyond) its original size. It will also become expected behavior once we
            // allow cached pages to be writable.
            debug!(blob_id, page_num, "updating duplicate page");

            let entry = &self.entries[slot];
            assert_eq!(entry.key, key);
            entry.referenced.store(true, Ordering::Relaxed);
            entry.ready.store(ready, Ordering::Relaxed);
            return Some(slot);
        }

        // New entry - check if we need to evict
        if self.entries.len() < self.capacity {
            let slot = self.entries.len();
            self.index.insert(key, slot);
            self.entries.push(CacheEntry {
                key,
                referenced: AtomicBool::new(true),
                ready: AtomicBool::new(ready),
            });
            return Some(slot);
        }

        // Cache full: find slot to evict and replace.
        let slot = self.next_evictable_slot()?;
        self.clock = (slot + 1) % self.entries.len();
        let entry = &mut self.entries[slot];
        if self.index.remove(&entry.key).is_none() {
            error!(?entry.key, "cache index missing entry during eviction");
        }
        self.index.insert(key, slot);
        entry.key = key;
        entry.referenced.store(true, Ordering::Relaxed);
        entry.ready.store(ready, Ordering::Relaxed);
        Some(slot)
    }

    /// Find the next clock slot that can be evicted.
    fn next_evictable_slot(&mut self) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let len = self.entries.len();
        for _ in 0..(len * 2) {
            let slot = self.clock;
            self.clock = (self.clock + 1) % len;
            let key = self.entries[slot].key;
            if self
                .page_fetches
                .get(&key)
                .and_then(Weak::upgrade)
                .is_some_and(|fetch| fetch.is_unresolved())
            {
                continue;
            }
            let entry = &self.entries[slot];
            if entry.referenced.swap(false, Ordering::Relaxed) {
                continue;
            }
            return Some(slot);
        }
        None
    }

    /// Reserve a mutable page buffer for a fetch of `key`.
    ///
    /// Returned buffer capacity is guaranteed to be at least `required_size`.
    fn try_reserve_fetch_buffer(
        &mut self,
        key: (u64, u64),
        required_size: usize,
    ) -> Option<IoBufMut> {
        let slot = self.prepare_slot(key, false)?;
        let current = std::mem::take(&mut self.slots[slot]);
        match current.try_into_mut() {
            Ok(mut recycled) => {
                if recycled.capacity() < required_size {
                    return Some(self.pool.alloc(required_size));
                }
                recycled.clear();
                Some(recycled)
            }
            Err(_) => Some(self.pool.alloc(required_size)),
        }
    }

    /// Return any unresolved in-flight fetch future to await for capacity progress.
    fn unresolved_fetch_to_wait_on(&self) -> Option<PageFetchFut> {
        self.page_fetches
            .values()
            .filter_map(Weak::upgrade)
            .find(|entry| entry.is_unresolved())
            .map(|entry| entry.future.clone())
    }

    /// Mark an in-flight fetch as failed, leaving the key as a cache miss.
    fn mark_fetch_failed(&mut self, key: (u64, u64)) {
        let Some(&slot) = self.index.get(&key) else {
            return;
        };
        let entry = &self.entries[slot];
        if entry.ready.load(Ordering::Relaxed) {
            // A ready page for this key already exists, so this failed fetch is stale.
            return;
        }
        entry.ready.store(false, Ordering::Relaxed);
        entry.referenced.store(false, Ordering::Relaxed);
    }

    /// Returns whether a resolved fetch result for `key` should be applied.
    fn should_accept_resolved_fetch(&self, key: (u64, u64)) -> bool {
        let Some(&slot) = self.index.get(&key) else {
            return true;
        };
        let entry = &self.entries[slot];
        !entry.ready.load(Ordering::Relaxed)
    }

    /// Remove and return all fetch-map entries whose futures have already resolved.
    fn take_resolved_fetches(&mut self) -> Vec<ResolvedFetch> {
        let resolved: Vec<_> = self
            .page_fetches
            .iter()
            .filter_map(|(key, entry)| {
                entry
                    .upgrade()
                    .and_then(|state| state.future.peek().cloned().map(|result| (*key, result)))
            })
            .collect();
        for (key, _) in &resolved {
            let _ = self.page_fetches.remove(key);
        }
        resolved
    }

    /// Remove dead weak fetch-map entries whose strong state has already been dropped.
    fn take_dead_fetch_tombstones(&mut self) -> Vec<(u64, u64)> {
        let dead: Vec<_> = self
            .page_fetches
            .iter()
            .filter_map(|(key, entry)| (entry.strong_count() == 0).then_some(*key))
            .collect();
        for key in &dead {
            let _ = self.page_fetches.remove(key);
        }
        dead
    }

    /// Remove the fetch-map entry for `key` if it still refers to `state` (or a dead tombstone).
    fn remove_fetch_if_matches(&mut self, key: (u64, u64), state: &Arc<PageFetchState>) {
        let should_remove = self.page_fetches.get(&key).is_some_and(|current| {
            current
                .upgrade()
                .is_none_or(|current_state| Arc::ptr_eq(&current_state, state))
        });
        if should_remove {
            let _ = self.page_fetches.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Checksum, *};
    use crate::{
        buffer::paged::CHECKSUM_SIZE, deterministic, BufferPool, BufferPoolConfig, Clock,
        Runner as _, Spawner as _, Storage as _,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize, NZU16};
    use futures::{
        future::{pending, ready},
        FutureExt,
    };
    use prometheus_client::registry::Registry;
    use std::{num::NonZeroU16, sync::Arc, time::Duration};

    // Logical page size (what CacheRef uses and what gets cached).
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PHYSICAL_PAGE_SIZE: NonZeroU16 = NZU16!(1036);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    fn read_cache(cache: &Cache, blob_id: u64, buf: &mut [u8], offset: u64) -> usize {
        let Some(page) = cache.read_at(blob_id, offset, buf.len()) else {
            return 0;
        };
        let len = page.len();
        buf[..len].copy_from_slice(page.as_ref());
        len
    }

    #[test_traced]
    fn test_cache_basic() {
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(10));

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        assert!(cache
            .insert_page((0, 0), vec![1; PAGE_SIZE.get() as usize].into())
            .is_ok());
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- should log a duplicate page warning but still work.
        assert!(cache
            .insert_page((0, 0), vec![2; PAGE_SIZE.get() as usize].into())
            .is_ok());
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            assert!(cache
                .insert_page((0, i), vec![i as u8; PAGE_SIZE.get() as usize].into())
                .is_ok());
        }
        // Page 0 should have been evicted.
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);
        // Page 1-10 should be in the cache.
        for i in 1u64..11 {
            let bytes_read = read_cache(&cache, 0, &mut buf, i * PAGE_SIZE_U64);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
        }

        // Test reading from an unaligned offset by adding 2 to an aligned offset. The read
        // should be 2 bytes short of a full logical page.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = read_cache(&cache, 0, &mut buf, PAGE_SIZE_U64 + 2);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize - 2);
        assert_eq!(
            &buf[..PAGE_SIZE.get() as usize - 2],
            [1; PAGE_SIZE.get() as usize - 2]
        );
    }

    #[test_traced]
    fn test_held_page_survives_eviction() {
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));

        assert!(cache
            .insert_page((0, 0), vec![1; PAGE_SIZE.get() as usize].into())
            .is_ok());
        let held = cache
            .read_at(0, 0, PAGE_SIZE.get() as usize)
            .expect("page should be cached");

        // Evict slot with a different page while `held` still aliases the old slot data.
        // This exercises the overwrite fallback path where slot recycling is not possible.
        assert!(cache
            .insert_page((0, 1), vec![2; PAGE_SIZE.get() as usize].into())
            .is_ok());
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.index.len(), 1);
        assert!(cache.index.contains_key(&(0, 1)));
        assert!(!cache.index.contains_key(&(0, 0)));

        // Held data remains valid after eviction until the reader drops it.
        assert_eq!(held.as_ref(), vec![1; PAGE_SIZE.get() as usize].as_slice());
    }

    #[test_traced]
    fn test_read_cached_returns_prefix_on_miss() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));
            let page = vec![3u8; PAGE_SIZE.get() as usize];
            cache_ref.cache(0, vec![page.clone().into()], 0).await;

            let (cached, cached_len) = cache_ref
                .read_cached(0, 0, PAGE_SIZE.get() as usize * 2)
                .await;
            assert_eq!(cached_len, PAGE_SIZE.get() as usize);
            assert_eq!(cached.coalesce().as_ref(), page.as_slice());
        });
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
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(10));
            assert_eq!(cache_ref.next_id(), 0);
            assert_eq!(cache_ref.next_id(), 1);
            for i in 0..11 {
                // Read expects logical bytes only (CRCs are stripped).
                let read = cache_ref
                    .read(&blob, 0, i * PAGE_SIZE_U64, PAGE_SIZE.get() as usize)
                    .await
                    .unwrap()
                    .coalesce();
                let expected = vec![i as u8; PAGE_SIZE.get() as usize];
                assert_eq!(read.as_ref(), expected.as_slice());
            }

            // Repeat the read to exercise reading from the page cache. Must start at 1 because
            // page 0 should be evicted.
            for i in 1..11 {
                let read = cache_ref
                    .read(&blob, 0, i * PAGE_SIZE_U64, PAGE_SIZE.get() as usize)
                    .await
                    .unwrap()
                    .coalesce();
                let expected = vec![i as u8; PAGE_SIZE.get() as usize];
                assert_eq!(read.as_ref(), expected.as_slice());
            }

            // Cleanup.
            blob.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_cache_max_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));

            // Use the largest page-aligned offset representable for the configured PAGE_SIZE.
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE_U64);

            // CacheRef::cache expects only logical bytes (no CRC).
            let logical_data = vec![42u8; PAGE_SIZE.get() as usize];

            // Caching exactly one page at the maximum offset should succeed.
            cache_ref
                .cache(0, vec![logical_data.into()], aligned_max_offset)
                .await;

            // Reading from the cache should return the logical bytes.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let page_cache = cache_ref.cache.read().await;
            let bytes_read = read_cache(&page_cache, 0, &mut buf, aligned_max_offset);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert!(buf.iter().all(|b| *b == 42));
        });
    }

    #[test_traced]
    fn test_cache_at_high_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use a very small logical page size (CHECKSUM_SIZE + 1 = 13) with high offset.
            const MIN_PAGE_SIZE: u64 = CHECKSUM_SIZE + 1;
            let cache_ref = CacheRef::from_pooler(
                &context,
                NZU16!((MIN_PAGE_SIZE + CHECKSUM_SIZE) as u16),
                NZUsize!(2),
            );

            // Create two logical pages for caching.
            let first = vec![1u8; MIN_PAGE_SIZE as usize];
            let second = vec![1u8; MIN_PAGE_SIZE as usize];

            // Cache pages at a high (but not max) aligned offset so we can verify both pages.
            // Use an offset that's a few pages below max to avoid overflow when verifying.
            let aligned_max_offset = u64::MAX - (u64::MAX % MIN_PAGE_SIZE);
            let high_offset = aligned_max_offset - (MIN_PAGE_SIZE * 2);
            cache_ref
                .cache(0, vec![first.into(), second.into()], high_offset)
                .await;

            // Verify the first page was cached correctly.
            let mut buf = vec![0u8; MIN_PAGE_SIZE as usize];
            let page_cache = cache_ref.cache.read().await;
            assert_eq!(
                read_cache(&page_cache, 0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));

            // Verify the second page was cached correctly.
            assert_eq!(
                read_cache(&page_cache, 0, &mut buf, high_offset + MIN_PAGE_SIZE),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
        });
    }

    #[test_traced]
    fn test_cache_max_offset_single_byte_page_does_not_overflow_increment() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Smallest logical page size is 1, so physical must be 1 + CHECKSUM_SIZE.
            let cache_ref =
                CacheRef::from_pooler(&context, NZU16!((CHECKSUM_SIZE as u16) + 1), NZUsize!(1));
            assert_eq!(cache_ref.page_size(), 1);

            // Caching one page at the maximum offset should succeed without overflow panic.
            cache_ref
                .cache(0, vec![vec![0xABu8].into()], u64::MAX)
                .await;

            let mut buf = [0u8; 1];
            let page_cache = cache_ref.cache.read().await;
            let bytes_read = read_cache(&page_cache, 0, &mut buf, u64::MAX);
            assert_eq!(bytes_read, 1);
            assert_eq!(buf[0], 0xAB);
        });
    }

    #[test_traced]
    fn test_stale_fetch_entry_success_is_scavenged() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));
            let (blob, _) = context.open("test", b"stale_success").await.unwrap();

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(IoBuf::from(vec![
                9u8;
                PAGE_SIZE.get()
                    as usize
            ])))
            .boxed()
            .shared();
            let _ = stale.clone().await;
            let stale_state = Arc::new(PageFetchState { future: stale });
            {
                let mut cache = cache_ref.cache.write().await;
                cache
                    .page_fetches
                    .insert((0, 0), Arc::downgrade(&stale_state));
            }

            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), vec![9u8; 64].as_slice());

            let cache = cache_ref.cache.read().await;
            assert!(!cache.page_fetches.contains_key(&(0, 0)));
            assert!(cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_stale_fetch_entry_error_is_scavenged_and_refetched() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));
            let (blob, size) = context.open("test", b"stale_error").await.unwrap();
            assert_eq!(size, 0);

            // One CRC-protected page in backing storage.
            let logical_data = vec![7u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_data);
            let record = Checksum::new(PAGE_SIZE.get(), crc);
            let mut page_data = logical_data.clone();
            page_data.extend_from_slice(&record.to_bytes());
            blob.write_at(0, page_data).await.unwrap();

            let stale: PageFetchFut = ready(Err::<IoBuf, Arc<Error>>(Arc::new(Error::ReadFailed)))
                .boxed()
                .shared();
            let _ = stale.clone().await;
            let stale_state = Arc::new(PageFetchState { future: stale });
            {
                let mut cache = cache_ref.cache.write().await;
                cache
                    .page_fetches
                    .insert((0, 0), Arc::downgrade(&stale_state));
            }

            let read = cache_ref
                .read(&blob, 0, 0, PAGE_SIZE.get() as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), logical_data.as_slice());

            let cache = cache_ref.cache.read().await;
            assert!(!cache.page_fetches.contains_key(&(0, 0)));
            assert!(cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_stale_fetch_entry_for_other_key_does_not_block_progress() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context.open("test", b"stale_other_key").await.unwrap();
            assert_eq!(size, 0);

            let logical_data = vec![4u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_data);
            let record = Checksum::new(PAGE_SIZE.get(), crc);
            let mut page_data = logical_data.clone();
            page_data.extend_from_slice(&record.to_bytes());
            blob.write_at(0, page_data).await.unwrap();

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(IoBuf::from(vec![
                9u8;
                PAGE_SIZE.get()
                    as usize
            ])))
            .boxed()
            .shared();
            let _ = stale.clone().await;
            let stale_state = Arc::new(PageFetchState { future: stale });
            {
                let mut cache = cache_ref.cache.write().await;
                cache
                    .page_fetches
                    .insert((7, 7), Arc::downgrade(&stale_state));
            }

            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), vec![4u8; 64].as_slice());

            let cache = cache_ref.cache.read().await;
            assert!(cache.page_fetches.is_empty());
        });
    }

    #[test_traced]
    fn test_stale_fetch_success_does_not_overwrite_newer_ready_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));
            let newer = vec![6u8; PAGE_SIZE.get() as usize];
            cache_ref.cache(0, vec![newer.clone().into()], 0).await;

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(IoBuf::from(vec![
                1u8;
                PAGE_SIZE.get()
                    as usize
            ])))
            .boxed()
            .shared();
            let _ = stale.clone().await;
            let stale_state = Arc::new(PageFetchState { future: stale });
            {
                let mut cache = cache_ref.cache.write().await;
                cache
                    .page_fetches
                    .insert((0, 0), Arc::downgrade(&stale_state));
            }

            // Trigger scavenging through an insertion on another key.
            cache_ref
                .cache(
                    0,
                    vec![vec![9u8; PAGE_SIZE.get() as usize].into()],
                    PAGE_SIZE_U64,
                )
                .await;

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read().await;
            let bytes_read = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, newer);
            assert!(!cache.page_fetches.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_failed_fetch_marks_not_ready_and_retry_succeeds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context.open("test", b"failed_fetch_retry").await.unwrap();
            assert_eq!(size, 0);

            // Corrupt physical page (invalid CRC record).
            blob.write_at(0, vec![0u8; PHYSICAL_PAGE_SIZE.get() as usize])
                .await
                .unwrap();

            let err = cache_ref.read(&blob, 0, 0, 64).await.unwrap_err();
            assert!(matches!(err, Error::ReadFailed));

            {
                let cache = cache_ref.cache.read().await;
                assert!(!cache.page_fetches.contains_key(&(0, 0)));
                let slot = *cache
                    .index
                    .get(&(0, 0))
                    .expect("failed fetch must reserve a slot for this key");
                let entry = &cache.entries[slot];
                assert!(!entry.ready.load(Ordering::Relaxed));
                assert!(!entry.referenced.load(Ordering::Relaxed));
            }

            // Rewrite the same page with valid logical data + CRC and ensure retry succeeds.
            let logical_data = vec![5u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_data);
            let record = Checksum::new(PAGE_SIZE.get(), crc);
            let mut page_data = logical_data.clone();
            page_data.extend_from_slice(&record.to_bytes());
            blob.write_at(0, page_data).await.unwrap();

            let read = cache_ref
                .read(&blob, 0, 0, PAGE_SIZE.get() as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), logical_data.as_slice());

            let cache = cache_ref.cache.read().await;
            let slot = *cache.index.get(&(0, 0)).expect("page should be cached");
            let entry = &cache.entries[slot];
            assert!(entry.ready.load(Ordering::Relaxed));
        });
    }

    #[test_traced]
    fn test_fetch_buffer_allocates_physical_size_when_logical_recycle_is_too_small() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Use logical 4096 and physical 4108 to cross a common size-class boundary.
            let logical_page_size = 4096usize;
            let physical_page_size = logical_page_size + CHECKSUM_SIZE as usize;
            let physical_page_size = NonZeroU16::new(physical_page_size as u16).unwrap();
            let cache_ref = CacheRef::from_pooler(&context, physical_page_size, NZUsize!(1));

            let (blob, size) = context
                .open("test", b"fetch_buffer_physical_size")
                .await
                .unwrap();
            assert_eq!(size, 0);

            let logical_data = vec![0xAB; logical_page_size];
            let crc = Crc32::checksum(&logical_data);
            let record = Checksum::new(logical_page_size as u16, crc);
            let mut page_data = logical_data.clone();
            page_data.extend_from_slice(&record.to_bytes());
            blob.write_at(0, page_data).await.unwrap();

            // If the fetch buffer reused a logical-sized slot allocation, this read can panic
            // inside read_at_buf(set_len). We assert it succeeds and returns correct bytes.
            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &logical_data[..64]);
        });
    }

    #[test_traced]
    fn test_misses_with_single_slot_do_not_panic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context.open("test", b"concurrent_misses").await.unwrap();
            assert_eq!(size, 0);

            let page_size = PAGE_SIZE.get() as usize;
            let physical_page_size = PHYSICAL_PAGE_SIZE.get() as u64;

            let mut page0 = vec![11u8; page_size];
            let crc0 = Crc32::checksum(&page0);
            page0.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc0).to_bytes());
            blob.write_at(0, page0).await.unwrap();

            let mut page1 = vec![22u8; page_size];
            let crc1 = Crc32::checksum(&page1);
            page1.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc1).to_bytes());
            blob.write_at(physical_page_size, page1).await.unwrap();

            let fut0 = cache_ref.read(&blob, 0, 0, 64);
            let fut1 = cache_ref.read(&blob, 0, PAGE_SIZE_U64, 64);
            let (read0, read1) = futures::join!(fut0, fut1);

            assert_eq!(
                read0.unwrap().coalesce().as_ref(),
                vec![11u8; 64].as_slice()
            );
            assert_eq!(
                read1.unwrap().coalesce().as_ref(),
                vec![22u8; 64].as_slice()
            );

            let cache = cache_ref.cache.read().await;
            assert!(cache.page_fetches.is_empty());
            assert_eq!(cache.entries.len(), 1);
        });
    }

    #[derive(Clone)]
    struct BlockingBlob {
        logical_page_size: usize,
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
        fill: u8,
    }

    impl BlockingBlob {
        fn new(
            logical_page_size: usize,
            fill: u8,
        ) -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            (
                Self {
                    logical_page_size,
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    release: Arc::new(Mutex::new(Some(release_rx))),
                    fill,
                },
                started_rx,
                release_tx,
            )
        }
    }

    impl crate::Blob for BlockingBlob {
        async fn read_at_buf(
            &self,
            _offset: u64,
            len: usize,
            buf: impl Into<crate::IoBufsMut> + Send,
        ) -> Result<crate::IoBufsMut, crate::Error> {
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            let release = self.release.lock().take();
            if let Some(release) = release {
                let _ = release.await;
            }

            let mut page = vec![self.fill; self.logical_page_size];
            let crc = Crc32::checksum(&page);
            page.extend_from_slice(&Checksum::new(self.logical_page_size as u16, crc).to_bytes());
            assert_eq!(len, page.len());

            let mut out = buf.into();
            // SAFETY: we fully initialize `len` bytes immediately below with `copy_from_slice`.
            unsafe { out.set_len(len) };
            out.copy_from_slice(&page);
            Ok(out)
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<crate::IoBufsMut, crate::Error> {
            self.read_at_buf(offset, len, crate::IoBufMut::with_capacity(len))
                .await
        }

        async fn write_at(
            &self,
            _offset: u64,
            _buf: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), crate::Error> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct PendingBlob {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl PendingBlob {
        fn new() -> (Self, oneshot::Receiver<()>) {
            let (started_tx, started_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                },
                started_rx,
            )
        }
    }

    impl crate::Blob for PendingBlob {
        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _buf: impl Into<crate::IoBufsMut> + Send,
        ) -> Result<crate::IoBufsMut, crate::Error> {
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            pending::<()>().await;
            unreachable!("pending future never resolves")
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<crate::IoBufsMut, crate::Error> {
            self.read_at_buf(offset, len, crate::IoBufMut::with_capacity(len))
                .await
        }

        async fn write_at(
            &self,
            _offset: u64,
            _buf: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), crate::Error> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            Ok(())
        }
    }

    #[test_traced]
    fn test_cancelled_first_fetcher_unresolved_entry_is_scavenged() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (pending_blob, started_rx) = PendingBlob::new();

            let cache_ref_for_task = cache_ref.clone();
            let first_fetcher = context.clone().spawn(move |_| async move {
                let _ = cache_ref_for_task.read(&pending_blob, 0, 0, 64).await;
            });

            started_rx.await.expect("missing start signal");
            first_fetcher.abort();
            let _ = first_fetcher.await;

            {
                let cache = cache_ref.cache.read().await;
                let tombstone_or_absent = cache
                    .page_fetches
                    .get(&(0, 0))
                    .is_none_or(|entry| entry.strong_count() == 0);
                assert!(tombstone_or_absent);
            }

            // Independent reads continue to make progress after cancellation cleanup.
            let (blob, size) = context
                .open("test", b"scavenge_after_cancel")
                .await
                .unwrap();
            assert_eq!(size, 0);
            let mut page = vec![7u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&page);
            page.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc).to_bytes());
            blob.write_at(0, page).await.unwrap();

            let read = cache_ref.read(&blob, 1, 0, 16).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), vec![7u8; 16].as_slice());

            let cache = cache_ref.cache.read().await;
            assert!(!cache.page_fetches.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_cancelled_first_fetcher_cleanup_is_taken_over_by_waiter() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blocking_blob, started_rx, release_tx) =
                BlockingBlob::new(PAGE_SIZE.get() as usize, 3);

            let first_cache = cache_ref.clone();
            let first_blob = blocking_blob.clone();
            let first = context.clone().spawn(move |_| async move {
                let _ = first_cache.read(&first_blob, 0, 0, 64).await;
            });

            started_rx.await.expect("missing start signal");

            let second_cache = cache_ref.clone();
            let second_blob = blocking_blob.clone();
            let second = context.clone().spawn(move |_| async move {
                second_cache.read(&second_blob, 0, 0, 64).await.unwrap()
            });

            for _ in 0..16 {
                let ready = {
                    let cache = cache_ref.cache.read().await;
                    cache
                        .page_fetches
                        .get(&(0, 0))
                        .is_some_and(|entry| entry.strong_count() >= 2)
                };
                if ready {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            first.abort();
            let _ = first.await;
            release_tx.send(()).expect("failed to release fetch");

            let read = second.await.expect("waiter task failed").coalesce();
            assert_eq!(read.as_ref(), vec![3u8; 64].as_slice());

            let cache = cache_ref.cache.read().await;
            assert!(cache.page_fetches.is_empty());
            let slot = *cache.index.get(&(0, 0)).expect("expected cached page");
            assert!(cache.entries[slot].ready.load(Ordering::Relaxed));
        });
    }

    #[test_traced]
    fn test_stranded_unresolved_fetch_entry_is_scavenged() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));

            let stranded: PageFetchFut = async {
                pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            .boxed()
            .shared();
            let stranded_state = Arc::new(PageFetchState { future: stranded });

            {
                let mut cache = cache_ref.cache.write().await;
                cache
                    .page_fetches
                    .insert((42, 7), Arc::downgrade(&stranded_state));
            }
            drop(stranded_state);

            cache_ref
                .cache(0, vec![vec![0xAAu8; PAGE_SIZE.get() as usize].into()], 0)
                .await;

            let cache = cache_ref.cache.read().await;
            assert!(!cache.page_fetches.contains_key(&(42, 7)));
        });
    }

    #[test_traced]
    fn test_first_fetcher_result_does_not_overwrite_newer_ready_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blob, started_rx, release_tx) = BlockingBlob::new(PAGE_SIZE.get() as usize, 1);

            let cache_ref_for_task = cache_ref.clone();
            let read_task = context.spawn(move |_| async move {
                cache_ref_for_task.read(&blob, 0, 0, 64).await.unwrap()
            });

            started_rx.await.expect("missing start signal");

            // Install newer ready data for the same key while first fetch is still in-flight.
            let newer = vec![9u8; PAGE_SIZE.get() as usize];
            cache_ref.cache(0, vec![newer.clone().into()], 0).await;

            release_tx.send(()).expect("failed to release fetch");

            let fetched = read_task.await.expect("read task failed").coalesce();
            assert_eq!(fetched.as_ref(), vec![1u8; 64].as_slice());

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read().await;
            let bytes = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes, PAGE_SIZE.get() as usize);
            assert_eq!(buf, newer);
            assert!(cache.page_fetches.is_empty());
        });
    }
}

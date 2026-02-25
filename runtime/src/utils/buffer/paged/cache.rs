//! A page cache for serving _logical_ page reads from [Blob] data in memory.
//!
//! # Logical vs Physical Page Sizes
//!
//! [CacheRef::new] is configured with a physical page size (logical bytes plus CRC record bytes).
//! The logical page size is derived as:
//! `physical_page_size - CHECKSUM_SIZE`.
//!
//! Reads from this cache always return only logical bytes. Internally, slot backing allocations are
//! physical-page sized so fetch paths can reuse slot memory directly for blob I/O.
//!
//! # Memory Bound Semantics
//!
//! Cache capacity bounds resident cache slots, not total process memory retained by read results.
//! Returned [IoBuf] slices are reference-counted and can outlive eviction, so memory for evicted
//! pages can remain live until all readers drop their references.
//!
//! # Allocation Semantics
//!
//! - Initialization: [Cache::new] eagerly allocates `capacity` physical-page slot buffers via
//!   [BufferPool::alloc_zeroed].
//! - Cache insert/update path: [Cache::insert_page] reuses a slot allocation when uniquely
//!   owned. If the slot is still aliased by readers, it allocates a replacement from the pool.
//! - Miss/fetch path: [CacheRef::read_after_page_fault] reserves an evictable cache slot and reuses
//!   that slot's backing allocation for blob I/O. If the slot buffer is still aliased by readers,
//!   it allocates a replacement from the pool.
//! - Caller ownership: [CacheRef::cache] copies logical bytes into cache slots and does not retain
//!   caller-provided buffers.
//!
//! # Concurrency Semantics
//!
//! Reads first probe the cache under a read lock. On miss, page fetches are deduplicated per
//! `(blob_id, page_num)` through per-slot fetch state, so concurrent readers typically await one
//! shared in-flight fetch. Cleanup uses a per-fetch claim bit so only one task finalizes slot
//! state.

use super::{Checksum, CHECKSUM_SIZE};
use crate::{Blob, BufMut, BufferPool, BufferPooler, Error, IoBuf, IoBufs};
use commonware_utils::sync::RwLock;
use futures::{future::Shared, FutureExt};
use std::{
    collections::HashMap,
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{debug, error, trace};

/// One cache slot (metadata + page buffer).
struct Slot {
    /// Physical-page-sized backing buffer.
    buf: IoBuf,

    /// Current slot occupancy/fetch state.
    state: SlotState,
}

/// Current occupancy/fetch state for one cache slot.
enum SlotState {
    /// Slot has no assigned key.
    Vacant,
    /// Slot contains a cached logical page for `key`.
    Filled {
        key: (u64, u64),
        referenced: AtomicBool,
    },
    /// Slot is reserved for an in-flight fetch of `key`.
    Reserved {
        key: (u64, u64),
        fetch: Arc<PageFetchState>,
    },
}

/// Type alias for the future stored for each in-flight page fetch.
///
/// We wrap [enum@Error] in an Arc so it will be cloneable, which is required for the future to be
/// [Shared]. The IoBuf contains the fetched, CRC-validated page bytes from storage.
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<IoBuf, Arc<Error>>> + Send>>>;

/// Shared state for one in-flight page fetch.
struct PageFetchState {
    /// Shared future for fetching one page from storage.
    future: PageFetchFut,
    /// Single-winner bit: exactly one waiter may finalize slot cleanup.
    cleanup_claimed: AtomicBool,
}

impl PageFetchState {
    fn new(future: PageFetchFut) -> Self {
        Self {
            future,
            cleanup_claimed: AtomicBool::new(false),
        }
    }

    /// Returns true for exactly one caller, which becomes responsible for cleanup/finalization.
    #[inline]
    fn try_claim_cleanup(&self) -> bool {
        !self.cleanup_claimed.swap(true, Ordering::AcqRel)
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
    /// page to the index of its slot in `slots`.
    ///
    /// # Invariants
    ///
    /// Each `index` entry maps to exactly one `slots` entry whose key is identical and whose
    /// state is either [SlotState::Filled] or [SlotState::Reserved].
    index: HashMap<(u64, u64), usize>,

    /// Per-slot cache storage (metadata + page buffer).
    ///
    /// Slots are fixed-size and preallocated to `capacity`.
    ///
    /// For ready pages, only the logical prefix is used for cache reads. The suffix (CRC/trailing
    /// bytes) may still be present depending on write path.
    slots: Vec<Slot>,

    /// Logical size of each cached page in bytes.
    logical_page_size: usize,

    /// Physical size of each page in bytes.
    physical_page_size: usize,

    /// The Clock replacement policy's clock hand index into `slots`.
    clock: usize,

    /// The maximum number of pages that will be cached.
    capacity: usize,

    /// Pool used for replacement allocations when a slot buffer is shared by readers.
    pool: BufferPool,
}

/// A shareable handle to a page cache.
///
/// [CacheRef] owns the sizing configuration and provides thread-safe cache operations for multiple
/// blobs identified by caller-provided blob ids.
#[derive(Clone)]
pub struct CacheRef {
    /// The logical size of each page in the underlying blobs managed by this page cache.
    ///
    /// # Warning
    ///
    /// You cannot change the page size once data has been written without invalidating it. (Reads
    /// on blobs that were written with a different page size will fail their integrity check.)
    logical_page_size: u64,

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
    /// `physical_page_size` is the on-disk page size, including checksum record bytes.
    ///
    /// The cache stores at most `capacity` pages, each exactly one logical page worth of bytes
    /// (`physical_page_size - CHECKSUM_SIZE`).
    /// Initialization eagerly allocates and zeroes all cache slots from `pool`.
    ///
    /// Capacity bounds the number of resident slots in this cache. Read results may outlive
    /// eviction and retain memory until dropped by readers.
    pub fn new(pool: BufferPool, physical_page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let physical_page_size = physical_page_size.get() as u64;
        assert!(
            physical_page_size > CHECKSUM_SIZE,
            "physical page size must be larger than checksum record"
        );
        let logical_page_size =
            NonZeroU16::new((physical_page_size - CHECKSUM_SIZE) as u16).unwrap();

        Self {
            logical_page_size: logical_page_size.get() as u64,
            next_id: Arc::new(AtomicU64::new(0)),
            cache: Arc::new(RwLock::new(Cache::new(
                pool.clone(),
                physical_page_size as usize,
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

    /// Returns the physical page size used by the underlying blob format.
    ///
    /// This is always `logical_page_size() + CHECKSUM_SIZE`.
    #[inline]
    pub const fn physical_page_size(&self) -> u64 {
        self.logical_page_size + CHECKSUM_SIZE
    }

    /// Returns the logical page size used by this page cache.
    ///
    /// This is the per-page byte count returned by cache reads.
    #[inline]
    pub const fn logical_page_size(&self) -> u64 {
        self.logical_page_size
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
    /// Returns `(buffers, bytes_read)` where `buffers` is the contiguous cached prefix starting at
    /// `logical_offset`. This method never performs blob I/O and can return fewer than `len` bytes
    /// on the first miss.
    pub(super) fn read_cached(
        &self,
        blob_id: u64,
        mut logical_offset: u64,
        len: usize,
    ) -> (IoBufs, usize) {
        let mut remaining = len;
        let mut out = IoBufs::default();
        let page_cache = self.cache.read();
        while remaining > 0 {
            let Some(page) = page_cache.read_at(blob_id, logical_offset, remaining) else {
                // Cache miss - return how many bytes we successfully read
                break;
            };
            remaining -= page.len();
            logical_offset += page.len() as u64;
            out.append(page);
        }
        (out, len - remaining)
    }

    /// Read `len` bytes for `[logical_offset, logical_offset + len)`.
    ///
    /// This is the convenience form that starts from an empty output buffer. For continuation
    /// reads with an already-cached prefix, use [Self::read_append].
    pub(super) async fn read<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        logical_offset: u64,
        len: usize,
    ) -> Result<IoBufs, Error> {
        let mut result = IoBufs::default();
        self.read_append(blob, blob_id, logical_offset, len, &mut result)
            .await?;
        Ok(result)
    }

    /// Append `len` bytes into `result` starting at absolute `logical_offset`.
    ///
    /// Existing bytes in `result` are preserved. This method only appends new bytes and does not
    /// reinterpret `logical_offset` relative to `result`.
    ///
    /// Callers should pass the absolute start of the missing suffix range in `logical_offset`.
    /// For example, if `cached_len` bytes were already appended from `start_offset`, pass
    /// `logical_offset = start_offset + cached_len`.
    ///
    /// Typical usage:
    /// - `read_cached(...)` fills an initial prefix
    /// - `read_append(...)` fetches and appends the remainder
    pub(super) async fn read_append<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        mut logical_offset: u64,
        len: usize,
        result: &mut IoBufs,
    ) -> Result<(), Error> {
        let mut remaining = len;

        // Read up to a page worth of data at a time from either the page cache or the `blob`,
        // until the requested data is fully read.
        while remaining > 0 {
            // Probe cache first under read lock.
            if let Some(page) = {
                let page_cache = self.cache.read();
                page_cache.read_at(blob_id, logical_offset, remaining)
            } {
                remaining -= page.len();
                logical_offset += page.len() as u64;
                result.append(page);
                continue;
            }

            // Handle page fault.
            let page = self
                .read_after_page_fault(blob, blob_id, logical_offset, remaining)
                .await?;
            remaining -= page.len();
            logical_offset += page.len() as u64;
            result.append(page);
        }

        Ok(())
    }

    /// Resolve one page miss for `(blob_id, page_num)`.
    ///
    /// If another task is already fetching this key, joins that in-flight shared future.
    /// Otherwise reserves an evictable slot, fetches into that slot's backing allocation, validates
    /// the physical page, and marks the slot ready.
    ///
    /// If no slot can be reserved because all slots are currently in `Fetching` state, performs an
    /// untracked fetch and returns bytes directly without caching.
    ///
    /// Locking semantics:
    /// - cache read/write locks are only used for short state transitions and cache probes
    /// - no storage I/O is awaited while holding a cache lock
    /// - exactly one waiter finalizes per-fetch slot state via [PageFetchState::try_claim_cleanup]
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

        let key = (blob_id, page_num);
        // Exactly one of these is populated before we leave the loop:
        // - `tracked`: fetch is represented in cache state and needs post-await finalization.
        // - `uncached`: fallback fetch when no slot is currently reservable.
        let mut tracked: Option<(Arc<PageFetchState>, usize)> = None;
        let mut uncached: Option<PageFetchFut> = None;
        loop {
            // There's a (small) chance the page was fetched and installed before we acquired
            // locks, so probe under a read lock before doing anything else.
            if let Some(page) = {
                let cache = self.cache.read();
                cache.read_at(blob_id, offset, max_len)
            } {
                return Ok(page);
            }

            // Create or join a future that retrieves this page from the underlying blob. This
            // requires a write lock since we may need to update per-slot fetch state.
            let mut cache = self.cache.write();

            // Re-check after acquiring write lock in case another task raced and installed it.
            if let Some(page) = cache.read_at(blob_id, offset, max_len) {
                return Ok(page);
            }

            // Check whether there's an on-going fetch for this key.
            if let Some((slot, state)) = cache.fetch_for_key(key) {
                if let Some(stale) = state.future.peek().cloned() {
                    // Cleanup stale resolved fetch state left by a cancelled first fetcher.
                    if state.try_claim_cleanup() {
                        cache.finish_fetch_if_current(slot, key, &state, stale);
                    }
                    continue;
                }

                // Another task is already fetching this page, so join its existing shared future.
                tracked = Some((state, slot));
                break;
            }

            let Some(slot) = cache.reserve_slot() else {
                // All slots are currently reserved for in-flight fetches. Fall back to an
                // uncached fetch so we can still serve this read. This is very unlikely
                // to happen in practice.
                uncached = Some(self.make_fetch_future(
                    blob.clone(),
                    page_num,
                    self.pool.alloc(self.physical_page_size() as usize),
                ));
                break;
            };

            // Nobody is currently fetching this page. Create a new shared future and reserve this
            // slot for it.
            let fetch_buf = cache.take_slot_buffer(slot);
            let state = Arc::new(PageFetchState::new(self.make_fetch_future(
                blob.clone(),
                page_num,
                fetch_buf,
            )));
            // Publish `(key -> slot)` + Reserved state atomically under this lock so followers can
            // join this fetch instead of launching duplicates.
            cache.index.insert(key, slot);
            cache.set_fetching(slot, key, state.clone());
            tracked = Some((state, slot));
            break;
        }

        if let Some(uncached) = uncached {
            // Uncached fallback path: await and return directly without touching cache state.
            return match uncached.await {
                Ok(page) => {
                    let bytes =
                        std::cmp::min(max_len, self.logical_page_size as usize - offset_in_page);
                    Ok(page.slice(offset_in_page..offset_in_page + bytes))
                }
                Err(err) => {
                    error!(page_num, ?err, "Page fetch failed");
                    Err(Error::ReadFailed)
                }
            };
        }

        let (fetch_state, fetch_slot) =
            tracked.expect("page fault must resolve to tracked or uncached fetch");

        // Await the shared fetch result. Exactly one waiter claims cleanup and finalizes slot
        // state.
        let fetch_result = fetch_state.future.clone().await;
        if fetch_state.try_claim_cleanup() {
            let mut cache = self.cache.write();
            cache.finish_fetch_if_current(fetch_slot, key, &fetch_state, fetch_result.clone());
        }

        match fetch_result {
            Ok(page) => {
                let bytes =
                    std::cmp::min(max_len, self.logical_page_size as usize - offset_in_page);
                Ok(page.slice(offset_in_page..offset_in_page + bytes))
            }
            Err(err) => {
                error!(page_num, ?err, "Page fetch failed");
                Err(Error::ReadFailed)
            }
        }
    }

    /// Build a shareable fetch future that reads one physical page and validates it.
    ///
    /// The returned buffer is the fetched physical page bytes. Callers consume only the logical
    /// prefix via [Self::logical_page_size].
    ///
    /// This function does not touch cache state, it only performs the storage read + CRC checks.
    fn make_fetch_future<B: Blob>(
        &self,
        blob: B,
        page_num: u64,
        buf: crate::IoBufMut,
    ) -> PageFetchFut {
        let logical_page_size = self.logical_page_size;
        let physical_page_size = self.physical_page_size();
        async move {
            let physical_page_start = page_num * physical_page_size;
            let page = blob
                .read_at_buf(physical_page_start, physical_page_size as usize, buf)
                .await
                .map_err(Arc::new)?
                .coalesce();
            let Some(record) = Checksum::validate_page(page.as_ref()) else {
                return Err(Arc::new(Error::InvalidChecksum));
            };
            // We should never fetch partial pages through the page cache. This can happen if a
            // non-last page is corrupted and falls back to a partial CRC.
            let (len, _) = record.get_crc();
            if len as u64 != logical_page_size {
                error!(
                    page_num,
                    expected = logical_page_size,
                    actual = len as u64,
                    "attempted to fetch partial page from blob"
                );
                return Err(Arc::new(Error::InvalidChecksum));
            }
            // Keep fetched physical-page bytes in slot backing so subsequent fetches can reuse
            // physical-sized allocations without extra pool churn.
            Ok(page.freeze())
        }
        .boxed()
        .shared()
    }

    /// Cache full logical pages from a contiguous logical-byte prefix.
    ///
    /// `logical_pages` is interpreted as a contiguous sequence of exactly `page_count` logical
    /// pages starting at `offset`. `offset` must be logical-page aligned.
    ///
    /// This method copies bytes into cache slots and is best effort: if insertion fails (for
    /// example, all slots are currently fetching and no slot is reservable), remaining pages are
    /// dropped after logging an error.
    /// This does not affect correctness; it only reduces cache hit rate.
    ///
    /// Locking semantics: this method acquires the cache write lock once and inserts as many pages
    /// as it can from the provided prefix.
    ///
    /// # Panics
    ///
    /// Panics if `offset` is not page aligned or if `logical_pages` does not contain enough bytes
    /// for `page_count` full logical pages.
    pub fn cache(&self, blob_id: u64, logical_pages: &IoBuf, offset: u64, page_count: usize) {
        if page_count == 0 {
            return;
        }
        let logical_page_size = self.logical_page_size as usize;
        let required_len = page_count * logical_page_size;
        assert!(required_len <= logical_pages.len());

        // Copy directly into cache slots.
        let logical_bytes = logical_pages.as_ref();
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);

        let mut page_idx = 0;
        let mut cache = self.cache.write();
        while page_idx < page_count {
            let current_page = page_num;
            let page_start = page_idx * logical_page_size;
            let page = &logical_bytes[page_start..page_start + logical_page_size];
            // Best-effort semantics: if no slot is reservable right now, stop caching.
            if cache.insert_page((blob_id, current_page), page).is_err() {
                error!(
                    blob_id,
                    page_num = current_page,
                    dropped_pages = page_count - page_idx,
                    "failed to cache pages"
                );
                return;
            }

            page_idx += 1;
            if page_idx < page_count {
                page_num = page_num
                    .checked_add(1)
                    .expect("page number overflow while caching");
            }
        }
    }
}

impl Cache {
    /// Return an empty page cache with capacity `capacity` logical pages of size
    /// `logical_page_size` and backing buffers sized for `physical_page_size`.
    ///
    /// Slot storage is eagerly allocated and zero-initialized.
    pub fn new(
        pool: BufferPool,
        physical_page_size: usize,
        logical_page_size: NonZeroU16,
        capacity: NonZeroUsize,
    ) -> Self {
        let logical_page_size = logical_page_size.get() as usize;
        assert!(
            physical_page_size >= logical_page_size,
            "physical page size must be >= logical page size"
        );
        let capacity = capacity.get();

        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(Slot {
                buf: pool.alloc_zeroed(physical_page_size).freeze(),
                state: SlotState::Vacant,
            });
        }

        Self {
            index: HashMap::new(),
            slots,
            logical_page_size,
            physical_page_size,
            clock: 0,
            capacity,
            pool,
        }
    }

    /// Returns the cached page for the given slot index.
    #[inline]
    fn page(&self, slot: usize) -> &IoBuf {
        assert!(slot < self.capacity);
        &self.slots[slot].buf
    }

    /// Convert an offset into the number of the page it belongs to and the offset within that page.
    const fn offset_to_page(logical_page_size: u64, offset: u64) -> (u64, u64) {
        (offset / logical_page_size, offset % logical_page_size)
    }

    /// Attempt to fetch blob data starting at `logical_offset` from the page cache.
    ///
    /// Returns `None` if the first page in the requested range isn't buffered.
    /// Returned bytes never cross a page boundary.
    ///
    /// This method only serves [SlotState::Filled] entries. Reserved in-flight entries are
    /// treated as misses.
    fn read_at(&self, blob_id: u64, logical_offset: u64, max_len: usize) -> Option<IoBuf> {
        let (page_num, offset_in_page) =
            Self::offset_to_page(self.logical_page_size as u64, logical_offset);
        let key = (blob_id, page_num);
        let slot = *self.index.get(&key)?;
        let SlotState::Filled {
            key: state_key,
            referenced,
        } = &self.slots[slot].state
        else {
            return None;
        };
        assert_eq!(*state_key, key);
        referenced.store(true, Ordering::Relaxed);

        let page = self.page(slot);
        // Serve only logical bytes even if slot backing currently includes CRC/trailing bytes.
        let bytes = std::cmp::min(max_len, self.logical_page_size - offset_in_page as usize);
        let end = offset_in_page as usize + bytes;
        assert!(page.len() >= end);
        Some(page.slice(offset_in_page as usize..end))
    }

    /// Put a page into the cache by copying bytes into the target slot.
    ///
    /// If the destination slot is uniquely owned, its existing allocation is reused.
    /// If the slot is shared by readers, a replacement allocation is taken from `pool`.
    ///
    /// Returns `Err(())` only when no slot is currently reservable.
    fn insert_page(&mut self, key: (u64, u64), page: &[u8]) -> Result<(), ()> {
        // Duplicate key update: reuse the same slot.
        let slot = if let Some(&slot) = self.index.get(&key) {
            let (blob_id, page_num) = key;
            match &self.slots[slot].state {
                SlotState::Filled {
                    key: state_key,
                    referenced,
                } => {
                    debug!(blob_id, page_num, "updating duplicate page");
                    assert_eq!(*state_key, key);
                    referenced.store(true, Ordering::Relaxed);
                }
                SlotState::Reserved { key: state_key, .. } => {
                    // A flush is inserting a page for a key that has an in-flight fetch.
                    // The flush data is authoritative, so we overwrite the Reserved slot.
                    debug!(
                        blob_id,
                        page_num, "overwriting reserved slot with flush data"
                    );
                    assert_eq!(*state_key, key);
                }
                SlotState::Vacant => {
                    unreachable!("index entry must point to Filled or Reserved slot");
                }
            }
            slot
        } else {
            // New key insert: reserve/evict one slot, then bind this key to it.
            let Some(slot) = self.reserve_slot() else {
                return Err(());
            };
            self.index.insert(key, slot);
            slot
        };
        assert_eq!(page.len(), self.logical_page_size);

        let mut dst = self.take_slot_buffer(slot);
        dst.put_slice(page);
        self.slots[slot].buf = dst.freeze();
        self.slots[slot].state = SlotState::Filled {
            key,
            referenced: AtomicBool::new(true),
        };
        Ok(())
    }

    /// Return the in-flight fetch state for `key`, if any.
    ///
    /// Only returns entries that are currently in [SlotState::Reserved] for the exact same key.
    fn fetch_for_key(&self, key: (u64, u64)) -> Option<(usize, Arc<PageFetchState>)> {
        let slot = *self.index.get(&key)?;
        match &self.slots[slot].state {
            SlotState::Reserved {
                key: state_key,
                fetch,
            } if *state_key == key => Some((slot, fetch.clone())),
            SlotState::Vacant | SlotState::Filled { .. } | SlotState::Reserved { .. } => None,
        }
    }

    /// Reserve an evictable slot.
    ///
    /// Pass 1 prefers vacant (no key) or unreferenced ready pages while clearing reference bits.
    /// Pass 2 force-selects the first non-fetching slot if needed.
    ///
    /// Orphaned reserved entries (no active waiters) are reclaimed opportunistically.
    /// Returns `None` only when every slot is currently in [`SlotState::Reserved`] with active
    /// waiters. In that case, the caller should fall back to an uncached fetch. This is expected
    /// to be rare in practice: it requires that every cache slot has a concurrent in-flight I/O
    /// with at least one live waiter, and the new miss targets a key not already being fetched.
    fn reserve_slot(&mut self) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }

        let mut chosen = None;
        for _ in 0..self.capacity {
            let slot = self.clock;
            self.clock = (self.clock + 1) % self.capacity;
            self.reclaim_reserved_slot(slot);
            let slot_ref = &self.slots[slot];
            match &slot_ref.state {
                // Empty slot: immediately usable.
                SlotState::Vacant => {
                    chosen = Some(slot);
                    break;
                }
                // In-flight fetches cannot be stolen.
                SlotState::Reserved { .. } => continue,
                SlotState::Filled { referenced, .. } => {
                    // Clock second-chance: clear the ref bit on first pass; pick it if already cold.
                    if referenced.swap(false, Ordering::Relaxed) {
                        continue;
                    }
                    chosen = Some(slot);
                    break;
                }
            }
        }

        if chosen.is_none() {
            for _ in 0..self.capacity {
                let slot = self.clock;
                self.clock = (self.clock + 1) % self.capacity;
                self.reclaim_reserved_slot(slot);
                let slot_ref = &self.slots[slot];
                match &slot_ref.state {
                    // Force progress on pass 2 by accepting any non-fetching slot.
                    SlotState::Vacant | SlotState::Filled { .. } => {
                        chosen = Some(slot);
                        break;
                    }
                    SlotState::Reserved { .. } => continue,
                }
            }
        }

        let slot = chosen?;
        self.evict_slot(slot);
        Some(slot)
    }

    /// Reclaim a reserved slot if its fetch is already resolved or orphaned.
    ///
    /// A slot is considered orphaned when the cache holds the only `Arc<PageFetchState>`,
    /// which means no task can still await/finish that fetch.
    fn reclaim_reserved_slot(&mut self, slot: usize) {
        enum Reclaim {
            Finalize {
                key: (u64, u64),
                state: Arc<PageFetchState>,
                result: Result<IoBuf, Arc<Error>>,
            },
            Evict,
        }

        let action = match &self.slots[slot].state {
            SlotState::Reserved { key, fetch } => fetch.future.peek().cloned().map_or_else(
                || {
                    if Arc::strong_count(fetch) == 1 {
                        Some(Reclaim::Evict)
                    } else {
                        None
                    }
                },
                |result| {
                    if fetch.try_claim_cleanup() {
                        Some(Reclaim::Finalize {
                            key: *key,
                            state: fetch.clone(),
                            result,
                        })
                    } else {
                        None
                    }
                },
            ),
            SlotState::Vacant | SlotState::Filled { .. } => None,
        };

        match action {
            Some(Reclaim::Finalize { key, state, result }) => {
                self.finish_fetch_if_current(slot, key, &state, result);
            }
            Some(Reclaim::Evict) => self.evict_slot(slot),
            None => {}
        }
    }

    /// Convert a slot to fetching state.
    ///
    /// Caller must already have inserted `key -> slot` into `index` under the same lock.
    fn set_fetching(&mut self, slot: usize, key: (u64, u64), state: Arc<PageFetchState>) {
        self.slots[slot].state = SlotState::Reserved { key, fetch: state };
    }

    /// Finalize fetch completion for `key` if `slot` still tracks `state`.
    ///
    /// This defends against races where slot/key ownership changed while the fetch was in-flight.
    fn finish_fetch_if_current(
        &mut self,
        slot: usize,
        key: (u64, u64),
        state: &Arc<PageFetchState>,
        result: Result<IoBuf, Arc<Error>>,
    ) {
        if self.slots.get(slot).is_none() {
            return;
        }
        let is_current = match &self.slots[slot].state {
            SlotState::Reserved {
                key: state_key,
                fetch,
            } => *state_key == key && Arc::ptr_eq(fetch, state),
            SlotState::Vacant | SlotState::Filled { .. } => false,
        };
        // Slot ownership changed while this fetch was in-flight, treat this result as stale.
        if !is_current {
            return;
        }

        match result {
            Ok(page) => {
                if page.len() < self.logical_page_size {
                    error!(
                        ?key,
                        page_len = page.len(),
                        logical_page_size = self.logical_page_size,
                        "fetched page shorter than logical page size"
                    );
                    self.evict_slot(slot);
                    return;
                }
                // `page` may include a physical suffix, reads remain bounded to logical size.
                let slot_ref = &mut self.slots[slot];
                slot_ref.buf = page;
                slot_ref.state = SlotState::Filled {
                    key,
                    referenced: AtomicBool::new(true),
                };
            }
            Err(_) => {
                self.evict_slot(slot);
            }
        }
    }

    /// Take a writable slot buffer for fetch or cache refill.
    ///
    /// Reuses the existing slot allocation when uniquely owned; otherwise allocates from the pool.
    fn take_slot_buffer(&mut self, slot: usize) -> crate::IoBufMut {
        let current = std::mem::take(&mut self.slots[slot].buf);
        match current.try_into_mut() {
            Ok(mut writable) => {
                assert!(writable.capacity() >= self.physical_page_size);
                writable.clear();
                writable
            }
            // Slot buffer is aliased by readers
            Err(_) => self.pool.alloc(self.physical_page_size),
        }
    }

    /// Evict any key currently assigned to `slot`, leaving the slot vacant.
    fn evict_slot(&mut self, slot: usize) {
        let slot_ref = &mut self.slots[slot];
        // Remove reverse index entry first, then clear slot state.
        let key = match &slot_ref.state {
            SlotState::Vacant => None,
            SlotState::Filled { key, .. } | SlotState::Reserved { key, .. } => Some(*key),
        };
        if let Some(old_key) = key {
            if self.index.remove(&old_key).is_none() {
                error!(?old_key, "cache index missing entry during eviction");
            }
        }
        slot_ref.state = SlotState::Vacant;
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

    fn cache_pages(cache_ref: &CacheRef, blob_id: u64, pages: Vec<IoBuf>, offset: u64) {
        if pages.is_empty() {
            return;
        }
        let mut logical_pages = cache_ref.pool().alloc(
            pages
                .iter()
                .map(IoBuf::len)
                .fold(0usize, usize::saturating_add),
        );
        for page in &pages {
            logical_pages.put_slice(page.as_ref());
        }
        let logical_pages = logical_pages.freeze();
        cache_ref.cache(blob_id, &logical_pages, offset, pages.len());
    }

    fn install_fetch_state(cache_ref: &CacheRef, key: (u64, u64), state: Arc<PageFetchState>) {
        let mut cache = cache_ref.cache.write();
        let slot = cache.reserve_slot().expect("failed to reserve cache slot");
        cache.index.insert(key, slot);
        cache.set_fetching(slot, key, state);
    }

    fn is_fetching(cache: &Cache, key: (u64, u64)) -> bool {
        let Some(&slot) = cache.index.get(&key) else {
            return false;
        };
        matches!(cache.slots[slot].state, SlotState::Reserved { .. })
    }

    /// Test blob that optionally blocks one read, then returns a valid physical page payload.
    ///
    /// Used by cancellation/takeover tests that need deterministic fetch ordering and successful
    /// page completion.
    #[derive(Clone)]
    struct BlockingBlob {
        logical_page_size: usize,
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
        fill: u8,
    }

    impl BlockingBlob {
        /// Build a blob that blocks one read until released via the returned sender.
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

    /// Test blob that signals read start and then never resolves.
    ///
    /// Used to model a cancelled first fetcher leaving an unresolved in-flight fetch state.
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
    fn test_cache_basic() {
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache: Cache = Cache::new(
            pool,
            PHYSICAL_PAGE_SIZE.get() as usize,
            PAGE_SIZE,
            NZUsize!(10),
        );

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        let page = vec![1; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Test replacement -- should log a duplicate page warning but still work.
        let page = vec![2; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        let bytes_read = read_cache(&cache, 0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        // Test exceeding the cache capacity.
        for i in 0u64..11 {
            let page = vec![i as u8; PAGE_SIZE.get() as usize];
            assert!(cache.insert_page((0, i), page.as_slice()).is_ok());
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
        let mut cache: Cache = Cache::new(
            pool,
            PHYSICAL_PAGE_SIZE.get() as usize,
            PAGE_SIZE,
            NZUsize!(1),
        );

        let page = vec![1; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        let held = cache
            .read_at(0, 0, PAGE_SIZE.get() as usize)
            .expect("page should be cached");

        // Evict slot with a different page while `held` still aliases the old slot data.
        // This exercises the overwrite fallback path where slot recycling is not possible.
        let page = vec![2; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 1), page.as_slice()).is_ok());
        assert_eq!(cache.slots.len(), 1);
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
            cache_pages(&cache_ref, 0, vec![page.clone().into()], 0);

            let (cached, cached_len) = cache_ref.read_cached(0, 0, PAGE_SIZE.get() as usize * 2);
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
            cache_pages(&cache_ref, 0, vec![logical_data.into()], aligned_max_offset);

            // Reading from the cache should return the logical bytes.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let page_cache = cache_ref.cache.read();
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
            cache_pages(
                &cache_ref,
                0,
                vec![first.into(), second.into()],
                high_offset,
            );

            // Verify the first page was cached correctly.
            let mut buf = vec![0u8; MIN_PAGE_SIZE as usize];
            let page_cache = cache_ref.cache.read();
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
            assert_eq!(cache_ref.logical_page_size(), 1);

            // Caching one page at the maximum offset should succeed without overflow panic.
            cache_pages(&cache_ref, 0, vec![vec![0xABu8].into()], u64::MAX);

            let mut buf = [0u8; 1];
            let page_cache = cache_ref.cache.read();
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
            install_fetch_state(&cache_ref, (0, 0), Arc::new(PageFetchState::new(stale)));

            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), vec![9u8; 64].as_slice());

            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (0, 0)));
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
            install_fetch_state(&cache_ref, (0, 0), Arc::new(PageFetchState::new(stale)));

            let read = cache_ref
                .read(&blob, 0, 0, PAGE_SIZE.get() as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), logical_data.as_slice());

            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (0, 0)));
            assert!(cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_stale_fetch_entry_for_other_key_is_reclaimed() {
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
            install_fetch_state(&cache_ref, (7, 7), Arc::new(PageFetchState::new(stale)));

            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), vec![4u8; 64].as_slice());

            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (7, 7)));
            assert!(!cache.index.contains_key(&(7, 7)));
        });
    }

    #[test_traced]
    fn test_stale_fetch_success_for_other_key_does_not_overwrite_ready_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(3));
            let newer = vec![6u8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![newer.clone().into()], 0);

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(IoBuf::from(vec![
                1u8;
                PAGE_SIZE.get()
                    as usize
            ])))
            .boxed()
            .shared();
            let _ = stale.clone().await;
            install_fetch_state(&cache_ref, (7, 7), Arc::new(PageFetchState::new(stale)));

            // Insert on another key. This should not affect ready data for key (0, 0).
            cache_pages(
                &cache_ref,
                0,
                vec![vec![9u8; PAGE_SIZE.get() as usize].into()],
                PAGE_SIZE_U64,
            );

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read();
            let bytes_read = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, newer);
            assert!(is_fetching(&cache, (7, 7)));
        });
    }

    #[test_traced]
    fn test_failed_fetch_does_not_leave_placeholder_and_retry_succeeds() {
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
                let cache = cache_ref.cache.read();
                assert!(
                    !cache.index.contains_key(&(0, 0)),
                    "failed fetch must not install a cache placeholder"
                );
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

            let cache = cache_ref.cache.read();
            assert!(cache.index.contains_key(&(0, 0)));
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

            let cache = cache_ref.cache.read();
            assert_eq!(cache.slots.len(), 1);
            assert!(!is_fetching(&cache, (0, 0)));
        });
    }

    #[test_traced]
    fn test_cancelled_first_fetcher_unresolved_entry_persists_until_completion() {
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

            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (0, 0)));
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

            context.sleep(Duration::from_millis(1)).await;

            first.abort();
            let _ = first.await;
            release_tx.send(()).expect("failed to release fetch");

            let read = second.await.expect("waiter task failed").coalesce();
            assert_eq!(read.as_ref(), vec![3u8; 64].as_slice());

            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (0, 0)));
            assert!(cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_stranded_unresolved_fetch_entry_is_reclaimed_for_other_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));

            let stranded: PageFetchFut = async {
                pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            .boxed()
            .shared();
            install_fetch_state(&cache_ref, (42, 7), Arc::new(PageFetchState::new(stranded)));

            cache_pages(
                &cache_ref,
                0,
                vec![vec![0xAAu8; PAGE_SIZE.get() as usize].into()],
                0,
            );

            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (42, 7)));
            assert!(cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_reserved_fetch_with_live_waiter_is_not_reclaimed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));

            let pending_fut: PageFetchFut = async {
                pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            .boxed()
            .shared();
            let state = Arc::new(PageFetchState::new(pending_fut));
            let waiter_ref = state.clone();
            install_fetch_state(&cache_ref, (42, 7), state);

            cache_pages(
                &cache_ref,
                0,
                vec![vec![0xAAu8; PAGE_SIZE.get() as usize].into()],
                0,
            );

            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (42, 7)));
            assert!(!cache.index.contains_key(&(0, 0)));
            drop(waiter_ref);
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

            // Install newer cached data for the same key while first fetch is still in-flight.
            let newer = vec![9u8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![newer.clone().into()], 0);

            release_tx.send(()).expect("failed to release fetch");

            let fetched = read_task.await.expect("read task failed").coalesce();
            assert_eq!(fetched.as_ref(), vec![1u8; 64].as_slice());

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read();
            let bytes = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes, PAGE_SIZE.get() as usize);
            assert_eq!(buf, newer);
            assert!(!is_fetching(&cache, (0, 0)));
        });
    }

    #[test_traced]
    fn test_all_slots_reserved_falls_back_to_uncached_fetch() {
        // When every cache slot is Reserved with a live waiter, a miss for a different key
        // should fall back to an uncached fetch and still return correct data.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context
                .open("test", b"all_reserved_fallback")
                .await
                .unwrap();
            assert_eq!(size, 0);

            // Write two valid physical pages to backing storage.
            let page_size = PAGE_SIZE.get() as usize;
            let physical_page_size = PHYSICAL_PAGE_SIZE.get() as u64;

            let logical0 = vec![0xAAu8; page_size];
            let crc0 = Crc32::checksum(&logical0);
            let mut phys0 = logical0.clone();
            phys0.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc0).to_bytes());
            blob.write_at(0, phys0).await.unwrap();

            let logical1 = vec![0xBBu8; page_size];
            let crc1 = Crc32::checksum(&logical1);
            let mut phys1 = logical1.clone();
            phys1.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc1).to_bytes());
            blob.write_at(physical_page_size, phys1).await.unwrap();

            // Fill the only slot with a Reserved entry that has a live waiter.
            let pending_fut: PageFetchFut = async {
                pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            .boxed()
            .shared();
            let state = Arc::new(PageFetchState::new(pending_fut));
            let _waiter = state.clone(); // keep strong count > 1
            install_fetch_state(&cache_ref, (42, 0), state);

            // Read a different key. All slots are reserved so this must use the uncached path.
            let read = cache_ref
                .read(&blob, 0, PAGE_SIZE_U64, 64)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), vec![0xBBu8; 64].as_slice());

            // The reserved slot for the other key should still be intact.
            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (42, 0)));
        });
    }

    #[test_traced]
    fn test_insert_page_overwrites_reserved_slot() {
        // When a flush inserts a page for a key that has an in-flight Reserved fetch,
        // the insert should overwrite the slot with Filled state.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(2));

            // Install a Reserved slot for key (0, 0).
            let pending_fut: PageFetchFut = async {
                pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            .boxed()
            .shared();
            install_fetch_state(
                &cache_ref,
                (0, 0),
                Arc::new(PageFetchState::new(pending_fut)),
            );

            {
                let cache = cache_ref.cache.read();
                assert!(is_fetching(&cache, (0, 0)));
            }

            // Insert a page for the same key via the flush path.
            let page_data = vec![0xCCu8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![page_data.clone().into()], 0);

            // The slot should now be Filled, not Reserved.
            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (0, 0)));
            let bytes_read = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, page_data);
        });
    }
}

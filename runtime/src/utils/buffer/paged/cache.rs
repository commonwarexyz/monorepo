//! A page cache for serving logical page reads from [Blob] data in memory.
//!
//! The cache stores validated physical pages (`page_size + CHECKSUM_SIZE`) in reusable slot
//! buffers, but all public read helpers expose only logical bytes. Callers therefore receive
//! immutable [IoBuf] slices or segmented [IoBufs] views over the cached logical ranges without any
//! checksum bytes.
//!
//! Reads are zero-copy on both hits and shared misses:
//! - cache hits return immutable slices into resident slot backing
//! - the first miss reserves one slot and fetches directly into that slot's physical-page-sized
//!   allocation
//! - concurrent followers join the same shared fetch future and slice the resolved page instead of
//!   re-reading or copying it
//!
//! Returned buffers are reference counted and may outlive cache eviction, so cache capacity bounds
//! resident slots rather than total retained read memory.
//!
//! Cache misses probe under a read lock, re-probe under a write lock, and then either join an
//! existing in-flight fetch or reserve one slot for the new fetch. No storage I/O is awaited while
//! holding a cache lock.

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

/// Shared future type for one in-flight page fetch.
type PageFetchFut = Shared<Pin<Box<dyn Future<Output = Result<IoBuf, Arc<Error>>> + Send>>>;

/// Shared state for one in-flight page fetch.
struct PageFetchState {
    /// Shared future that reads and validates one physical page.
    future: PageFetchFut,
    /// Exactly one waiter may finalize slot cleanup for this fetch generation.
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
    slots: Vec<Slot>,

    /// Logical size of each page in bytes.
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

/// A reference to a page cache that can be shared across threads via cloning, along with the
/// logical page size used by the underlying blob format.
#[derive(Clone)]
pub struct CacheRef {
    /// The logical size of each page in the underlying blobs managed by this page cache.
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
    /// The cache stores at most `capacity` pages, each exactly `page_size` logical bytes.
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

    /// The logical page size used by this page cache.
    #[inline]
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }

    /// The physical page size used by on-disk reads handled by this cache.
    #[inline]
    const fn physical_page_size(&self) -> u64 {
        self.page_size + CHECKSUM_SIZE
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

    /// Attempt to read bytes from cache only, stopping at the first miss.
    ///
    /// Returns `(buffers, bytes_read)` where `buffers` is the cached logical prefix starting at
    /// `logical_offset`. The returned bytes are logically contiguous but may be segmented across
    /// multiple [IoBuf] slices. This method never performs blob I/O and can therefore return fewer
    /// than `len` bytes when the first miss is encountered.
    pub(super) fn read_cached(
        &self,
        blob_id: u64,
        mut logical_offset: u64,
        len: usize,
    ) -> (IoBufs, usize) {
        let mut remaining = len;
        let mut out = IoBufs::default();
        let cache = self.cache.read();
        while remaining > 0 {
            let Some(page) = cache.read_at(blob_id, logical_offset, remaining) else {
                break;
            };
            remaining -= page.len();
            logical_offset += page.len() as u64;
            out.append(page);
        }
        (out, len - remaining)
    }

    /// Read the logical range `[logical_offset, logical_offset + len)`.
    ///
    /// The returned [IoBufs] is logically contiguous but may remain segmented across cache-hit
    /// slices and newly fetched pages. This is the convenience form that starts from an empty
    /// output buffer. For continuation reads with an already-cached prefix, use [Self::read_append].
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

    /// Append `len` logical bytes into `result` starting at absolute `logical_offset`.
    ///
    /// Existing bytes in `result` are preserved. This method only appends new bytes and does not
    /// reinterpret `logical_offset` relative to `result`, so callers can seed `result` with a
    /// cached prefix and use this method to fetch only the missing suffix.
    pub(super) async fn read_append<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        mut logical_offset: u64,
        len: usize,
        result: &mut IoBufs,
    ) -> Result<(), Error> {
        let mut remaining = len;

        while remaining > 0 {
            if let Some(page) = {
                let cache = self.cache.read();
                cache.read_at(blob_id, logical_offset, remaining)
            } {
                remaining -= page.len();
                logical_offset += page.len() as u64;
                result.append(page);
                continue;
            }

            let page = self
                .read_after_page_fault(blob, blob_id, logical_offset, remaining)
                .await?;
            remaining -= page.len();
            logical_offset += page.len() as u64;
            result.append(page);
        }

        Ok(())
    }

    /// Resolve one logical page miss for `(blob_id, page_num)`.
    ///
    /// If another task is already fetching this key, joins that in-flight shared future. Otherwise
    /// reserves an evictable slot, fetches into that slot's physical-page-sized backing allocation,
    /// validates the page, and marks the slot ready.
    ///
    /// If no slot can be reserved because all slots are currently reserved, performs an uncached
    /// fetch and returns a logical slice directly without installing anything in the cache.
    ///
    /// No storage I/O is awaited while holding a cache lock.
    pub(super) async fn read_after_page_fault<B: Blob>(
        &self,
        blob: &B,
        blob_id: u64,
        offset: u64,
        max_len: usize,
    ) -> Result<IoBuf, Error> {
        assert!(max_len > 0);

        let (page_num, offset_in_page) = Cache::offset_to_page(self.page_size, offset);
        let offset_in_page = offset_in_page as usize;
        trace!(page_num, blob_id, "page fault");

        let key = (blob_id, page_num);
        let mut tracked: Option<(Arc<PageFetchState>, usize)> = None;
        let mut uncached: Option<PageFetchFut> = None;
        loop {
            if let Some(page) = {
                let cache = self.cache.read();
                cache.read_at(blob_id, offset, max_len)
            } {
                return Ok(page);
            }

            let mut cache = self.cache.write();
            if let Some(page) = cache.read_at(blob_id, offset, max_len) {
                return Ok(page);
            }

            if let Some((slot, state)) = cache.fetch_for_key(key) {
                if let Some(stale) = state.future.peek().cloned() {
                    let err = match &stale {
                        Ok(_) => None,
                        Err(err) => Some(err.clone()),
                    };
                    if state.try_claim_cleanup() {
                        let finalized = cache.finish_fetch_if_current(slot, key, &state, stale);
                        let log_error = err.is_some() && finalized;
                        if let (true, Some(err)) = (log_error, err) {
                            error!(blob_id, page_num, ?err, "page fetch failed");
                        }
                    }
                    continue;
                }

                tracked = Some((state, slot));
                break;
            }

            let Some(slot) = cache.reserve_slot() else {
                uncached = Some(self.make_fetch_future(
                    blob.clone(),
                    page_num,
                    self.pool.alloc(self.physical_page_size() as usize),
                ));
                break;
            };

            let fetch_buf = cache.take_slot_buffer(slot);
            let state = Arc::new(PageFetchState::new(self.make_fetch_future(
                blob.clone(),
                page_num,
                fetch_buf,
            )));
            cache.index.insert(key, slot);
            cache.set_fetching(slot, key, state.clone());
            tracked = Some((state, slot));
            break;
        }

        if let Some(uncached) = uncached {
            return match uncached.await {
                Ok(page) => {
                    let bytes = std::cmp::min(max_len, self.page_size as usize - offset_in_page);
                    Ok(page.slice(offset_in_page..offset_in_page + bytes))
                }
                Err(err) => {
                    error!(blob_id, page_num, ?err, "page fetch failed");
                    Err(Error::ReadFailed)
                }
            };
        }

        let (fetch_state, fetch_slot) =
            tracked.expect("page fault must resolve to tracked or uncached fetch");

        let fetch_result = fetch_state.future.clone().await;
        let log_error = if fetch_state.try_claim_cleanup() {
            let mut cache = self.cache.write();
            let finalized =
                cache.finish_fetch_if_current(fetch_slot, key, &fetch_state, fetch_result.clone());
            fetch_result.is_err() && finalized
        } else {
            false
        };

        match fetch_result {
            Ok(page) => {
                let bytes = std::cmp::min(max_len, self.page_size as usize - offset_in_page);
                Ok(page.slice(offset_in_page..offset_in_page + bytes))
            }
            Err(err) => {
                if log_error {
                    error!(blob_id, page_num, ?err, "page fetch failed");
                }
                Err(Error::ReadFailed)
            }
        }
    }

    /// Build a shareable fetch future that reads one physical page and validates it.
    ///
    /// The future returns the fetched physical page so a successful tracked miss can install that
    /// same backing directly into a cache slot without another copy or allocation.
    fn make_fetch_future<B: Blob>(
        &self,
        blob: B,
        page_num: u64,
        buf: crate::IoBufMut,
    ) -> PageFetchFut {
        let logical_page_size = self.page_size;
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
            let (len, _) = record.get_crc();
            if len as u64 != logical_page_size {
                error!(
                    page_num,
                    expected = logical_page_size,
                    actual = len as u64,
                    "attempted to fetch partial page from blob",
                );
                return Err(Arc::new(Error::InvalidChecksum));
            }

            Ok(page.freeze())
        }
        .boxed()
        .shared()
    }

    /// Cache the provided full logical pages, returning trailing bytes that did not fill a whole
    /// page. `offset` must be page aligned.
    ///
    /// This method is best-effort. If insertion fails because all slots are currently reserved, the
    /// remaining pages are dropped after logging an error. This affects cache hit rate, not
    /// correctness.
    pub fn cache(&self, blob_id: u64, mut buf: &[u8], offset: u64) -> usize {
        let logical_page_size = self.page_size as usize;
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);

        let mut cache = self.cache.write();
        while buf.len() >= logical_page_size {
            let current_page = page_num;
            let page = &buf[..logical_page_size];
            if cache.insert_page((blob_id, current_page), page).is_err() {
                error!(
                    blob_id,
                    page_num = current_page,
                    dropped_pages = buf.len() / logical_page_size,
                    "failed to cache pages",
                );
                break;
            }

            buf = &buf[logical_page_size..];
            if !buf.is_empty() {
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
    /// Return an empty page cache with a max capacity of `capacity` logical pages, each backed by
    /// a physical-page-sized allocation.
    pub fn new(pool: BufferPool, logical_page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let logical_page_size = logical_page_size.get() as usize;
        let physical_page_size = logical_page_size + CHECKSUM_SIZE as usize;
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

    /// Convert an offset into the number of the page it belongs to and the offset within that
    /// page.
    const fn offset_to_page(logical_page_size: u64, offset: u64) -> (u64, u64) {
        (offset / logical_page_size, offset % logical_page_size)
    }

    /// Attempt to fetch blob data starting at `logical_offset` from the page cache.
    ///
    /// Returns `None` if the first page in the requested range is not buffered.
    /// Returned bytes never cross a page boundary.
    ///
    /// Reserved in-flight entries are treated as misses.
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
        let bytes = std::cmp::min(max_len, self.logical_page_size - offset_in_page as usize);
        let end = offset_in_page as usize + bytes;
        assert!(page.len() >= end);
        Some(page.slice(offset_in_page as usize..end))
    }

    /// Put a page into the cache by copying logical bytes into a target slot.
    ///
    /// If the destination slot is uniquely owned, its existing allocation is reused. If the slot is
    /// shared by readers, a replacement allocation is taken from `pool`.
    ///
    /// Returns `Err(())` only when no slot is currently reservable.
    fn insert_page(&mut self, key: (u64, u64), page: &[u8]) -> Result<(), ()> {
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
                    debug!(
                        blob_id,
                        page_num, "overwriting reserved slot with flush data"
                    );
                    assert_eq!(*state_key, key);
                }
                SlotState::Vacant => {
                    unreachable!("index entry must point to a filled or reserved slot");
                }
            }
            slot
        } else {
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
    /// Pass 1 prefers vacant or unreferenced ready pages while clearing reference bits.
    /// Pass 2 force-selects the first non-fetching slot if needed.
    ///
    /// Orphaned reserved entries (no active waiters) are reclaimed opportunistically.
    /// Returns `None` only when every slot is currently reserved with active waiters.
    fn reserve_slot(&mut self) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }

        let mut chosen = None;
        for _ in 0..self.capacity {
            let slot = self.clock;
            self.clock = (self.clock + 1) % self.capacity;
            self.reclaim_reserved_slot(slot);
            match &self.slots[slot].state {
                SlotState::Vacant => {
                    chosen = Some(slot);
                    break;
                }
                SlotState::Reserved { .. } => continue,
                SlotState::Filled { referenced, .. } => {
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
                match &self.slots[slot].state {
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
    /// Resolved fetches are finalized exactly once via `cleanup_claimed`. Unresolved fetches are
    /// only evicted when no live waiter still holds the shared state.
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
                let err = match &result {
                    Ok(_) => None,
                    Err(err) => Some(err.clone()),
                };
                let finalized = self.finish_fetch_if_current(slot, key, &state, result);
                let log_error = err.is_some() && finalized;
                if let (true, Some(err)) = (log_error, err) {
                    error!(blob_id = key.0, page_num = key.1, ?err, "page fetch failed");
                }
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
    /// Returns `true` when this call still owned the current slot generation and therefore applied
    /// the success or eviction transition. Returns `false` if the slot has already been repurposed.
    /// This defends against races where slot/key ownership changed while the fetch was in-flight.
    fn finish_fetch_if_current(
        &mut self,
        slot: usize,
        key: (u64, u64),
        state: &Arc<PageFetchState>,
        result: Result<IoBuf, Arc<Error>>,
    ) -> bool {
        if self.slots.get(slot).is_none() {
            return false;
        }
        let is_current = match &self.slots[slot].state {
            SlotState::Reserved {
                key: state_key,
                fetch,
            } => *state_key == key && Arc::ptr_eq(fetch, state),
            SlotState::Vacant | SlotState::Filled { .. } => false,
        };
        if !is_current {
            return false;
        }

        match result {
            Ok(page) => {
                if page.len() < self.physical_page_size {
                    error!(
                        ?key,
                        page_len = page.len(),
                        physical_page_size = self.physical_page_size,
                        "fetched page shorter than physical page size",
                    );
                    self.evict_slot(slot);
                    return true;
                }
                self.slots[slot].buf = page;
                self.slots[slot].state = SlotState::Filled {
                    key,
                    referenced: AtomicBool::new(true),
                };
            }
            Err(_) => self.evict_slot(slot),
        }

        true
    }

    /// Take a writable slot buffer for fetch or cache refill.
    ///
    /// Reuses the existing slot allocation when uniquely owned; otherwise allocates from the pool.
    fn take_slot_buffer(&mut self, slot: usize) -> crate::IoBufMut {
        let current = std::mem::take(&mut self.slots[slot].buf);
        match current.try_into_mut() {
            Ok(mut writable) => {
                assert!(
                    writable.capacity() >= self.physical_page_size,
                    "slot buffer capacity ({}) < physical_page_size ({})",
                    writable.capacity(),
                    self.physical_page_size,
                );
                writable.clear();
                writable
            }
            Err(_) => self.pool.alloc(self.physical_page_size),
        }
    }

    /// Evict any key currently assigned to `slot`, leaving the slot vacant.
    fn evict_slot(&mut self, slot: usize) {
        let slot_ref = &mut self.slots[slot];
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
        deterministic, BufferPool, BufferPoolConfig, Clock as _, Runner as _, Spawner as _,
        Storage as _,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize, NZU16};
    use futures::{
        future::{pending, ready},
        FutureExt,
    };
    use prometheus_client::registry::Registry;
    use std::{
        num::NonZeroU16,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PHYSICAL_PAGE_SIZE: NonZeroU16 = NZU16!(1036);
    const PAGE_SIZE_U64: u64 = PAGE_SIZE.get() as u64;

    /// Build a physical-page-sized `IoBuf` with logical bytes filled with `fill` plus a valid CRC.
    fn physical_page(fill: u8) -> IoBuf {
        let logical = vec![fill; PAGE_SIZE.get() as usize];
        let crc = Crc32::checksum(&logical);
        let record = Checksum::new(PAGE_SIZE.get(), crc);
        let mut buf = logical;
        buf.extend_from_slice(&record.to_bytes());
        assert_eq!(buf.len(), PHYSICAL_PAGE_SIZE.get() as usize);
        IoBuf::from(buf)
    }

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
        let _ = cache_ref.cache(blob_id, logical_pages.as_ref(), offset);
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

    fn fetch_state_refs(cache: &Cache, key: (u64, u64)) -> usize {
        cache
            .fetch_for_key(key)
            .map(|(_, state)| Arc::strong_count(&state).saturating_sub(1))
            .unwrap_or(0)
    }

    async fn ok_blob_op() -> Result<(), crate::Error> {
        Ok(())
    }

    async fn read_failed<T>() -> Result<T, crate::Error> {
        Err(Error::ReadFailed)
    }

    /// Test blob that optionally blocks one read, then returns a valid physical page payload.
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
            // SAFETY: we fully initialize `len` bytes below.
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
            ok_blob_op().await
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            ok_blob_op().await
        }
    }

    /// Test blob that signals read start and then never resolves.
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
            pending::<Result<crate::IoBufsMut, crate::Error>>().await
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
            ok_blob_op().await
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            ok_blob_op().await
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

    impl crate::Blob for ControlledBlob {
        async fn read_at(&self, offset: u64, len: usize) -> Result<crate::IoBufsMut, crate::Error> {
            self.read_at_buf(offset, len, crate::IoBufsMut::default())
                .await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _buf: impl Into<crate::IoBufsMut> + Send,
        ) -> Result<crate::IoBufsMut, crate::Error> {
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
                ControlledBlobResult::Success(page) => {
                    Ok(crate::IoBufsMut::from(page.as_ref().clone()))
                }
                ControlledBlobResult::Error => Err(Error::ReadFailed),
            }
        }

        async fn write_at(
            &self,
            _offset: u64,
            _buf: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            ok_blob_op().await
        }
    }

    /// Test blob that always fails reads immediately.
    #[derive(Clone)]
    struct ErrorBlob;

    impl crate::Blob for ErrorBlob {
        async fn read_at(&self, _offset: u64, _len: usize) -> Result<crate::IoBufsMut, crate::Error> {
            read_failed().await
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _buf: impl Into<crate::IoBufsMut> + Send,
        ) -> Result<crate::IoBufsMut, crate::Error> {
            read_failed().await
        }

        async fn write_at(
            &self,
            _offset: u64,
            _buf: impl Into<crate::IoBufs> + Send,
        ) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn resize(&self, _len: u64) -> Result<(), crate::Error> {
            ok_blob_op().await
        }

        async fn sync(&self) -> Result<(), crate::Error> {
            ok_blob_op().await
        }
    }

    #[test_traced]
    fn test_helper_blobs_cover_trait_surface() {
        // The inline test helpers live in this file, so exercise their trait surface directly
        // instead of paying permanent coverage tax for dormant wrappers and no-op methods.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // BlockingBlob should forward `read_at` through `read_at_buf` and honor the release gate.
            let (blocking_blob, started_rx, release_tx) =
                BlockingBlob::new(PAGE_SIZE.get() as usize, 0xAB);
            let blocking_reader = {
                let blob = blocking_blob.clone();
                context.clone().spawn(move |_| async move {
                    blob.read_at(0, PHYSICAL_PAGE_SIZE.get() as usize)
                        .await
                        .unwrap()
                        .coalesce()
                })
            };
            started_rx.await.expect("blocking read never started");
            blocking_blob.write_at(0, IoBufs::default()).await.unwrap();
            blocking_blob.resize(0).await.unwrap();
            blocking_blob.sync().await.unwrap();
            release_tx.send(()).expect("failed to release blocking blob");
            assert_eq!(
                blocking_reader.await.expect("blocking read failed").len(),
                PHYSICAL_PAGE_SIZE.get() as usize
            );

            // PendingBlob's `read_at` wrapper should be abort-safe, and its no-op mutable methods
            // should still satisfy the Blob contract when called directly.
            let (pending_blob, started_rx) = PendingBlob::new();
            let pending_reader = {
                let blob = pending_blob.clone();
                context.clone().spawn(move |_| async move {
                    let _ = blob.read_at(0, 1).await;
                })
            };
            started_rx.await.expect("pending read never started");
            pending_reader.abort();
            let _ = pending_reader.await;
            pending_blob.write_at(0, IoBufs::default()).await.unwrap();
            pending_blob.resize(0).await.unwrap();
            pending_blob.sync().await.unwrap();

            // ControlledBlob should support both the direct read wrapper and the no-op mutable API.
            let controlled_blob = ControlledBlob {
                started: Arc::new(Mutex::new(None)),
                release: Arc::new(Mutex::new(None)),
                reads: Arc::new(AtomicUsize::new(1)),
                result: ControlledBlobResult::Success(Arc::new(physical_page(7).as_ref().to_vec())),
            };
            let controlled = controlled_blob
                .read_at(0, PHYSICAL_PAGE_SIZE.get() as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(controlled.len(), PHYSICAL_PAGE_SIZE.get() as usize);
            controlled_blob.write_at(0, IoBufs::default()).await.unwrap();
            controlled_blob.resize(0).await.unwrap();
            controlled_blob.sync().await.unwrap();

            // ErrorBlob should fail both read entry points while leaving its mutable operations as
            // harmless no-ops for the specific tests that use it.
            assert!(matches!(ErrorBlob.read_at(0, 1).await, Err(Error::ReadFailed)));
            assert!(matches!(
                ErrorBlob
                    .read_at_buf(0, 1, crate::IoBufsMut::default())
                    .await,
                Err(Error::ReadFailed)
            ));
            ErrorBlob.write_at(0, IoBufs::default()).await.unwrap();
            ErrorBlob.resize(0).await.unwrap();
            ErrorBlob.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_from_pooler_logical_derives_physical_page_size() {
        // `from_pooler` should preserve the logical page size while deriving the physical fetch
        // size from the CRC-bearing on-disk format.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));

            assert_eq!(cache_ref.page_size(), PAGE_SIZE.get() as u64);
            let cache = cache_ref.cache.read();
            assert_eq!(cache.logical_page_size, PAGE_SIZE.get() as usize);
            assert_eq!(
                cache.physical_page_size,
                PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize
            );
        });
    }

    #[test_traced]
    fn test_cache_basic() {
        // Exercise direct cache insertion, replacement, and cross-page reads without involving
        // blob I/O so the basic indexing and slicing behavior is explicit.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(10));

        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        assert_eq!(read_cache(&cache, 0, &mut buf, 0), 0);

        let page = vec![1; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        assert_eq!(read_cache(&cache, 0, &mut buf, 0), PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        let page = vec![2; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        assert_eq!(read_cache(&cache, 0, &mut buf, 0), PAGE_SIZE.get() as usize);
        assert_eq!(buf, [2; PAGE_SIZE.get() as usize]);

        for i in 0u64..11 {
            let page = vec![i as u8; PAGE_SIZE.get() as usize];
            assert!(cache.insert_page((0, i), page.as_slice()).is_ok());
        }
        assert_eq!(read_cache(&cache, 0, &mut buf, 0), 0);
        for i in 1u64..11 {
            assert_eq!(
                read_cache(&cache, 0, &mut buf, i * PAGE_SIZE_U64),
                PAGE_SIZE.get() as usize
            );
            assert_eq!(buf, [i as u8; PAGE_SIZE.get() as usize]);
        }

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
        // Evicting a slot must not invalidate an immutable read view that already aliases the old
        // slot backing.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));

        let page = vec![1; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 0), page.as_slice()).is_ok());
        let held = cache
            .read_at(0, 0, PAGE_SIZE.get() as usize)
            .expect("page should be cached");

        let page = vec![2; PAGE_SIZE.get() as usize];
        assert!(cache.insert_page((0, 1), page.as_slice()).is_ok());
        assert_eq!(cache.slots.len(), 1);
        assert_eq!(cache.index.len(), 1);
        assert!(cache.index.contains_key(&(0, 1)));
        assert!(!cache.index.contains_key(&(0, 0)));

        assert_eq!(held.as_ref(), vec![1; PAGE_SIZE.get() as usize].as_slice());
    }

    #[test_traced]
    fn test_read_cached_returns_prefix_on_miss() {
        // `read_cached` should stop at the first miss and return only the cached logical prefix.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let page = vec![3u8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![page.clone().into()], 0);

            let (cached, cached_len) = cache_ref.read_cached(0, 0, PAGE_SIZE.get() as usize * 2);
            assert_eq!(cached_len, PAGE_SIZE.get() as usize);
            assert_eq!(cached.coalesce().as_ref(), page.as_slice());
        });
    }

    #[test_traced]
    fn test_cache_read_with_blob() {
        // Fill a real blob with physical pages, then verify reads populate and reuse the page
        // cache across repeated access.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let physical_page_size = PAGE_SIZE_U64 + CHECKSUM_SIZE;
            let (blob, size) = context.open("test", b"blob").await.expect("open failed");
            assert_eq!(size, 0);
            for i in 0..11 {
                let logical_data = vec![i as u8; PAGE_SIZE.get() as usize];
                let crc = Crc32::checksum(&logical_data);
                let record = Checksum::new(PAGE_SIZE.get(), crc);
                let mut page_data = logical_data;
                page_data.extend_from_slice(&record.to_bytes());
                blob.write_at(i * physical_page_size, page_data)
                    .await
                    .unwrap();
            }

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));
            assert_eq!(cache_ref.next_id(), 0);
            assert_eq!(cache_ref.next_id(), 1);
            for i in 0..11 {
                let read = cache_ref
                    .read(&blob, 0, i * PAGE_SIZE_U64, PAGE_SIZE.get() as usize)
                    .await
                    .unwrap()
                    .coalesce();
                let expected = vec![i as u8; PAGE_SIZE.get() as usize];
                assert_eq!(read.as_ref(), expected.as_slice());
            }

            for i in 1..11 {
                let read = cache_ref
                    .read(&blob, 0, i * PAGE_SIZE_U64, PAGE_SIZE.get() as usize)
                    .await
                    .unwrap()
                    .coalesce();
                let expected = vec![i as u8; PAGE_SIZE.get() as usize];
                assert_eq!(read.as_ref(), expected.as_slice());
            }

            blob.sync().await.unwrap();
        });
    }

    #[test_traced]
    fn test_cache_max_page() {
        // The cache index math should tolerate offsets near `u64::MAX` as long as they remain
        // page aligned.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let aligned_max_offset = u64::MAX - (u64::MAX % PAGE_SIZE_U64);
            let logical_data = vec![42u8; PAGE_SIZE.get() as usize];

            cache_pages(&cache_ref, 0, vec![logical_data.into()], aligned_max_offset);

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let page_cache = cache_ref.cache.read();
            let bytes_read = read_cache(&page_cache, 0, &mut buf, aligned_max_offset);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert!(buf.iter().all(|b| *b == 42));
        });
    }

    #[test_traced]
    fn test_cache_at_high_offset() {
        // Multi-page insertions near the top of the `u64` range must still be addressable without
        // overflow in page-number arithmetic.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const MIN_PAGE_SIZE: u64 = CHECKSUM_SIZE + 1;
            let cache_ref =
                CacheRef::from_pooler(&context, NZU16!(MIN_PAGE_SIZE as u16), NZUsize!(2));

            let first = vec![1u8; MIN_PAGE_SIZE as usize];
            let second = vec![1u8; MIN_PAGE_SIZE as usize];
            let aligned_max_offset = u64::MAX - (u64::MAX % MIN_PAGE_SIZE);
            let high_offset = aligned_max_offset - (MIN_PAGE_SIZE * 2);
            cache_pages(
                &cache_ref,
                0,
                vec![first.into(), second.into()],
                high_offset,
            );

            let mut buf = vec![0u8; MIN_PAGE_SIZE as usize];
            let page_cache = cache_ref.cache.read();
            assert_eq!(
                read_cache(&page_cache, 0, &mut buf, high_offset),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
            assert_eq!(
                read_cache(&page_cache, 0, &mut buf, high_offset + MIN_PAGE_SIZE),
                MIN_PAGE_SIZE as usize
            );
            assert!(buf.iter().all(|b| *b == 1));
        });
    }

    #[test_traced]
    fn test_cache_max_offset_single_byte_page_does_not_overflow_increment() {
        // A one-byte logical page is the tightest possible offset increment and should still cache
        // the last addressable byte correctly.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(1));
            assert_eq!(cache_ref.page_size(), 1);

            cache_pages(&cache_ref, 0, vec![vec![0xABu8].into()], u64::MAX);

            let mut buf = [0u8; 1];
            let page_cache = cache_ref.cache.read();
            let bytes_read = read_cache(&page_cache, 0, &mut buf, u64::MAX);
            assert_eq!(bytes_read, 1);
            assert_eq!(buf[0], 0xAB);
        });
    }

    #[test_traced]
    fn test_cache_stops_when_page_number_increment_overflows() {
        // If caching starts at the highest aligned offset, the first page may fit but incrementing
        // to the next page number must stop cleanly and report the uncached tail bytes.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(2));
            let max_offset = u64::MAX;
            let logical = vec![0x11u8, 0x22u8];

            let remaining = cache_ref.cache(0, &logical, max_offset);
            assert_eq!(remaining, 1);

            let mut buf = [0u8; 1];
            let cache = cache_ref.cache.read();
            assert_eq!(read_cache(&cache, 0, &mut buf, max_offset), 1);
            assert_eq!(buf, [0x11u8]);
            assert_eq!(read_cache(&cache, 0, &mut buf, 0), 0);
        });
    }

    #[test_traced]
    fn test_stale_fetch_entry_success_is_scavenged() {
        // A resolved reserved entry should be finalized opportunistically when the next reader
        // notices it, rather than forcing a refetch.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let (blob, _) = context.open("test", b"stale_success").await.unwrap();

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(physical_page(9)))
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
        // A resolved error placeholder must be evicted so the next reader can retry the page from
        // storage instead of inheriting a dead reserved entry.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let (blob, size) = context.open("test", b"stale_error").await.unwrap();
            assert_eq!(size, 0);

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
        // Reclaiming one stale reserved slot should free capacity for a different key instead of
        // pinning the cache indefinitely.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context.open("test", b"stale_other_key").await.unwrap();
            assert_eq!(size, 0);

            let logical_data = vec![4u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical_data);
            let record = Checksum::new(PAGE_SIZE.get(), crc);
            let mut page_data = logical_data.clone();
            page_data.extend_from_slice(&record.to_bytes());
            blob.write_at(0, page_data).await.unwrap();

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(physical_page(9)))
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
        // Finalizing an unrelated stale success must not overwrite a newer page that already owns
        // the cache slot.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(3));
            let newer = vec![6u8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![newer.clone().into()], 0);

            let stale: PageFetchFut = ready(Ok::<IoBuf, Arc<Error>>(physical_page(1)))
                .boxed()
                .shared();
            let _ = stale.clone().await;
            install_fetch_state(&cache_ref, (7, 7), Arc::new(PageFetchState::new(stale)));

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
        // A failed fetch should leave the key absent so the next read can retry cleanly after the
        // underlying data is repaired.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context.open("test", b"failed_fetch_retry").await.unwrap();
            assert_eq!(size, 0);

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
    fn test_partial_page_fetch_is_rejected_and_not_cached() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Write a valid partial page directly to storage. Append can use this format for the
            // tail page, but the page cache must never install it as a cached full page.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context
                .open("test", b"partial_page_fetch_rejected")
                .await
                .unwrap();
            assert_eq!(size, 0);

            let partial_len = 64usize;
            let logical = vec![0x5Au8; partial_len];
            let crc = Crc32::checksum(&logical);
            let mut physical = logical.clone();
            physical.resize(PAGE_SIZE.get() as usize, 0);
            physical.extend_from_slice(&Checksum::new(partial_len as u16, crc).to_bytes());
            assert_eq!(physical.len(), PHYSICAL_PAGE_SIZE.get() as usize);
            blob.write_at(0, physical).await.unwrap();

            // The read must fail and leave no cache entry behind for retry or overwrite.
            let err = cache_ref.read(&blob, 0, 0, partial_len).await.unwrap_err();
            assert!(matches!(err, Error::ReadFailed));

            let cache = cache_ref.cache.read();
            assert!(!cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_fetch_buffer_allocates_physical_size_when_logical_recycle_is_too_small() {
        // Recycled logical-page buffers are too small for physical reads, so the fetch path must
        // allocate physical-page-sized storage instead of reusing undersized backing.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let logical_page_size = 4096usize;
            let cache_ref = CacheRef::from_pooler(
                &context,
                NonZeroU16::new(logical_page_size as u16).unwrap(),
                NZUsize!(1),
            );

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

            let read = cache_ref.read(&blob, 0, 0, 64).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &logical_data[..64]);
        });
    }

    #[test_traced]
    fn test_misses_with_single_slot_do_not_panic() {
        // Two misses that contend for a single cache slot should still complete even if one read
        // ends up uncached.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
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
        // Canceling the original waiter must not silently evict an unresolved in-flight fetch that
        // still has a live storage operation behind it.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
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
        // If the first waiter disappears after the shared fetch starts, a follower must finalize
        // the cache entry when the fetch completes.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
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
    fn test_followers_keep_single_flight_after_first_fetcher_cancellation() {
        // Once a fetch is in flight, later followers must continue sharing it even if the original
        // caller is canceled before completion.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));

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

            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.clone().spawn(move |_| async move {
                let _ = cache_ref_for_first
                    .read(&blob_for_first, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await;
            });
            started_rx.await.expect("first read never started");

            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.clone().spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await
                    .expect("second read failed")
                    .coalesce()
            });

            loop {
                let joined = {
                    let cache = cache_ref.cache.read();
                    is_fetching(&cache, (blob_id, 0)) && fetch_state_refs(&cache, (blob_id, 0)) >= 3
                };
                if joined {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            first.abort();
            assert!(matches!(first.await, Err(Error::Closed)));

            let cache_ref_for_third = cache_ref.clone();
            let blob_for_third = blob.clone();
            let third = context.clone().spawn(move |_| async move {
                cache_ref_for_third
                    .read(&blob_for_third, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await
                    .expect("third read failed")
                    .coalesce()
            });

            loop {
                let third_entered = {
                    let cache = cache_ref.cache.read();
                    reads.load(Ordering::Relaxed) > 1 || fetch_state_refs(&cache, (blob_id, 0)) >= 3
                };
                if third_entered {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            let _ = release_tx.send(());
            let second_buf = second.await.expect("second task failed");
            let third_buf = third.await.expect("third task failed");
            assert_eq!(second_buf.as_ref(), logical_page.as_slice());
            assert_eq!(third_buf.as_ref(), logical_page.as_slice());

            assert_eq!(reads.load(Ordering::Relaxed), 1);

            let (cached, cached_len) = cache_ref.read_cached(blob_id, 0, PAGE_SIZE.get() as usize);
            assert_eq!(cached_len, PAGE_SIZE.get() as usize);
            assert_eq!(cached.coalesce().as_ref(), logical_page.as_slice());

            let fourth = cache_ref
                .read(&blob, blob_id, 0, PAGE_SIZE.get() as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(fourth.as_ref(), logical_page.as_slice());
            assert_eq!(reads.load(Ordering::Relaxed), 1);
        });
    }

    #[test_traced]
    fn test_page_fetch_error_removes_entry_for_all_waiters() {
        // Shared fetch errors should evict the reserved entry once and force later readers to
        // start a fresh fetch rather than inheriting a poisoned slot.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10));

            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let reads = Arc::new(AtomicUsize::new(0));
            let blob = ControlledBlob {
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
                reads: reads.clone(),
                result: ControlledBlobResult::Error,
            };

            let cache_ref_for_first = cache_ref.clone();
            let blob_for_first = blob.clone();
            let first = context.clone().spawn(move |_| async move {
                cache_ref_for_first
                    .read(&blob_for_first, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await
            });
            started_rx.await.expect("first erroring read never started");

            let cache_ref_for_second = cache_ref.clone();
            let blob_for_second = blob.clone();
            let second = context.clone().spawn(move |_| async move {
                cache_ref_for_second
                    .read(&blob_for_second, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await
            });

            loop {
                let joined = {
                    let cache = cache_ref.cache.read();
                    fetch_state_refs(&cache, (blob_id, 0)) >= 3
                };
                if joined {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            let _ = release_tx.send(());

            assert!(matches!(first.await, Ok(Err(Error::ReadFailed))));
            assert!(matches!(second.await, Ok(Err(Error::ReadFailed))));
            assert_eq!(reads.load(Ordering::Relaxed), 1);

            {
                let cache = cache_ref.cache.read();
                assert!(!is_fetching(&cache, (blob_id, 0)));
                assert!(!cache.index.contains_key(&(blob_id, 0)));
            }

            let (cached, cached_len) = cache_ref.read_cached(blob_id, 0, PAGE_SIZE.get() as usize);
            assert_eq!(cached_len, 0);
            assert!(cached.is_empty());

            assert!(matches!(
                cache_ref
                    .read(&blob, blob_id, 0, PAGE_SIZE.get() as usize)
                    .await,
                Err(Error::ReadFailed)
            ));
            assert_eq!(reads.load(Ordering::Relaxed), 2);
        });
    }

    #[test_traced]
    fn test_stranded_unresolved_fetch_entry_is_reclaimed_for_other_keys() {
        // An unresolved fetch with no remaining waiters should be reclaimable when another key
        // needs the slot.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));

            let stranded: PageFetchFut = pending::<Result<IoBuf, Arc<Error>>>().boxed().shared();
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
        // A reserved slot with a live waiter must not be stolen by unrelated cache pressure.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));

            let pending_fut: PageFetchFut =
                pending::<Result<IoBuf, Arc<Error>>>().boxed().shared();
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
        // If a slot has been repurposed while the original fetch was still in flight, the late
        // result must not overwrite the newer page.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, started_rx, release_tx) = BlockingBlob::new(PAGE_SIZE.get() as usize, 1);

            let cache_ref_for_task = cache_ref.clone();
            let read_task = context.spawn(move |_| async move {
                cache_ref_for_task.read(&blob, 0, 0, 64).await.unwrap()
            });

            started_rx.await.expect("missing start signal");

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
        // When every slot is reserved, reads should still succeed by fetching directly from the
        // blob without disturbing existing in-flight fetch ownership.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let (blob, size) = context
                .open("test", b"all_reserved_fallback")
                .await
                .unwrap();
            assert_eq!(size, 0);

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

            let pending_fut: PageFetchFut =
                pending::<Result<IoBuf, Arc<Error>>>().boxed().shared();
            let state = Arc::new(PageFetchState::new(pending_fut));
            let _waiter = state.clone();
            install_fetch_state(&cache_ref, (42, 0), state);

            let read = cache_ref
                .read(&blob, 0, PAGE_SIZE_U64, 64)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), vec![0xBBu8; 64].as_slice());

            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (42, 0)));
        });
    }

    #[test_traced]
    fn test_cache_insert_drops_pages_when_all_slots_are_reserved() {
        // Best-effort caching should give up and return the full logical input when every slot is
        // reserved by an active fetch.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let state = Arc::new(PageFetchState::new(
                pending::<Result<IoBuf, Arc<Error>>>().boxed().shared(),
            ));
            let _waiter = state.clone();
            install_fetch_state(&cache_ref, (9, 9), state);

            let page = vec![0x77u8; PAGE_SIZE.get() as usize];
            let remaining = cache_ref.cache(0, &page, 0);
            assert_eq!(remaining, PAGE_SIZE.get() as usize);

            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (9, 9)));
            assert!(!cache.index.contains_key(&(0, 0)));
        });
    }

    #[test_traced]
    fn test_all_slots_reserved_fallback_error_does_not_touch_cache() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Reserve the only slot for an unrelated in-flight fetch so the read must fall back to
            // an uncached blob read.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let pending_fut: PageFetchFut =
                pending::<Result<IoBuf, Arc<Error>>>().boxed().shared();
            let state = Arc::new(PageFetchState::new(pending_fut));
            let _waiter = state.clone();
            install_fetch_state(&cache_ref, (42, 0), state);

            // The fallback read should report the blob error without disturbing the reserved slot.
            let err = cache_ref
                .read(&ErrorBlob, 0, PAGE_SIZE_U64, 64)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::ReadFailed));

            let cache = cache_ref.cache.read();
            assert!(is_fetching(&cache, (42, 0)));
            assert!(cache.index.contains_key(&(42, 0)));
            assert!(!cache.index.contains_key(&(0, 1)));
        });
    }

    #[test_traced]
    fn test_insert_page_overwrites_reserved_slot() {
        // Explicit cache insertion should be able to replace a reserved slot for the same key once
        // the caller already has the full logical page bytes.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));

            let pending_fut: PageFetchFut =
                pending::<Result<IoBuf, Arc<Error>>>().boxed().shared();
            install_fetch_state(
                &cache_ref,
                (0, 0),
                Arc::new(PageFetchState::new(pending_fut)),
            );

            {
                let cache = cache_ref.cache.read();
                assert!(is_fetching(&cache, (0, 0)));
            }

            let page_data = vec![0xCCu8; PAGE_SIZE.get() as usize];
            cache_pages(&cache_ref, 0, vec![page_data.clone().into()], 0);

            let mut buf = vec![0u8; PAGE_SIZE.get() as usize];
            let cache = cache_ref.cache.read();
            assert!(!is_fetching(&cache, (0, 0)));
            let bytes_read = read_cache(&cache, 0, &mut buf, 0);
            assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
            assert_eq!(buf, page_data);
        });
    }

    #[test]
    #[should_panic(expected = "index entry must point to a filled or reserved slot")]
    fn test_insert_page_panics_on_vacant_index_entry() {
        // The cache index must never point at a vacant slot. If it does, fail loudly instead of
        // silently corrupting cache ownership.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        cache.index.insert((0, 0), 0);

        let page = vec![0u8; PAGE_SIZE.get() as usize];
        let _ = cache.insert_page((0, 0), &page);
    }

    #[test]
    fn test_fetch_for_key_ignores_mismatched_reserved_entry() {
        // A reserved slot is only a match when both the index entry and the reserved key agree.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        let state = Arc::new(PageFetchState::new(
            ready(Ok::<IoBuf, Arc<Error>>(physical_page(1))).boxed().shared(),
        ));
        cache.index.insert((0, 0), 0);
        cache.set_fetching(0, (1, 1), state);

        assert!(cache.fetch_for_key((0, 0)).is_none());
    }

    #[test]
    fn test_reserve_slot_handles_empty_slot_vector() {
        // Defensive callers should get `None` rather than a panic if a malformed cache somehow has
        // no slots at all.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache {
            index: HashMap::new(),
            slots: Vec::new(),
            logical_page_size: PAGE_SIZE.get() as usize,
            physical_page_size: PHYSICAL_PAGE_SIZE.get() as usize,
            clock: 0,
            capacity: 0,
            pool,
        };

        assert!(cache.reserve_slot().is_none());
    }

    #[test]
    fn test_reserve_slot_prefers_unreferenced_ready_page() {
        // Pass 1 of the clock algorithm should immediately select an unreferenced ready page.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        let page = vec![0x44u8; PAGE_SIZE.get() as usize];
        cache.insert_page((0, 0), &page).unwrap();

        let SlotState::Filled { referenced, .. } = &cache.slots[0].state else {
            panic!("slot should contain a filled page");
        };
        referenced.store(false, Ordering::Relaxed);

        assert_eq!(cache.reserve_slot(), Some(0));
        assert!(matches!(cache.slots[0].state, SlotState::Vacant));
        assert!(cache.index.is_empty());
    }

    #[test]
    fn test_reclaim_reserved_slot_noops_when_cleanup_already_claimed() {
        // Only one waiter is allowed to finalize a resolved fetch generation. Later reclaim
        // attempts should leave the reserved slot unchanged.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));

        let fetch = ready(Ok::<IoBuf, Arc<Error>>(physical_page(5)))
            .boxed()
            .shared();
        futures::executor::block_on(fetch.clone()).unwrap();
        let state = Arc::new(PageFetchState::new(fetch));
        assert!(state.try_claim_cleanup());

        cache.index.insert((0, 0), 0);
        cache.set_fetching(0, (0, 0), state);
        cache.reclaim_reserved_slot(0);

        assert!(matches!(cache.slots[0].state, SlotState::Reserved { .. }));
        assert!(cache.index.contains_key(&(0, 0)));
    }

    #[test]
    fn test_finish_fetch_if_current_returns_false_for_missing_slot() {
        // Out-of-bounds cleanup must be ignored instead of panicking.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        let state = Arc::new(PageFetchState::new(
            ready(Ok::<IoBuf, Arc<Error>>(physical_page(1))).boxed().shared(),
        ));

        assert!(!cache.finish_fetch_if_current(7, (0, 0), &state, Ok(physical_page(1))));
    }

    #[test]
    fn test_finish_fetch_if_current_rejects_short_pages() {
        // Successful fetch cleanup still needs to verify that the returned buffer holds a full
        // physical page before installing it into a slot.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        let state = Arc::new(PageFetchState::new(
            ready(Ok::<IoBuf, Arc<Error>>(physical_page(1))).boxed().shared(),
        ));

        cache.index.insert((0, 0), 0);
        cache.set_fetching(0, (0, 0), state.clone());
        let short = IoBuf::from(vec![0u8; CHECKSUM_SIZE as usize]);

        assert!(cache.finish_fetch_if_current(0, (0, 0), &state, Ok(short)));
        assert!(matches!(cache.slots[0].state, SlotState::Vacant));
        assert!(cache.index.is_empty());
    }

    #[test]
    fn test_evict_slot_clears_slot_even_when_index_is_missing() {
        // Eviction should still clear the slot state even if the index has already been corrupted
        // or manually pruned.
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let mut cache = Cache::new(pool, PAGE_SIZE, NZUsize!(1));
        let page = vec![0x99u8; PAGE_SIZE.get() as usize];
        cache.insert_page((0, 0), &page).unwrap();
        cache.index.clear();

        cache.evict_slot(0);

        assert!(matches!(cache.slots[0].state, SlotState::Vacant));
        assert!(cache.index.is_empty());
    }
}

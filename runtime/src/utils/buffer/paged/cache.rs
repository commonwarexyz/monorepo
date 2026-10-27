//! A page cache for caching _logical_ pages of [Blob] data in memory. The cache is unaware of the
//! physical page format used by the blob, which is left to the blob implementation.
//!
//! # Shared Reads
//!
//! Concurrent readers often miss the same pages, for example a prefetch and the read it serves.
//! Rather than read such a page again, a reader joins the read of it already in flight.
//!
//! A page fault reads a page nobody else is reading with a standalone fetch, and a batched miss
//! ([CacheRef::read_after_misses]) reads every such page with one [Blob::read_many] call, a batch
//! that validates and caches each page as it arrives and delivers it to the readers waiting on
//! it. The read that started the batch receives every page and waits for the batch to end, so a
//! late read error still fails it. Other readers join by selecting the pages the batch has yet to
//! publish, which arrive in their own inbox. Fetches and batches run as [Shared] futures that
//! every waiting reader drives, so no reader depends on a slow or dropped one, and each
//! underlying read is polled about once per wake however many readers are waiting.
//!
//! A reader joins everything it needs before driving any of it, examining its misses over a few
//! holds of the cache's write lock and registering its own batch only at the end of the last
//! hold, so another reader that misses one of those pages in between starts its own read of it,
//! and the page is read twice. A batch claims each page's selections under that lock, so a
//! reader that selects an unpublished page always gets the page or the batch's error. The cache
//! takes its lock before any batch's lock, and holds batches weakly so a finished or dropped
//! batch never needs the cache lock.

use super::{
    CHECKSUM_SIZE, get_page_with_checksum_from_blob, physical_page, validate_physical_page,
};
use crate::{BLOB_PAGE_SIZE, Blob, Error, IoBuf, IoBufMut, ReadOptions};
use ahash::{AHashMap, AHashSet};
use commonware_utils::{
    Widen, cache,
    futures::{Shared, WeakShared},
    sync::{Mutex, RwLock, RwLockWriteGuard},
};
use futures::{FutureExt, Stream, TryStreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use std::{
    collections::{VecDeque, hash_map::Entry},
    mem,
    num::{NonZeroU16, NonZeroUsize},
    pin::{Pin, pin},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
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
///
/// Dropping an armed guard takes the cache lock, so it must not happen while the lock is held.
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

    /// Await the shared fetch. The future itself logs failures, caches the resolved page, and
    /// removes the in-flight marker before it returns, so waiters only need cancellation cleanup
    /// while the fetch is still unresolved.
    async fn wait(mut self) -> Result<IoBuf, Error> {
        let result = (&mut self.fetch).await;
        self.disarm();
        result
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

/// Missing pages a batched read examines before it yields the cache's write lock to any thread
/// waiting for it, so a read with many misses does not keep cache hits and publishes waiting for
/// its whole scan. A page this read found unread before yielding may be read by another reader
/// before this read registers its batch, so overlapping reads can read such a page more than once.
const MISSES_PER_LOCK: usize = 64;

/// Resident pages an eviction visits before it yields the cache's write lock to any thread
/// waiting for it, so dropping a blob with many cached pages does not keep cached reads waiting
/// for the whole walk.
const PAGES_PER_LOCK: usize = 4096;

/// The read of a [Batch]. It fails if the read fails or does not yield every page exactly once.
type BatchFuture = BoxFuture<'static, Result<(), Error>>;

/// A handle to a [BatchFuture] that any of the batch's readers can drive.
type BatchDriver = Shared<BatchFuture>;

/// A page delivered to a reader, as its tag and either its logical bytes or why it failed
/// validation.
type Delivery = (usize, Result<IoBuf, Error>);

/// The reader that started a [Batch], which receives every page tagged with its index.
const STARTER: usize = 0;

/// Where a page goes for one joiner, as the tag the joiner selected it with and the joiner's
/// reader.
type Joiner = (usize, usize);

/// What a [Batch] has yet to publish, who joined it, and what it published to each reader.
/// `joiners` changes only while the cache lock is also held, so a reader that finds a page
/// unpublished can select it in the same hold.
struct BatchState {
    /// The joiners of each page not yet published. `None` once the page is published, or the
    /// batch fails.
    joiners: Box<[Option<Vec<Joiner>>]>,
    /// The pages published to each reader and not yet taken, by reader, starting with [STARTER].
    /// `None` once the reader is dropped. A dropped reader's slot stays until the batch ends, since
    /// the selections it made still name it, so this grows with every reader that joins.
    inboxes: Vec<Option<VecDeque<Delivery>>>,
    /// Why the batch failed, once it has.
    error: Option<Error>,
}

/// An in-flight read of some pages of one blob with one [Blob::read_many] call.
struct Batch {
    blob_id: u64,
    /// The page numbers, strictly increasing. A page's index in this list identifies it.
    pages: Box<[u64]>,
    state: Mutex<BatchState>,
}

impl Batch {
    fn new(blob_id: u64, pages: Vec<u64>) -> Self {
        let state = BatchState {
            joiners: vec![Some(Vec::new()); pages.len()].into(),
            inboxes: vec![Some(VecDeque::new())],
            error: None,
        };
        Self {
            blob_id,
            pages: pages.into(),
            state: Mutex::new(state),
        }
    }

    /// Read the batch's pages from `physical` (their physical ranges in `blob`), publishing each
    /// as it arrives. A page failing validation is published as failed while the others continue.
    /// A read error, or a read that does not yield every page exactly once, fails the batch.
    ///
    /// The future owns `_retire` from its creation, so the batch retires once the future ends or
    /// is dropped, polled or not.
    async fn read<B: Blob>(
        self: Arc<Self>,
        cache: Arc<RwLock<Cache>>,
        blob: Arc<B>,
        physical: Vec<(u64, usize)>,
        page_size: NonZeroU16,
        _retire: RetireGuard,
    ) -> Result<(), Error> {
        let result = async {
            // CacheRef retains the pages, so the source pages need not remain in the OS page
            // cache.
            let mut stream = pin!(blob.read_many(&physical, ReadOptions::DONT_CACHE));
            while let Some((index, bufs)) = stream.try_next().await? {
                // Each page is yielded exactly once (see Blob::read_many).
                let Some(&page_num) = self.pages.get(index) else {
                    return Err(Error::ReadFailed);
                };
                let page = validate_physical_page(bufs.coalesce())
                    .and_then(|(page, _)| cacheable_page(page, page_num, page_size))
                    .inspect_err(|err| error!(page_num, ?err, "Batched page failed validation"));
                self.publish(&cache, index, page)?;
            }
            if self.state.lock().joiners.iter().any(Option::is_some) {
                return Err(Error::ReadFailed);
            }
            Ok(())
        }
        .await;
        if let Err(err) = &result {
            self.fail(&cache, err);
        }
        result
    }

    /// Publish the outcome of the page at `index`. Caches the page if it is valid and delivers it
    /// to the starter and the page's joiners. Fails if the page was already published.
    fn publish(
        &self,
        cache: &RwLock<Cache>,
        index: usize,
        result: Result<IoBuf, Error>,
    ) -> Result<(), Error> {
        let mut cache = cache.write();
        let mut state = self.state.lock();
        let BatchState {
            joiners, inboxes, ..
        } = &mut *state;
        let Some(joiners) = joiners[index].take() else {
            return Err(Error::ReadFailed);
        };
        if let Ok(page) = &result {
            cache.cache(self.blob_id, page.as_ref(), self.pages[index]);
        }
        drop(cache);
        for (tag, reader) in joiners {
            if let Some(inbox) = &mut inboxes[reader] {
                inbox.push_back((tag, result.clone()));
            }
        }
        if let Some(inbox) = &mut inboxes[STARTER] {
            inbox.push_back((index, result));
        }
        Ok(())
    }

    /// Fail the batch. Records why and takes its joiners under the cache lock, so no reader
    /// selects a page the batch will never publish.
    fn fail(&self, cache: &RwLock<Cache>, err: &Error) {
        error!(blob_id = self.blob_id, ?err, "Batched page read failed");
        let _cache = cache.write();
        let mut state = self.state.lock();
        state.error = Some(err.clone());
        state.joiners.fill(None);
    }
}

/// Batches to unregister, with their blobs.
type Retired = Arc<Mutex<Vec<(u64, Weak<Batch>)>>>;

/// Queues its [Batch] for [BatchRegistry] to unregister when dropped. Dropping it takes only the
/// queue's lock, never the cache lock.
struct RetireGuard {
    retired: Retired,
    blob_id: u64,
    batch: Weak<Batch>,
}

impl Drop for RetireGuard {
    fn drop(&mut self) {
        let batch = std::mem::take(&mut self.batch);
        self.retired.lock().push((self.blob_id, batch));
    }
}

/// A [Batch] and its driver, as registered.
type Registration = (Weak<Batch>, WeakShared<BatchFuture>);

/// The cache's batches, by blob, so readers that miss a page a batch has yet to publish join it.
///
/// Batches are registered weakly, so the registry never keeps a driver alive. A batch retires when
/// its driver ends or is dropped. The batch's read then drops its [RetireGuard], which queues the
/// batch, and [Self::unregister_retired] removes it.
#[derive(Default)]
struct BatchRegistry {
    by_blob: AHashMap<u64, Vec<Registration>>,
    retired: Retired,
}

impl BatchRegistry {
    /// A batch of `blob_id` that has yet to publish page `page_num`, with the page's index in it
    /// and a handle that drives it.
    fn find_unpublished(
        &self,
        blob_id: u64,
        page_num: u64,
    ) -> Option<(Arc<Batch>, usize, BatchDriver)> {
        self.by_blob
            .get(&blob_id)?
            .iter()
            .find_map(|(batch, driver)| {
                let batch = batch.upgrade()?;
                let index = batch.pages.binary_search(&page_num).ok();
                let index = index.filter(|&index| batch.state.lock().joiners[index].is_some())?;
                // A batch whose driver was dropped since the last unregistration never publishes.
                Some((batch, index, driver.upgrade()?))
            })
    }

    /// A guard that retires `batch` when dropped, for its read to own.
    fn retire_on_drop(&self, batch: &Arc<Batch>) -> RetireGuard {
        RetireGuard {
            retired: self.retired.clone(),
            blob_id: batch.blob_id,
            batch: Arc::downgrade(batch),
        }
    }

    /// Register `batch`, read by `driver`.
    fn register(&mut self, batch: &Arc<Batch>, driver: &BatchDriver) {
        self.by_blob
            .entry(batch.blob_id)
            .or_default()
            .push((Arc::downgrade(batch), driver.downgrade()));
    }

    /// Unregister the batches retired since the last call, scanning each affected blob once.
    fn unregister_retired(&mut self) {
        let mut retired = std::mem::take(&mut *self.retired.lock());
        if retired.is_empty() {
            return;
        }

        // A registered batch's allocation outlives it while the registry holds its weak
        // reference, so no other batch can share its address.
        let batches: AHashSet<*const Batch> =
            retired.iter().map(|(_, batch)| batch.as_ptr()).collect();
        retired.sort_unstable_by_key(|(blob_id, _)| *blob_id);
        retired.dedup_by_key(|(blob_id, _)| *blob_id);
        for (blob_id, _) in retired {
            if let Entry::Occupied(mut registered) = self.by_blob.entry(blob_id) {
                registered
                    .get_mut()
                    .retain(|(batch, _)| !batches.contains(&batch.as_ptr()));
                if registered.get().is_empty() {
                    registered.remove();
                }
            }
        }
    }
}

/// A read's interest in some pages of a [Batch]. Yields each selected page with its tag as the
/// batch publishes it, or an error if the page fails validation or the batch fails first.
struct Subscription {
    batch: Arc<Batch>,
    /// This reader's inbox in [BatchState::inboxes].
    reader: usize,
    /// Deliveries taken from the inbox and not yet yielded.
    taken: VecDeque<Delivery>,
    /// Count of selected pages not yet delivered.
    remaining: usize,
    /// A handle on the batch's driver, released once every selected page is delivered.
    driver: Option<BatchDriver>,
}

impl Subscription {
    /// Subscribe the read that started `batch` to every page, delivered tagged with its index.
    fn starting(batch: Arc<Batch>, driver: BatchDriver) -> Self {
        Self {
            remaining: batch.pages.len(),
            driver: Some(driver),
            batch,
            reader: STARTER,
            taken: VecDeque::new(),
        }
    }

    /// Subscribe a joiner to `batch`, selecting no pages yet.
    fn joining(batch: Arc<Batch>, driver: BatchDriver) -> Self {
        let reader = {
            let mut state = batch.state.lock();
            state.inboxes.push(Some(VecDeque::new()));
            state.inboxes.len() - 1
        };
        Self {
            driver: Some(driver),
            batch,
            reader,
            taken: VecDeque::new(),
            remaining: 0,
        }
    }

    /// Select the page at `index` with `tag`. Call with the cache lock held, after finding the
    /// page unpublished, and before the first poll.
    fn select(&mut self, index: usize, tag: usize) {
        let mut state = self.batch.state.lock();
        let BatchState {
            joiners, inboxes, ..
        } = &mut *state;
        let joiners = joiners[index]
            .as_mut()
            .expect("only unpublished pages are selected");

        // Prune the joiners of dropped subscriptions only when the list is full, then leave as
        // much room as there are live joiners, so each selection costs amortized constant time.
        if joiners.len() == joiners.capacity() {
            joiners.retain(|&(_, reader)| inboxes[reader].is_some());
            joiners.reserve(joiners.len());
        }
        joiners.push((tag, self.reader));
        self.remaining += 1;
    }

    /// Take the next page delivered to this reader, if any.
    fn take(&mut self) -> Option<Delivery> {
        if self.taken.is_empty() {
            let mut state = self.batch.state.lock();
            if let Some(inbox) = &mut state.inboxes[self.reader] {
                mem::swap(inbox, &mut self.taken);
            }
        }
        self.taken.pop_front()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Stop deliveries to this reader, and free those it never took after unlocking.
        let inbox = self.batch.state.lock().inboxes[self.reader].take();
        drop(inbox);
    }
}

impl Stream for Subscription {
    type Item = Result<(usize, IoBuf), Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        // Take a delivered page, or else drive the batch and look again, since driving may deliver
        // one of this reader's pages while others stay pending. Pages are delivered only while a
        // reader drives the batch, and the driver wakes every reader that found it busy once that
        // reader stops (see [Shared]), so the inbox needs no waker. A completed driver has made
        // every delivery and is never polled again.
        let delivery = match this.take() {
            Some(delivery) => delivery,
            None => {
                let driver = this.driver.as_mut();
                if driver.is_some_and(|driver| driver.poll_unpin(cx).is_ready()) {
                    this.driver = None;
                }
                match this.take() {
                    Some(delivery) => delivery,
                    None if this.driver.is_some() => return Poll::Pending,
                    None => {
                        // The batch ended before delivering every selected page, so it failed.
                        this.remaining = 0;
                        let error = this.batch.state.lock().error.clone();
                        return Poll::Ready(Some(Err(error.unwrap_or(Error::ReadFailed))));
                    }
                }
            }
        };
        let (tag, result) = delivery;
        this.remaining -= 1;
        if this.remaining == 0 {
            this.driver = None;
        }
        Poll::Ready(Some(result.map(|page| (tag, page))))
    }
}

/// Where a page-fault read gets its page. It is chosen under the cache lock and awaited after the
/// lock is released.
enum PageSource {
    /// A standalone fetch of the page.
    Fetch(PageFetch),
    /// A subscription to the page in another reader's batch.
    Batch(Subscription),
}

impl PageSource {
    /// Wait for the page, keyed by `key` in the cache's in-flight fetches.
    async fn wait(self, cache: &RwLock<Cache>, key: (u64, u64)) -> Result<IoBuf, Error> {
        match self {
            Self::Fetch(fetch) => PageFetchGuard::new(cache, key, fetch).wait().await,
            Self::Batch(mut subscription) => {
                let delivery = subscription.try_next().await?;
                let (_, page) = delivery.expect("a subscription yields the page it selected");
                Ok(page)
            }
        }
    }
}

/// The pieces of a read's buffers that one page fills, each `(page number, offset in page,
/// piece)`.
type Pieces<'a, 'b> = &'a mut [(u64, usize, &'b mut [u8])];

/// A batched read's share of a [Batch], which is a subscription to the pages it needs and the
/// pieces each fills.
struct BatchRead<'a, 'b> {
    subscription: Subscription,
    /// The pieces each selected page fills, by tag.
    pieces: Vec<Pieces<'a, 'b>>,
    /// For the read that started the batch, a handle on the driver to await, so a read error after
    /// the batch's last page still fails the read.
    completion: Option<BatchDriver>,
}

impl<'a, 'b> BatchRead<'a, 'b> {
    /// The share of the read that started `batch`, whose pages fill `pieces`, by index.
    fn starting(batch: Arc<Batch>, driver: BatchDriver, pieces: Vec<Pieces<'a, 'b>>) -> Self {
        Self {
            completion: Some(driver.clone()),
            subscription: Subscription::starting(batch, driver),
            pieces,
        }
    }

    /// The share of a read that joins `batch`, selecting no pages yet.
    fn joining(batch: Arc<Batch>, driver: BatchDriver) -> Self {
        Self {
            subscription: Subscription::joining(batch, driver),
            pieces: Vec::new(),
            completion: None,
        }
    }

    /// Select the page at `index` to fill `pieces`. Call with the cache lock held, after finding
    /// the page unpublished, and before the first poll.
    fn select(&mut self, index: usize, pieces: Pieces<'a, 'b>) {
        self.subscription.select(index, self.pieces.len());
        self.pieces.push(pieces);
    }

    /// Copy each selected page into its pieces as the batch delivers it, then, if this read
    /// started the batch, await the driver's end.
    async fn complete(mut self) -> Result<(), Error> {
        while let Some((tag, page)) = self.subscription.try_next().await? {
            copy_page(page.as_ref(), self.pieces[tag]);
        }
        match self.completion {
            Some(driver) => driver.await,
            None => Ok(()),
        }
    }
}

/// Copy the bytes of each `(page number, offset in page, piece)` out of `page`.
fn copy_page(page: &[u8], pieces: Pieces<'_, '_>) {
    for (_, offset, piece) in pieces {
        piece.copy_from_slice(&page[*offset..*offset + piece.len()]);
    }
}

/// A [Cache] caches pages of [Blob] data in memory after verifying the integrity of each.
///
/// A single page cache can be used to cache data from multiple blobs by assigning a unique id to
/// each.
///
/// Eviction uses the Clock2Q+ replacement algorithm. All page buffers are pre-allocated at
/// construction and reused in place, so caching never allocates page buffers after construction.
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

    /// A map of currently executing page fetches to ensure only one task at a time is trying to
    /// fetch a specific page.
    page_fetches: AHashMap<(u64, u64), PageFetchEntry>,

    /// The batches in flight, so readers that miss one of their unpublished pages join them.
    batches: BatchRegistry,
    /// Which slots hold each blob's pages, so eviction visits only resident pages.
    residency: Residency,

    /// The first page each pruned blob may cache, so a pruned page that a read fetches again
    /// stays out. A blob's bound leaves with its last handle.
    pruned: AHashMap<u64, u64>,
}

/// Slot index marking either end of a chain.
const NONE: u32 = u32::MAX;

/// Blob id of a slot that holds no live page.
const NO_BLOB: u64 = u64::MAX;

/// A cache slot's place in the chain of the blob whose page it holds.
#[derive(Clone, Copy)]
struct Link {
    blob_id: u64,
    prev: u32,
    next: u32,
}

/// The resident pages of each blob, chained through the cache's slots.
///
/// A slot joins a blob's chain when one of the blob's pages is cached in it. It leaves when that
/// page is evicted or when another blob's page displaces it.
struct Residency {
    /// Indexed by cache slot.
    links: Vec<Link>,
    /// The first slot of each blob's chain.
    heads: AHashMap<u64, u32>,
}

impl Residency {
    /// Residency for a cache of `capacity` slots, none holding a page yet.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is `u32::MAX` or greater.
    fn new(capacity: usize) -> Self {
        assert!(
            capacity < Widen::widen(NONE),
            "page cache capacity must fit a u32 slot index"
        );
        let unlinked = Link {
            blob_id: NO_BLOB,
            prev: NONE,
            next: NONE,
        };
        Self {
            links: vec![unlinked; capacity],
            heads: AHashMap::new(),
        }
    }

    /// Record that `slot` holds a page of `blob_id`. A slot that held another blob's page leaves
    /// that blob's chain.
    fn link(&mut self, slot: usize, blob_id: u64) {
        let link = self.links[slot];
        if link.blob_id == blob_id {
            return;
        }
        if link.blob_id != NO_BLOB {
            self.unlink(slot);
        }
        let index = u32::try_from(slot).expect("slot index must fit a u32");
        let head = self.heads.insert(blob_id, index).unwrap_or(NONE);
        if head != NONE {
            self.links[Widen::widen(head)].prev = index;
        }
        self.links[slot] = Link {
            blob_id,
            prev: NONE,
            next: head,
        };
    }

    /// Record that `slot` no longer holds a page of its blob.
    fn unlink(&mut self, slot: usize) {
        let Link {
            blob_id,
            prev,
            next,
        } = self.links[slot];
        if prev != NONE {
            self.links[Widen::widen(prev)].next = next;
        } else if next != NONE {
            self.heads.insert(blob_id, next);
        } else {
            self.heads.remove(&blob_id);
        }
        if next != NONE {
            self.links[Widen::widen(next)].prev = prev;
        }
        self.links[slot] = Link {
            blob_id: NO_BLOB,
            prev: NONE,
            next: NONE,
        };
    }

    /// The first slot of `blob_id`'s chain.
    fn head(&self, blob_id: u64) -> Option<usize> {
        self.heads.get(&blob_id).map(|&slot| Widen::widen(slot))
    }

    /// The slot after `slot` in its chain.
    fn next(&self, slot: usize) -> Option<usize> {
        let next = self.links[slot].next;
        (next != NONE).then_some(Widen::widen(next))
    }

    /// Whether `slot` holds a page of `blob_id`.
    fn holds(&self, slot: usize, blob_id: u64) -> bool {
        self.links[slot].blob_id == blob_id
    }
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

    /// Shareable reference to the page cache.
    cache: Arc<RwLock<Cache>>,
}

impl CacheRef {
    /// Create a shared page-cache handle.
    ///
    /// The cache stores at most `capacity` pages, each exactly `page_size` bytes (see
    /// [Self::page_size] for how this relates to a page's physical size on disk).
    /// Initialization eagerly allocates and zeroes all cache slots. Eviction follows
    /// the cache's Clock2Q+ replacement algorithm.
    ///
    /// Any `page_size` is accepted, but physical pages that do not align with blob pages (see the
    /// module docs) amplify cold random reads. Use [super::page_size] to pick an aligned value.
    /// Cache misses request [ReadOptions::DONT_CACHE] because the fetched page is retained here.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is `u32::MAX` or greater.
    pub fn new(page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let page_size_u64: u64 = page_size.widen();
        let physical_page_size = page_size_u64 + CHECKSUM_SIZE;
        if !physical_page_size.is_multiple_of(u64::from(BLOB_PAGE_SIZE))
            && !u64::from(BLOB_PAGE_SIZE).is_multiple_of(physical_page_size)
        {
            debug!(
                page_size = page_size.get(),
                physical_page_size, "physical pages do not align with blob pages"
            );
        }

        Self {
            page_size,
            next_id: Arc::new(AtomicU64::new(0)),
            cache: Arc::new(RwLock::new(Cache::new(page_size, capacity))),
        }
    }

    /// The page size used by this page cache: the logical payload bytes stored per page. Each
    /// page occupies `page_size() + CHECKSUM_SIZE` bytes on disk (its physical size).
    #[inline]
    pub const fn page_size(&self) -> NonZeroU16 {
        self.page_size
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
        let page_cache = self.cache.read();
        while !buf.is_empty() {
            let count = page_cache.read_at(blob_id, buf, logical_offset);
            if count == 0 {
                // Cache miss. Return how many bytes were read.
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
    /// in `ranges` start at the first missing byte, with any cached prefix already copied into
    /// the destination and excluded from the remaining slice.
    pub(super) fn read_cached_many(&self, blob_id: u64, ranges: &mut Vec<(&mut [u8], u64)>) {
        let page_cache = self.cache.read();
        let page_size = page_cache.page_size;

        // Resolve every range's first page before copying any data. The lookups are
        // independent, so batching them lets the core overlap their memory latency instead of
        // stalling each lookup behind the previous range's copy.
        let mut srcs: Vec<Option<&[u8]>> = Vec::with_capacity(ranges.len());
        for (buf, offset) in ranges.iter() {
            let (page_num, offset_in_page, remaining) = Cache::locate(page_size, *offset);
            let seg = std::cmp::min(buf.len(), remaining);
            srcs.push(
                page_cache
                    .get_page(blob_id, page_num)
                    .map(|page| &page.as_ref()[offset_in_page..offset_in_page + seg]),
            );
        }

        // Copy resolved pages, dropping fully-cached ranges and retaining only unread suffixes.
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
                    *offset += done as u64;
                    *buf = std::mem::take(buf).split_at_mut(done).1;
                    return true;
                }
                done += count;
            }
            false
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

    /// Complete the unread suffixes a [Self::read_cached_many] probe left in `ranges` (each
    /// `(destination, logical offset)`, non-empty, in ascending offset order).
    ///
    /// Each page the ranges touch is copied from the cache when resident, joined when another
    /// reader is fetching it, alone or in a batch, and otherwise read with one batched blob read
    /// that validates, caches, and serves each page as it arrives. Other readers that miss a page
    /// of that batch join it. Serving never depends on the cache still holding a page, so no page
    /// this call reads is read again to serve it. A page failing validation returns an error, like
    /// a single fetch, as does a failed read of this call's own batch, or of a joined batch while
    /// this call still awaits one of its pages. Pages cached before it remain, subject to normal
    /// eviction.
    pub(super) async fn read_after_misses<B: Blob>(
        &self,
        blob: &Arc<B>,
        blob_id: u64,
        ranges: Vec<(&mut [u8], u64)>,
    ) -> Result<(), Error> {
        // Split every range at page boundaries. Copy resident pieces now, before this call's own
        // insertions can evict their pages.
        let mut waiting = Vec::new();
        {
            let cache = self.cache.read();
            for (mut buf, mut offset) in ranges {
                while !buf.is_empty() {
                    let (page_num, offset_in_page, remaining) =
                        Cache::locate(self.page_size, offset);
                    let len = remaining.min(buf.len());
                    let (piece, rest) = std::mem::take(&mut buf).split_at_mut(len);
                    if cache.read_at(blob_id, piece, offset) == 0 {
                        waiting.push((page_num, offset_in_page, piece));
                    }
                    offset += Widen::widen(len);
                    buf = rest;
                }
            }
        }

        // Group the waiting pieces by page, which the ranges' offset order keeps adjacent, each
        // with its page's physical range, computed up front so starting a batch cannot fail.
        let page_size: u64 = self.page_size.widen();
        let mut misses = Vec::new();
        for pieces in waiting.chunk_by_mut(|(a, _, _), (b, _, _)| a == b) {
            misses.push((physical_page(pieces[0].0, page_size)?, pieces));
        }

        // Join a source for every page before driving any. Copy pages that became resident, join
        // the fetches and batches other readers have in flight, and read the rest with one batch
        // of this call's own, registered so later readers join it.
        let mut fetches = Vec::new();
        let mut reads: Vec<BatchRead<'_, '_>> = Vec::new();
        {
            let mut unread = Vec::new();
            let mut cache = self.cache.write();
            cache.batches.unregister_retired();
            for (i, (physical, pieces)) in misses.into_iter().enumerate() {
                if i > 0 && i % MISSES_PER_LOCK == 0 {
                    RwLockWriteGuard::bump(&mut cache);
                }
                let page_num = pieces[0].0;
                let key = (blob_id, page_num);
                if let Some(page) = cache.get_page(blob_id, page_num) {
                    copy_page(page.as_ref(), pieces);
                } else if let Some(entry) = cache.page_fetches.get_mut(&key) {
                    entry.waiters += 1;
                    let fetch = PageFetchGuard::new(&self.cache, key, entry.fetch.clone());
                    fetches.push((fetch, pieces));
                } else if let Some((batch, index, driver)) =
                    cache.batches.find_unpublished(blob_id, page_num)
                {
                    let joined = reads
                        .iter()
                        .rposition(|read| Arc::ptr_eq(&read.subscription.batch, &batch));
                    let joined = joined.unwrap_or_else(|| {
                        reads.push(BatchRead::joining(batch, driver));
                        reads.len() - 1
                    });
                    reads[joined].select(index, pieces);
                } else {
                    unread.push((physical, pieces));
                }
            }
            if !unread.is_empty() {
                let (physical, pieces): (Vec<_>, Vec<_>) = unread.into_iter().unzip();
                let pages = pieces.iter().map(|pieces| pieces[0].0).collect();
                let batch = Arc::new(Batch::new(blob_id, pages));
                let retire = cache.batches.retire_on_drop(&batch);
                let read = batch.clone().read(
                    self.cache.clone(),
                    blob.clone(),
                    physical,
                    self.page_size,
                    retire,
                );
                let driver = Shared::new(read.boxed());
                cache.batches.register(&batch, &driver);
                reads.push(BatchRead::starting(batch, driver, pieces));
            }
        }

        // Copy each page into its pieces as its source supplies it. Completing in any order lets
        // the first error return at once.
        let fetches = fetches
            .into_iter()
            .map(|(fetch, pieces)| async move {
                copy_page(fetch.wait().await?.as_ref(), pieces);
                Ok(())
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<()>();
        let reads = reads
            .into_iter()
            .map(BatchRead::complete)
            .collect::<FuturesUnordered<_>>()
            .try_collect::<()>();
        futures::try_join!(fetches, reads)?;
        Ok(())
    }

    /// Fetch the requested page after encountering a page fault, which may involve joining the
    /// fetch or batch already reading it, or retrieving it from `blob` & caching the result in the
    /// page cache. Returns the number of bytes read, which should always be non-zero.
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

        // Join the fetch or batch another reader has in flight for this page, or else create a
        // future that retrieves it from the underlying blob. This requires a write lock on the
        // page cache, since joining or creating either one updates the cache's in-flight state.
        let key = (blob_id, page_num);
        let source = {
            let mut cache = self.cache.write();

            // There's a (small) chance the page was fetched & buffered by another task before we
            // were able to acquire the write lock, so check the cache before doing anything else.
            let count = cache.read_at(blob_id, buf, offset);
            if count != 0 {
                return Ok(count);
            }

            let Cache {
                page_fetches,
                batches,
                ..
            } = &mut *cache;
            match page_fetches.entry(key) {
                Entry::Occupied(o) => {
                    // Another thread is already fetching this page, so clone its existing future.
                    let entry = o.into_mut();
                    entry.waiters += 1;
                    PageSource::Fetch(entry.fetch.clone())
                }
                Entry::Vacant(v) => {
                    batches.unregister_retired();
                    if let Some((batch, index, driver)) =
                        batches.find_unpublished(blob_id, page_num)
                    {
                        // Another reader's batch is reading this page, so join it.
                        let mut subscription = Subscription::joining(batch, driver);
                        subscription.select(index, 0);
                        PageSource::Batch(subscription)
                    } else {
                        // Nobody is currently fetching this page, so create a future that will do
                        // the work. fetch_cacheable_page handles CRC validation and returns only
                        // logical bytes.
                        let blob = blob.clone();
                        let cache = Arc::clone(&self.cache);
                        let page_size = self.page_size;
                        let future = async move {
                            let result =
                                fetch_cacheable_page(blob.as_ref(), page_num, page_size).await;
                            if let Err(err) = &result {
                                error!(page_num, ?err, "Page fetch failed");
                            }

                            // This shared future still owns `page_fetches[key]`. As long as at
                            // least one waiter remains armed, that entry pins this generation in
                            // place, so a replacement fetch for the same page cannot be inserted
                            // before we cache the successful result below. Only when every waiter
                            // cancels can the last guard remove the entry and let a later reader
                            // start a new generation.
                            let mut cache = cache.write();
                            if let Ok(page) = &result {
                                cache.cache(blob_id, page.as_ref(), page_num);
                            }
                            let _ = cache.page_fetches.remove(&key);
                            result
                        };

                        // Make the future shareable and insert it into the map.
                        let fetch = Shared::new(future.boxed());
                        v.insert(PageFetchEntry {
                            fetch: fetch.clone(),
                            waiters: 1,
                        });
                        PageSource::Fetch(fetch)
                    }
                }
            }
        };
        let page_buf = source.wait(&self.cache, key).await?;

        // Copy the requested portion of the page into the buffer.
        let bytes_to_copy = std::cmp::min(buf.len(), page_buf.len() - offset_in_page);
        buf[..bytes_to_copy]
            .copy_from_slice(&page_buf.as_ref()[offset_in_page..offset_in_page + bytes_to_copy]);

        Ok(bytes_to_copy)
    }

    /// Cache the provided pages of data in the page cache, returning the remaining bytes that
    /// didn't fill a whole page. `offset` must be page aligned, and `blob_id` must not be
    /// `u64::MAX`. The cache reserves that id for empty slots.
    ///
    /// # Panics
    ///
    /// Panics if `offset` is not page aligned, or if `blob_id` is `u64::MAX`.
    pub fn cache(&self, blob_id: u64, buf: &[u8], offset: u64) -> usize {
        assert_ne!(blob_id, NO_BLOB, "blob id must not be u64::MAX");
        let page_size: usize = self.page_size.widen();
        buf.len() - self.cache_pages(blob_id, buf.chunks_exact(page_size), offset)
    }

    /// Insert whole logical pages under one cache lock, returning the number of bytes consumed,
    /// whether or not the blob's pruning bound admitted their pages.
    pub(super) fn cache_pages<'a>(
        &self,
        blob_id: u64,
        pages: impl Iterator<Item = &'a [u8]>,
        offset: u64,
    ) -> usize {
        let (mut page_num, offset_in_page) = self.offset_to_page(offset);
        assert_eq!(offset_in_page, 0);
        let mut consumed = 0;
        let mut page_cache = self.cache.write();
        for page in pages {
            page_cache.cache(blob_id, page, page_num);
            consumed += page.len();
            page_num = match page_num.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        consumed
    }

    /// Drop the cached pages of blob `blob_id` lying entirely below logical offset `below` and
    /// keep them out, so a read that fetches one of them again does not cache it. Their slots are
    /// freed for new pages, and the bytes remain readable from the blob.
    ///
    /// Each call records its bound before walking the blob's pages, so a call whose bound does not
    /// advance returns without walking. The earlier call that recorded the bound may still be
    /// walking, and it removes every page below that bound.
    pub(super) fn evict(&self, blob_id: u64, below: u64) {
        let page_size: u64 = self.page_size.widen();
        let bound = below / page_size;

        // Pruning at a blob boundary evicts below offset zero of the oldest retained blob. No page
        // lies below the first, so skip the lock and the walk.
        if bound == 0 {
            return;
        }

        // Pages below the previous bound cannot return and the walk that recorded it removes them,
        // so a bound that does not advance adds nothing to evict.
        let mut cache = self.cache.write();
        let pruned = cache.pruned.entry(blob_id).or_insert(0);
        if bound <= *pruned {
            return;
        }
        *pruned = bound;
        Self::evict_resident(cache, blob_id, |page_num| page_num < bound);
    }

    /// Drop every page cached under `blob_id` and its bound, once no handle can read the blob
    /// again.
    fn evict_blob(&self, blob_id: u64) {
        let mut cache = self.cache.write();
        cache.pruned.remove(&blob_id);
        Self::evict_resident(cache, blob_id, |_| true);
    }

    /// Walk the chain of `blob_id` and remove each page whose page number satisfies `evict`.
    ///
    /// The walk yields the lock after every [PAGES_PER_LOCK] visits, but only until it has visited
    /// as many slots as the cache holds, because other threads may move the next slot to the
    /// chain's head during a yield and send the walk back over pages it kept. No chain spans more
    /// slots than the cache, so an undisturbed walk yields throughout, and the walk after its last
    /// yield visits each slot at most once. Every walk therefore visits fewer than twice the
    /// cache's capacity.
    fn evict_resident(
        mut cache: RwLockWriteGuard<'_, Cache>,
        blob_id: u64,
        evict: impl Fn(u64) -> bool,
    ) {
        let capacity = cache.cache.capacity();
        let mut cursor = cache.residency.head(blob_id);
        let mut visited = 0usize;
        while let Some(slot) = cursor {
            visited += 1;
            cursor = cache.residency.next(slot);
            let &(_, page_num) = cache
                .cache
                .key_at(slot)
                .expect("a linked slot must hold a live page");
            if evict(page_num) {
                cache.cache.remove_at(slot);
                cache.residency.unlink(slot);
            }

            // While the lock is yielded, other threads only unlink slots, link slots at the head,
            // or give a slot another page of the same blob without moving it. None of these
            // reorders the remaining slots, so if the next slot is still in the chain, every page
            // resident before the yield that the walk has yet to reach still follows it.
            // Otherwise resume from the head.
            if let Some(next) = cursor
                && visited.is_multiple_of(PAGES_PER_LOCK)
                && visited < capacity
            {
                RwLockWriteGuard::bump(&mut cache);
                #[cfg(test)]
                tests::eviction_yielded(&mut cache, next);
                if !cache.residency.holds(next, blob_id) {
                    cursor = cache.residency.head(blob_id);
                }
            }
        }
    }

    /// Drop all cached pages while retaining the backing page buffers for reuse.
    ///
    /// Call only when no reads are in flight for this cache.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

impl Cache {
    /// Return a new empty page cache with a max cache capacity of `capacity` pages, each of size
    /// `page_size` bytes.
    pub fn new(page_size: NonZeroU16, capacity: NonZeroUsize) -> Self {
        let slot_size: usize = page_size.widen();
        let mut cache = cache::Cache::new(capacity);
        cache.prefill(|| IoBufMut::zeroed(slot_size));
        let hints = capacity.get().saturating_mul(2).next_power_of_two();
        Self {
            cache,
            hints: vec![usize::MAX; hints],
            page_size,
            page_fetches: AHashMap::new(),
            batches: BatchRegistry::default(),
            residency: Residency::new(capacity.get()),
            pruned: AHashMap::new(),
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

    /// Put the given `page` into the page cache and record its slot hint, unless the page lies
    /// below its blob's pruning bound.
    fn cache(&mut self, blob_id: u64, page: &[u8], page_num: u64) {
        let page_size: usize = self.page_size.widen();
        assert_eq!(page.len(), page_size);
        if self
            .pruned
            .get(&blob_id)
            .is_some_and(|&bound| page_num < bound)
        {
            return;
        }
        let (slot, buf) = self
            .cache
            .get_or_insert_mut((blob_id, page_num), || IoBufMut::zeroed(page_size));
        buf.as_mut().copy_from_slice(page);
        let hint = self.hint_index(blob_id, page_num);
        self.hints[hint] = slot;
        self.residency.link(slot, blob_id);
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
        self.batches = BatchRegistry::default();
        self.residency = Residency::new(self.cache.capacity());
        self.pruned.clear();
    }
}

/// The page-cache identity of one blob, held by every handle that can read it through the cache.
/// Dropping the last one drops the blob's cached pages and its pruning bound, since no reader can
/// reach them again.
///
/// Dropping takes the cache's write lock, so the cache itself must never own a lease.
pub(super) struct PageLease {
    cache_ref: CacheRef,
    id: u64,
}

impl PageLease {
    /// Lease a fresh blob id from `cache_ref`.
    pub(super) fn new(cache_ref: CacheRef) -> Self {
        let id = cache_ref.next_id();
        Self { cache_ref, id }
    }

    /// The blob's page-cache id.
    pub(super) const fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for PageLease {
    fn drop(&mut self) {
        self.cache_ref.evict_blob(self.id);
    }
}

/// Fetch one logical page for insertion into the page cache.
async fn fetch_cacheable_page(
    blob: &impl Blob,
    page_num: u64,
    page_size: NonZeroU16,
) -> Result<IoBuf, Error> {
    // CacheRef retains the page, so the source page need not remain in the OS page cache.
    let width: u64 = page_size.widen();
    let (page, _) =
        get_page_with_checksum_from_blob(blob, page_num, width, ReadOptions::DONT_CACHE).await?;
    cacheable_page(page, page_num, page_size)
}

/// Return a validated page's logical bytes, rejecting partial pages because cache entries must
/// always contain a full logical page.
fn cacheable_page(page: IoBuf, page_num: u64, page_size: NonZeroU16) -> Result<IoBuf, Error> {
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
    use super::{
        super::{
            Checksum,
            view::{Tail, View},
        },
        *,
    };
    use crate::{
        Clock as _, Handle, IoBufMut, IoBufs, IoBufsMut, Runner as _, Spawner as _, Storage as _,
        Supervisor as _, WriteOptions, buffer::paged::CHECKSUM_SIZE, deterministic,
        mocks::MigratingReadBlob,
    };
    use commonware_cryptography::Crc32;
    use commonware_macros::{select, test_traced};
    use commonware_utils::{
        NZU16, NZUsize,
        channel::{
            mpsc::{UnboundedReceiver, unbounded_channel},
            oneshot,
        },
        sync::Mutex,
    };
    use futures::{future::pending, poll};
    use rand::{RngExt as _, seq::SliceRandom as _};
    use rstest::rstest;
    use std::{
        cell::{Cell, RefCell},
        future::poll_fn,
        num::NonZeroU16,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Waker,
        time::Duration,
    };

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
        let mut cache: Cache = Cache::new(PAGE_SIZE, NZUsize!(10));

        // Cache stores logical-sized pages.
        let mut buf = vec![0; PAGE_SIZE.get() as usize];
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, 0);

        cache.cache(0, &[1; PAGE_SIZE.get() as usize], 0);
        let bytes_read = cache.read_at(0, &mut buf, 0);
        assert_eq!(bytes_read, PAGE_SIZE.get() as usize);
        assert_eq!(buf, [1; PAGE_SIZE.get() as usize]);

        // Re-caching the same page overwrites it in place.
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
        let mut cache: Cache = Cache::new(PAGE_SIZE, NZUsize!(2));
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
        R::Context: crate::Clock + crate::Spawner + crate::Storage,
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));
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

                    // Publish the handoff only after the source's poll has returned, then park on
                    // an unrelated signal so source wakeups cannot repoll the cache read.
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
        executor.start(|_| async move {
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));

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
        executor.start(|_| async move {
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));

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

    /// Write `pages` CRC-protected physical pages (page `i` filled with byte `i`) and return the
    /// blob.
    async fn checksummed_blob<S: crate::Storage>(storage: &S, pages: u64) -> Arc<S::Blob> {
        let physical_page_size = PAGE_SIZE_U64 + CHECKSUM_SIZE;
        let (blob, size) = storage.open("fill", b"blob").await.unwrap();
        assert_eq!(size, 0);
        for i in 0..pages {
            let logical = vec![i as u8; PAGE_SIZE.get() as usize];
            let crc = Crc32::checksum(&logical);
            let mut page = logical;
            page.extend_from_slice(&Checksum::new(PAGE_SIZE.get(), crc).to_bytes());
            blob.write_at(i * physical_page_size, page, WriteOptions::default())
                .await
                .unwrap();
        }
        Arc::new(blob)
    }

    #[test_traced]
    fn test_read_after_misses_serves_ranges() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (recording, recordings) = crate::mocks::RecordingContext::new(context);
            let blob = checksummed_blob(&recording, 8).await;
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));
            let page = PAGE_SIZE.get() as usize;

            // Page 2 is already resident, so only the other pages the ranges touch are read: a
            // range inside page 0, one straddling pages 3-4, and one ending in page 6.
            let mut buf = vec![0u8; page];
            cache_ref
                .read_after_miss(&blob, 0, &mut buf, 2 * PAGE_SIZE_U64)
                .await
                .unwrap();
            recordings.clear();
            let ranges = [
                (5u64, 3usize),
                (2 * PAGE_SIZE_U64 + 1, 2),
                (3 * PAGE_SIZE_U64 + page as u64 - 1, 2),
                (5 * PAGE_SIZE_U64, page + 1),
            ];
            let mut bufs: Vec<Vec<u8>> = ranges.iter().map(|&(_, len)| vec![0; len]).collect();
            let pending: Vec<(&mut [u8], u64)> = bufs
                .iter_mut()
                .zip(ranges)
                .map(|(buf, (offset, _))| (buf.as_mut_slice(), offset))
                .collect();
            cache_ref
                .read_after_misses(&blob, 0, pending)
                .await
                .unwrap();
            assert_eq!(recordings.snapshot().reads.len(), 5);
            for ((offset, len), buf) in ranges.into_iter().zip(&bufs) {
                let expected: Vec<u8> = (offset..offset + len as u64)
                    .map(|o| (o / PAGE_SIZE_U64) as u8)
                    .collect();
                assert_eq!(buf, &expected);
            }

            // The pages read are cached, so later reads complete without a blob read.
            recordings.clear();
            for (offset, len) in ranges {
                let mut buf = vec![0u8; len];
                cache_ref
                    .read_after_miss(&blob, 0, &mut buf, offset)
                    .await
                    .unwrap();
            }
            assert!(recordings.snapshot().reads.is_empty());

            // Ranges on resident pages alone need no blob read at all.
            let mut inside = [0u8; 1];
            let mut straddling = [0u8; 2];
            cache_ref
                .read_after_misses(
                    &blob,
                    0,
                    vec![
                        (inside.as_mut_slice(), 7),
                        (
                            straddling.as_mut_slice(),
                            3 * PAGE_SIZE_U64 + page as u64 - 1,
                        ),
                    ],
                )
                .await
                .unwrap();
            assert_eq!((inside, straddling), ([0], [3, 4]));
            assert!(recordings.snapshot().reads.is_empty());
        });
    }

    #[test_traced]
    fn test_read_after_misses_rejects_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let blob = checksummed_blob(&context, 3).await;
            let physical_page_size = PAGE_SIZE_U64 + CHECKSUM_SIZE;
            blob.write_at(physical_page_size + 1, vec![0xFF], WriteOptions::default())
                .await
                .unwrap();
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));

            // A corrupt page fails the read and never enters the cache. Pages that passed their
            // own validation before the failure may already be resident.
            let mut bufs = [[0u8; 1]; 3];
            let pending: Vec<(&mut [u8], u64)> = bufs
                .iter_mut()
                .zip([0, PAGE_SIZE_U64, 2 * PAGE_SIZE_U64])
                .map(|(buf, offset)| (buf.as_mut_slice(), offset))
                .collect();
            assert!(matches!(
                cache_ref.read_after_misses(&blob, 0, pending).await,
                Err(Error::InvalidChecksum)
            ));
            let mut buf = [0u8; 1];
            assert_eq!(cache_ref.read_cached(0, &mut buf, PAGE_SIZE_U64), 0);

            // The intact pages are served on their own.
            let mut bufs = [[0u8; 1]; 2];
            let pending: Vec<(&mut [u8], u64)> = bufs
                .iter_mut()
                .zip([0, 2 * PAGE_SIZE_U64])
                .map(|(buf, offset)| (buf.as_mut_slice(), offset))
                .collect();
            cache_ref
                .read_after_misses(&blob, 0, pending)
                .await
                .unwrap();
            assert_eq!(bufs, [[0], [2]]);
        });
    }

    #[test_traced]
    fn test_read_many_into_reads_each_missing_page_once() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (recording, recordings) = crate::mocks::RecordingContext::new(context);
            let blob = checksummed_blob(&recording, 40).await;

            // Fill a 20-page cache, whose probation queue holds only 2 pages, with pages 20..40.
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(20));
            for page in 20..40 {
                let mut buf = [0u8; 1];
                cache_ref
                    .read_after_miss(&blob, 0, &mut buf, page * PAGE_SIZE_U64)
                    .await
                    .unwrap();
            }
            recordings.clear();

            // Caching the 10 missing pages evicts most of them before they are served, but each
            // is still read from the blob once.
            let size = 40 * PAGE_SIZE_U64;
            let view = View {
                blob: &blob,
                cache_ref: &cache_ref,
                id: 0,
                size,
                tail_offset: size,
                tail: Tail::Sealed(&[]),
            };
            let offsets: Vec<u64> = (0..10).map(|page| page * PAGE_SIZE_U64).collect();
            let mut buf = vec![0u8; offsets.len()];
            let served = view
                .read_many_into(&mut buf, &offsets, NZUsize!(1))
                .await
                .unwrap();
            assert_eq!(served, 0);
            assert_eq!(buf, (0u8..10).collect::<Vec<_>>());
            assert_eq!(recordings.snapshot().reads.len(), offsets.len());
        });
    }

    #[test_traced]
    fn test_read_many_into_copies_resident_pages_first() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (recording, recordings) = crate::mocks::RecordingContext::new(context);
            let blob = checksummed_blob(&recording, 6).await;

            // Page 1 is resident in a 2-page cache. Caching the five other pages one item spans
            // evicts it, yet it is never read from the blob.
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));
            let mut buf = [0u8; 1];
            cache_ref
                .read_after_miss(&blob, 0, &mut buf, PAGE_SIZE_U64)
                .await
                .unwrap();
            recordings.clear();

            let size = 6 * PAGE_SIZE_U64;
            let view = View {
                blob: &blob,
                cache_ref: &cache_ref,
                id: 0,
                size,
                tail_offset: size,
                tail: Tail::Sealed(&[]),
            };
            let mut buf = vec![0u8; size as usize];
            let served = view
                .read_many_into(&mut buf, &[0], NZUsize!(size as usize))
                .await
                .unwrap();
            assert_eq!(served, 0);
            let expected: Vec<u8> = (0..size).map(|o| (o / PAGE_SIZE_U64) as u8).collect();
            assert_eq!(buf, expected);
            assert_eq!(recordings.snapshot().reads.len(), 5);
        });
    }

    /// A physical page whose first `len` logical bytes equal `value` and are covered by its
    /// checksum. The rest of its logical bytes are zero.
    fn page_bytes(value: u8, len: u16) -> Vec<u8> {
        let mut page = vec![value; usize::from(len)];
        let crc = Crc32::checksum(&page);
        page.resize(PAGE_SIZE.get() as usize, 0);
        page.extend_from_slice(&Checksum::new(len, crc).to_bytes());
        page
    }

    /// Physical page `page` of a test blob, whose logical bytes all equal the page's index.
    fn full_page(page: usize) -> Vec<u8> {
        page_bytes(page as u8, PAGE_SIZE.get())
    }

    /// [full_page] with a corrupted first byte, which fails validation.
    fn corrupt_page(page: usize) -> Vec<u8> {
        let mut bytes = full_page(page);
        bytes[0] ^= 0xFF;
        bytes
    }

    /// Serves [full_page]s, holding each page's first read until its gate opens.
    struct GatedBlob {
        gates: Mutex<Vec<Option<oneshot::Receiver<()>>>>,
        reads: Mutex<Vec<usize>>,
        /// A page whose next read returns corrupted bytes.
        corrupt: Mutex<Option<usize>>,
        /// Polls of the streams [Blob::read_many] returns.
        polls: AtomicUsize,
    }

    impl GatedBlob {
        /// A blob of `pages` pages, with the senders that open each page's gate.
        fn new(pages: usize) -> (Arc<Self>, Vec<Option<oneshot::Sender<()>>>) {
            let (opens, gates) = (0..pages)
                .map(|_| {
                    let (open, gate) = oneshot::channel();
                    (Some(open), Some(gate))
                })
                .unzip();
            let blob = Self {
                gates: Mutex::new(gates),
                reads: Mutex::new(Vec::new()),
                corrupt: Mutex::new(None),
                polls: AtomicUsize::new(0),
            };
            (Arc::new(blob), opens)
        }

        /// How many reads of `page` have started.
        fn reads_of(&self, page: usize) -> usize {
            self.reads
                .lock()
                .iter()
                .filter(|&&read| read == page)
                .count()
        }
    }

    impl Blob for GatedBlob {
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
            offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            let page = (offset / (PAGE_SIZE_U64 + CHECKSUM_SIZE)) as usize;
            self.reads.lock().push(page);
            let corrupted = self.corrupt.lock().take_if(|corrupt| *corrupt == page);
            let bytes = if corrupted.is_some() {
                corrupt_page(page)
            } else {
                full_page(page)
            };
            let gate = self.gates.lock()[page].take();
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            Ok(IoBufsMut::from(bytes))
        }

        fn read_many(
            &self,
            ranges: &[(u64, usize)],
            options: ReadOptions,
        ) -> impl futures::Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
            let mut reads = Box::pin(crate::read_each(self, ranges, options));
            futures::stream::poll_fn(move |cx| {
                self.polls.fetch_add(1, Ordering::Relaxed);
                reads.as_mut().poll_next(cx)
            })
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

    /// A step of a [ScriptedBlob]'s batched read that runs with the read's context.
    type Hook = Box<dyn FnMut(&mut Context<'_>) -> Poll<()> + Send>;

    /// One step of a [ScriptedBlob]'s batched read.
    enum Step {
        /// Yield these physical bytes as the read of the range at this index.
        Yield(usize, Vec<u8>),
        /// Fail the read.
        Fail(Error),
        /// Wait for the gate to open before taking the next step.
        Wait(oneshot::Receiver<()>),
        /// Poll this, with the context the read is polled with, until it is ready.
        Call(Hook),
    }

    impl Step {
        /// Yield [full_page] `index` as the read of the range at `index`.
        fn page(index: usize) -> Self {
            Self::Yield(index, full_page(index))
        }
    }

    /// A blob whose first batched read yields its script, whatever ranges it is asked for. It
    /// serves no other read.
    struct ScriptedBlob(Mutex<Vec<Step>>);

    impl ScriptedBlob {
        fn new(script: Vec<Step>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(script)))
        }
    }

    impl Blob for ScriptedBlob {
        async fn read_at(
            &self,
            _offset: u64,
            _len: usize,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            unreachable!("only batched reads are scripted")
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            unreachable!("only batched reads are scripted")
        }

        fn read_many(
            &self,
            _ranges: &[(u64, usize)],
            _options: ReadOptions,
        ) -> impl futures::Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
            let steps = std::mem::take(&mut *self.0.lock());
            futures::stream::unfold(steps.into_iter(), |mut steps| async move {
                loop {
                    match steps.next()? {
                        Step::Yield(index, bytes) => {
                            return Some((Ok((index, IoBufsMut::from(bytes))), steps));
                        }
                        Step::Fail(err) => return Some((Err(err), steps)),
                        Step::Wait(gate) => {
                            let _ = gate.await;
                        }
                        Step::Call(mut call) => poll_fn(|cx| call(cx)).await,
                    }
                }
            })
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

    /// Open every gate in `opens` not yet opened.
    fn open(opens: &mut [Option<oneshot::Sender<()>>]) {
        for open in opens.iter_mut().filter_map(Option::take) {
            let _ = open.send(());
        }
    }

    /// Read the first byte of each of `pages` (ascending) of `blob` (cache id 0) with one batched
    /// read.
    async fn read_first_bytes<B: Blob>(
        blob: &Arc<B>,
        cache_ref: &CacheRef,
        pages: &[u64],
    ) -> Result<Vec<u8>, Error> {
        let size = pages.last().map_or(0, |last| (last + 1) * PAGE_SIZE_U64);
        let view = View {
            blob,
            cache_ref,
            id: 0,
            size,
            tail_offset: size,
            tail: Tail::Sealed(&[]),
        };
        let offsets: Vec<u64> = pages.iter().map(|page| page * PAGE_SIZE_U64).collect();
        let mut buf = vec![0u8; pages.len()];
        view.read_many_into(&mut buf, &offsets, NZUsize!(1)).await?;
        Ok(buf)
    }

    /// Read the first byte of page `page` of `blob` (cache id 0), starting at a cache miss.
    async fn read_first_byte<B: Blob>(
        blob: &Arc<B>,
        cache_ref: &CacheRef,
        page: u64,
    ) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        cache_ref
            .read_after_miss(blob, 0, &mut buf, page * PAGE_SIZE_U64)
            .await?;
        Ok(buf[0])
    }

    /// Assert that the cache holds no standalone fetch and no live batch.
    fn assert_idle(cache_ref: &CacheRef) {
        let cache = cache_ref.cache.read();
        assert!(cache.page_fetches.is_empty());
        let mut batches = cache.batches.by_blob.values().flatten();
        assert!(batches.all(|(batch, _)| batch.strong_count() == 0));
    }

    /// For each page of each live batch, how many joiners wait on it and how many of those are
    /// still subscribed, or `None` once the page is published.
    fn joiners(cache_ref: &CacheRef) -> Vec<Option<(usize, usize)>> {
        let cache = cache_ref.cache.read();
        let batches = cache.batches.by_blob.values().flatten();
        let batches = batches.filter_map(|(batch, _)| batch.upgrade());
        batches
            .flat_map(|batch| {
                let state = batch.state.lock();
                let pages = state.joiners.iter().map(|joiners| {
                    joiners.as_ref().map(|joiners| {
                        let live = joiners
                            .iter()
                            .filter(|&&(_, reader)| state.inboxes[reader].is_some());
                        (joiners.len(), live.count())
                    })
                });
                pages.collect::<Vec<_>>()
            })
            .collect()
    }

    /// The pages that subscribed joiners selected and have yet to receive.
    fn selected(cache_ref: &CacheRef) -> usize {
        let pages = joiners(cache_ref);
        pages.iter().flatten().map(|(_, live)| live).sum()
    }

    /// Counts the wakes of a task polled by hand.
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test_traced]
    fn test_read_many_into_joins_fetch_in_flight() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const PAGES: u64 = 10;
            let (blob, mut opens) = GatedBlob::new(PAGES as usize);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));

            // Another reader starts fetching page 0.
            let mut first = pin!(read_first_byte(&blob, &cache_ref, 0));
            assert!(poll!(first.as_mut()).is_pending());

            // A batch over every page joins that fetch rather than reading page 0 again, although
            // its own insertions evict page 0 once that fetch completes.
            let pages: Vec<u64> = (0..PAGES).collect();
            let mut second = pin!(read_first_bytes(&blob, &cache_ref, &pages));
            assert!(poll!(second.as_mut()).is_pending());
            opens[0].take().unwrap().send(()).unwrap();
            assert_eq!(first.await.unwrap(), 0);
            open(&mut opens);
            assert_eq!(second.await.unwrap(), (0..PAGES as u8).collect::<Vec<_>>());
            assert_eq!(blob.reads_of(0), 1);
        });
    }

    #[test_traced]
    fn test_overlapping_reads_read_each_page_once() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const PAGES: u64 = 7;
            let (blob, mut opens) = GatedBlob::new(PAGES as usize);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of pages 0-3 starts reading. An overlapping batch of pages 2-5 joins it for
            // pages 2 and 3 and reads only pages 4 and 5.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2, 3]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut second = pin!(read_first_bytes(&blob, &cache_ref, &[2, 3, 4, 5]));
            assert!(poll!(second.as_mut()).is_pending());

            // A batch of pages 1, 5, and 6 joins both batches and reads only page 6, and a single
            // read of page 3 joins the first batch.
            let mut third = pin!(read_first_bytes(&blob, &cache_ref, &[1, 5, 6]));
            assert!(poll!(third.as_mut()).is_pending());
            let mut single = pin!(read_first_byte(&blob, &cache_ref, 3));
            assert!(poll!(single.as_mut()).is_pending());
            assert_eq!(selected(&cache_ref), 2 + (1 + 1) + 1);

            open(&mut opens);
            assert_eq!(first.await.unwrap(), [0, 1, 2, 3]);
            assert_eq!(second.await.unwrap(), [2, 3, 4, 5]);
            assert_eq!(third.await.unwrap(), [1, 5, 6]);
            assert_eq!(single.await.unwrap(), 3);
            for page in 0..PAGES as usize {
                assert_eq!(blob.reads_of(page), 1);
            }
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_joining_many_pages_selects_all_before_driving() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const PAGES: u64 = 3 * MISSES_PER_LOCK as u64;
            let (blob, mut opens) = GatedBlob::new(PAGES as usize);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2 * PAGES as usize));
            let pages: Vec<u64> = (0..PAGES).collect();
            let expected: Vec<u8> = pages.iter().map(|&page| page as u8).collect();

            // A batch of every page starts reading and is left unpolled.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &pages));
            assert!(poll!(first.as_mut()).is_pending());

            // A read of the same pages, examined over several holds of the lock, selects every
            // page in its first poll.
            let mut second = pin!(read_first_bytes(&blob, &cache_ref, &pages));
            assert!(poll!(second.as_mut()).is_pending());
            assert_eq!(selected(&cache_ref), PAGES as usize);

            open(&mut opens);
            assert_eq!(second.await.unwrap(), expected);
            assert_eq!(first.await.unwrap(), expected);
            assert_eq!(blob.reads.lock().len(), PAGES as usize);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_read_joins_unpolled_batch_under_eviction() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Fill a 20-page cache, whose probation queue holds only 2 pages, with pages 20..40.
            let (blob, mut opens) = GatedBlob::new(40);
            open(&mut opens[20..]);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(20));
            for page in 20..40 {
                read_first_byte(&blob, &cache_ref, page).await.unwrap();
            }
            blob.reads.lock().clear();

            // A batch of pages 0..10 starts reading and is left unpolled while its reads finish.
            let pages: Vec<u64> = (0..10).collect();
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &pages));
            assert!(poll!(first.as_mut()).is_pending());
            open(&mut opens);

            // A read of the same pages joins every page and drives the batch. Caching the pages
            // evicts most of them before either read copies them, yet each is read only once.
            let expected: Vec<u8> = (0..10).collect();
            assert_eq!(
                read_first_bytes(&blob, &cache_ref, &pages).await.unwrap(),
                expected
            );
            assert_eq!(first.await.unwrap(), expected);
            assert_eq!(blob.reads.lock().len(), pages.len());
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_read_joining_batch_outlives_its_starter() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(2);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of both pages starts reading, and a read of page 1 joins it.
            let mut first = Box::pin(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut second = pin!(read_first_byte(&blob, &cache_ref, 1));
            assert!(poll!(second.as_mut()).is_pending());

            // The read that started the batch is cancelled, and the joined read completes the
            // batch without reading page 1 again.
            drop(first);
            open(&mut opens);
            assert_eq!(second.await.unwrap(), 1);
            assert_eq!(blob.reads.lock().len(), 2);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_joined_read_finishes_before_its_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(3);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
            assert!(poll!(first.as_mut()).is_pending());

            // A read of page 1 completes once that page arrives, while the batch waits for the
            // others.
            let mut second = pin!(read_first_byte(&blob, &cache_ref, 1));
            assert!(poll!(second.as_mut()).is_pending());
            opens[1].take().unwrap().send(()).unwrap();
            assert_eq!(second.await.unwrap(), 1);
            assert_eq!(joiners(&cache_ref), [Some((0, 0)), None, Some((0, 0))]);

            open(&mut opens);
            assert_eq!(first.await.unwrap(), [0, 1, 2]);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_batch_read_polled_once_per_completion() {
        const PAGES: usize = 32;
        const JOINERS: usize = 4;

        // Stream polls while each page of one batch arrives on its own, with `joiners` other
        // reads of the same pages waiting on the batch.
        let polls = |joiners: usize| {
            deterministic::Runner::default().start(|context| async move {
                let (blob, mut opens) = GatedBlob::new(PAGES);
                let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2 * PAGES));
                let pages: Vec<u64> = (0..PAGES as u64).collect();
                let reads: Vec<_> = (0..=joiners)
                    .map(|_| {
                        let (blob, cache_ref, pages) =
                            (blob.clone(), cache_ref.clone(), pages.clone());
                        context.child("reader").spawn(move |_| async move {
                            read_first_bytes(&blob, &cache_ref, &pages).await.unwrap()
                        })
                    })
                    .collect();
                context.sleep(Duration::from_millis(10)).await;
                let before = blob.polls.load(Ordering::Relaxed);
                for open in &mut opens {
                    let _ = open.take().unwrap().send(());
                    context.sleep(Duration::from_millis(1)).await;
                }
                let expected: Vec<u8> = (0..PAGES as u8).collect();
                for read in futures::future::join_all(reads).await {
                    assert_eq!(read.unwrap(), expected);
                }
                for page in 0..PAGES {
                    assert_eq!(blob.reads_of(page), 1);
                }
                blob.polls.load(Ordering::Relaxed) - before
            })
        };

        // Every completion wakes every reader, but only the first to run polls the read. The
        // others find it not woken since and only wait.
        let alone = polls(0);
        let joined = polls(JOINERS);
        assert!(
            joined <= alone + PAGES,
            "{joined} stream polls with {JOINERS} joiners, {alone} alone"
        );
    }

    #[test]
    fn test_reader_that_stops_driving_rewakes_waiting_reader() {
        type Read = Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send>>;
        let starter: Arc<Mutex<Option<Read>>> = Arc::default();
        let starter_wakes = Arc::new(Wakes::default());
        let starter_waker = Waker::from(starter_wakes.clone());
        let woken_before = Arc::new(AtomicUsize::new(0));
        let stalled: Arc<Mutex<Option<Waker>>> = Arc::default();

        // The batch's read stalls, keeping the waker it is polled with, then yields page 0. Next,
        // its read is woken while it is still being polled, and in that window the starter, as if
        // on another thread, takes page 0 and polls the driver. Last, it yields page 1.
        let mut first_call = true;
        let stall = {
            let stalled = stalled.clone();
            move |cx: &mut Context<'_>| {
                if !std::mem::take(&mut first_call) {
                    return Poll::Ready(());
                }
                *stalled.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        };
        let mut first_call = true;
        let race = {
            let (starter, waker) = (starter.clone(), starter_waker.clone());
            let (wakes, woken_before) = (starter_wakes.clone(), woken_before.clone());
            move |cx: &mut Context<'_>| {
                if !std::mem::take(&mut first_call) {
                    return Poll::Ready(());
                }
                cx.waker().wake_by_ref();
                let mut starter = starter.lock();
                let read = starter.as_mut().unwrap().as_mut();
                assert!(read.poll(&mut Context::from_waker(&waker)).is_pending());
                woken_before.store(wakes.0.load(Ordering::SeqCst), Ordering::SeqCst);
                Poll::Pending
            }
        };
        let blob = ScriptedBlob::new(vec![
            Step::Call(Box::new(stall)),
            Step::page(0),
            Step::Call(Box::new(race)),
            Step::page(1),
        ]);
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

        // The starter reads both pages with one batch, which stalls.
        *starter.lock() = Some(Box::pin({
            let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
            async move { read_first_bytes(&blob, &cache_ref, &[0, 1]).await }
        }));
        let poll_starter = || {
            let mut starter = starter.lock();
            let read = starter.as_mut().unwrap().as_mut();
            read.poll(&mut Context::from_waker(&starter_waker))
        };
        assert!(poll_starter().is_pending());

        // The stalled read makes progress, which wakes the starter. Before the starter runs, a
        // read of page 0 joins the batch and drives it, gets its page, and stops driving.
        stalled.lock().take().unwrap().wake();
        let mut joiner = pin!(read_first_byte(&blob, &cache_ref, 0));
        let joined = joiner
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(joined, Poll::Ready(Ok(0))));

        // The joiner's poll ended after the read was woken, so it re-woke the starter, which runs
        // again and finishes.
        assert!(starter_wakes.0.load(Ordering::SeqCst) > woken_before.load(Ordering::SeqCst));
        assert!(matches!(poll_starter(), Poll::Ready(Ok(ref bytes)) if bytes == &[0, 1]));
    }

    /// Bounds each wait of [test_reader_that_stops_driving_rewakes_waiting_reader_on_tokio]'s
    /// schedule. Every step normally completes at once, so the bound only turns a stall into a
    /// failure.
    const SCHEDULE_DEADLINE: Duration = Duration::from_secs(30);

    /// A page a batched blob read yields (see [Blob::read_many]).
    type Completion = Result<(usize, IoBufsMut), Error>;

    /// A blob whose batched read of two pages yields the completions another thread sends it, and
    /// pauses its first poll that finds none after the first, keeping the waker it registered.
    struct CompletionBlob {
        completions: Mutex<Option<UnboundedReceiver<Completion>>>,
        /// Signals that the stream paused.
        paused: std::sync::mpsc::Sender<()>,
        /// Resumes the paused stream.
        resume: Mutex<std::sync::mpsc::Receiver<()>>,
        /// Completions the stream yielded.
        yielded: AtomicUsize,
    }

    impl Blob for CompletionBlob {
        async fn read_at(
            &self,
            _offset: u64,
            _len: usize,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            unreachable!("pages are read in batches")
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
            _options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            unreachable!("pages are read in batches")
        }

        fn read_many(
            &self,
            ranges: &[(u64, usize)],
            _options: ReadOptions,
        ) -> impl futures::Stream<Item = Completion> + Send {
            assert_eq!(ranges.len(), 2);
            let mut completions = self.completions.lock().take().unwrap();
            let mut paused = false;
            futures::stream::poll_fn(move |cx| {
                if self.yielded.load(Ordering::SeqCst) == 2 {
                    return Poll::Ready(None);
                }
                let result = completions.poll_recv(cx);
                if result.is_ready() {
                    self.yielded.fetch_add(1, Ordering::SeqCst);
                }

                // Hold the first poll that finds no completion after the first was yielded, as
                // when its thread is preempted, so the last completion arrives before it returns.
                if result.is_pending() && self.yielded.load(Ordering::SeqCst) == 1 && !paused {
                    paused = true;
                    self.paused.send(()).unwrap();
                    self.resume.lock().recv_timeout(SCHEDULE_DEADLINE).unwrap();
                }
                result
            })
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

    /// The schedule of [test_reader_that_stops_driving_rewakes_waiting_reader], on worker threads
    /// of the multi-threaded tokio runtime. A two-page batch's last completion arrives while a
    /// read of page 0 that joined the batch drives it, and the batch's starter, woken by the first
    /// completion, is polled meanwhile and finds the batch busy. The joiner gets its page and
    /// stops driving. The starter must still finish, with nothing outside the batch to wake it.
    #[test]
    fn test_reader_that_stops_driving_rewakes_waiting_reader_on_tokio() {
        let runner = crate::tokio::Runner::new(crate::tokio::Config::new().with_worker_threads(4));
        runner.start(|context| async move {
            for _ in 0..20 {
                let (completions, receiver) = unbounded_channel();
                let (paused_tx, paused_rx) = std::sync::mpsc::channel();
                let (resume_stream_tx, resume_stream_rx) = std::sync::mpsc::channel();
                let blob = Arc::new(CompletionBlob {
                    completions: Mutex::new(Some(receiver)),
                    paused: paused_tx,
                    resume: Mutex::new(resume_stream_rx),
                    yielded: AtomicUsize::new(0),
                });
                let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));

                // The starter reads pages 0 and 1 with one batch, and its first poll finds no
                // completion. Its second poll, after the first completion woke it, holds its
                // thread until the last completion has arrived, then finds the joiner driving.
                let (first_polled_tx, first_polled_rx) = std::sync::mpsc::channel();
                let (second_poll_tx, second_poll_rx) = std::sync::mpsc::channel();
                let (resume_starter_tx, resume_starter_rx) = std::sync::mpsc::channel();
                let (second_polled_tx, second_polled_rx) = std::sync::mpsc::channel();
                let starter = context.child("starter").spawn({
                    let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
                    move |_| async move {
                        let mut read = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
                        let mut polls = 0;
                        poll_fn(move |cx| {
                            polls += 1;
                            if polls == 2 {
                                second_poll_tx.send(()).unwrap();
                                resume_starter_rx.recv_timeout(SCHEDULE_DEADLINE).unwrap();
                            }
                            let result = read.as_mut().poll(cx);
                            if polls <= 2 {
                                assert!(result.is_pending());
                                let polled = if polls == 1 {
                                    &first_polled_tx
                                } else {
                                    &second_polled_tx
                                };
                                polled.send(()).unwrap();
                            }
                            result
                        })
                        .await
                    }
                });

                // Deliver each completion at its point in the schedule, start the joiner once
                // the starter's second poll holds its thread, and resume the paused stream only
                // after the starter found the batch busy.
                let (start_joiner_tx, start_joiner_rx) = oneshot::channel();
                let schedule = std::thread::spawn(move || {
                    first_polled_rx.recv_timeout(SCHEDULE_DEADLINE).unwrap();
                    completions
                        .send(Ok((0, IoBufsMut::from(full_page(0)))))
                        .unwrap();
                    second_poll_rx.recv_timeout(SCHEDULE_DEADLINE).unwrap();
                    start_joiner_tx.send(()).unwrap();
                    paused_rx.recv_timeout(SCHEDULE_DEADLINE).unwrap();
                    completions
                        .send(Ok((1, IoBufsMut::from(full_page(1)))))
                        .unwrap();
                    resume_starter_tx.send(()).unwrap();
                    second_polled_rx.recv_timeout(SCHEDULE_DEADLINE).unwrap();
                    resume_stream_tx.send(()).unwrap();
                });
                select! {
                    result = start_joiner_rx => result.unwrap(),
                    _ = context.sleep(SCHEDULE_DEADLINE) => panic!("starter was not polled again"),
                }

                // The joiner reads page 0, joining the batch and driving it until it pauses.
                let joiner = context.child("joiner").spawn({
                    let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
                    move |_| async move { read_first_byte(&blob, &cache_ref, 0).await }
                });
                let joined = select! {
                    result = joiner => result.unwrap(),
                    _ = context.sleep(SCHEDULE_DEADLINE) => panic!("joiner stalled"),
                };
                assert_eq!(joined.unwrap(), 0);
                schedule.join().unwrap();

                // Nothing outside the batch wakes the starter again.
                let started = select! {
                    result = starter => result.unwrap(),
                    _ = context.sleep(SCHEDULE_DEADLINE) => {
                        panic!("starter stalled after the joiner left")
                    },
                };
                assert_eq!(started.unwrap(), [0, 1]);
                assert_eq!(blob.yielded.load(Ordering::SeqCst), 2);
                assert_idle(&cache_ref);
            }
        });
    }

    #[rstest]
    #[case::ends(false)]
    #[case::fails(true)]
    fn test_starting_read_waits_for_its_batch_to_end(#[case] fail: bool) {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (start, started) = oneshot::channel();
            let (end, ended) = oneshot::channel();
            let mut script = vec![
                Step::Wait(started),
                Step::page(0),
                Step::page(1),
                Step::Wait(ended),
            ];
            if fail {
                script.push(Step::Fail(Error::ReadFailed));
            }
            let blob = ScriptedBlob::new(script);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A read of both pages starts a batch, and a read of page 0 joins it.
            let mut read = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(read.as_mut()).is_pending());
            let mut joiner = pin!(read_first_byte(&blob, &cache_ref, 0));
            assert!(poll!(joiner.as_mut()).is_pending());

            // The joiner finishes with its page. The starting read has both its pages, but waits
            // for its batched read to end, which may still fail it.
            start.send(()).unwrap();
            assert_eq!(joiner.await.unwrap(), 0);
            assert!(poll!(read.as_mut()).is_pending());
            end.send(()).unwrap();
            let result = read.await;
            if fail {
                assert!(matches!(result, Err(Error::ReadFailed)));
            } else {
                assert_eq!(result.unwrap(), [0, 1]);
            }
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_failed_page_fails_its_readers() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(2);
            *blob.corrupt.lock() = Some(1);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of both pages starts reading, and a read of each page joins it.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut zero = pin!(read_first_byte(&blob, &cache_ref, 0));
            assert!(poll!(zero.as_mut()).is_pending());
            let mut one = pin!(read_first_byte(&blob, &cache_ref, 1));
            assert!(poll!(one.as_mut()).is_pending());

            // Page 1 fails validation, which fails every read waiting on it.
            open(&mut opens[1..]);
            assert!(matches!(first.await, Err(Error::InvalidChecksum)));
            assert!(matches!(one.await, Err(Error::InvalidChecksum)));

            // A later read of page 1 reads it again rather than join the batch, which still reads
            // page 0 for its other read.
            assert_eq!(read_first_byte(&blob, &cache_ref, 1).await.unwrap(), 1);
            open(&mut opens);
            assert_eq!(zero.await.unwrap(), 0);
            assert_eq!(blob.reads_of(1), 2);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_failed_read_fails_readers_still_waiting() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (start, started) = oneshot::channel();
            let (fail, failed) = oneshot::channel();
            let blob = ScriptedBlob::new(vec![
                Step::Wait(started),
                Step::page(0),
                Step::Wait(failed),
                Step::Fail(Error::ReadFailed),
            ]);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of pages 0-2 starts reading. A read of page 0, a read of page 2, and a read
            // of pages 0 and 2 join it.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut zero = pin!(read_first_byte(&blob, &cache_ref, 0));
            assert!(poll!(zero.as_mut()).is_pending());
            let mut two = pin!(read_first_byte(&blob, &cache_ref, 2));
            assert!(poll!(two.as_mut()).is_pending());
            let mut second = pin!(read_first_bytes(&blob, &cache_ref, &[0, 2]));
            assert!(poll!(second.as_mut()).is_pending());

            // The batch publishes page 0, which completes the read of page 0 alone. Then the
            // batch's read fails, which fails every read still waiting on it, and no later read
            // joins the failed batch.
            start.send(()).unwrap();
            assert_eq!(zero.await.unwrap(), 0);
            fail.send(()).unwrap();
            assert!(matches!(first.await, Err(Error::ReadFailed)));
            assert!(
                cache_ref
                    .cache
                    .read()
                    .batches
                    .find_unpublished(0, 2)
                    .is_none()
            );
            assert!(matches!(two.await, Err(Error::ReadFailed)));
            assert!(matches!(second.await, Err(Error::ReadFailed)));
            assert_idle(&cache_ref);
        });
    }

    #[rstest]
    #[case::out_of_order(vec![Step::page(2), Step::page(0), Step::page(1)], None)]
    #[case::out_of_range(vec![Step::page(0), Step::page(3)], Some(Error::ReadFailed))]
    #[case::duplicate(
        vec![Step::page(0), Step::page(0), Step::page(1), Step::page(2)],
        Some(Error::ReadFailed)
    )]
    #[case::missing(vec![Step::page(0), Step::page(1)], Some(Error::ReadFailed))]
    #[case::corrupt(
        vec![Step::page(0), Step::Yield(1, corrupt_page(1)), Step::page(2)],
        Some(Error::InvalidChecksum)
    )]
    #[case::partial(
        vec![Step::page(0), Step::Yield(1, page_bytes(1, 100)), Step::page(2)],
        Some(Error::InvalidChecksum)
    )]
    #[case::error(
        vec![Step::page(0), Step::Fail(Error::BlobInsufficientLength)],
        Some(Error::BlobInsufficientLength)
    )]
    fn test_batch_checks_read_many_output(
        #[case] script: Vec<Step>,
        #[case] expected: Option<Error>,
    ) {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (start, started) = oneshot::channel();
            let blob =
                ScriptedBlob::new(std::iter::once(Step::Wait(started)).chain(script).collect());
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of pages 0-2 starts reading, and a read of the same pages joins it.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut second = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
            assert!(poll!(second.as_mut()).is_pending());

            // Both reads see the batch's result.
            start.send(()).unwrap();
            let (first, second) = futures::join!(first, second);
            for result in [first, second] {
                match &expected {
                    None => assert_eq!(result.unwrap(), [0, 1, 2]),
                    Some(expected) => assert_eq!(
                        std::mem::discriminant(&result.unwrap_err()),
                        std::mem::discriminant(expected)
                    ),
                }
            }
            assert_idle(&cache_ref);
        });
    }

    // The cache joins its sources unordered, so every case must fail while the first page is
    // blocked. The 30 and 31 cases straddle the cutoff above which futures-util's `try_join_all`
    // would hold the error behind that page.
    #[rstest]
    #[case::thirty_fetches(30, false)]
    #[case::thirty_one_fetches(31, false)]
    #[case::thirty_batches(30, true)]
    #[case::thirty_one_batches(31, true)]
    fn test_read_fails_as_soon_as_any_source_fails(#[case] count: usize, #[case] batched: bool) {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(count);
            *blob.corrupt.lock() = Some(count - 1);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));

            // Other reads start reading each page, alone or in a batch of one.
            let (blob, cache_ref) = (&blob, &cache_ref);
            let mut sources: Vec<_> = (0..count as u64)
                .map(|page| {
                    Box::pin(async move {
                        if batched {
                            read_first_bytes(blob, cache_ref, &[page]).await.map(|_| ())
                        } else {
                            read_first_byte(blob, cache_ref, page).await.map(|_| ())
                        }
                    })
                })
                .collect();
            for source in &mut sources {
                assert!(poll!(source.as_mut()).is_pending());
            }

            // A read of every page joins them all. The last page fails validation while the
            // first is still blocked, which fails the read at once.
            let pages: Vec<u64> = (0..count as u64).collect();
            let mut read = pin!(read_first_bytes(blob, cache_ref, &pages));
            assert!(poll!(read.as_mut()).is_pending());
            opens[count - 1].take().unwrap().send(()).unwrap();
            assert!(matches!(
                poll!(read.as_mut()),
                Poll::Ready(Err(Error::InvalidChecksum))
            ));
        });
    }

    #[test_traced]
    fn test_each_page_routes_to_its_joiners_only() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const PAGES: u64 = 4;
            let (blob, mut opens) = GatedBlob::new(PAGES as usize);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));
            let pages: Vec<u64> = (0..PAGES).collect();
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &pages));
            assert!(poll!(first.as_mut()).is_pending());

            // A read of each page joins the batch, so each page waits on that read only.
            let mut singles: Vec<_> = pages
                .iter()
                .map(|&page| Box::pin(read_first_byte(&blob, &cache_ref, page)))
                .collect();
            for single in &mut singles {
                assert!(poll!(single.as_mut()).is_pending());
            }
            assert_eq!(joiners(&cache_ref), [Some((1, 1)); PAGES as usize]);

            open(&mut opens);
            for (page, single) in singles.into_iter().enumerate() {
                assert_eq!(single.await.unwrap(), page as u8);
            }
            assert_eq!(first.await.unwrap(), [0, 1, 2, 3]);
            assert_eq!(blob.reads.lock().len(), PAGES as usize);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_many_reads_join_one_page() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const READS: usize = 128;
            let (blob, mut opens) = GatedBlob::new(1);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0]));
            assert!(poll!(first.as_mut()).is_pending());

            // Many reads of the page join the batch, and every one stays selected.
            let mut reads: Vec<_> = (0..READS)
                .map(|_| Box::pin(read_first_byte(&blob, &cache_ref, 0)))
                .collect();
            for read in &mut reads {
                assert!(poll!(read.as_mut()).is_pending());
            }
            assert_eq!(joiners(&cache_ref), [Some((READS, READS))]);

            open(&mut opens);
            for read in reads {
                assert_eq!(read.await.unwrap(), 0);
            }
            assert_eq!(first.await.unwrap(), [0]);
            assert_eq!(blob.reads.lock().len(), 1);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_subscription_dropped_unpolled_gets_no_pages() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(2);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of pages 0 and 1 starts reading. A subscription selects page 0 and is
            // dropped before it is ever polled.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(first.as_mut()).is_pending());
            let batch = {
                let cache = cache_ref.cache.write();
                let (batch, index, driver) = cache.batches.find_unpublished(0, 0).unwrap();
                let mut subscription = Subscription::joining(batch.clone(), driver);
                subscription.select(index, 0);
                let reader = subscription.reader;
                drop(subscription);
                assert!(batch.state.lock().inboxes[reader].is_none());
                batch
            };

            // Publishing page 0 skips the dropped subscription, and the batch still serves its
            // starting read.
            open(&mut opens);
            assert_eq!(first.await.unwrap(), [0, 1]);
            let state = batch.state.lock();
            assert!(state.inboxes[1..].iter().all(Option::is_none));
            drop(state);
            drop(batch);
            assert_eq!(blob.reads_of(0), 1);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_page_delivered_before_batch_fails_still_serves_its_reader() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (start, started) = oneshot::channel();
            let blob = ScriptedBlob::new(vec![
                Step::Wait(started),
                Step::page(0),
                Step::Fail(Error::ReadFailed),
            ]);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of pages 0 and 1 starts reading. A read of page 0 and a read of pages 0
            // and 1 join it.
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(first.as_mut()).is_pending());
            let mut zero = pin!(read_first_byte(&blob, &cache_ref, 0));
            assert!(poll!(zero.as_mut()).is_pending());
            let mut both = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1]));
            assert!(poll!(both.as_mut()).is_pending());

            // Only the starting read drives the batch. It publishes page 0 to both joiners, which
            // are not polled meanwhile, and then fails.
            start.send(()).unwrap();
            assert!(matches!(first.await, Err(Error::ReadFailed)));

            // The joiner that already has its page finishes with it. The one still missing page 1
            // fails with the batch.
            assert_eq!(zero.await.unwrap(), 0);
            assert!(matches!(both.await, Err(Error::ReadFailed)));
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_cancelled_joins_do_not_disturb_other_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(3);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));
            let mut first = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
            assert!(poll!(first.as_mut()).is_pending());

            // A read of pages 1 and 2 joins the stalled batch.
            let mut kept = pin!(read_first_bytes(&blob, &cache_ref, &[1, 2]));
            assert!(poll!(kept.as_mut()).is_pending());
            assert_eq!(selected(&cache_ref), 2);

            // Reads that join it and are cancelled stop counting as selections.
            {
                let mut joined = pin!(read_first_bytes(&blob, &cache_ref, &[0, 1, 2]));
                assert!(poll!(joined.as_mut()).is_pending());
                let mut single = pin!(read_first_byte(&blob, &cache_ref, 1));
                assert!(poll!(single.as_mut()).is_pending());
                assert_eq!(selected(&cache_ref), 2 + 3 + 1);
            }
            assert_eq!(selected(&cache_ref), 2);

            // Their selections stay until a later join of the page prunes them, so 64 cancelled
            // joins of page 1 leave only a few behind.
            for _ in 0..64 {
                let mut cancelled = pin!(read_first_byte(&blob, &cache_ref, 1));
                assert!(poll!(cancelled.as_mut()).is_pending());
            }
            let (selections, subscribed) = joiners(&cache_ref)[1].unwrap();
            assert_eq!(subscribed, 1);
            assert!(selections < 8, "{selections} selections remain");

            open(&mut opens);
            assert_eq!(kept.await.unwrap(), [1, 2]);
            assert_eq!(first.await.unwrap(), [0, 1, 2]);
            assert_eq!(blob.reads.lock().len(), 3);
            assert_idle(&cache_ref);
        });
    }

    #[test_traced]
    fn test_dropped_batches_are_unregistered() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(8);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // Batches of four blobs, and four more of one of them, start reading and are dropped.
            let started = (0..4)
                .map(|id| (id, id))
                .chain((4..8).map(|page| (0, page)));
            for (id, page) in started {
                let mut buf = [0u8; 1];
                let ranges = vec![(buf.as_mut_slice(), page * PAGE_SIZE_U64)];
                let mut read = pin!(cache_ref.read_after_misses(&blob, id, ranges));
                assert!(poll!(read.as_mut()).is_pending());
            }
            assert_idle(&cache_ref);
            open(&mut opens);

            // A later read of a dropped batch's page reads it again, and its lookup unregisters
            // every dropped batch.
            assert_eq!(read_first_byte(&blob, &cache_ref, 0).await.unwrap(), 0);
            assert_eq!(blob.reads_of(0), 2);
            assert!(cache_ref.cache.read().batches.by_blob.is_empty());
        });
    }

    #[test_traced]
    fn test_batch_whose_driver_was_dropped_is_not_joined() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, mut opens) = GatedBlob::new(1);
            open(&mut opens);
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(16));

            // A batch of page 0 outlives its driver, as when a read holding it already has its
            // pages but every handle on the driver is dropped.
            let batch = Arc::new(Batch::new(0, vec![0]));
            let driver: BatchDriver = Shared::new(pending::<Result<(), Error>>().boxed());
            cache_ref.cache.write().batches.register(&batch, &driver);
            drop(driver);

            // A read of page 0 reads it itself rather than wait on the batch forever.
            assert_eq!(read_first_byte(&blob, &cache_ref, 0).await.unwrap(), 0);
            assert_eq!(blob.reads_of(0), 1);
        });
    }

    #[test_traced]
    fn test_overlapping_reads_with_cancellations() {
        for seed in 0..16 {
            let executor = deterministic::Runner::seeded(seed);
            executor.start(|mut context| async move {
                const PAGES: u64 = MISSES_PER_LOCK as u64 + 8;
                let (blob, mut opens) = GatedBlob::new(PAGES as usize);
                let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));

                // Batched reads of every page or of random pages, and single reads, start at
                // random times.
                let mut readers = Vec::new();
                for _ in 0..8 {
                    let mut pages: Vec<u64> = if context.random_bool(0.25) {
                        (0..PAGES).collect()
                    } else {
                        (0..PAGES).filter(|_| context.random_bool(0.3)).collect()
                    };
                    if pages.is_empty() {
                        pages.push(context.random_range(0..PAGES));
                    }
                    let single = pages.len() == 1 && context.random_bool(0.5);
                    let expected: Vec<u8> = pages.iter().map(|&page| page as u8).collect();
                    let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
                    let reader = context.child("reader").spawn(move |_| async move {
                        if single {
                            read_first_byte(&blob, &cache_ref, pages[0])
                                .await
                                .map(|byte| vec![byte])
                        } else {
                            read_first_bytes(&blob, &cache_ref, &pages).await
                        }
                    });
                    readers.push((reader, expected));
                    let delay = context.random_range(0..3);
                    context.sleep(Duration::from_millis(delay)).await;
                }

                // Pages arrive in a random order while random reads are cancelled.
                let mut order: Vec<usize> = (0..PAGES as usize).collect();
                order.shuffle(&mut context);
                for page in order {
                    open(&mut opens[page..=page]);
                    if context.random_bool(0.05) {
                        readers[context.random_range(0..readers.len())].0.abort();
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }

                // Every read that was not cancelled returns its pages.
                for (reader, expected) in readers {
                    if let Ok(result) = reader.await {
                        assert_eq!(result.unwrap(), expected);
                    }
                }
                assert_idle(&cache_ref);
            });
        }
    }

    #[test_traced]
    fn test_concurrent_reads_read_each_page_once() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Concurrent reads of every page of a blob that spans several holds of the lock,
            // through a cache that holds every page.
            const PAGES: u64 = 3 * MISSES_PER_LOCK as u64;
            let (recording, recordings) = crate::mocks::RecordingContext::new(context);
            let blob = checksummed_blob(&recording, PAGES).await;
            let context = recording.inner;
            recordings.clear();
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2 * PAGES as usize));
            let readers = (0..4).map(|_| {
                let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
                context.child("reader").spawn(move |_| async move {
                    let pages: Vec<u64> = (0..PAGES).collect();
                    read_first_bytes(&blob, &cache_ref, &pages).await.unwrap()
                })
            });
            let expected: Vec<u8> = (0..PAGES).map(|page| page as u8).collect();
            for reader in futures::future::join_all(readers).await {
                assert_eq!(reader.unwrap(), expected);
            }

            // On one thread, no read runs between another's lock holds, so each joins the batch
            // of the first, and every page is read once.
            assert_eq!(recordings.snapshot().reads.len(), PAGES as usize);
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default())
    )]
    fn test_read_many_into_serves_misses<R: crate::Runner>(#[case] runner: R)
    where
        R::Context: crate::Storage,
    {
        runner.start(|context| async move {
            // Items straddling every page boundary of 40 pages, read through a 4-page cache
            // that evicts most pages before they are served.
            let blob = checksummed_blob(&context, 40).await;
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));
            let size = 40 * PAGE_SIZE_U64;
            let view = View {
                blob: &blob,
                cache_ref: &cache_ref,
                id: 0,
                size,
                tail_offset: size,
                tail: Tail::Sealed(&[]),
            };
            let offsets: Vec<u64> = (1..40).map(|page| page * PAGE_SIZE_U64 - 2).collect();
            let mut buf = vec![0u8; offsets.len() * 4];
            view.read_many_into(&mut buf, &offsets, NZUsize!(4))
                .await
                .unwrap();
            let expected: Vec<u8> = offsets
                .iter()
                .flat_map(|&offset| (offset..offset + 4).map(|o| (o / PAGE_SIZE_U64) as u8))
                .collect();
            assert_eq!(buf, expected);
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default())
    )]
    fn test_concurrent_reads_with_eviction_and_cancellation<R: crate::Runner>(#[case] runner: R)
    where
        R::Context: crate::Clock + crate::Spawner + crate::Storage,
    {
        runner.start(|context| async move {
            // Overlapping reads of a blob that spans several holds of the lock, through a 4-page
            // cache, with every third read cancelled.
            const PAGES: u64 = 3 * MISSES_PER_LOCK as u64;
            let blob = checksummed_blob(&context, PAGES).await;
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));
            let readers: Vec<_> = (0..8)
                .map(|reader| {
                    let pages: Vec<u64> = (reader * 8..PAGES).collect();
                    let (blob, cache_ref) = (blob.clone(), cache_ref.clone());
                    let handle = context.child("reader").spawn(move |_| async move {
                        read_first_bytes(&blob, &cache_ref, &pages).await
                    });
                    (reader, handle)
                })
                .collect();
            context.sleep(Duration::from_millis(1)).await;
            for (_, handle) in readers.iter().step_by(3) {
                handle.abort();
            }

            // Every read that was not cancelled returns its pages.
            for (reader, handle) in readers {
                select! {
                    result = handle => {
                        if reader % 3 != 0 {
                            let expected: Vec<u8> =
                                (reader * 8..PAGES).map(|page| page as u8).collect();
                            assert_eq!(result.unwrap().unwrap(), expected);
                        }
                    },
                    _ = context.sleep(Duration::from_secs(10)) => panic!("a read hung"),
                }
            }
        });
    }

    #[test_traced]
    fn test_cache_at_high_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Use the minimum page size (CHECKSUM_SIZE + 1 = 13) with high offset.
            const MIN_PAGE_SIZE: u64 = CHECKSUM_SIZE + 1;
            let cache_ref = CacheRef::new(NZU16!(MIN_PAGE_SIZE as u16), NZUsize!(2));

            // Create two pages worth of logical data without CRCs, since CacheRef::cache expects
            // logical bytes only.
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));

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
                    .read_after_miss(&blob_for_third, blob_id, &mut third_buf, 0)
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
                .read_after_miss(&blob, blob_id, &mut fourth_buf, 0)
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
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));

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
        executor.start(|_| async move {
            let blob_id = 0;
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
    fn test_read_cached_many_resumes_after_evicted_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(3));
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
        executor.start(|_| async move {
            let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(1));
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
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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
        // Insert one page past capacity so page 0 is evicted and its slot is reused for page 2.
        // Page 0's hint now points at a slot holding page 2's key, so the batched read must report
        // page 0 as a miss (never page 2's bytes) while still serving the live pages.
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));
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
        // overwrites the earlier blob's hint. The hint only proposes a [cache::Cache] slot.
        // [cache::Cache::get_at] validates the full (blob, page) key, so each blob reads back its
        // own bytes (the clobbered one through the fallback lookup), never the other's.
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));
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
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2));
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

    #[test]
    fn test_eviction_walks_resident_pages_only() {
        // An insert that displaces a page takes its slot out of the old blob's chain, so evicting
        // a blob removes exactly its resident pages and leaves other blobs' pages in place. A
        // partial eviction keeps the pages at or above its bound.
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(4));
        let page_size: usize = PAGE_SIZE.widen();
        let cached = |blob_id: u64, page: u64| {
            let mut probe = vec![0u8; page_size];
            cache_ref.read_cached(blob_id, &mut probe, page * PAGE_SIZE_U64) == page_size
        };
        let resident =
            |blob_id: u64, pages: u64| (0..pages).filter(|&page| cached(blob_id, page)).count();
        let chain_len = |blob_id: u64| {
            let cache = cache_ref.cache.read();
            let mut len = 0;
            let mut cursor = cache.residency.head(blob_id);
            while let Some(slot) = cursor {
                len += 1;
                cursor = cache.residency.next(slot);
            }
            len
        };

        // Fill the cache with blob 0, then let blob 1 displace at least one of its pages. Each
        // chain's length equals its blob's resident page count.
        for page in 0..4 {
            cache_ref.cache(0, &vec![1; page_size], page * PAGE_SIZE_U64);
        }
        for page in 0..2 {
            cache_ref.cache(1, &vec![2; page_size], page * PAGE_SIZE_U64);
        }
        let (blob0, blob1) = (resident(0, 4), resident(1, 2));
        assert_eq!(blob0 + blob1, 4);
        assert!(blob0 < 4);
        assert_eq!((chain_len(0), chain_len(1)), (blob0, blob1));

        // Evicting blob 0 leaves blob 1's pages, and blob 0's chain is gone.
        cache_ref.evict_blob(0);
        assert_eq!(resident(0, 4), 0);
        assert_eq!(resident(1, 2), blob1);
        assert_eq!((chain_len(0), chain_len(1)), (0, blob1));

        // A partial eviction of blob 2 below page 2 removes pages 0 and 1 and keeps page 2.
        for page in 0..3 {
            cache_ref.cache(2, &vec![3; page_size], page * PAGE_SIZE_U64);
        }
        assert!(cached(2, 0) && cached(2, 1) && cached(2, 2));
        cache_ref.evict(2, 2 * PAGE_SIZE_U64);
        assert!(!cached(2, 0) && !cached(2, 1) && cached(2, 2));
        assert_eq!(chain_len(2), resident(2, 3));

        // The evicted pages stay out when cached again, a lower bound changes nothing, and the
        // bound leaves with the blob.
        cache_ref.cache(2, &vec![3; page_size], 0);
        assert!(!cached(2, 0));
        cache_ref.evict(2, PAGE_SIZE_U64);
        assert!(!cached(2, 0) && cached(2, 2));
        cache_ref.cache(2, &vec![3; page_size], PAGE_SIZE_U64);
        assert!(!cached(2, 1));
        cache_ref.evict_blob(2);
        cache_ref.cache(2, &vec![3; page_size], 0);
        assert!(cached(2, 0));
    }

    /// Called with the lock released at each yield of an eviction walk, with the slot the walk
    /// resumes at.
    type EvictionHook = Box<dyn FnMut(usize)>;

    thread_local! {
        /// The hook for eviction walks on this thread.
        static EVICTION_YIELD: RefCell<Option<EvictionHook>> = const { RefCell::new(None) };
    }

    /// Run this thread's [EVICTION_YIELD] hook, if any, with `cache` unlocked. Evictions the hook
    /// starts do not run it again.
    pub(super) fn eviction_yielded(cache: &mut RwLockWriteGuard<'_, Cache>, next: usize) {
        let Some(mut hook) = EVICTION_YIELD.take() else {
            return;
        };
        RwLockWriteGuard::unlocked(cache, || hook(next));
        EVICTION_YIELD.set(Some(hook));
    }

    /// Evict the pages of `blob_id` that satisfy `evict` while `churn` changes the cache at each
    /// yield, and return how many slots the walk visited and how often it yielded. Fails if the
    /// walk exceeds the bounds [CacheRef::evict_resident] promises.
    fn evict_with_churn(
        cache_ref: &CacheRef,
        blob_id: u64,
        evict: impl Fn(u64) -> bool,
        mut churn: impl FnMut(usize) + 'static,
    ) -> (usize, usize) {
        let capacity = cache_ref.cache.read().cache.capacity();
        let max_yields = (capacity - 1) / PAGES_PER_LOCK;
        let yields = Rc::new(Cell::new(0));
        let counted = yields.clone();
        EVICTION_YIELD.set(Some(Box::new(move |next| {
            counted.set(counted.get() + 1);
            assert!(
                counted.get() <= max_yields,
                "eviction yielded more than {max_yields} times"
            );
            churn(next);
        })));
        let visits = Cell::new(0);
        CacheRef::evict_resident(cache_ref.cache.write(), blob_id, |page| {
            visits.set(visits.get() + 1);
            evict(page)
        });
        EVICTION_YIELD.set(None);
        let visits = visits.get();
        assert!(visits < 2 * capacity, "eviction visited {visits} slots");
        (visits, yields.get())
    }

    fn is_cached(cache_ref: &CacheRef, blob_id: u64, page: u64) -> bool {
        let mut probe = vec![0u8; PAGE_SIZE.widen()];
        cache_ref.read_cached(blob_id, &mut probe, page * PAGE_SIZE_U64) == probe.len()
    }

    #[test]
    fn test_partial_eviction_bounded_when_resume_slot_leaves_chain() {
        // Blob 0 holds page 0, linked first so it ends the chain, and enough kept pages above it
        // to yield. Blob 1 fills the rest of the cache.
        let kept = PAGES_PER_LOCK + 1;
        let page_size: usize = PAGE_SIZE.widen();
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(2 * kept + 1));
        let data = vec![1u8; page_size * kept];
        cache_ref.cache(0, &data[..page_size], 0);
        cache_ref.cache(0, &data, PAGE_SIZE_U64);
        cache_ref.cache(1, &data, 0);

        // At each yield, another thread drops blob 0's kept pages but spares page 0, as
        // displacement can. It then moves a new blob into the freed slots and caches the kept
        // pages again in the slots the previous blob vacated. The slot the walk would resume at
        // leaves blob 0's chain every time.
        let churn_ref = cache_ref.clone();
        let mut foreign = 1;
        let (_, yields) = evict_with_churn(
            &cache_ref,
            0,
            |page| page < 1,
            move |next| {
                CacheRef::evict_resident(churn_ref.cache.write(), 0, |page| page != 0);
                churn_ref.cache(foreign + 1, &data, 0);
                churn_ref.evict_blob(foreign);
                churn_ref.cache(0, &data, PAGE_SIZE_U64);
                foreign += 1;
                assert!(!churn_ref.cache.read().residency.holds(next, 0));
            },
        );
        assert!(yields > 0);

        // Page 0 was resident throughout and is gone. The kept pages remain.
        assert!(!is_cached(&cache_ref, 0, 0));
        assert!((1..=Widen::widen(kept)).all(|page| is_cached(&cache_ref, 0, page)));
    }

    #[test]
    fn test_partial_eviction_bounded_when_resume_slot_moves_to_head() {
        // Blob 0 fills the cache with page 0, linked first so it ends the chain, and kept pages
        // above it spanning several yields.
        let kept = 3 * PAGES_PER_LOCK + 1;
        let page_size: usize = PAGE_SIZE.widen();
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(kept + 1));
        cache_ref.cache(0, &vec![1; page_size], 0);
        cache_ref.cache(0, &vec![1; page_size * kept], PAGE_SIZE_U64);

        // At each yield, another thread evicts the page the walk would resume at and appends a page
        // of blob 0. The new page reuses the freed slot and links it at the head of the chain, so
        // the slot stays in the chain, but resuming there revisits every kept page.
        let churn_ref = cache_ref.clone();
        let mut appended: u64 = Widen::widen(kept);
        let (visits, yields) = evict_with_churn(
            &cache_ref,
            0,
            |page| page < 1,
            move |next| {
                let (_, resumed) = *churn_ref.cache.read().cache.key_at(next).unwrap();
                CacheRef::evict_resident(churn_ref.cache.write(), 0, |page| page == resumed);
                appended += 1;
                churn_ref.cache(0, &vec![1; page_size], appended * PAGE_SIZE_U64);
                assert_eq!(churn_ref.cache.read().residency.head(0), Some(next));
            },
        );
        assert!(yields > 0 && visits > kept + 1);

        // Page 0 was resident throughout and is gone. Every other page of blob 0 remains.
        assert!(!is_cached(&cache_ref, 0, 0));
        let resident = (1..=Widen::widen(kept + yields))
            .filter(|&page| is_cached(&cache_ref, 0, page))
            .count();
        assert_eq!(resident, kept);
    }

    #[test]
    fn test_blob_eviction_yields_every_pages_per_lock() {
        // An undisturbed walk yields after every PAGES_PER_LOCK visits and removes every page.
        let pages = 3 * PAGES_PER_LOCK + 1;
        let page_size: usize = PAGE_SIZE.widen();
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(pages));
        cache_ref.cache(0, &vec![1; page_size * pages], 0);
        let (visits, yields) = evict_with_churn(&cache_ref, 0, |_| true, |_| {});
        assert_eq!((visits, yields), (pages, 3));
        assert!(cache_ref.cache.read().residency.head(0).is_none());
        assert!((0..Widen::widen(pages)).all(|page| !is_cached(&cache_ref, 0, page)));
    }

    #[test]
    fn test_partial_eviction_refuses_inserts_below_bound_while_yielding() {
        // Eviction records its bound before walking the blob's pages, so pages below the bound that
        // another thread caches while the walk yields are refused.
        let kept = PAGES_PER_LOCK + 1;
        let page_size: usize = PAGE_SIZE.widen();
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(kept + 2));
        cache_ref.cache(0, &vec![1; page_size * kept], 2 * PAGE_SIZE_U64);
        assert!((2..Widen::widen(kept + 2)).all(|page| is_cached(&cache_ref, 0, page)));

        // At the yield, another thread caches pages 0 and 1. Both lie below the bound, and two
        // slots are vacant, so only the bound keeps them out.
        let churn_ref = cache_ref.clone();
        let yields = Rc::new(Cell::new(0));
        let counted = yields.clone();
        EVICTION_YIELD.set(Some(Box::new(move |_| {
            counted.set(counted.get() + 1);
            churn_ref.cache(0, &vec![2; page_size * 2], 0);
        })));
        cache_ref.evict(0, 2 * PAGE_SIZE_U64);
        EVICTION_YIELD.set(None);
        assert_eq!(yields.get(), 1);

        // The pages below the bound stayed out, and every kept page remains.
        assert!(!is_cached(&cache_ref, 0, 0) && !is_cached(&cache_ref, 0, 1));
        assert!((2..Widen::widen(kept + 2)).all(|page| is_cached(&cache_ref, 0, page)));
    }

    #[test_traced]
    fn test_read_cached_many_evicted_page_is_a_miss() {
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(1));
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
        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(10));
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

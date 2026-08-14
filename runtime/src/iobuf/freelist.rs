//! Striped global freelist for one buffer-pool size class.
//!
//! A [Freelist] owns one stable [PooledOwner] record for every possible buffer
//! in a size class. Globally free buffers are represented by owner indices in
//! cache-isolated, mutex-protected vectors.
//!
//! Each thread has one stable home stripe. Returns lock stripes from that home
//! and spill past stripes at their exact preallocated limit. Those limits sum
//! to the freelist capacity, so valid returns do not allocate while holding a
//! lock. Takes skip stripes known to be empty, then lock and scan from the same
//! home. The first insertion and last removal update one exact nonempty hint
//! while holding the stripe lock, so empty probes avoid mutex traffic.
//! Stripe locks are blocking. An operation can wait for a lock holder even
//! when another stripe could otherwise satisfy it.
//!
//! The freelist does not track global membership separately. Its caller must
//! return only uniquely owned buffers created by this freelist, return each
//! buffer exactly once, and provide distinct entries in every batch.
//!
//! A [PooledBuffer] does not carry its allocation layout. Every created or
//! claimed buffer must eventually return to this freelist before the freelist
//! is dropped. An outstanding buffer that never returns leaks. Buffer-pool
//! leases keep the owning size class and this freelist alive until valid
//! returns complete.

use super::owner::{PooledBuffer, PooledOwner};
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    cell::Cell,
    num::{NonZeroU32, NonZeroUsize},
    ptr,
    sync::atomic::Ordering,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::{
            cell::UnsafeCell,
            sync::{
                Mutex,
                MutexGuard,
                atomic::{AtomicBool, AtomicUsize},
            },
            thread,
        };
    } else {
        use commonware_utils::sync::{Mutex, MutexGuard};
        use std::{
            cell::UnsafeCell,
            sync::atomic::{AtomicBool, AtomicUsize},
            thread,
        };
    }
}

/// Maximum number of cache-isolated lock stripes in one freelist.
const MAX_STRIPES: usize = 4_096;
/// Minimum stripe target when capacity permits.
const MIN_STRIPES: usize = 8;

#[cfg(not(feature = "loom"))]
#[inline(always)]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

#[cfg(feature = "loom")]
#[inline(always)]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("freelist mutex must not be poisoned")
}

#[inline(always)]
#[allow(clippy::missing_const_for_fn)]
fn owner_ptr(owner: &UnsafeCell<PooledOwner>) -> ptr::NonNull<PooledOwner> {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "loom"))] {
            ptr::NonNull::new(owner.get()).expect("owner pointers are non-null")
        } else {
            owner.with(|owner| {
                ptr::NonNull::new(owner.cast_mut()).expect("owner pointers are non-null")
            })
        }
    }
}

/// One hard-bounded free vector and its lock.
struct Stripe {
    /// Exact nonempty hint, changed only while holding `free`.
    available: AtomicBool,
    free: Mutex<Vec<u32>>,
    limit: usize,
}

/// Bounded striped freelist of tracked buffers for one size class.
pub struct Freelist {
    layout: Layout,
    created: CachePadded<AtomicUsize>,
    owners: Box<[CachePadded<UnsafeCell<PooledOwner>>]>,
    stripes: Box<[CachePadded<Stripe>]>,
    stripe_mask: usize,
}

// SAFETY: owner storage is stable for the lifetime of the freelist. The buffer
// pool contract places each created owner either outside the global freelist or
// in exactly one mutex-protected stripe.
unsafe impl Send for Freelist {}
// SAFETY: same ownership and locking discipline as the Send implementation.
unsafe impl Sync for Freelist {}

impl Freelist {
    /// Creates a new fixed-capacity freelist.
    ///
    /// Parallelism selects a power-of-two stripe target with a floor of up to
    /// [MIN_STRIPES] and a cap of [MAX_STRIPES]. Each stripe preallocates its
    /// exact share of the total capacity.
    ///
    /// If prefill is true, all buffers are created and parked before this
    /// method returns.
    pub fn new(
        capacity: NonZeroU32,
        parallelism: NonZeroUsize,
        layout: Layout,
        prefill: bool,
    ) -> Self {
        assert!(layout.size() > 0, "layout size must be non-zero");
        let capacity = capacity.get() as usize;
        let stripe_count = Self::stripe_count(capacity, parallelism.get());
        let stripe_mask = stripe_count - 1;

        let owners = (0..capacity)
            .map(|owner_index| {
                CachePadded::new(UnsafeCell::new(PooledOwner::new(
                    u32::try_from(owner_index).expect("owner index must fit in u32"),
                    layout.size(),
                )))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let mut free = (0..stripe_count)
            .map(|stripe| {
                Vec::with_capacity(Self::stripe_capacity(capacity, stripe_count, stripe))
            })
            .collect::<Vec<_>>();

        if prefill {
            for owner_index in 0..capacity {
                // SAFETY: construction exclusively initializes this stable owner.
                let buffer = unsafe {
                    PooledBuffer::new(owner_ptr(&owners[owner_index]), layout, false)
                };
                free[owner_index & stripe_mask].push(buffer.into_owner_index());
            }
        }

        let stripes = free
            .into_iter()
            .enumerate()
            .map(|(stripe, free)| {
                CachePadded::new(Stripe {
                    available: AtomicBool::new(!free.is_empty()),
                    free: Mutex::new(free),
                    limit: Self::stripe_capacity(capacity, stripe_count, stripe),
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            layout,
            created: CachePadded::new(AtomicUsize::new(if prefill { capacity } else { 0 })),
            owners,
            stripes,
            stripe_mask,
        }
    }

    #[inline]
    fn stripe_count(capacity: usize, parallelism: usize) -> usize {
        let capacity_ceiling = 1usize << capacity.ilog2();
        parallelism
            .checked_next_power_of_two()
            .unwrap_or(MAX_STRIPES)
            .max(MIN_STRIPES.min(capacity_ceiling))
            .min(MAX_STRIPES)
            .min(capacity_ceiling)
    }

    #[inline(always)]
    const fn stripe_capacity(capacity: usize, stripes: usize, stripe: usize) -> usize {
        ((capacity - 1 - stripe) / stripes) + 1
    }

    /// Creates a new tracked buffer and assigns its permanent owner index.
    ///
    /// Returns None after all creation permits have been claimed. Draining
    /// does not reopen permits.
    #[inline(always)]
    pub(super) fn try_create(&self, zeroed: bool) -> Option<PooledBuffer> {
        let capacity = self.owners.len();
        #[allow(deprecated)]
        let owner_index = self
            .created
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |created| {
                (created < capacity).then_some(created + 1)
            })
            .ok()?;

        // SAFETY: creation admission assigns this owner exactly once. Its
        // address remains stable for the freelist lifetime.
        Some(unsafe { PooledBuffer::new(self.owner(owner_index as u32), self.layout, zeroed) })
    }

    /// Returns one tracked buffer, starting from this thread's home stripe.
    #[inline]
    pub fn put(&self, buffer: PooledBuffer) {
        self.put_from(buffer, self.home_stripe());
    }

    /// Returns one buffer starting from an already-resolved home stripe.
    fn put_from(&self, buffer: PooledBuffer, start: usize) {
        let mut owner_index = Some(buffer.into_owner_index());
        loop {
            for offset in 0..self.stripes.len() {
                let stripe = &self.stripes[(start + offset) & self.stripe_mask];
                let mut free = lock(&stripe.free);
                if free.len() == stripe.limit {
                    continue;
                }

                let was_empty = free.is_empty();
                debug_assert!(free.len() < free.capacity());
                free.push(owner_index.take().expect("owner index is published once"));
                if was_empty {
                    stripe.available.store(true, Ordering::Release);
                }
                return;
            }

            // Aggregate room exists for every valid outside buffer, but racing
            // operations can move that room during one scan.
            thread::yield_now();
        }
    }

    /// Returns several tracked buffers, starting from this thread's home.
    ///
    /// The complete batch is collected before any buffer is published.
    /// Publication fills one hard-bounded stripe at a time.
    ///
    /// The iterator should not panic. Buffers yielded before a panic may leak.
    #[inline]
    pub fn put_batch(&self, entries: impl IntoIterator<Item = PooledBuffer>) {
        self.put_batch_from(entries, self.home_stripe());
    }

    /// Returns several buffers using an already-resolved home stripe.
    fn put_batch_from(
        &self,
        entries: impl IntoIterator<Item = PooledBuffer>,
        start: usize,
    ) {
        let mut entries = entries.into_iter();
        let Some(first) = entries.next() else {
            return;
        };
        let Some(second) = entries.next() else {
            self.put_from(first, start);
            return;
        };

        let reserve = entries
            .size_hint()
            .0
            .saturating_add(2)
            .min(self.owners.len());
        let mut owner_indices = Vec::with_capacity(reserve);
        owner_indices.push(first.into_owner_index());
        owner_indices.push(second.into_owner_index());
        owner_indices.extend(entries.map(PooledBuffer::into_owner_index));

        while !owner_indices.is_empty() {
            let before = owner_indices.len();
            for offset in 0..self.stripes.len() {
                let stripe = &self.stripes[(start + offset) & self.stripe_mask];
                let mut free = lock(&stripe.free);
                let count = (stripe.limit - free.len()).min(owner_indices.len());
                let was_empty = free.is_empty();
                for _ in 0..count {
                    debug_assert!(free.len() < free.capacity());
                    free.push(owner_indices.pop().expect("count is bounded by length"));
                }
                if was_empty && count != 0 {
                    stripe.available.store(true, Ordering::Release);
                }
                if owner_indices.is_empty() {
                    return;
                }
            }

            if owner_indices.len() == before {
                thread::yield_now();
            }
        }
    }

    /// Takes any one globally available buffer.
    ///
    /// The scan reports empty only after every stripe is either known empty or
    /// observed empty under its mutex.
    #[inline]
    pub fn take(&self) -> Option<PooledBuffer> {
        self.take_from(self.home_stripe())
    }

    /// Takes one buffer using an already-resolved home stripe.
    #[inline(always)]
    fn take_from(&self, start: usize) -> Option<PooledBuffer> {
        for offset in 0..self.stripes.len() {
            let stripe = &self.stripes[(start + offset) & self.stripe_mask];
            if !stripe.available.load(Ordering::Acquire) {
                continue;
            }
            let mut free = lock(&stripe.free);
            if let Some(owner_index) = Self::pop_locked(stripe, &mut free) {
                drop(free);
                return Some(self.claim(owner_index));
            }
        }
        None
    }

    /// Takes up to max globally available buffers.
    ///
    /// Claimed buffers are detached while their stripe is locked. All callback
    /// invocations happen after every lock has been released. The callback must
    /// not panic because remaining detached buffers would be stranded.
    #[inline]
    pub fn take_batch(&self, max: usize, mut on_entry: impl FnMut(PooledBuffer)) -> usize {
        self.take_batch_from(max, self.home_stripe(), &mut on_entry)
    }

    /// Takes a batch using an already-resolved home stripe.
    fn take_batch_from(
        &self,
        max: usize,
        start: usize,
        mut on_entry: impl FnMut(PooledBuffer),
    ) -> usize {
        let max = max.min(self.owners.len());
        if max == 0 {
            return 0;
        }
        if max == 1 {
            let Some(buffer) = self.take_from(start) else {
                return 0;
            };
            on_entry(buffer);
            return 1;
        }

        let mut detached = Vec::with_capacity(max);
        for offset in 0..self.stripes.len() {
            let stripe = &self.stripes[(start + offset) & self.stripe_mask];
            if !stripe.available.load(Ordering::Acquire) {
                continue;
            }
            let mut free = lock(&stripe.free);
            while detached.len() < max {
                let Some(owner_index) = Self::pop_locked(stripe, &mut free) else {
                    break;
                };
                detached.push(owner_index);
            }
            if detached.len() == max {
                break;
            }
        }

        if detached.is_empty() {
            return 0;
        }
        let count = detached.len();
        for owner_index in detached {
            on_entry(self.claim(owner_index));
        }
        count
    }

    /// Deallocates every buffer currently parked in the global freelist.
    ///
    /// Creation permits remain consumed. Each stripe receives an empty vector
    /// with the same reserved capacity before detached buffers are deallocated.
    pub fn drain(&self) -> usize {
        let mut drained = 0;

        for stripe in &self.stripes {
            let detached = {
                let mut free = lock(&stripe.free);
                let detached = std::mem::replace(&mut *free, Vec::with_capacity(stripe.limit));
                stripe.available.store(false, Ordering::Release);
                detached
            };

            for owner_index in detached {
                let buffer = self.claim(owner_index);
                // SAFETY: this freelist created the detached buffer with this
                // exact layout and removed its owner index under lock.
                unsafe { buffer.deallocate(self.layout) };
                drained += 1;
            }
        }

        drained
    }

    #[inline(always)]
    fn owner(&self, owner_index: u32) -> ptr::NonNull<PooledOwner> {
        let owner = self
            .owners
            .get(owner_index as usize)
            .expect("owner index must belong to this freelist");
        owner_ptr(owner)
    }

    /// Returns one stable home stripe for the current thread.
    #[inline(always)]
    fn home_stripe(&self) -> usize {
        if self.stripe_mask == 0 {
            return 0;
        }
        take_thread_id() & self.stripe_mask
    }

    /// Removes one owner index and maintains the stripe's availability hint.
    #[inline(always)]
    fn pop_locked(stripe: &Stripe, free: &mut MutexGuard<'_, Vec<u32>>) -> Option<u32> {
        let Some(owner_index) = free.pop() else {
            stripe.available.store(false, Ordering::Release);
            return None;
        };
        if free.is_empty() {
            stripe.available.store(false, Ordering::Release);
        }
        Some(owner_index)
    }

    /// Reconstructs unique ownership after removing an index from a stripe.
    #[inline(always)]
    fn claim(&self, owner_index: u32) -> PooledBuffer {
        // SAFETY: the buffer-pool contract makes a globally stored owner index
        // unique, and the caller removed this index from its stripe.
        let buffer = unsafe { PooledBuffer::from_owner(self.owner(owner_index)) };
        #[cfg(feature = "loom")]
        buffer.assert_unique_sentinel();
        buffer
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        static NEXT_TAKE_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
    } else {
        loom::lazy_static! {
            static ref NEXT_TAKE_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        thread_local! {
            static TAKE_THREAD_ID: Cell<Option<usize>> = const { Cell::new(None) };
        }
    } else {
        loom::thread_local! {
            static TAKE_THREAD_ID: Cell<Option<usize>> = Cell::new(None);
        }
    }
}

/// Returns one stable process-local id for the current thread.
#[inline(always)]
fn take_thread_id() -> usize {
    TAKE_THREAD_ID.with(|thread_id| {
        if let Some(id) = thread_id.get() {
            return id;
        }

        let id = NEXT_TAKE_THREAD_ID.fetch_add(1, Ordering::Relaxed);
        thread_id.set(Some(id));
        id
    })
}

impl Drop for Freelist {
    fn drop(&mut self) {
        self.drain();
    }
}

#[cfg(all(test, not(feature = "loom")))]
pub(super) mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool as StdAtomicBool, Ordering as StdOrdering},
            mpsc,
        },
        time::Duration,
    };

    const TEST_LAYOUT: Layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => panic!("valid test layout"),
    };

    pub fn created(freelist: &Freelist) -> usize {
        freelist.created.load(Ordering::Relaxed)
    }

    pub fn len(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| lock(&stripe.free).len())
            .sum()
    }

    pub fn num_stripes(freelist: &Freelist) -> usize {
        freelist.stripes.len()
    }

    fn lazy(capacity: u32, parallelism: usize) -> Freelist {
        Freelist::new(
            NonZeroU32::new(capacity).expect("positive capacity"),
            NonZeroUsize::new(parallelism).expect("positive parallelism"),
            TEST_LAYOUT,
            false,
        )
    }

    fn prefilled(capacity: u32, parallelism: usize) -> Freelist {
        Freelist::new(
            NonZeroU32::new(capacity).expect("positive capacity"),
            NonZeroUsize::new(parallelism).expect("positive parallelism"),
            TEST_LAYOUT,
            true,
        )
    }

    fn take_all(freelist: &Freelist) -> Vec<PooledBuffer> {
        let mut buffers = Vec::new();
        loop {
            let taken = freelist.take_batch(usize::MAX, |buffer| buffers.push(buffer));
            if taken == 0 {
                return buffers;
            }
        }
    }

    #[test]
    fn test_creation_prefill_and_drain() {
        let set = lazy(3, 2);
        let buffers = (0..3)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();
        assert_eq!(
            buffers
                .iter()
                .map(PooledBuffer::owner_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(format!("{:?}", buffers[0]).contains("owner_index"));
        assert!(set.try_create(false).is_none());
        assert_eq!(created(&set), 3);

        set.put_batch(buffers);
        assert_eq!(len(&set), 3);
        assert_eq!(set.drain(), 3);
        assert_eq!(len(&set), 0);
        assert!(set.try_create(false).is_none());

        let set = prefilled(3, 2);
        assert_eq!(created(&set), 3);
        assert_eq!(len(&set), 3);
        assert!(set.try_create(false).is_none());
    }

    #[test]
    fn test_zeroed_creation() {
        let set = lazy(1, 1);
        let buffer = set.try_create(true).expect("creation permit");
        // SAFETY: the buffer owns a live allocation with TEST_LAYOUT bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), TEST_LAYOUT.size()) };
        assert!(bytes.iter().all(|&byte| byte == 0));
        set.put(buffer);
    }

    #[test]
    fn test_stripe_geometry_is_bounded_and_preallocated() {
        assert_eq!(Freelist::stripe_count(1, usize::MAX), 1);
        assert_eq!(Freelist::stripe_count(3, 1), 2);
        assert_eq!(Freelist::stripe_count(12, 1), MIN_STRIPES);
        assert_eq!(Freelist::stripe_count(12, 9), 8);
        assert_eq!(Freelist::stripe_count(65_536, usize::MAX), MAX_STRIPES);

        let set = prefilled(19, 8);
        assert_eq!(num_stripes(&set), 8);
        for (index, stripe) in set.stripes.iter().enumerate() {
            let free = lock(&stripe.free);
            let expected = Freelist::stripe_capacity(19, 8, index);
            assert_eq!(stripe.limit, expected);
            assert_eq!(free.len(), expected);
            assert!(free.capacity() >= expected);
            assert!(
                free.iter()
                    .all(|owner_index| *owner_index as usize & set.stripe_mask == index)
            );
        }
    }

    #[test]
    fn test_returner_home_batch_spills_past_hard_limit() {
        let set = lazy(19, 8);
        let home = set.home_stripe();
        let count = set.stripes[home].limit + 1;
        let buffers = (0..count)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();

        set.put_batch(buffers);
        assert_eq!(lock(&set.stripes[home].free).len(), set.stripes[home].limit);
        assert_eq!(len(&set), count);
        assert_eq!(set.drain(), count);
    }

    #[test]
    fn test_put_waits_for_locked_full_home() {
        let set = Arc::new(lazy(2, 2));
        let first = set.try_create(false).expect("first creation permit");
        let second = set.try_create(false).expect("second creation permit");
        set.put_from(first, 0);

        let guard = lock(&set.stripes[0].free);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                set.put_from(second, 0);
                done_tx.send(()).expect("signal completion");
            })
        };

        assert!(done_rx.recv_timeout(Duration::from_millis(10)).is_err());
        drop(guard);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("return must finish after home unlocks");
        worker.join().expect("worker must not panic");
        assert_eq!(lock(&set.stripes[1].free).len(), 1);
    }

    #[test]
    fn test_put_batch_waits_for_locked_full_home() {
        let set = Arc::new(lazy(4, 2));
        let mut buffers = (0..4).map(|_| set.try_create(false).expect("creation permit"));
        let first = buffers.next().expect("first buffer");
        let second = buffers.next().expect("second buffer");
        let third = buffers.next().expect("third buffer");
        let fourth = buffers.next().expect("fourth buffer");
        set.put_from(first, 0);

        let guard = lock(&set.stripes[0].free);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                set.put_batch_from([second, third, fourth], 0);
                done_tx.send(()).expect("signal completion");
            })
        };

        assert!(done_rx.recv_timeout(Duration::from_millis(10)).is_err());
        drop(guard);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("batch return must finish after home unlocks");
        worker.join().expect("worker must not panic");
        assert_eq!(
            set.stripes[1..]
                .iter()
                .map(|stripe| lock(&stripe.free).len())
                .sum::<usize>(),
            3
        );
    }

    #[test]
    fn test_returner_homes_redistribute_fixed_owner_skew() {
        let set = lazy(64, 8);
        let mut outside = (0..57)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();
        let mut skewed = Vec::new();
        for owner_index in (0..57).step_by(8) {
            let index = outside
                .iter()
                .position(|buffer| buffer.owner_index() == owner_index)
                .expect("created skewed owner");
            skewed.push(outside.swap_remove(index));
        }

        for (home, buffer) in skewed.into_iter().enumerate() {
            set.put_from(buffer, home);
        }

        for stripe in &set.stripes {
            assert_eq!(lock(&stripe.free).len(), 1);
        }
        set.put_batch(outside);
        assert_eq!(set.drain(), 57);
    }

    #[test]
    fn test_take_batch_scans_stripes_and_calls_back_after_unlock() {
        let set = prefilled(8, 4);
        let count = set.take_batch(8, |buffer| set.put(buffer));
        assert_eq!(count, 8);
        assert_eq!(len(&set), 8);
        assert_eq!(set.take_batch(0, |_| unreachable!()), 0);
    }

    #[test]
    fn test_take_waits_for_locked_stripe() {
        let set = Arc::new(prefilled(1, 1));
        let guard = lock(&set.stripes[0].free);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                started_tx.send(()).expect("signal start");
                done_tx.send(set.take()).expect("send take result");
            })
        };

        started_rx.recv().expect("worker started");
        assert!(done_rx.recv_timeout(Duration::from_millis(10)).is_err());
        drop(guard);
        let buffer = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("take must finish after unlock")
            .expect("locked stripe must preserve its buffer");
        worker.join().expect("worker must not panic");
        set.put(buffer);
    }

    #[test]
    fn test_take_waits_for_home_before_later_stripe() {
        let set = Arc::new(prefilled(2, 2));
        let first_guard = lock(&set.stripes[0].free);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                started_tx.send(()).expect("signal start");
                done_tx
                    .send(set.take_from(0))
                    .expect("send take result");
            })
        };

        started_rx.recv().expect("worker started");
        assert!(done_rx.recv_timeout(Duration::from_millis(10)).is_err());
        drop(first_guard);
        let result = done_rx.recv_timeout(Duration::from_secs(1));
        worker.join().expect("worker must not panic");

        let buffer = result
            .expect("take must finish after the home stripe unlocks")
            .expect("home stripe must remain productive");
        assert_eq!(buffer.owner_index(), 0);
        set.put(buffer);
    }

    #[test]
    fn test_take_batch_waits_for_home_before_later_stripe() {
        let set = Arc::new(prefilled(2, 2));
        let first_guard = lock(&set.stripes[0].free);
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || {
                started_tx.send(()).expect("signal start");
                let mut buffers = Vec::new();
                let count = set.take_batch_from(2, 0, |buffer| buffers.push(buffer));
                done_tx
                    .send((count, buffers))
                    .expect("send batch result");
            })
        };

        started_rx.recv().expect("worker started");
        assert!(done_rx.recv_timeout(Duration::from_millis(10)).is_err());
        drop(first_guard);
        let result = done_rx.recv_timeout(Duration::from_secs(1));
        worker.join().expect("worker must not panic");

        let (count, mut buffers) = result.expect("batch take must finish after home unlocks");
        assert_eq!(count, 2);
        buffers.sort_by_key(PooledBuffer::owner_index);
        assert_eq!(buffers[0].owner_index(), 0);
        assert_eq!(buffers[1].owner_index(), 1);
        set.put_batch(buffers);
    }

    #[test]
    fn test_concurrent_take_and_put_preserve_unique_ownership() {
        const CAPACITY: usize = 64;
        const THREADS: usize = 8;
        const ROUNDS: usize = 1_000;

        let set = Arc::new(prefilled(CAPACITY as u32, THREADS));
        let outside = Arc::new(
            (0..CAPACITY)
                .map(|_| StdAtomicBool::new(false))
                .collect::<Vec<_>>(),
        );
        let start = Arc::new(Barrier::new(THREADS));
        let mut workers = Vec::new();

        for _ in 0..THREADS {
            let set = Arc::clone(&set);
            let outside = Arc::clone(&outside);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..ROUNDS {
                    let buffer = loop {
                        if let Some(buffer) = set.take() {
                            break buffer;
                        }
                        std::thread::yield_now();
                    };
                    let owner_index = buffer.owner_index() as usize;
                    assert!(!outside[owner_index].swap(true, StdOrdering::Relaxed));
                    assert!(outside[owner_index].swap(false, StdOrdering::Relaxed));
                    set.put(buffer);
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker must not panic");
        }
        assert_eq!(len(&set), CAPACITY);
        assert_eq!(set.drain(), CAPACITY);
    }

    #[test]
    fn test_concurrent_batches_respect_hard_stripe_limits() {
        const CAPACITY: usize = 64;
        const THREADS: usize = 8;

        let set = Arc::new(lazy(CAPACITY as u32, THREADS));
        let buffers = (0..CAPACITY)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();
        let mut batches = (0..THREADS).map(|_| Vec::new()).collect::<Vec<_>>();
        for (index, buffer) in buffers.into_iter().enumerate() {
            batches[index % THREADS].push(buffer);
        }
        let start = Arc::new(Barrier::new(THREADS));
        let mut workers = Vec::new();

        for batch in batches {
            let set = Arc::clone(&set);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                set.put_batch(batch);
            }));
        }

        for worker in workers {
            worker.join().expect("worker must not panic");
        }
        assert_eq!(len(&set), CAPACITY);
        for stripe in &set.stripes {
            let free = lock(&stripe.free);
            assert_eq!(free.len(), stripe.limit);
            assert!(free.len() <= free.capacity());
        }
        assert_eq!(set.drain(), CAPACITY);
    }

    #[test]
    fn test_concurrent_creation_assigns_unique_owners() {
        const CAPACITY: usize = 64;
        let set = Arc::new(lazy(CAPACITY as u32, 8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let set = Arc::clone(&set);
            workers.push(std::thread::spawn(move || {
                let mut owner_indices = Vec::new();
                while let Some(buffer) = set.try_create(false) {
                    owner_indices.push(buffer.owner_index());
                    set.put(buffer);
                }
                owner_indices
            }));
        }

        let owner_indices = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker must not panic"))
            .collect::<HashSet<_>>();
        assert_eq!(owner_indices.len(), CAPACITY);
        assert_eq!(created(&set), CAPACITY);
        assert_eq!(len(&set), CAPACITY);
    }

    #[test]
    fn test_drain_leaves_room_for_late_return() {
        let set = prefilled(4, 2);
        let outside = set.take().expect("one outside buffer");
        assert_eq!(set.drain(), 3);
        set.put(outside);
        assert_eq!(set.drain(), 1);
    }

    #[test]
    fn test_take_all_covers_every_owner_once() {
        let set = prefilled(19, 8);
        let buffers = take_all(&set);
        assert_eq!(buffers.len(), 19);
        assert_eq!(
            buffers
                .iter()
                .map(PooledBuffer::owner_index)
                .collect::<HashSet<_>>()
                .len(),
            19
        );
        set.put_batch(buffers);
    }

    #[test]
    fn test_last_take_clears_nonempty_hint() {
        let set = prefilled(1, 1);
        let buffer = set.take().expect("prefilled buffer");
        assert!(!set.stripes[0].available.load(Ordering::Relaxed));
        assert!(set.take().is_none());

        set.put(buffer);
        assert!(set.stripes[0].available.load(Ordering::Acquire));
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize};
    use loom::{sync::Arc, thread};

    const TEST_LAYOUT: Layout = match Layout::from_size_align(8, 8) {
        Ok(layout) => layout,
        Err(_) => panic!("valid test layout"),
    };

    fn prefilled(capacity: u32) -> Freelist {
        Freelist::new(NZU32!(capacity), NZUsize!(1), TEST_LAYOUT, true)
    }

    #[test]
    fn completed_put_is_discoverable() {
        loom::model(|| {
            let set = Arc::new(Freelist::new(NZU32!(1), NZUsize!(1), TEST_LAYOUT, false));
            let buffer = set.try_create(false).expect("creation permit");
            let returned = Arc::new(AtomicBool::new(false));

            let worker = {
                let set = Arc::clone(&set);
                let returned = Arc::clone(&returned);
                thread::spawn(move || {
                    set.put(buffer);
                    returned.store(true, Ordering::Release);
                })
            };

            while !returned.load(Ordering::Acquire) {
                thread::yield_now();
            }
            let buffer = set.take().expect("completed put must be found");
            worker.join().expect("worker must not panic");
            set.put(buffer);
        });
    }

    #[test]
    fn two_takers_cannot_claim_one_owner() {
        loom::model(|| {
            let set = Arc::new(prefilled(1));
            let first = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.take())
            };
            let second = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.take())
            };

            let first = first.join().expect("first taker must not panic");
            let second = second.join().expect("second taker must not panic");
            assert_ne!(first.is_some(), second.is_some());
            set.put(first.or(second).expect("one taker must succeed"));
        });
    }

    #[test]
    fn concurrent_puts_preserve_both_owners() {
        loom::model(|| {
            let set = Arc::new(Freelist::new(NZU32!(2), NZUsize!(1), TEST_LAYOUT, false));
            let first = set.try_create(false).expect("first permit");
            let second = set.try_create(false).expect("second permit");

            let first_put = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(first))
            };
            let second_put = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put(second))
            };
            first_put.join().expect("first put must not panic");
            second_put.join().expect("second put must not panic");

            let first = set.take().expect("first owner");
            let second = set.take().expect("second owner");
            assert_ne!(first.owner_index(), second.owner_index());
            set.put_batch([first, second]);
        });
    }

    #[test]
    fn locked_stripe_is_not_reported_empty() {
        loom::model(|| {
            let set = Arc::new(prefilled(1));
            let guard = lock(&set.stripes[0].free);
            let taker = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.take())
            };
            thread::yield_now();
            drop(guard);

            let buffer = taker
                .join()
                .expect("taker must not panic")
                .expect("locked stripe must not be missed");
            set.put(buffer);
        });
    }

    #[test]
    fn return_waits_for_locked_full_home() {
        loom::model(|| {
            let set = Arc::new(Freelist::new(
                NZU32!(2),
                NZUsize!(2),
                TEST_LAYOUT,
                false,
            ));
            let first = set.try_create(false).expect("first creation permit");
            let second = set.try_create(false).expect("second creation permit");
            set.put_from(first, 0);

            let guard = lock(&set.stripes[0].free);
            let returner = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.put_from(second, 0))
            };
            thread::yield_now();
            drop(guard);
            returner.join().expect("returner must not panic");

            let first = set.take().expect("first returned buffer");
            let second = set.take().expect("second returned buffer");
            set.put_batch([first, second]);
        });
    }

    #[test]
    fn take_and_drain_partition_owners() {
        loom::model(|| {
            let set = Arc::new(prefilled(2));
            let taker = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.take())
            };
            let drainer = {
                let set = Arc::clone(&set);
                thread::spawn(move || set.drain())
            };

            let taken = taker.join().expect("taker must not panic");
            let drained = drainer.join().expect("drainer must not panic");
            assert_eq!(usize::from(taken.is_some()) + drained, 2);
            if let Some(buffer) = taken {
                set.put(buffer);
                assert_eq!(set.drain(), 1);
            }
        });
    }
}

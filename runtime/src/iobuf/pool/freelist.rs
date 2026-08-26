//! Striped global freelist for one buffer-pool size class.
//!
//! Each size class has a fixed number of slots. A slot combines one stable
//! [`PooledOwner`] record with one data allocation after that slot is created.
//! The [`Freelist`] owns the slot table, the allocation layout, and every
//! buffer currently available for global reuse.
//!
//! A buffer moves through these ownership states:
//!
//! ```text
//!                        create or take
//!  +----------------+ --------------------> +-----------------------+
//!  | global stripe  |                       | checked out or in TLS |
//!  | Vec<slot id>   | <-------------------- | cache                 |
//!  +----------------+          put          +-----------------------+
//! ```
//!
//! The global representation is deliberately small. Stripes store only `u32`
//! slot ids. The corresponding owner records never move:
//!
//! ```text
//!  Freelist
//!  +-- slots:   [ PooledOwner ][ PooledOwner ][ PooledOwner ] ...
//!  +-- stripes: [ available | Mutex<Vec<u32>> | hard limit ] ...
//!
//!                      slot 5
//!  stripe vector  --------------------->  slots[5]
//! ```
//!
//! # Striping
//!
//! Every thread receives a stable process-local id. The low bits select that
//! thread's home stripe. A put starts at the home stripe and continues in
//! wrapped order only when a stripe has reached its hard limit. A take follows
//! the same wrapped order and may claim any available slot. Slot ids can
//! therefore migrate between stripes as buffers are returned by different
//! threads.
//!
//! Stripe limits are fixed at construction and sum to the freelist capacity.
//! Each vector requests its limit as initial capacity, and operations enforce
//! that limit even if the allocator reserves more. A valid put therefore does
//! not grow a vector while holding its lock. If racing operations move the
//! remaining room during a complete scan, the put yields and retries.
//!
//! # Availability hints and locking
//!
//! Each stripe has an [`AtomicBool`] that avoids locking a stripe observed to
//! be empty. The vector remains authoritative. The first put into an empty
//! vector publishes `true`, and the take that removes the final slot publishes
//! `false`. Both transitions happen while the stripe is locked. A taker may
//! observe a stale `false` and skip that stripe unless it has synchronized with
//! the thread that completed the put.
//!
//! Stripe locks are blocking. A take that observes a positive hint waits for
//! that stripe even if a later stripe could satisfy it. A failed scan is one
//! bounded concurrent miss, not a linearizable snapshot of global emptiness.
//! A retry may succeed after an overlapping return completes.
//!
//! # Caller contract
//!
//! This is not a general-purpose container. It relies on the buffer pool to
//! maintain exclusive ownership. Callers must return only buffers created by
//! this freelist, return each buffer exactly once, and provide distinct buffers
//! in each batch. Violating that contract can duplicate a slot or exceed a
//! stripe's aggregate capacity.
//!
//! [`PooledBuffer`] does not carry its allocation layout. Every created or
//! claimed buffer must eventually return before this freelist is dropped. An
//! outstanding buffer that never returns leaks. Buffer-pool leases keep the
//! owning size class and this freelist alive until valid returns complete.

use crate::iobuf::owner::{PooledBuffer, PooledOwner};
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
                Mutex, MutexGuard,
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

/// Preferred minimum stripe count when the capacity can support it.
///
/// The floor prevents a low or underestimated parallelism setting from
/// collapsing ordinary pools onto one hot lock. Capacity still bounds the
/// count, so small size classes never allocate empty stripes.
const MIN_STRIPES: usize = 8;

/// Maximum number of cache-isolated stripes in one freelist.
///
/// The cap bounds both cache-padded metadata and the cost of an empty scan when
/// configured parallelism is extremely large.
const MAX_STRIPES: usize = 4_096;

/// One cache-isolated collection of globally free slots with a fixed slot limit.
struct Stripe {
    /// Advisory nonempty hint used to skip stripe locks.
    ///
    /// The value changes only while `free` is locked. `true` requires locking
    /// and inspecting authoritative `free`. A taker may observe a stale `false`
    /// unless it has synchronized with the thread that completed the insertion.
    available: AtomicBool,
    /// Slot ids currently owned by the global freelist in this stripe.
    free: Mutex<Vec<u32>>,
    /// Maximum number of slot ids that `free` may contain.
    ///
    /// The vector is created with this requested capacity during construction.
    limit: usize,
}

impl Stripe {
    /// Creates a stripe from its preallocated initial free-slot vector.
    fn new(free: Vec<u32>, limit: usize) -> Self {
        assert!(free.len() <= limit);
        assert!(free.capacity() >= limit);
        Self {
            available: AtomicBool::new(!free.is_empty()),
            free: Mutex::new(free),
            limit,
        }
    }

    /// Locks the authoritative free-slot vector.
    ///
    /// Production mutexes do not expose poisoning. Loom uses the standard
    /// poisoning API, and a poisoned model indicates a prior test panic rather
    /// than a recoverable freelist state.
    #[inline(always)]
    fn lock(&self) -> MutexGuard<'_, Vec<u32>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "loom")] {
                self.free
                    .lock()
                    .expect("freelist mutex must not be poisoned")
            } else {
                self.free.lock()
            }
        }
    }

    /// Removes one slot while maintaining the availability hint.
    ///
    /// `free` must be the guard obtained from [`Self::lock`] for this stripe.
    #[inline(always)]
    fn pop(&self, free: &mut MutexGuard<'_, Vec<u32>>) -> Option<u32> {
        // A taker can load `true` before another taker removes the final slot,
        // so the locked vector may already be empty.
        let slot = free.pop()?;

        // Publish the last removal before releasing the stripe lock.
        if free.is_empty() {
            self.available.store(false, Ordering::Release);
        }
        Some(slot)
    }
}

/// Fixed-capacity striped freelist for one buffer-pool size class.
///
/// The freelist owns every stable pooled-owner slot and the exact layout used
/// for its data allocation. Globally available slots are stored as compact ids
/// in stripes with fixed slot limits. Checked-out buffers and thread-local
/// caches may temporarily own slots, but their leases keep this freelist alive
/// until they return.
pub struct Freelist {
    /// Exact layout shared by every data allocation in this size class.
    layout: Layout,
    /// Number of permanent creation permits consumed so far.
    ///
    /// The cache padding isolates concurrent lazy creation from stripe state.
    created: CachePadded<AtomicUsize>,
    /// Stable owner record for every possible slot in this size class.
    ///
    /// Boxing prevents the records from moving after pointers escape.
    slots: Box<[CachePadded<UnsafeCell<PooledOwner>>]>,
    /// Cache-isolated free-slot vectors selected by thread home.
    stripes: Box<[CachePadded<Stripe>]>,
    /// `stripes.len() - 1`, used for power-of-two wrapped indexing.
    stripe_mask: usize,
}

// SAFETY: slot storage is stable for the lifetime of the freelist. The buffer
// pool contract places each created slot either outside the global freelist or
// in exactly one mutex-protected stripe.
unsafe impl Send for Freelist {}
// SAFETY: same ownership and locking discipline as the Send implementation.
unsafe impl Sync for Freelist {}

impl Freelist {
    /// Creates a fixed-capacity freelist for one allocation layout.
    ///
    /// `parallelism` selects a power-of-two stripe target. When capacity allows,
    /// the target is at least [`MIN_STRIPES`] and never exceeds
    /// [`MAX_STRIPES`]. The count also never exceeds the greatest power of two
    /// no larger than `capacity`, which ensures every stripe has a nonzero hard
    /// limit.
    ///
    /// Each stripe preallocates its exact share of total capacity. If `prefill`
    /// is `true`, every slot's data allocation is created and parked before
    /// this method returns.
    ///
    /// # Panics
    ///
    /// Panics when `layout` is zero-sized. Allocation failure invokes the
    /// process allocation error handler.
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

        let slots = (0..capacity)
            .map(|slot| {
                CachePadded::new(UnsafeCell::new(PooledOwner::new(
                    u32::try_from(slot).expect("slot must fit in u32"),
                    layout.size(),
                )))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        // Build the free vectors before their mutexes exist. This keeps prefill
        // allocation and initialization outside every stripe lock.
        let mut free = (0..stripe_count)
            .map(|stripe| Vec::with_capacity(Self::stripe_capacity(capacity, stripe_count, stripe)))
            .collect::<Vec<_>>();

        if prefill {
            for slot in 0..capacity {
                // SAFETY: construction exclusively initializes this stable slot.
                let buffer =
                    unsafe { PooledBuffer::new(Self::cell_ptr(&slots[slot]), layout, false) };
                free[slot & stripe_mask].push(buffer.into_slot());
            }
        }

        let stripes = free
            .into_iter()
            .enumerate()
            .map(|(stripe, free)| {
                let limit = Self::stripe_capacity(capacity, stripe_count, stripe);
                CachePadded::new(Stripe::new(free, limit))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            layout,
            created: CachePadded::new(AtomicUsize::new(if prefill { capacity } else { 0 })),
            slots,
            stripes,
            stripe_mask,
        }
    }

    /// Selects a power-of-two stripe count from capacity and parallelism.
    ///
    /// The minimum protects low parallelism estimates from a single hot lock.
    /// The maximum bounds metadata and empty scans. The capacity ceiling keeps
    /// every stripe useful and makes wrapped indexing a mask operation.
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

    /// Returns the exact hard limit for one stripe.
    ///
    /// Slots are distributed by `slot & (stripes - 1)` during prefill. This
    /// formula gives the matching quotient plus remainder distribution, whose
    /// limits sum exactly to `capacity`.
    #[inline(always)]
    const fn stripe_capacity(capacity: usize, stripes: usize, stripe: usize) -> usize {
        (capacity - stripe).div_ceil(stripes)
    }

    /// Creates a new tracked buffer and assigns its permanent slot id.
    ///
    /// Returns `None` after all creation permits have been consumed. Draining
    /// does not reopen permits because each slot is initialized at most once.
    #[inline(always)]
    pub(super) fn try_create(&self, zeroed: bool) -> Option<PooledBuffer> {
        let capacity = self.slots.len();

        // The successful old counter value is a unique permanent slot id. This
        // admission does not publish slot state, so relaxed ordering is enough.
        #[allow(deprecated)]
        let slot = self
            .created
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |created| {
                (created < capacity).then_some(created + 1)
            })
            .ok()?;

        // SAFETY: creation admission assigns this slot exactly once. Its
        // address remains stable for the freelist lifetime.
        Some(unsafe { PooledBuffer::new(self.slot(slot as u32), self.layout, zeroed) })
    }

    /// Returns one uniquely owned buffer to global availability.
    ///
    /// The scan starts at the current thread's home stripe. Full stripes are
    /// skipped in wrapped order. Under the caller contract, aggregate room
    /// exists for every returned buffer, although racing operations can move
    /// that room during a scan.
    pub fn put(&self, buffer: PooledBuffer) {
        let start = self.home_stripe();
        let slot = buffer.into_slot();
        loop {
            for offset in 0..self.stripes.len() {
                let stripe = &self.stripes[(start + offset) & self.stripe_mask];
                let mut free = stripe.lock();
                if free.len() == stripe.limit {
                    continue;
                }

                let was_empty = free.is_empty();
                free.push(slot);
                if was_empty {
                    // Publish the first insertion before releasing the lock.
                    stripe.available.store(true, Ordering::Release);
                }
                return;
            }

            // Aggregate room exists for every valid outside buffer, but racing
            // operations can move that room during one scan.
            thread::yield_now();
        }
    }

    /// Returns several uniquely owned buffers to global availability.
    ///
    /// The iterator is consumed into compact slot ids before any slot is
    /// published. Publication starts at the current thread's home and fills
    /// each stripe only to its fixed slot limit. No two stripe locks are held
    /// together.
    ///
    /// The iterator must contain distinct buffers created by this freelist. It
    /// should not panic because buffers yielded before a panic may leak.
    pub fn put_batch(&self, buffers: impl IntoIterator<Item = PooledBuffer>) {
        // Keep empty and singleton batches off the staging path. Internal
        // slot-id scratch is needed only when publishing multiple buffers.
        let mut buffers = buffers.into_iter();
        let Some(first) = buffers.next() else {
            return;
        };
        let Some(second) = buffers.next() else {
            self.put(first);
            return;
        };

        let reserve = buffers
            .size_hint()
            .0
            .saturating_add(2)
            .min(self.slots.len());
        let mut slots = Vec::with_capacity(reserve);
        slots.push(first.into_slot());
        slots.push(second.into_slot());
        slots.extend(buffers.map(PooledBuffer::into_slot));

        // The iterator is fully staged, so publication performs no caller work
        // or scratch allocation while a stripe is locked.
        let start = self.home_stripe();
        while !slots.is_empty() {
            let before = slots.len();
            for offset in 0..self.stripes.len() {
                // Fill only the stripe's fixed remaining room so pushes cannot
                // allocate under the lock. Publish an empty-to-nonempty
                // transition before unlocking.
                let stripe = &self.stripes[(start + offset) & self.stripe_mask];
                let mut free = stripe.lock();
                let count = (stripe.limit - free.len()).min(slots.len());
                let was_empty = free.is_empty();
                for _ in 0..count {
                    free.push(slots.pop().expect("count is bounded by length"));
                }
                if was_empty && count != 0 {
                    stripe.available.store(true, Ordering::Release);
                }
                if slots.is_empty() {
                    return;
                }
            }

            // Valid returns guarantee aggregate room, but racing operations can
            // move it throughout a pass. Yield only when the pass parks nothing.
            if slots.len() == before {
                thread::yield_now();
            }
        }
    }

    /// Takes any one globally available buffer, if observed.
    ///
    /// The scan starts at the current thread's home. Stripes with a negative
    /// availability hint are skipped without locking. A positive stripe is
    /// locked and checked authoritatively.
    ///
    /// `None` means this bounded scan found no slot. It is not a linearizable
    /// empty snapshot because a concurrent put may still be in progress.
    #[inline]
    pub fn take(&self) -> Option<PooledBuffer> {
        // A negative hint can skip locking. A positive hint requires an
        // authoritative check under the mutex because another taker may have
        // emptied the stripe.
        let start = self.home_stripe();
        for offset in 0..self.stripes.len() {
            let stripe = &self.stripes[(start + offset) & self.stripe_mask];
            if !stripe.available.load(Ordering::Acquire) {
                continue;
            }
            let mut free = stripe.lock();
            if let Some(slot) = stripe.pop(&mut free) {
                // Reconstructing the buffer touches only stable slot state, so
                // keep it outside the critical section.
                drop(free);
                return Some(self.claim(slot));
            }
        }
        None
    }

    /// Takes up to `max` globally available buffers.
    ///
    /// Slot ids are detached while each stripe is locked. All buffers are
    /// reconstructed and passed to `on_buffer` only after every lock has been
    /// released. A short result means the bounded scan found fewer than `max`
    /// slots, not that no overlapping put can make more available.
    ///
    /// `on_buffer` must not panic because any remaining detached slots would be
    /// stranded outside both the freelist and the caller.
    #[inline]
    pub fn take_batch(&self, max: usize, mut on_buffer: impl FnMut(PooledBuffer)) -> usize {
        // Clamp oversized requests to the freelist capacity. Empty requests
        // return immediately, while singleton requests reuse the scalar path
        // and avoid batch scratch allocation.
        let max = match max.min(self.slots.len()) {
            0 => return 0,
            1 => {
                let Some(buffer) = self.take() else {
                    return 0;
                };
                on_buffer(buffer);
                return 1;
            }
            max => max,
        };

        // Keep scans that observe only negative hints allocation-free. Reserve
        // detached-slot scratch after the first positive hint but before locking.
        let mut detached = Vec::new();
        let start = self.home_stripe();
        for offset in 0..self.stripes.len() {
            let stripe = &self.stripes[(start + offset) & self.stripe_mask];
            if !stripe.available.load(Ordering::Acquire) {
                continue;
            }
            if detached.capacity() == 0 {
                detached = Vec::with_capacity(max);
            }

            // Detach only compact slot ids while this stripe is locked. Buffer
            // reconstruction and caller callbacks remain outside every lock.
            let mut free = stripe.lock();
            while detached.len() < max {
                let Some(slot) = stripe.pop(&mut free) else {
                    break;
                };
                detached.push(slot);
            }
            if detached.len() == max {
                break;
            }
        }

        // A positive hint can become stale before its stripe is locked, leaving
        // the scan with allocated scratch but no detached slots.
        if detached.is_empty() {
            return 0;
        }

        // No stripe locks remain held, so callbacks may safely reenter the
        // freelist while ownership of each detached slot is transferred.
        let count = detached.len();
        for slot in detached {
            on_buffer(self.claim(slot));
        }
        count
    }

    /// Deallocates every buffer currently parked in this freelist.
    ///
    /// Buffers still checked out or held in a thread-local cache may return during
    /// or after this call. Each stripe is therefore replaced under lock with an
    /// empty vector reserved to its original limit, so a return never grows the
    /// vector while holding the stripe lock. Detached buffers are deallocated
    /// after the lock is released.
    ///
    /// Draining does not restore creation permits, so deallocated buffers cannot
    /// be recreated through this freelist.
    pub fn drain(&self) -> usize {
        let mut drained = 0;
        for stripe in &self.stripes {
            // Allocate before locking so late returns never wait for allocator
            // work that is independent of the protected vector swap.
            let replacement = Vec::with_capacity(stripe.limit);
            let detached = {
                let mut free = stripe.lock();
                let detached = std::mem::replace(&mut *free, replacement);
                stripe.available.store(false, Ordering::Release);
                detached
            };

            drained += self.deallocate_detached(detached);
        }

        drained
    }

    /// Deallocates buffers whose slots are no longer owned by a stripe.
    fn deallocate_detached(&self, detached: Vec<u32>) -> usize {
        let count = detached.len();
        for slot in detached {
            // SAFETY: detachment gives this method unique ownership of the buffer,
            // which this freelist allocated with `self.layout`.
            unsafe { self.claim(slot).deallocate(self.layout) };
        }
        count
    }

    /// Returns the stable owner pointer for one slot id.
    #[inline(always)]
    fn slot(&self, slot: u32) -> ptr::NonNull<PooledOwner> {
        let owner = self
            .slots
            .get(slot as usize)
            .expect("slot must belong to this freelist");
        Self::cell_ptr(owner)
    }

    /// Obtains the stable pointer stored by one platform-specific cell.
    #[inline(always)]
    #[allow(clippy::missing_const_for_fn)]
    fn cell_ptr(owner: &UnsafeCell<PooledOwner>) -> ptr::NonNull<PooledOwner> {
        cfg_if::cfg_if! {
            if #[cfg(not(feature = "loom"))] {
                ptr::NonNull::new(owner.get()).expect("slot pointers are non-null")
            } else {
                owner.with(|owner| {
                    ptr::NonNull::new(owner.cast_mut()).expect("slot pointers are non-null")
                })
            }
        }
    }

    /// Returns the current thread's stable home stripe in this freelist.
    #[inline(always)]
    fn home_stripe(&self) -> usize {
        if self.stripe_mask == 0 {
            return 0;
        }
        current_thread_id() & self.stripe_mask
    }

    /// Reconstructs unique ownership after removing a slot from a stripe.
    #[inline(always)]
    fn claim(&self, slot: u32) -> PooledBuffer {
        // SAFETY: the buffer-pool contract makes a globally stored slot unique,
        // and the caller removed this slot from its stripe.
        let buffer = unsafe { PooledBuffer::from_owner(self.slot(slot)) };
        #[cfg(feature = "loom")]
        buffer.assert_parked_sentinel();
        buffer
    }
}

impl Drop for Freelist {
    fn drop(&mut self) {
        // Every checked-out or TLS-cached slot keeps the size class alive until it
        // returns. Final destruction therefore owns every live allocation and
        // needs no replacement capacity for a later return.
        for index in 0..self.stripes.len() {
            #[cfg(feature = "loom")]
            let detached = std::mem::take(
                self.stripes[index]
                    .free
                    .get_mut()
                    .expect("freelist mutex must not be poisoned"),
            );
            #[cfg(not(feature = "loom"))]
            let detached = std::mem::take(self.stripes[index].free.get_mut());

            self.deallocate_detached(detached);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        /// Next process-local id assigned to a thread that touches a freelist.
        static NEXT_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
    } else {
        loom::lazy_static! {
            /// Next model-local id assigned to a thread that touches a freelist.
            static ref NEXT_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "loom"))] {
        thread_local! {
            /// Stable id used to select this thread's home in every freelist.
            static THREAD_ID: Cell<Option<usize>> = const { Cell::new(None) };
        }
    } else {
        loom::thread_local! {
            /// Stable id used to select this modeled thread's freelist home.
            static THREAD_ID: Cell<Option<usize>> = Cell::new(None);
        }
    }
}

/// Returns one stable process-local id for the current thread.
#[inline(always)]
fn current_thread_id() -> usize {
    THREAD_ID.with(|thread_id| {
        if let Some(id) = thread_id.get() {
            return id;
        }

        // The id is used only for load distribution, so wraparound and ordering
        // relative to freelist contents have no correctness significance.
        let id = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
        thread_id.set(Some(id));
        id
    })
}

#[cfg(all(test, not(feature = "loom")))]
pub(super) mod tests {
    use super::*;
    use crate::{BufferPool, BufferPoolConfig, IoBufMut, iobuf::PoolError};
    use std::{
        alloc::{GlobalAlloc, System},
        cell::Cell,
        collections::HashSet,
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool as StdAtomicBool, Ordering as StdOrdering},
        },
    };

    /// Allocation layout shared by native freelist tests.
    const TEST_LAYOUT: Layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => panic!("valid test layout"),
    };

    /// Returns the number of permanent creation permits consumed.
    pub fn created(freelist: &Freelist) -> usize {
        freelist.created.load(Ordering::Relaxed)
    }

    /// Returns the number of slots currently parked across all stripes.
    pub fn len(freelist: &Freelist) -> usize {
        freelist
            .stripes
            .iter()
            .map(|stripe| stripe.lock().len())
            .sum()
    }

    /// Returns the number of stripes selected during construction.
    pub fn num_stripes(freelist: &Freelist) -> usize {
        freelist.stripes.len()
    }

    /// Creates an empty freelist whose slots are allocated lazily.
    fn lazy(capacity: u32, parallelism: usize) -> Freelist {
        Freelist::new(
            NonZeroU32::new(capacity).expect("positive capacity"),
            NonZeroUsize::new(parallelism).expect("positive parallelism"),
            TEST_LAYOUT,
            false,
        )
    }

    /// Creates a freelist with every slot allocated and globally available.
    fn prefilled(capacity: u32, parallelism: usize) -> Freelist {
        Freelist::new(
            NonZeroU32::new(capacity).expect("positive capacity"),
            NonZeroUsize::new(parallelism).expect("positive parallelism"),
            TEST_LAYOUT,
            true,
        )
    }

    /// Takes every slot visible through repeated bounded batch scans.
    fn take_all(freelist: &Freelist) -> Vec<PooledBuffer> {
        let mut buffers = Vec::new();
        loop {
            let taken = freelist.take_batch(usize::MAX, |buffer| buffers.push(buffer));
            if taken == 0 {
                return buffers;
            }
        }
    }

    /// Verifies lazy creation, prefill, fixed permits, and explicit draining.
    #[test]
    fn test_creation_prefill_and_drain() {
        let set = lazy(3, 2);
        let buffers = (0..3)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();
        assert_eq!(
            buffers.iter().map(PooledBuffer::slot).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(format!("{:?}", buffers[0]).contains("slot"));
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

    /// Verifies that zeroed lazy creation initializes every data byte.
    #[test]
    fn test_zeroed_creation() {
        let set = lazy(1, 1);
        let buffer = set.try_create(true).expect("creation permit");
        // SAFETY: the buffer owns a live allocation with TEST_LAYOUT bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), TEST_LAYOUT.size()) };
        assert!(bytes.iter().all(|&byte| byte == 0));
        set.put(buffer);
    }

    /// Verifies stripe-count bounds, exact limits, and preallocated capacity.
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
            let free = stripe.lock();
            let expected = Freelist::stripe_capacity(19, 8, index);
            assert_eq!(stripe.limit, expected);
            assert_eq!(free.len(), expected);
            assert!(free.capacity() >= expected);
            assert!(
                free.iter()
                    .all(|slot| *slot as usize & set.stripe_mask == index)
            );
        }
    }

    /// Verifies that a batch spills past its home stripe's hard limit.
    #[test]
    fn test_returner_home_batch_spills_past_hard_limit() {
        let set = lazy(19, 8);
        let home = set.home_stripe();
        let count = set.stripes[home].limit + 1;
        let buffers = (0..count)
            .map(|_| set.try_create(false).expect("creation permit"))
            .collect::<Vec<_>>();

        set.put_batch(buffers);
        assert_eq!(set.stripes[home].lock().len(), set.stripes[home].limit);
        assert_eq!(len(&set), count);
        assert_eq!(set.drain(), count);
    }

    /// Verifies that one thread keeps a stable, in-range home stripe.
    #[test]
    fn test_thread_home_is_stable_and_bounded() {
        let set = lazy(64, 8);
        let home = set.home_stripe();
        assert!(home < set.stripes.len());
        for _ in 0..32 {
            assert_eq!(set.home_stripe(), home);
        }
    }

    /// Verifies multi-stripe batch scans and callbacks after all unlocks.
    #[test]
    fn test_take_batch_scans_stripes_and_calls_back_after_unlock() {
        let set = prefilled(8, 4);
        let count = set.take_batch(8, |buffer| set.put(buffer));
        assert_eq!(count, 8);
        assert_eq!(len(&set), 8);
        assert_eq!(set.take_batch(0, |_| unreachable!()), 0);
    }

    /// Verifies empty and singleton put and take batch paths.
    #[test]
    fn test_empty_and_singleton_batches() {
        let set = lazy(1, 1);
        set.put_batch(std::iter::empty());
        assert_eq!(set.take_batch(1, |_| unreachable!()), 0);

        let buffer = set.try_create(false).expect("creation permit");
        set.put_batch([buffer]);

        let mut taken = None;
        assert_eq!(set.take_batch(1, |buffer| taken = Some(buffer)), 1);
        set.put(taken.expect("singleton callback receives the buffer"));
    }

    /// Verifies unique ownership across contended scalar take and put cycles.
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
                    let slot = buffer.slot() as usize;
                    assert!(!outside[slot].swap(true, StdOrdering::Relaxed));
                    assert!(outside[slot].swap(false, StdOrdering::Relaxed));
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

    /// Verifies concurrent batch publication respects every hard stripe limit.
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
            let free = stripe.lock();
            assert_eq!(free.len(), stripe.limit);
            assert!(free.len() <= free.capacity());
        }
        assert_eq!(set.drain(), CAPACITY);
    }

    /// Verifies concurrent lazy creation assigns each slot exactly once.
    #[test]
    fn test_concurrent_creation_assigns_unique_slots() {
        const CAPACITY: usize = 64;
        let set = Arc::new(lazy(CAPACITY as u32, 8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let set = Arc::clone(&set);
            workers.push(std::thread::spawn(move || {
                let mut slots = Vec::new();
                while let Some(buffer) = set.try_create(false) {
                    slots.push(buffer.slot());
                    set.put(buffer);
                }
                slots
            }));
        }

        let slots = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker must not panic"))
            .collect::<HashSet<_>>();
        assert_eq!(slots.len(), CAPACITY);
        assert_eq!(created(&set), CAPACITY);
        assert_eq!(len(&set), CAPACITY);
    }

    /// Verifies drain preserves reserved room for an outstanding late return.
    #[test]
    fn test_drain_leaves_room_for_late_return() {
        let set = prefilled(4, 2);
        let outside = set.take().expect("one outside buffer");
        assert_eq!(set.drain(), 3);
        set.put(outside);
        assert_eq!(set.drain(), 1);
    }

    /// Verifies repeated maximum batches return every slot exactly once.
    #[test]
    fn test_take_all_covers_every_slot_once() {
        let set = prefilled(19, 8);
        let buffers = take_all(&set);
        assert_eq!(buffers.len(), 19);
        assert_eq!(
            buffers
                .iter()
                .map(PooledBuffer::slot)
                .collect::<HashSet<_>>()
                .len(),
            19
        );
        set.put_batch(buffers);
    }

    /// Verifies the final removal clears and the next put restores the hint.
    #[test]
    fn test_last_take_clears_nonempty_hint() {
        let set = prefilled(1, 1);
        let buffer = set.take().expect("prefilled buffer");
        assert!(!set.stripes[0].available.load(Ordering::Relaxed));
        assert!(set.take().is_none());

        set.put(buffer);
        assert!(set.stripes[0].available.load(Ordering::Acquire));
    }

    struct TrackingAllocator;

    std::thread_local! {
        static ALLOCATION_CALLS: Cell<Option<usize>> = const { Cell::new(None) };
    }

    #[global_allocator]
    static ALLOCATOR: TrackingAllocator = TrackingAllocator;

    fn record_allocation() {
        ALLOCATION_CALLS.with(|calls| {
            if let Some(count) = calls.get() {
                calls.set(Some(count + 1));
            }
        });
    }

    // SAFETY: Every operation delegates to the system allocator with unchanged
    // arguments. Recording an allocation only updates a thread-local cell.
    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            // SAFETY: The caller supplies the layout required by GlobalAlloc.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            // SAFETY: The caller supplies the layout required by GlobalAlloc.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: The pointer was allocated through this wrapper, which
            // delegates every allocation to System with the same layout.
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record_allocation();
            // SAFETY: The pointer and layout came from System through this wrapper,
            // and the caller supplies the new size required by GlobalAlloc.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    fn allocation_calls_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
        ALLOCATION_CALLS.with(|calls| assert!(calls.replace(Some(0)).is_none()));
        let result = f();
        let calls = ALLOCATION_CALLS.with(|calls| calls.replace(None).expect("tracking enabled"));
        (result, calls)
    }

    /// Verifies populated final destruction does not reserve replacement capacity.
    #[test]
    fn test_populated_final_drop_is_allocation_free() {
        let set = prefilled(19, 8);

        let ((), allocation_calls) = allocation_calls_during(|| drop(set));
        assert_eq!(
            allocation_calls, 0,
            "final destruction must not allocate replacement capacity"
        );
    }

    /// Verifies an exhausted TLS batch probe does not allocate result scratch.
    #[test]
    fn test_exhausted_batched_tls_miss_is_allocation_free() {
        const BUFFER_SIZE: usize = 64;
        const CAPACITY: usize = 4;

        let size = NonZeroUsize::new(BUFFER_SIZE).expect("positive buffer size");
        let config = BufferPoolConfig::for_network()
            .with_size_class_range(
                size,
                size,
                NonZeroU32::new(CAPACITY as u32).expect("positive capacity"),
            )
            .with_max_thread_cache_capacity(
                NonZeroUsize::new(CAPACITY).expect("positive cache capacity"),
            );
        let mut registry = crate::telemetry::metrics::Registry::default();
        let pool = BufferPool::new(config, &mut registry);

        // Exhaust the class before tracking allocations. Measuring only the
        // repeated miss excludes pool setup and lazy buffer creation.
        let _held: [IoBufMut; CAPACITY] = std::array::from_fn(|_| {
            pool.try_alloc(BUFFER_SIZE)
                .expect("lazy allocation within capacity")
        });
        assert!(matches!(
            pool.try_alloc(BUFFER_SIZE),
            Err(PoolError::Exhausted)
        ));

        let (result, allocation_calls) = allocation_calls_during(|| pool.try_alloc(BUFFER_SIZE));
        assert!(matches!(result, Err(PoolError::Exhausted)));
        assert_eq!(
            allocation_calls, 0,
            "an exhausted TLS batch probe must not allocate scratch"
        );
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use commonware_utils::{NZU32, NZUsize};
    use loom::{sync::Arc, thread};

    /// Small allocation layout used to keep model state compact.
    const TEST_LAYOUT: Layout = match Layout::from_size_align(8, 8) {
        Ok(layout) => layout,
        Err(_) => panic!("valid test layout"),
    };

    const OPERATION_STARTED: usize = 1;
    const OPERATION_FINISHED: usize = 2;

    /// Creates an empty freelist for one Loom model.
    fn empty(capacity: u32) -> Freelist {
        Freelist::new(NZU32!(capacity), NZUsize!(1), TEST_LAYOUT, false)
    }

    /// Creates a fully available freelist for one Loom model.
    fn prefilled(capacity: u32) -> Freelist {
        Freelist::new(NZU32!(capacity), NZUsize!(1), TEST_LAYOUT, true)
    }

    /// Parks one test buffer in a chosen stripe without exercising routing.
    fn park_in_stripe(set: &Freelist, index: usize, buffer: PooledBuffer) {
        let stripe = &set.stripes[index];
        let mut free = stripe.lock();
        assert!(free.len() < stripe.limit);
        free.push(buffer.into_slot());
        stripe.available.store(true, Ordering::Release);
    }

    /// Requires a modeled operation to remain incomplete while its home guard is held.
    fn assert_waiting(phase: &AtomicUsize) {
        while phase.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }
        thread::yield_now();
        assert_eq!(
            phase.load(Ordering::Acquire),
            OPERATION_STARTED,
            "operation skipped its locked home stripe"
        );
    }

    /// Verifies that a release/acquire handoff makes a completed return
    /// discoverable.
    #[test]
    fn completed_put_is_discoverable_after_handoff() {
        loom::model(|| {
            let set = Arc::new(empty(1));
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

            // The release/acquire handoff orders the hint publication before
            // the scan.
            while !returned.load(Ordering::Acquire) {
                thread::yield_now();
            }
            let buffer = set.take().expect("completed put must be found");
            worker.join().expect("worker must not panic");
            set.put(buffer);
        });
    }

    /// Verifies that two concurrent takers cannot claim one slot twice.
    #[test]
    fn two_takers_cannot_claim_one_slot() {
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

    /// Verifies that concurrent returns preserve both distinct slots.
    #[test]
    fn concurrent_puts_preserve_both_slots() {
        loom::model(|| {
            let set = Arc::new(empty(2));
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

            let first = set.take().expect("first slot");
            let second = set.take().expect("second slot");
            assert_ne!(first.slot(), second.slot());
            set.put_batch([first, second]);
        });
    }

    /// Verifies that a take waits for its positive home before a later stripe.
    #[test]
    fn take_waits_for_home_before_later_stripe() {
        loom::model(|| {
            let set = Arc::new(prefilled(2));
            let phase = Arc::new(AtomicUsize::new(0));
            let guard = set.stripes[0].lock();
            let taker = {
                let set = Arc::clone(&set);
                let phase = Arc::clone(&phase);
                thread::spawn(move || {
                    assert_eq!(set.home_stripe(), 0);
                    phase.store(OPERATION_STARTED, Ordering::Release);
                    let buffer = set.take();
                    phase.store(OPERATION_FINISHED, Ordering::Release);
                    buffer
                })
            };

            assert_waiting(&phase);
            drop(guard);

            let buffer = taker
                .join()
                .expect("taker must not panic")
                .expect("home stripe must remain productive");
            assert_eq!(phase.load(Ordering::Acquire), OPERATION_FINISHED);
            assert_eq!(buffer.slot(), 0);
            set.put(buffer);
        });
    }

    /// Verifies that a return waits for its full home before a later stripe.
    #[test]
    fn put_waits_for_full_home_before_later_stripe() {
        loom::model(|| {
            let set = Arc::new(empty(2));
            let parked = set.try_create(false).expect("first creation permit");
            let returning = set.try_create(false).expect("second creation permit");
            park_in_stripe(&set, 0, parked);

            let phase = Arc::new(AtomicUsize::new(0));
            let guard = set.stripes[0].lock();
            let returner = {
                let set = Arc::clone(&set);
                let phase = Arc::clone(&phase);
                thread::spawn(move || {
                    assert_eq!(set.home_stripe(), 0);
                    phase.store(OPERATION_STARTED, Ordering::Release);
                    set.put(returning);
                    phase.store(OPERATION_FINISHED, Ordering::Release);
                })
            };

            assert_waiting(&phase);
            drop(guard);
            returner.join().expect("returner must not panic");
            assert_eq!(phase.load(Ordering::Acquire), OPERATION_FINISHED);
            assert_eq!(set.stripes[0].lock().len(), 1);
            assert_eq!(set.stripes[1].lock().len(), 1);
        });
    }

    /// Verifies that a batch return waits for its full home before spilling.
    #[test]
    fn put_batch_waits_for_full_home_before_later_stripes() {
        loom::model(|| {
            let set = Arc::new(empty(4));
            let first = set.try_create(false).expect("first creation permit");
            let second = set.try_create(false).expect("second creation permit");
            let third = set.try_create(false).expect("third creation permit");
            let fourth = set.try_create(false).expect("fourth creation permit");
            park_in_stripe(&set, 0, first);

            let phase = Arc::new(AtomicUsize::new(0));
            let guard = set.stripes[0].lock();
            let returner = {
                let set = Arc::clone(&set);
                let phase = Arc::clone(&phase);
                thread::spawn(move || {
                    assert_eq!(set.home_stripe(), 0);
                    phase.store(OPERATION_STARTED, Ordering::Release);
                    set.put_batch([second, third, fourth]);
                    phase.store(OPERATION_FINISHED, Ordering::Release);
                })
            };

            assert_waiting(&phase);
            drop(guard);
            returner.join().expect("returner must not panic");
            assert_eq!(phase.load(Ordering::Acquire), OPERATION_FINISHED);
            for stripe in &set.stripes {
                assert_eq!(stripe.lock().len(), 1);
            }
        });
    }

    /// Verifies that a batch take waits for its home before scanning onward.
    #[test]
    fn take_batch_waits_for_home_before_later_stripe() {
        loom::model(|| {
            let set = Arc::new(prefilled(2));
            let phase = Arc::new(AtomicUsize::new(0));
            let guard = set.stripes[0].lock();
            let taker = {
                let set = Arc::clone(&set);
                let phase = Arc::clone(&phase);
                thread::spawn(move || {
                    assert_eq!(set.home_stripe(), 0);
                    phase.store(OPERATION_STARTED, Ordering::Release);
                    let mut buffers = Vec::new();
                    let count = set.take_batch(2, |buffer| buffers.push(buffer));
                    phase.store(OPERATION_FINISHED, Ordering::Release);
                    (count, buffers)
                })
            };

            assert_waiting(&phase);
            drop(guard);
            let (count, mut buffers) = taker.join().expect("taker must not panic");
            assert_eq!(phase.load(Ordering::Acquire), OPERATION_FINISHED);
            assert_eq!(count, 2);
            buffers.sort_by_key(PooledBuffer::slot);
            assert_eq!(buffers[0].slot(), 0);
            assert_eq!(buffers[1].slot(), 1);
            set.put_batch(buffers);
        });
    }

    /// Verifies that concurrent take and drain partition all parked slots.
    #[test]
    fn take_and_drain_partition_slots() {
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

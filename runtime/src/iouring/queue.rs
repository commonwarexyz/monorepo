//! A bounded FIFO queue in a ring buffer, with one owner and shared thieves.
//!
//! Each pool worker's run queue is a [`Queue`] of its runnables. Only the
//! holder of its [`Owner`] pushes and pops. Other workers hold the shared
//! handle and steal half of an unclaimed backlog with [`Queue::steal_into`].
//!
//! # Overview
//!
//! Work usually stays in the run queue of the worker that queued it. An idle
//! worker steals the oldest half of another worker's backlog, and a push into a
//! full queue moves the newest half to the pool's global queue.
//!
//! The queue keeps its values in a ring of [`CAPACITY`] slots, and three
//! positions divide the ring. The owner pushes at `tail` and pops at `real`,
//! so the values from `real` up to `tail` are queued. A thief claims the oldest
//! half of them, rounded down, by moving `real` past that half. It then moves
//! the claimed values into its own queue while `steal` still marks where they
//! start, and `steal` catches up with `real` once it is done. Every other slot
//! is free, and the free slots wrap around the end of the ring. With eight
//! slots, while a thief moves `b` and `c`:
//!
//! ```text
//!                     steal            real            tail
//!                       v               v               v
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |       |       |   b   |   c   |   d   |   e   |       |       |
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |<--- free ---->|<-- claimed -->|<-- queued --->|<--- free ---->|
//! ```
//!
//! # Positions
//!
//! Positions keep counting past the end of the ring and wrap as `u32` values,
//! so a position selects its slot modulo [`CAPACITY`]. `steal` and `real` share
//! one atomic word, so a claim or a pop moves `real` in the same exchange that
//! checks whether a claim is held:
//!
//! ```text
//!          63                32 31                 0
//!         +--------------------+--------------------+
//!   head  |       steal        |        real        |   AtomicU64
//!         +--------------------+--------------------+
//!
//!          31                 0
//!         +--------------------+
//!   tail  |        tail        |                        AtomicU32
//!         +--------------------+
//! ```
//!
//! `steal` equals `real` unless a claim is held, and a second thief backs off
//! while one is. Releasing a claim lifts `steal` to the current `real`, which
//! owner pops may have moved past the claim. Only the owner writes `tail`.
//!
//! # Invariants
//!
//! The following invariants use wrapping distances, rather than numeric
//! comparisons of the indices:
//! - `steal <= real <= tail` and `tail - steal <= CAPACITY`.
//! - `[real, tail)` contains the queue's initialized values. An overflow
//!   iterator separately owns the removed newest half until it is exhausted.
//! - `steal != real` means one claim holds `[steal, claim_end)`, where
//!   `claim_end` is the `real` its exchange stored. The owner's pops can move
//!   `real` beyond `claim_end` while the claim is held.
//! - `[tail, steal + CAPACITY)` is free except for a live overflow's slots.
//!   Only the owner writes free slots, and a release store of `tail`
//!   publishes their values.
//! - Every value is read at most once, and its slot is written again only
//!   after that read.
//!
//! # Ordering
//!
//! A release store of `tail` publishes initialized slots to a thief's
//! acquiring tail load. Releasing a claim publishes its completed reads
//! through `head`, which the owner acquires before reusing those slots.
//! Shared head updates also release the tail publications they observed, so
//! acquiring the head before loading the tail keeps that tail from lagging
//! behind the head. An overflow can still advance the tail after the head
//! snapshot, so a claim refreshes an apparent backlog larger than capacity.
//! The owner reads its own tail with relaxed loads, since only it writes it.
//!
//! # Overflow
//!
//! A push into a full queue exchanges the head to `(tail, tail)`, taking every
//! value, then republishes the oldest half by storing `tail + CAPACITY / 2`:
//! in a full ring buffer, the `CAPACITY / 2` positions after the old tail map
//! onto the oldest half's slots. The newest half is owned by an iterator
//! borrowing the owner, which excludes writes to those slots until it is
//! consumed. A push decides from one snapshot of the head whether it
//! publishes, overflows, or leaves the queue to a held claim, and retries when
//! the exchange finds the head moved.
//!
//! An overflow in a queue of eight slots:
//!
//! ```text
//!   before: full, with steal = real = 0 and tail = 8, as the owner pushes i
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |   a   |   b   |   c   |   d   |   e   |   f   |   g   |   h   |
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |<-------- oldest half -------->|<-------- newest half -------->|
//!
//!   after: head (0, 0) -> (8, 8), then tail 8 -> 12
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |   a   |   b   |   c   |   d   |   e   |   f   |   g   |   h   |
//!   +-------+-------+-------+-------+-------+-------+-------+-------+
//!   |<- queued, positions 8 to 11 ->|<--- read by the Overflow ---->|
//!
//!   the caller then sends e f g h, and after them i, to the global queue
//! ```
//!
//! # Stealing
//!
//! A steal takes half the unclaimed backlog, rounded down, so a lone value
//! stays with its owner. It claims the values with one exchange on the head,
//! moves them into the thief's own queue, releases the claim, then publishes
//! them with one tail store. It goes only into a queue with at least half its
//! slots free, so the batch always fits. [`Queue::is_stealable`] is a hint
//! about the source's backlog. The claim checks the source again, and the
//! steal also checks the destination's room.
//!
//! A steal from a queue of eight slots into an empty one:
//!
//! ```text
//!   before: steal = real = 0, tail = 7
//!               0       1       2       3       4       5       6       7
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   source  |   a   |   b   |   c   |   d   |   e   |   f   |   g   |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!           |<---------------------- queued ----------------------->|
//!
//!   1. the thief claims 3 of 7 (real 0 -> 3), then the owner pops d and e (real 3 -> 5)
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   source  |   a   |   b   |   c   |       |       |   f   |   g   |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!           |<------ claimed ------>|<-- popped --->|<-- queued --->|
//!
//!   2. the thief copies a b c, releases (steal 0 -> 5), then publishes (its tail 0 -> 3)
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   source  |       |       |       |       |       |   f   |   g   |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!                                                   |<-- queued --->|
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   thief   |   a   |   b   |   c   |       |       |       |       |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!           |<------ queued ------->|
//! ```
//!
//! A steal assumes that a thief does not stall between its head load and its
//! claim exchange while the indices advance through a full `2^32` positions,
//! after which the head could read as it did and the exchange succeed with a
//! stale count. Once the exchange succeeds the claim pins `steal`, so
//! `tail - steal <= CAPACITY` bounds further progress to `CAPACITY` positions.
//! At one position per nanosecond, the exposed window would need to exceed four
//! seconds. An overflow advances `real` by `CAPACITY` and `tail` by half as
//! much, so the assumption counts positions rather than operations. A bound on
//! the claim size alone would not make a stale claim safe. The owner's own
//! exchanges need no such assumption: while it stalls it pushes nothing, so
//! thieves can move `real` no further than `tail`, and the head cannot return
//! to the value the owner loaded.
//!
//! # Pops without an exchange
//!
//! A queue built exclusive has no reader but its owner, so the owner pops with
//! plain loads and a store rather than an exchange. [`Queue::steal_into`]
//! asserts that its source is shared. A pool of one worker has no other worker
//! to steal from its run queue, so that queue is exclusive.
//!
//! The owner of a shared queue also pops a lone value with a store when no
//! claim is held. A claim takes half the backlog, rounded down, so none takes a
//! lone value, and only the owner can push more, which its pop excludes. A
//! thief still expecting the pre-pop head needs a later tail publication to see
//! two values. That publication follows the head store, so acquiring the tail
//! orders the store before the thief's stale exchange, which fails unless the
//! thief stalled through a full `2^32` positions (see Stealing).
//!
//! # Dropping handles
//!
//! The owner must remove its unclaimed values before dropping. A thief may
//! still own claimed values after that. An overflow must be exhausted before
//! dropping. A nonempty owner or an unexhausted overflow panics on drop unless
//! the thread is already unwinding. These drops do not destroy unread values,
//! which may leak.

use super::task::UnsafeCell;
use crossbeam_utils::CachePadded;
use std::{cell::Cell, marker::PhantomData, mem::MaybeUninit, thread};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{Arc, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}};
    } else {
        use std::sync::{Arc, atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering}};
    }
}

/// Number of slots in a queue, small under loom so models reach a full queue.
pub const CAPACITY: usize = if cfg!(feature = "loom") { 4 } else { 256 };

/// Half the capacity: what an overflow keeps, as a position count.
const HALF: u32 = CAPACITY as u32 / 2;

/// Fewest values an unclaimed queue holds for a steal to take any, since a
/// steal takes half rounded down.
pub const STEALABLE: usize = 2;

/// Mask that selects a position's slot.
const MASK: usize = CAPACITY - 1;

/// Positions select slots by masking, and a full queue's distance must fit in
/// a wrapping `u32` comparison.
const _: () = assert!(CAPACITY.is_power_of_two() && CAPACITY < 1 << 31);

/// The slots of a queue's ring and the positions that divide them, shared by
/// its [`Queue`] and [`Owner`] handles. See the module docs for the invariants
/// every access keeps.
struct Inner<T> {
    /// `steal << 32 | real`: the oldest unreleased position and the next
    /// position the owner pops.
    head: AtomicU64,
    /// One past the newest published value, written only by the owner.
    tail: AtomicU32,
    /// Whether the unique owner has been taken.
    owned: AtomicBool,
    /// Whether no reader but the owner ever touches the queue, fixed at
    /// construction.
    exclusive: bool,
    /// Storage for unclaimed, claimed, and overflow values. A pop owns its
    /// slot from the head update until its read completes.
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

// SAFETY: the module's invariants give each slot one writer and one reader,
// and the head and tail orderings transfer values between threads without
// overlap.
unsafe impl<T: Send> Sync for Inner<T> {}
// SAFETY: the queue owns its values and each value can move between threads.
unsafe impl<T: Send> Send for Inner<T> {}

/// Shared handle of a queue, through which thieves steal and from which its
/// owner is taken.
pub struct Queue<T>(
    /// Shared indices and storage, kept alive by every queue and owner handle.
    Arc<CachePadded<Inner<T>>>,
);

/// Unique owner of a queue, movable between threads but never shared.
pub struct Owner<T>(
    /// The same indices and storage reached by the shared queue handle.
    Arc<CachePadded<Inner<T>>>,
    /// Prevent sharing the owner while permitting it to move between threads.
    PhantomData<Cell<()>>,
);

/// Result of publishing a value into a queue.
pub enum Push<'a, T> {
    /// The value was published, with the length computed from the push's head
    /// snapshot. A concurrent claim can make this an overestimate.
    Pushed(
        /// Available length computed from the push's head snapshot.
        usize,
    ),
    /// The queue was full: the newest half and the new value must be published
    /// elsewhere, in that order.
    Overflow(
        /// Removed newest half, which must be exhausted.
        Overflow<'a, T>,
        /// New value that was not inserted.
        T,
    ),
    /// No slot was free while a thief held a claim, so only the new value must
    /// move elsewhere.
    Claimed(
        /// New value that was not inserted.
        T,
    ),
}

/// Newest half of a full queue, yielded oldest first.
///
/// The iterator must be exhausted before it is dropped. Its mutable borrow
/// excludes owner writes until every removed slot has been read.
pub struct Overflow<'a, T> {
    /// The queue's owner, borrowed until the batch is consumed.
    owner: &'a mut Owner<T>,
    /// Next position to read.
    next: u32,
    /// One past the last position to read.
    end: u32,
}

/// Split a head into `(steal, real)`.
const fn unpack(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

/// Pack `steal` and `real` into a head.
const fn pack(steal: u32, real: u32) -> u64 {
    (steal as u64) << 32 | real as u64
}

impl<T> Queue<T> {
    /// An empty queue that thieves may steal from.
    pub fn shared() -> Self {
        Self::at(0, false)
    }

    /// An empty queue that no thief may steal from.
    pub fn exclusive() -> Self {
        Self::at(0, true)
    }

    /// An empty queue starting at a chosen wrapping position.
    fn at(position: u32, exclusive: bool) -> Self {
        Self(Arc::new(CachePadded::new(Inner {
            head: AtomicU64::new(pack(position, position)),
            tail: AtomicU32::new(position),
            owned: AtomicBool::new(false),
            exclusive,
            slots: (0..CAPACITY)
                .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
                .collect(),
        })))
    }

    /// Take the owner, panicking if it was already taken, even if it has since
    /// been dropped.
    pub fn owner(&self) -> Owner<T> {
        assert!(
            !self.0.owned.swap(true, Ordering::AcqRel),
            "queue already owned"
        );
        Owner(self.0.clone(), PhantomData)
    }

    /// Whether a snapshot shows no claim and at least [`STEALABLE`] values.
    /// Concurrent changes can make this hint stale before a steal claims them.
    pub fn is_stealable(&self) -> bool {
        // Shared head updates release the tail they observed. Acquire the
        // head first so the tail cannot lag behind it and turn the wrapping
        // distance into a false backlog.
        let (steal, real) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Acquire);
        steal == real && tail.wrapping_sub(real) >= STEALABLE as u32
    }

    /// Move half the unclaimed backlog, rounded down, into `into`, returning
    /// how many values moved.
    ///
    /// Moves none when the backlog holds fewer than [`STEALABLE`] values, while
    /// another thief holds a claim, or when `into` has fewer than half its
    /// slots free. The claim is released before the values are published in
    /// `into` with one tail store. Panics if `into` belongs to this queue or
    /// this queue is exclusive.
    #[must_use]
    pub fn steal_into(&self, into: &mut Owner<T>) -> usize {
        assert!(!self.0.exclusive, "cannot steal from an exclusive queue");
        assert!(
            !Arc::ptr_eq(&into.0, &self.0),
            "cannot steal into the source queue"
        );

        // Only this owner writes the destination tail. Acquiring its head
        // observes completed claim reads before their slots are reused.
        let tail = into.0.tail.load(Ordering::Relaxed);
        let (steal, _) = unpack(into.0.head.load(Ordering::Acquire));
        if tail.wrapping_sub(steal) > HALF {
            return 0;
        }

        let Some((first, count)) = self.claim() else {
            return 0;
        };
        for offset in 0..count {
            // SAFETY: the source claim owns this initialized slot.
            let value = unsafe { self.0.read(first.wrapping_add(offset)) };

            // SAFETY: the destination had half its slots free before the
            // claim, the owner is borrowed, and thieves only add room.
            unsafe { into.0.write(tail.wrapping_add(offset), value) };
        }

        self.release_claim(first, count);
        into.0
            .tail
            .store(tail.wrapping_add(count), Ordering::Release);
        count as usize
    }

    /// Claim half the published backlog, rounded down, returning the first
    /// claimed position and the count, or `None` while another claim is held
    /// or fewer than [`STEALABLE`] values are published. Every bound is
    /// checked before the exchange, so the caller can move and release the
    /// claimed values without further bound checks.
    fn claim(&self) -> Option<(u32, u32)> {
        let mut head = self.0.head.load(Ordering::Acquire);
        loop {
            let (steal, real) = unpack(head);
            if steal != real {
                return None;
            }

            // Acquire the owner's release publication before reading any
            // slot that a successful claim grants us.
            let tail = self.0.tail.load(Ordering::Acquire);
            let available = tail.wrapping_sub(real);

            // An overflow can pair an old head with the republished tail. That
            // head cannot be claimed, so refresh it before checking bounds.
            if available > CAPACITY as u32 {
                head = self.0.head.load(Ordering::Acquire);
                continue;
            }

            let count = available / 2;
            if count == 0 {
                return None;
            }
            assert!(count <= HALF, "claim exceeds half the queue");
            let claimed = pack(steal, real.wrapping_add(count));

            // Release carries the observed tail to later acquiring head
            // readers, preserving their head-before-tail snapshot order.
            match self
                .0
                .head
                .compare_exchange(head, claimed, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some((real, count)),
                Err(actual) => head = actual,
            }
        }
    }

    /// Release a claim once its slots have been read, lifting `steal` to the
    /// current `real`, which owner pops may have moved past the claim. The
    /// caller must hold exactly this claim and have read every claimed slot.
    fn release_claim(&self, first: u32, count: u32) {
        let mut head = pack(first, first.wrapping_add(count));
        loop {
            let (_, real) = unpack(head);

            // Release lets an owner that acquires this head reuse the read
            // slots.
            match self.0.head.compare_exchange(
                head,
                pack(real, real),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => head = actual,
            }
        }
    }
}

impl<T> Owner<T> {
    /// Values available to the owner, excluding a pending claim.
    pub fn len(&self) -> usize {
        let (_, real) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Relaxed);
        tail.wrapping_sub(real) as usize
    }

    /// Slots free for publication. A pending claim holds its slots, and those
    /// the owner popped past it, until it is released.
    pub fn room(&self) -> usize {
        let (steal, _) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Relaxed);
        CAPACITY - tail.wrapping_sub(steal) as usize
    }

    /// Whether the owner has no available values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Publish a value, or hand back what a full queue cannot hold, as
    /// [`Push`] describes.
    ///
    /// Every attempt decides from one head snapshot. A failed overflow
    /// exchange retries publication, since a released claim can make room.
    pub fn push(&mut self, value: T) -> Push<'_, T> {
        self.push_with(value, || {})
    }

    /// Publish as [`Self::push`] does, running `after_snapshot` after each
    /// attempt's head snapshot, where a test pauses the owner.
    fn push_with(&mut self, value: T, mut after_snapshot: impl FnMut()) -> Push<'_, T> {
        loop {
            // Acquire completed claim reads before writing a freed slot.
            let head = self.0.head.load(Ordering::Acquire);
            let (steal, real) = unpack(head);
            let tail = self.0.tail.load(Ordering::Relaxed);
            after_snapshot();

            if tail.wrapping_sub(steal) < CAPACITY as u32 {
                // SAFETY: the acquired steal index excludes pending readers,
                // and the unpublished tail slot is free.
                unsafe { self.0.write(tail, value) };

                let tail = tail.wrapping_add(1);
                self.0.tail.store(tail, Ordering::Release);
                return Push::Pushed(tail.wrapping_sub(real) as usize);
            }

            if steal != real {
                return Push::Claimed(value);
            }

            assert_eq!(
                tail.wrapping_sub(real),
                CAPACITY as u32,
                "overflow requires a full queue"
            );

            // The exchange arbitrates against a claim and releases the
            // owner's preceding tail publications to later head readers.
            if self
                .0
                .head
                .compare_exchange(head, pack(tail, tail), Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            self.0
                .tail
                .store(tail.wrapping_add(HALF), Ordering::Release);

            return Push::Overflow(
                Overflow {
                    owner: self,
                    next: real.wrapping_add(HALF),
                    end: tail,
                },
                value,
            );
        }
    }

    /// Take the oldest value available to the owner.
    #[must_use]
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.0.exclusive {
            // No other reader moves the head, so plain accesses suffice.
            let (_, real) = unpack(self.0.head.load(Ordering::Relaxed));
            let tail = self.0.tail.load(Ordering::Relaxed);
            if real == tail {
                return None;
            }

            let next = real.wrapping_add(1);
            self.0.head.store(pack(next, next), Ordering::Relaxed);

            // SAFETY: an exclusive queue has no reader but its owner, so this
            // initialized slot is the owner's alone, and the mutable borrow
            // excludes writes.
            return Some(unsafe { self.0.read(real) });
        }

        let mut head = self.0.head.load(Ordering::Acquire);
        loop {
            let (steal, real) = unpack(head);
            let tail = self.0.tail.load(Ordering::Relaxed);
            if real == tail {
                return None;
            }

            let next_real = real.wrapping_add(1);

            // No claim is held, and none can take a lone value, so a store
            // pops it. Release orders this head after the tail stores before
            // it, as the exchange does, so a thief that acquires it loads a
            // tail at or past `next_real`.
            if steal == real && tail.wrapping_sub(real) == 1 {
                self.0
                    .head
                    .store(pack(next_real, next_real), Ordering::Release);

                // SAFETY: no claim holds or can take this initialized slot,
                // and the mutable borrow excludes writes.
                return Some(unsafe { self.0.read(real) });
            }

            let next = if steal == real {
                pack(next_real, next_real)
            } else {
                pack(steal, next_real)
            };

            // Release carries the owner's tail stores to thieves that acquire
            // this head before loading the tail.
            match self
                .0
                .head
                .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    // SAFETY: the exchange gave the owner this initialized
                    // slot, and the mutable borrow excludes writes.
                    return Some(unsafe { self.0.read(real) });
                }
                Err(actual) => head = actual,
            }
        }
    }

    /// Publish a batch with one tail store. Panics if it exceeds
    /// [`Self::room`] or the iterator misreports its length.
    pub fn push_batch(&mut self, mut values: impl ExactSizeIterator<Item = T>) {
        let count = values.len();
        assert!(count <= self.room(), "batch exceeds queue room");

        let tail = self.0.tail.load(Ordering::Relaxed);
        for offset in 0..count {
            let value = values.next().expect("batch shorter than its exact length");

            // SAFETY: room bounds this unpublished span, the owner is
            // borrowed, and pending claims cannot overlap it.
            unsafe { self.0.write(tail.wrapping_add(offset as u32), value) };
        }

        assert!(
            values.next().is_none(),
            "batch longer than its exact length"
        );

        self.0
            .tail
            .store(tail.wrapping_add(count as u32), Ordering::Release);
    }
}

impl<T> Inner<T> {
    /// Read a value from an exclusively owned initialized slot.
    ///
    /// # Safety
    ///
    /// The caller must own `position` through a successful pop, a claim, or an
    /// overflow exchange, and exclude writes until the read completes.
    unsafe fn read(&self, position: u32) -> T {
        self.slots[position as usize & MASK].with_mut(|ptr| {
            // SAFETY: the caller owns this initialized slot by contract.
            unsafe { (*ptr).assume_init_read() }
        })
    }

    /// Initialize a free slot before it is published.
    ///
    /// # Safety
    ///
    /// The caller must be the owner and must have established room at
    /// `position`, excluding pending readers until the write completes.
    unsafe fn write(&self, position: u32, value: T) {
        self.slots[position as usize & MASK].with_mut(|ptr| {
            // SAFETY: the caller owns this free slot by contract.
            unsafe { ptr.write(MaybeUninit::new(value)) };
        });
    }
}

impl<T> Iterator for Overflow<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next == self.end {
            return None;
        }

        let position = self.next;
        self.next = self.next.wrapping_add(1);

        // SAFETY: the overflow exchange gave this iterator the newest half.
        // Its owner borrow excludes writes, and the republished oldest half
        // occupies disjoint slots.
        Some(unsafe { self.owner.0.read(position) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.end.wrapping_sub(self.next) as usize;
        (count, Some(count))
    }
}

impl<T> ExactSizeIterator for Overflow<'_, T> {}

impl<T> Drop for Overflow<'_, T> {
    fn drop(&mut self) {
        // An unread value would be lost. While panicking, it leaks instead.
        if !thread::panicking() {
            assert_eq!(self.next, self.end, "overflow was not exhausted");
        }
    }
}

impl<T> Drop for Owner<T> {
    fn drop(&mut self) {
        // Unclaimed values must be removed before the owner drops. Catch an
        // undrained queue on its owner's thread rather than wherever the last
        // shared handle drops. Pending claims belong to their thieves.
        if !thread::panicking() {
            assert!(self.is_empty(), "owner dropped a nonempty queue");
        }
    }
}

impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        // A claim or value still here when the last handle drops was leaked.
        if !thread::panicking() {
            let (steal, real) = unpack(self.head.load(Ordering::Relaxed));
            assert_eq!(steal, real, "queue dropped with a pending claim");
            assert_eq!(
                real,
                self.tail.load(Ordering::Relaxed),
                "queue dropped nonempty"
            );
        }
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
pub mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Barrier, atomic::AtomicUsize, mpsc},
    };

    /// Claims held by a test in place of a paused thief.
    impl<T> Queue<T> {
        /// Claim the oldest `count` values as a thief paused after its claim
        /// exchange would hold them. Panics unless no claim is held and `count`
        /// is positive, at most [`HALF`], and within the available values, or if
        /// another head update wins the exchange. The caller must read and release
        /// the returned claim exactly once through [`Self::finish_claim`].
        pub(crate) fn hold_claim(&self, count: u32) -> (u32, u32) {
            let head = self.0.head.load(Ordering::Acquire);
            let (steal, real) = unpack(head);
            let tail = self.0.tail.load(Ordering::Acquire);
            assert_eq!(steal, real);
            assert!(count > 0 && count <= HALF && count <= tail.wrapping_sub(real));

            assert!(
                self.0
                    .head
                    .compare_exchange(
                        head,
                        pack(real, real.wrapping_add(count)),
                        Ordering::AcqRel,
                        Ordering::Acquire
                    )
                    .is_ok()
            );
            (real, count)
        }

        /// Read a held claim's values and release it, as the paused thief would.
        /// The caller must own the unread claim returned by [`Self::hold_claim`].
        pub(crate) fn finish_claim(&self, claim: (u32, u32)) -> Vec<T> {
            let (first, count) = claim;
            let values = (0..count)
                .map(|offset| {
                    // SAFETY: hold_claim gave the caller exclusive ownership of this
                    // initialized slot, and the release follows every read.
                    unsafe { self.0.read(first.wrapping_add(offset)) }
                })
                .collect();

            self.release_claim(first, count);
            values
        }
    }

    /// Push a value that must fit.
    fn push<T>(owner: &mut Owner<T>, value: T) {
        assert!(matches!(owner.push(value), Push::Pushed(_)));
    }

    /// Pop every value the owner holds.
    fn drain<T>(owner: &mut Owner<T>) -> Vec<T> {
        std::iter::from_fn(|| owner.pop()).collect()
    }

    /// Take every value from a queue whose owner is gone.
    fn take_unowned<T>(queue: &Queue<T>) -> Vec<T> {
        // A held claim would belong to its thief, so none may be pending.
        let (steal, real) = unpack(queue.0.head.load(Ordering::Acquire));
        assert_eq!(steal, real);
        let tail = queue.0.tail.load(Ordering::Acquire);

        let values = (0..tail.wrapping_sub(real))
            .map(|offset| {
                // SAFETY: the owner is gone and no claim is held, so this test
                // is the only reader of the queue's initialized values.
                unsafe { queue.0.read(real.wrapping_add(offset)) }
            })
            .collect();

        // Moving the head to the tail marks the values taken, so the queue drops empty.
        queue.0.head.store(pack(tail, tail), Ordering::Release);
        values
    }

    /// Counts its drops, so a value read twice or never shows.
    struct Counted(
        /// Identity used to check that every published value is returned.
        usize,
        /// Shared count of destroyed values.
        Arc<AtomicUsize>,
    );

    impl Drop for Counted {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Both queue kinds hold `CAPACITY` values in FIFO order, pushed one at a
    /// time or as a batch, and interleaved pops and pushes keep the order.
    #[test]
    fn test_fifo_up_to_capacity() {
        for queue in [Queue::shared(), Queue::exclusive()] {
            // A new queue is empty with every slot free.
            let mut owner = queue.owner();
            assert!(owner.is_empty());
            assert_eq!(owner.room(), CAPACITY);

            // Each push reports the length including the new value, up to capacity.
            for value in 0..CAPACITY {
                match owner.push(value) {
                    Push::Pushed(len) => assert_eq!(len, value + 1),
                    _ => panic!("push before capacity overflowed"),
                }
            }

            // The full queue has no room, and pops return the values in push order.
            assert_eq!(owner.len(), CAPACITY);
            assert_eq!(owner.room(), 0);
            assert_eq!(drain(&mut owner), (0..CAPACITY).collect::<Vec<_>>());

            // A batch fills the same capacity and drains in the same order.
            owner.push_batch(0..CAPACITY);
            assert_eq!(drain(&mut owner), (0..CAPACITY).collect::<Vec<_>>());

            // Pops and pushes interleave in order.
            push(&mut owner, 0);
            push(&mut owner, 1);
            assert_eq!(owner.pop(), Some(0));
            push(&mut owner, 2);
            assert_eq!(drain(&mut owner), [1, 2]);
        }
    }

    /// Pushes, pops and an overflow keep their order while positions wrap
    /// past `u32::MAX`.
    #[test]
    fn test_positions_wrap_across_the_maximum() {
        for exclusive in [false, true] {
            // Start eight positions before the maximum, so a full ring wraps past it.
            let queue = Queue::at(u32::MAX - 7, exclusive);
            let mut owner = queue.owner();

            // A full batch wraps past the maximum and drains in order.
            owner.push_batch(0..CAPACITY);
            assert_eq!(drain(&mut owner), (0..CAPACITY).collect::<Vec<_>>());

            // Refill so the next push overflows with positions already wrapped.
            owner.push_batch(0..CAPACITY);
            match owner.push(CAPACITY) {
                Push::Overflow(batch, value) => {
                    assert_eq!(
                        batch.collect::<Vec<_>>(),
                        (CAPACITY / 2..CAPACITY).collect::<Vec<_>>()
                    );
                    assert_eq!(value, CAPACITY);
                }
                _ => panic!("full wrapping queue did not overflow"),
            }

            // The oldest half stays queued in order.
            assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
        }
    }

    /// A shared owner pops a lone value with a store, here at zero and across
    /// the maximum, leaving the queue empty and unclaimed.
    #[test]
    fn test_lone_value_pops_across_the_maximum() {
        for position in [0, u32::MAX] {
            let queue = Queue::at(position, false);
            let mut owner = queue.owner();

            // A lone value is not stealable, since a steal takes half rounded down.
            push(&mut owner, 7);
            assert!(!queue.is_stealable());

            // The pop moves steal and real together, so no claim appears held.
            assert_eq!(owner.pop(), Some(7));
            let next = position.wrapping_add(1);
            assert_eq!(unpack(queue.0.head.load(Ordering::Acquire)), (next, next));
            assert!(!queue.is_stealable());
            assert!(owner.pop().is_none());
        }
    }

    /// An overflow hands out the newest half, then the new value, and keeps
    /// the oldest half with room for as many more.
    #[test]
    fn test_overflow_keeps_the_oldest_half() {
        for queue in [Queue::shared(), Queue::exclusive()] {
            let mut owner = queue.owner();
            owner.push_batch(0..CAPACITY);

            // A push into the full queue overflows.
            match owner.push(CAPACITY) {
                Push::Overflow(mut batch, value) => {
                    // The batch reports its exact length as it is consumed.
                    assert_eq!(batch.len(), CAPACITY / 2);
                    assert_eq!(batch.next(), Some(CAPACITY / 2));
                    assert_eq!(batch.len(), CAPACITY / 2 - 1);

                    // The newest half comes out oldest first, followed by the new value.
                    let mut exported = vec![CAPACITY / 2];
                    exported.extend(batch);
                    exported.push(value);
                    assert_eq!(exported, (CAPACITY / 2..=CAPACITY).collect::<Vec<_>>());
                }
                _ => panic!("full queue did not overflow"),
            }

            // The oldest half stays queued, with room for as many more.
            assert_eq!(owner.len(), CAPACITY / 2);
            assert_eq!(owner.room(), CAPACITY / 2);

            // New values fill the freed half and queue behind the oldest half.
            owner.push_batch(CAPACITY + 1..CAPACITY + 1 + CAPACITY / 2);
            let mut expected = (0..CAPACITY / 2).collect::<Vec<_>>();
            expected.extend(CAPACITY + 1..CAPACITY + 1 + CAPACITY / 2);
            assert_eq!(drain(&mut owner), expected);
        }
    }

    /// A steal moves half a backlog between queues whose positions wrap past
    /// `u32::MAX`.
    #[test]
    fn test_steal_wraps_across_the_maximum() {
        // Both queues start near the maximum, so the source's backlog and the
        // destination's slots wrap past it.
        let source = Queue::at(u32::MAX - 7, false);
        let destination = Queue::at(u32::MAX - 3, false);
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..CAPACITY);

        // The steal takes the oldest half across the wrap.
        assert_eq!(source.steal_into(&mut into), CAPACITY / 2);

        // The stolen half, then the owner's remaining half, restore the push order.
        let mut values = drain(&mut into);
        values.extend(drain(&mut owner));
        assert_eq!(values, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal takes half the backlog rounded down, so a lone value is never
    /// stolen, and `is_stealable` agrees.
    #[test]
    fn test_steal_takes_half_rounded_down() {
        for available in [1usize, 2, 3, 7, 8, 255, 256] {
            let source = Queue::shared();
            let destination = Queue::shared();
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..available);

            // The hint agrees with the steal, which takes half the backlog rounded down.
            let count = available / 2;
            assert_eq!(source.is_stealable(), count != 0);
            assert_eq!(source.steal_into(&mut into), count);

            // The thief holds the oldest values, and the owner keeps the rest in order.
            assert_eq!(drain(&mut into), (0..count).collect::<Vec<_>>());
            assert_eq!(drain(&mut owner), (count..available).collect::<Vec<_>>());
        }
    }

    /// A steal refuses a destination whose room a held claim pins at zero,
    /// even once its owner is empty, and proceeds after the release.
    #[test]
    fn test_steal_room_counts_a_pending_claim() {
        let source = Queue::shared();
        let destination = Queue::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(CAPACITY..2 * CAPACITY);
        into.push_batch(0..CAPACITY);

        // A thief claims half the full destination, and its owner pops the rest.
        let claim = destination.hold_claim(HALF);
        let mut seen = drain(&mut into);

        // The held claim still pins every slot, so the empty destination has no
        // room and a steal into it moves nothing.
        assert!(into.is_empty());
        assert_eq!(into.room(), 0);
        assert!(!destination.is_stealable());
        assert_eq!(source.steal_into(&mut into), 0);
        assert_eq!(owner.len(), CAPACITY);

        // Releasing the claim frees every slot, so the steal proceeds.
        seen.extend(destination.finish_claim(claim));
        assert_eq!(into.room(), CAPACITY);
        assert_eq!(source.steal_into(&mut into), CAPACITY / 2);

        // Every value from both queues is handed out exactly once.
        seen.extend(drain(&mut into));
        seen.extend(drain(&mut owner));
        seen.sort_unstable();
        assert_eq!(seen, (0..2 * CAPACITY).collect::<Vec<_>>());
    }

    /// A steal fills a destination holding exactly half its capacity and
    /// refuses one holding one value more.
    #[test]
    fn test_steal_needs_half_the_destination_free() {
        for (held, moved) in [(HALF as usize, CAPACITY / 2), (HALF as usize + 1, 0)] {
            // Fill the source, and give the destination `held` values.
            let source = Queue::shared();
            let destination = Queue::shared();
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..CAPACITY);
            into.push_batch(CAPACITY..CAPACITY + held);

            // The steal moves half the source only if half the destination is free.
            assert_eq!(source.steal_into(&mut into), moved);

            // Every value from both queues is handed out exactly once.
            let mut seen = drain(&mut into);
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, (0..CAPACITY + held).collect::<Vec<_>>());
        }
    }

    /// A push into a full queue under a claim hands back only the new value.
    #[test]
    fn test_full_queue_with_a_claim_moves_only_the_new_value() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY);

        // A claim held in the full queue rules out an overflow, so the push
        // returns only the new value, and a second thief sees the claim.
        let claim = queue.hold_claim(HALF);
        assert!(matches!(owner.push(CAPACITY), Push::Claimed(value) if value == CAPACITY));
        assert!(!queue.is_stealable());

        // The claim and the owner together hold every queued value, in push order.
        let mut seen = queue.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal takes nothing while another thief holds a claim.
    #[test]
    fn test_second_thief_backs_off_a_pending_claim() {
        let source = Queue::shared();
        let destination = Queue::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..CAPACITY);

        // While one thief holds a claim, a second steal moves nothing.
        let claim = source.hold_claim(HALF);
        assert_eq!(source.steal_into(&mut into), 0);

        // The claim and the owner together hold every value, in push order.
        let mut seen = source.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A held claim does not block a push while the queue has a free slot.
    #[test]
    fn test_pending_claim_with_room_allows_a_push() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY - 1);

        // A claim on half the backlog leaves the last slot free, so the push
        // publishes and reports only the unclaimed length.
        let claim = queue.hold_claim(HALF);
        assert!(matches!(owner.push(CAPACITY - 1), Push::Pushed(len) if len == CAPACITY / 2));

        // The claim and the owner together hold every value, in push order.
        let mut seen = queue.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A claim taken after a full push's snapshot fails the overflow exchange,
    /// and the retry hands back only the new value.
    #[test]
    fn test_claim_between_push_snapshot_and_exchange_retries() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY);

        // Take a claim after the first attempt's snapshot, so its overflow
        // exchange fails and the retry sees the claim.
        let mut claim = None;
        let mut attempts = 0;
        match owner.push_with(CAPACITY, || {
            attempts += 1;
            if claim.is_none() {
                claim = Some(queue.hold_claim(HALF));
            }
        }) {
            Push::Claimed(value) => assert_eq!(value, CAPACITY),
            _ => panic!("push did not retry after the new claim"),
        }

        // Exactly one retry follows the failed exchange.
        assert_eq!(attempts, 2);

        // The claim and the owner together hold every value, in push order.
        let mut seen = queue.finish_claim(claim.unwrap());
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal that completes between a push's snapshot of a full queue and its
    /// decision makes room, so the push retries and publishes rather than
    /// overflowing from a stale snapshot.
    #[test]
    fn test_completed_steal_between_push_snapshot_and_exchange() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY);

        // The thief steals only once signaled, then reports that its steal is done.
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let thief = thread::spawn(move || {
            let destination = Queue::shared();
            let mut into = destination.owner();

            // Wait for the push's snapshot, then take half the full queue.
            start_rx.recv().unwrap();
            assert_eq!(queue.steal_into(&mut into), CAPACITY / 2);
            let values = drain(&mut into);
            done_tx.send(()).unwrap();
            values
        });

        // Pause the first attempt after its snapshot until the steal completes.
        let mut first = true;
        let result = owner.push_with(CAPACITY, || {
            if first {
                first = false;
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            }
        });

        // The stale overflow exchange fails, and the retry finds the freed half
        // and publishes.
        assert!(matches!(result, Push::Pushed(len) if len == CAPACITY / 2 + 1));
        drop(result);

        // The thief and the owner together hold every value once.
        let mut seen = thief.join().unwrap();
        seen.extend(drain(&mut owner));
        seen.sort_unstable();
        assert_eq!(seen, (0..=CAPACITY).collect::<Vec<_>>());
    }

    /// A batch beyond the room panics and publishes nothing, whether queued
    /// values or a pending claim take the room.
    #[test]
    fn test_batch_asserts_room() {
        let queue = Queue::<usize>::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY - 1);

        // Two values exceed the one free slot, so the batch panics and the
        // queue keeps only its earlier values.
        assert!(catch_unwind(AssertUnwindSafe(|| owner.push_batch(0..2))).is_err());
        assert_eq!(drain(&mut owner), (0..CAPACITY - 1).collect::<Vec<_>>());

        // Popping past a held claim leaves the owner empty with no room.
        owner.push_batch(0..CAPACITY);
        let claim = queue.hold_claim(HALF);
        let mut seen = drain(&mut owner);
        assert!(owner.is_empty());

        // Even one value exceeds the room, which the claim pins at zero.
        assert!(
            catch_unwind(AssertUnwindSafe(
                || owner.push_batch(std::iter::once(CAPACITY))
            ))
            .is_err()
        );

        // Only the claimed and popped values come out, so the batch published nothing.
        seen.extend(queue.finish_claim(claim));
        seen.sort_unstable();
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// Dropping an owner with a queued value panics on the owner's thread.
    #[test]
    fn test_nonempty_owner_drop_panics() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        push(&mut owner, 1);

        // The drop panics while a value is still queued.
        let result = catch_unwind(AssertUnwindSafe(|| drop(owner)));
        assert!(result.is_err());

        // The drop did not destroy the value, so take it back before the queue drops.
        assert_eq!(take_unowned(&queue), [1]);
    }

    /// Dropping an overflow before it is exhausted panics.
    #[test]
    fn test_unexhausted_overflow_drop_panics() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY);

        // Dropping the overflow without reading its newest half panics.
        let result = catch_unwind(AssertUnwindSafe(|| match owner.push(CAPACITY) {
            Push::Overflow(batch, _) => drop(batch),
            _ => panic!("expected overflow"),
        }));
        assert!(result.is_err());

        // The oldest half stays queued for the owner.
        assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
    }

    /// An unwind through an unexhausted overflow and a nonempty owner does
    /// not panic again.
    #[test]
    fn test_unwinding_skips_drop_assertions() {
        assert!(
            catch_unwind(|| {
                let queue = Queue::shared();
                let mut owner = queue.owner();
                owner.push_batch(0..CAPACITY);

                // Hold an unexhausted overflow while the owner keeps the oldest half.
                let _batch = match owner.push(CAPACITY) {
                    Push::Overflow(batch, _) => batch,
                    _ => panic!("expected overflow"),
                };

                // Unwinding drops both without a second panic, which would abort.
                panic!("unwind with an unexhausted overflow");
            })
            .is_err()
        );
    }

    /// A queue hands out its owner once.
    #[test]
    fn test_second_owner_panics() {
        let queue = Queue::<usize>::shared();
        let _owner = queue.owner();

        assert!(catch_unwind(AssertUnwindSafe(|| queue.owner())).is_err());
    }

    /// A steal into the source queue panics.
    #[test]
    fn test_self_steal_panics() {
        let queue = Queue::<usize>::shared();
        let mut owner = queue.owner();

        assert!(catch_unwind(AssertUnwindSafe(|| queue.steal_into(&mut owner))).is_err());
    }

    /// A steal from an exclusive queue panics and leaves its values in place.
    #[test]
    fn test_steal_from_an_exclusive_queue_panics() {
        let source = Queue::exclusive();
        let destination = Queue::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..4);

        // The steal panics before claiming, so the owner still pops every value.
        assert!(catch_unwind(AssertUnwindSafe(|| source.steal_into(&mut into))).is_err());
        assert_eq!(drain(&mut owner), [0, 1, 2, 3]);
    }

    /// An owner pushing, popping and overflowing against two stealing threads
    /// hands every value out once and drops it once.
    #[test]
    fn test_owner_and_two_thieves_account_for_every_value_once() {
        let total = if cfg!(miri) { 64 } else { 4096 };
        let queue = Arc::new(Queue::<Counted>::shared());
        let mut owner = queue.owner();
        let done = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(3));
        let drops = Arc::new(AtomicUsize::new(0));

        // Each thief steals into its own queue and collects what it moved.
        let thieves: Vec<_> = (0..2)
            .map(|_| {
                let queue = queue.clone();
                let done = done.clone();
                let barrier = barrier.clone();

                thread::spawn(move || {
                    let destination = Queue::shared();
                    let mut into = destination.owner();
                    let mut seen = Vec::new();
                    barrier.wait();

                    // Keep stealing until a steal finds nothing after the owner is done.
                    loop {
                        if queue.steal_into(&mut into) > 0 {
                            for value in drain(&mut into) {
                                seen.push(value.0);
                            }
                        } else if done.load(Ordering::Acquire) {
                            break;
                        } else {
                            thread::yield_now();
                        }
                    }
                    seen
                })
            })
            .collect();

        // Start the owner together with both thieves.
        let mut seen = Vec::new();
        barrier.wait();

        // Push every value, collecting what a claim or an overflow hands back,
        // and pop every third value to race the thieves.
        for value in 0..total {
            match owner.push(Counted(value, drops.clone())) {
                Push::Pushed(_) => {}
                Push::Claimed(value) => seen.push(value.0),
                Push::Overflow(batch, value) => {
                    seen.extend(batch.map(|value| value.0));
                    seen.push(value.0);
                }
            }

            if value % 3 == 0
                && let Some(value) = owner.pop()
            {
                seen.push(value.0);
            }
        }

        // Tell the thieves to stop once a steal finds nothing.
        done.store(true, Ordering::Release);

        // Gather the thieves' values and whatever the owner still holds.
        for thief in thieves {
            seen.extend(thief.join().unwrap());
        }
        seen.extend(drain(&mut owner).into_iter().map(|value| value.0));

        // Every value is handed out once and dropped once.
        seen.sort_unstable();
        assert_eq!(seen, (0..total).collect::<Vec<_>>());
        assert_eq!(drops.load(Ordering::Relaxed), total);
    }

    /// Queues and owners move between threads, queues are shared, and owners
    /// are not.
    #[test]
    fn test_handles_are_send_and_the_owner_is_not_sync() {
        fn send<T: Send>() {}
        fn sync<T: Sync>() {}

        /// Resolving the check is ambiguous exactly when the type is `Sync`,
        /// since both implementations then match.
        trait AmbiguousIfSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        struct SyncMarker;
        impl<T: ?Sized + Sync> AmbiguousIfSync<SyncMarker> for T {}

        // Both handles move between threads and the queue is shared, even for
        // values that are not `Sync`.
        send::<Queue<Cell<usize>>>();
        sync::<Queue<Cell<usize>>>();
        send::<Owner<Cell<usize>>>();

        // This resolves only because the owner is not `Sync`.
        let _ = <Owner<usize> as AmbiguousIfSync<_>>::check;
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// Pop every value the owner holds.
    fn drain<T>(owner: &mut Owner<T>) -> Vec<T> {
        std::iter::from_fn(|| owner.pop()).collect()
    }

    /// Push `value`, collecting whatever the queue hands back into `seen`.
    fn collect_push(owner: &mut Owner<usize>, value: usize, seen: &mut Vec<usize>) {
        match owner.push(value) {
            Push::Pushed(_) => {}
            Push::Claimed(value) => seen.push(value),
            Push::Overflow(batch, value) => {
                seen.extend(batch);
                seen.push(value);
            }
        }
    }

    /// Steal once from `queue` into a fresh queue, returning every value taken.
    fn steal_once(queue: &Queue<usize>) -> Vec<usize> {
        let destination = Queue::shared();
        let mut into = destination.owner();

        // The thief's queue holds exactly as many values as the steal reports.
        let moved = queue.steal_into(&mut into);
        let seen = drain(&mut into);
        assert_eq!(seen.len(), moved);
        seen
    }

    /// Lone values pushed and popped across the wrapping position, then a
    /// refill that overflows and a drain, racing two steals, hand every value
    /// out once.
    #[test]
    fn test_lone_pops_refill_and_overflow_across_the_maximum_against_a_thief() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(3);
        builder.check(|| {
            // Start two positions before the maximum, so the pushes wrap past it.
            let queue = Queue::at(u32::MAX - 1, false);
            let mut owner = queue.owner();

            // The thief steals twice while the owner works.
            let thief = thread::spawn(move || {
                let mut seen = steal_once(&queue);
                seen.extend(steal_once(&queue));
                seen
            });

            // Push and pop two lone values, which no steal can take.
            let mut seen = Vec::new();
            for value in 0..2 {
                collect_push(&mut owner, value, &mut seen);
                seen.extend(owner.pop());
            }

            // Push one value more than the capacity, overflowing unless a steal
            // made room, then drain the rest.
            for value in 2..=CAPACITY + 2 {
                collect_push(&mut owner, value, &mut seen);
            }
            seen.extend(drain(&mut owner));

            // The owner and the thief together hand out every value once.
            seen.extend(thief.join().unwrap());
            seen.sort_unstable();
            assert_eq!(seen, (0..=CAPACITY + 2).collect::<Vec<_>>());
        });
    }

    /// An owner that drains and drops its queue while a thief holds a claim
    /// across the wrapping position leaves the claimed values to the thief,
    /// and every value is handed out once.
    #[test]
    fn test_owner_drops_while_a_thief_holds_a_claim() {
        loom::model(|| {
            // Fill a queue whose positions wrap past the maximum.
            let queue = Queue::at(u32::MAX - 1, false);
            let mut owner = queue.owner();
            owner.push_batch(0..CAPACITY);

            // A thief holds the oldest half and reads it on its own thread.
            let claim = queue.hold_claim(HALF);
            let thief = thread::spawn(move || queue.finish_claim(claim));

            // The owner drains its half and drops, possibly while the claim is held.
            let mut seen = drain(&mut owner);
            drop(owner);

            // The thief and the owner together hand out every value once.
            seen.extend(thief.join().unwrap());
            seen.sort_unstable();
            assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
        });
    }

    /// An owner's pop racing two thieves hands every value out once.
    #[test]
    fn test_owner_pop_against_two_thieves() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let queue = Arc::new(Queue::shared());
            let mut owner = queue.owner();
            owner.push_batch(0..3);

            // Two thieves each attempt one steal.
            let thieves: Vec<_> = (0..2)
                .map(|_| {
                    let queue = queue.clone();
                    thread::spawn(move || steal_once(&queue))
                })
                .collect();

            // The owner pops once, racing both steals.
            let mut seen = Vec::new();
            seen.extend(owner.pop());

            // Every value comes out once, from a thief or from the owner.
            for thief in thieves {
                seen.extend(thief.join().unwrap());
            }
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, vec![0, 1, 2]);
        });
    }

    /// Pushes and pops across the wrapping position racing a steal hand every
    /// value out once, with loom tracking each slot's accesses.
    #[test]
    fn test_push_against_steal_tracks_cells() {
        loom::model(|| {
            // Two values end at the maximum, so the next pushes wrap past it.
            let queue = Queue::at(u32::MAX - 1, false);
            let mut owner = queue.owner();
            owner.push_batch(0..2);

            // One steal races the owner's pops and pushes.
            let thief = thread::spawn(move || steal_once(&queue));

            // The owner pops both values, then pushes two more past the wrap.
            let mut seen = Vec::new();
            seen.extend(owner.pop());
            seen.extend(owner.pop());
            collect_push(&mut owner, 2, &mut seen);
            collect_push(&mut owner, 3, &mut seen);

            // Every value comes out once, from the thief or from the owner.
            seen.extend(thief.join().unwrap());
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, vec![0, 1, 2, 3]);
        });
    }

    /// A thief racing the owner's push and pop of a lone value never sees a
    /// stealable backlog and takes nothing, while the pop stores the head.
    #[test]
    fn test_lone_value_pop_against_a_thief() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let queue = Queue::shared();
            let mut owner = queue.owner();

            // The thief checks and steals twice, and never finds a backlog.
            let thief = thread::spawn(move || {
                for _ in 0..2 {
                    assert!(!queue.is_stealable());
                    assert!(steal_once(&queue).is_empty());
                }
            });

            // The owner pushes and pops one value, so the queue never holds two.
            assert!(matches!(owner.push(7), Push::Pushed(1)));
            assert_eq!(owner.pop(), Some(7));

            // The pop took the value, so nothing remains once the thief finishes.
            thief.join().unwrap();
            assert!(owner.is_empty());
        });
    }

    /// A push into a full queue racing a steal overflows, retries, or moves
    /// only the new value, and every value is handed out once. The yield
    /// after the push's snapshot exposes the steal that completes before the
    /// push decides.
    #[test]
    fn test_full_overflow_against_a_thief() {
        loom::model(|| {
            let queue = Queue::shared();
            let mut owner = queue.owner();
            owner.push_batch(0..CAPACITY);

            // One steal races a push into the full queue.
            let thief = thread::spawn(move || steal_once(&queue));

            // The push yields after each snapshot, so the steal can complete
            // before the push decides.
            let mut seen = Vec::new();
            match owner.push_with(CAPACITY, thread::yield_now) {
                Push::Pushed(_) => {}
                Push::Claimed(value) => seen.push(value),
                Push::Overflow(batch, value) => {
                    seen.extend(batch);
                    seen.push(value);
                }
            }

            // Every value comes out once, from the push, the thief, or the owner.
            seen.extend(thief.join().unwrap());
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, (0..=CAPACITY).collect::<Vec<_>>());
        });
    }

    /// Values a steal publishes in its own queue are visible to a third worker
    /// that steals from that queue, and the slots they vacate are reused.
    #[test]
    fn test_stolen_values_are_published_and_slots_reused() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            // Fill three source queues with distinct values.
            let sources: Vec<_> = (0..3).map(|_| Arc::new(Queue::shared())).collect();
            let mut owners: Vec<_> = sources.iter().map(|queue| queue.owner()).collect();
            for (index, owner) in owners.iter_mut().enumerate() {
                owner.push_batch(index * CAPACITY..(index + 1) * CAPACITY);
            }

            // The destination starts half full, so the first steal into it fits,
            // and later ones fit only after the third worker steals from it.
            let destination = Arc::new(Queue::shared());
            let mut into = destination.owner();
            into.push_batch(100..102);

            // One worker steals from each source into the destination.
            let transferring = thread::spawn(move || {
                for queue in sources {
                    let _ = queue.steal_into(&mut into);
                }
                into
            });

            // A third worker steals what the transfers publish in the destination.
            let stealing = thread::spawn(move || {
                let last = Queue::shared();
                let mut owner = last.owner();
                let mut seen = Vec::new();

                for _ in 0..3 {
                    let _ = destination.steal_into(&mut owner);
                    seen.extend(drain(&mut owner));
                }
                seen
            });

            // Gather what the third worker, the destination, and each source hold.
            let mut seen = stealing.join().unwrap();
            let mut into = transferring.join().unwrap();
            seen.extend(drain(&mut into));
            for owner in &mut owners {
                seen.extend(drain(owner));
            }

            // Every source value and both initial destination values come out once.
            seen.sort_unstable();
            let mut expected: Vec<_> = (0..3 * CAPACITY).collect();
            expected.extend(100..102);
            assert_eq!(seen, expected);
        });
    }
}

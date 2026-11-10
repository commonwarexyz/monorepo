//! A bounded FIFO queue in a ring buffer, with one owner and shared thieves.
//!
//! Each pool worker's run queue is a [`Queue`] of its runnables. Only the
//! holder of its [`Owner`] pushes and pops. Other workers hold the shared
//! handle and steal half of an unclaimed backlog with
//! [`Queue::steal_into_if`].
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
//! half of them, rounded up, by moving `real` past that half. It then moves
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
//! so a position selects its slot modulo [`CAPACITY`]. The head holds `real`
//! and the gap `real - steal` in one atomic word, so a claim or a pop moves
//! `real` in the same exchange that checks whether a claim is held. The gap is
//! at most `tail - steal`, which never exceeds [`CAPACITY`], so it fits in 9
//! bits. The head counts `real` in the 55 bits below them, and the low 32 of
//! those are the position the tail and the slots use. The higher bits only
//! make the head repeat later (see [Stealing](#stealing)). Below, a head is
//! written `(real, gap)`.
//!
//! ```text
//!          63     55 54                32 31                0
//!         +---------+--------------------+-------------------+
//!   head  |   gap   |  real, high bits   |  real, low bits   |   AtomicU64
//!         +---------+--------------------+-------------------+
//!
//!                                         31                0
//!                                        +-------------------+
//!   tail                                 |       tail        |   AtomicU32
//!                                        +-------------------+
//! ```
//!
//! The gap is zero, and `steal` equals `real`, unless a claim is held. A second
//! thief backs off while one is. Owner pops may move `real` past a held claim,
//! widening the gap, so releasing the claim clears the gap and lifts `steal` to
//! the current `real`. Only the owner writes `tail`.
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
//! A push into a full queue exchanges the head to `(real + CAPACITY, 0)`, whose
//! position is the tail, taking every value. It then republishes the oldest
//! half by storing `tail + CAPACITY / 2`.
//!
//! In a full ring buffer, the `CAPACITY / 2` positions after the old tail map
//! onto the oldest half's slots. An iterator that borrows the owner takes the
//! newest half, and the borrow excludes writes to those slots until the
//! iterator is consumed. A push decides from one snapshot of the head whether
//! it publishes, overflows, or hands back only the new value because a claim
//! is held. It retries when its overflow exchange finds the head moved.
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
//!   after: head (0, 0) -> (8, 0), then tail 8 -> 12
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
//! A steal takes half the unclaimed backlog, rounded up, so even a lone value
//! can move to a thief. It claims the values with one exchange on the head,
//! moves them into the thief's own queue, releases the claim, then publishes
//! them with one tail store. It goes only into a queue with at least half its
//! slots free, so the batch always fits. [`Queue::backlog`] is a hint
//! about the source's backlog. The claim checks the source again, and the
//! steal also checks the destination's room.
//!
//! The thief may refuse a lone value. It decides from the value's 55-bit head
//! count inside the claim, on the head snapshot that the claim's exchange
//! compares, so a lone claim takes exactly the value at the count it
//! approved. A count names one queued value: every pop or claim moves `real`
//! past it, and a push makes the backlog two, so a lone value seen twice at
//! the same count has stayed queued in between, unless the count went round
//! all `2^55` positions in between, the stall assumption below. The backlog
//! hint reports that count as well.
//!
//! The owner can mark a value as it pushes it, and the queue keeps the 55-bit
//! count of the newest marked value, stored before the tail store that
//! publishes it. A lone value is the newest one queued, so it is marked
//! exactly when its count is the one kept, and a thief that sees it through
//! the tail sees its mark too. The thief's decision also learns whether the
//! lone value is marked. The mark is only a hint for that decision: the
//! claim's exchange alone decides which value a steal takes. A stale mark
//! names a queued value only after the head's count repeats.
//!
//! Under loom, a queue can be built to claim half rounded down instead, so
//! it never takes or reports a lone value. Models of the idle protocol use it
//! to bound their interleavings.
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
//!   1. the thief claims 4 of 7 (real 0 -> 4), then the owner pops e (real 4 -> 5)
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   source  |   a   |   b   |   c   |   d   |       |   f   |   g   |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!           |<---------- claimed ---------->|popped |<-- queued --->|
//!
//!   2. the thief copies a b c d, releases (steal 0 -> 5), then publishes (its tail 0 -> 4)
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   source  |       |       |       |       |       |   f   |   g   |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!                                                   |<-- queued --->|
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!   thief   |   a   |   b   |   c   |   d   |       |       |       |       |
//!           +-------+-------+-------+-------+-------+-------+-------+-------+
//!           |<----------- queued ---------->|
//! ```
//!
//! A steal assumes that a thief does not stall between its head load and its
//! claim exchange while the indices advance through a full `2^55` positions,
//! after which the head could read as it did and the exchange succeed with a
//! stale count. The tail and the slots only need `u32` positions, and the head
//! counts `real` over 55 bits so that it repeats only that rarely. Once the
//! exchange succeeds the claim pins `steal`, so `tail - steal <= CAPACITY`
//! bounds further progress to `CAPACITY` positions. At one position per
//! nanosecond, the exposed window would need to last `2^55` nanoseconds, about
//! 417 days. An overflow advances `real` by `CAPACITY` and `tail` by half as
//! much, so the assumption counts positions rather than operations. A stale
//! count can exceed the values then queued, so even a claim of one value could
//! read a free slot.
//!
//! The owner's own exchanges need no such assumption. While the owner stalls it
//! pushes nothing, so thieves can move `real` no further than `tail`, and the
//! head cannot return to the value the owner loaded.
//!
//! # Pops
//!
//! A queue built exclusive has no reader but its owner, so the owner pops with
//! plain loads and a store rather than an exchange. [`Queue::steal_into_if`]
//! asserts that its source is shared. A pool of one worker has no other worker
//! to steal from its run queue, so that queue is exclusive.
//!
//! The owner of a shared queue pops every value with an exchange on the head,
//! a lone one included, since a claim rounded up can take a lone value. The
//! exchange arbitrates between the pop and such a claim: whichever moves
//! `real` first owns the value, and the other finds the queue empty.
//!
//! # Dropping handles
//!
//! The owner must remove its unclaimed values before dropping. A thief may
//! still own claimed values after that. An overflow must be exhausted before
//! dropping. A nonempty owner or an unexhausted overflow panics on drop unless
//! the thread is already unwinding. These drops do not destroy unread values,
//! which may leak.

use super::task::UnsafeCell;
use commonware_utils::Widen;
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

/// Fewest values an unclaimed queue holds for a steal to take any. A steal
/// takes half rounded up, so one is enough.
pub const STEALABLE: usize = 1;

/// Mask that selects a position's slot.
const MASK: usize = CAPACITY - 1;

/// Bits of a head that count `real`. The gap `real - steal` fills the rest.
const REAL_BITS: u32 = 55;

/// Mask that selects a head's `real` count.
const REAL_MASK: u64 = (1 << REAL_BITS) - 1;

/// The mark of a queue that has never queued a marked value. No 55-bit count
/// equals it.
const UNMARKED: u64 = u64::MAX;

/// Positions select slots by masking, a full queue's distance must fit in a
/// wrapping `u32` comparison, and the gap field must hold every gap from zero
/// to the capacity.
const _: () = assert!(CAPACITY.is_power_of_two() && CAPACITY < 1 << (u64::BITS - REAL_BITS));

/// The low 32 bits of a head's count are its `u32` position, which needs the
/// count to be at least that wide.
const _: () = assert!(REAL_BITS >= u32::BITS);

/// The slots of a queue's ring and the positions that divide them, shared by
/// its [`Queue`] and [`Owner`] handles. See the module docs for the invariants
/// every access keeps.
struct Inner<T> {
    /// `gap << REAL_BITS | real`: the next position the owner pops, counted
    /// over [`REAL_BITS`] bits, and how far it lies past the oldest unreleased
    /// position.
    head: AtomicU64,
    /// One past the newest published value, written only by the owner.
    tail: AtomicU32,
    /// The 55-bit head count of the newest value pushed marked, or
    /// [`UNMARKED`]. Written only by the owner, before the tail store that
    /// publishes that value.
    marked: AtomicU64,
    /// Whether the unique owner has been taken.
    owned: AtomicBool,
    /// Whether no reader but the owner ever touches the queue, fixed at
    /// construction.
    exclusive: bool,
    /// Loom only: whether claims take half the backlog rounded down, so a
    /// lone value is never claimed or reported stealable.
    #[cfg(feature = "loom")]
    round_down: bool,
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
    /// The value was published.
    Pushed(
        /// Available length computed from the push's head snapshot. A
        /// concurrent claim can make it an overestimate.
        usize,
    ),
    /// The queue was full, so the newest half and the new value must be
    /// published elsewhere, in that order.
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

/// What a snapshot of a queue offers a thief, as [`Queue::backlog`] reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backlog {
    /// Nothing a claim could take: no value, or a claim already held.
    None,
    /// One unclaimed value, at this 55-bit head count, and whether it was
    /// pushed marked.
    Lone(u64, bool),
    /// Two or more unclaimed values.
    More,
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

/// Split a head into `real`, counted over 55 bits, and the gap `real - steal`.
/// The low 32 bits of `real` are its position.
const fn unpack(head: u64) -> (u64, u32) {
    (head & REAL_MASK, (head >> REAL_BITS) as u32)
}

/// Pack `real`, reduced to 55 bits, and the gap `real - steal` into a head.
const fn pack(real: u64, gap: u32) -> u64 {
    (gap as u64) << REAL_BITS | (real & REAL_MASK)
}

/// The position of `steal`, the oldest unreleased value, from an unpacked
/// head.
const fn steal(real: u64, gap: u32) -> u32 {
    (real as u32).wrapping_sub(gap)
}

/// The 55-bit count of `position`, a position at most [`CAPACITY`] past the
/// head count `real`.
const fn count_at(real: u64, position: u32) -> u64 {
    real.wrapping_add(position.wrapping_sub(real as u32) as u64) & REAL_MASK
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

    /// An empty queue whose head starts at a chosen 55-bit count, so its
    /// position is that count's low 32 bits.
    fn at(real: u64, exclusive: bool) -> Self {
        assert!(real <= REAL_MASK, "start must fit the head's count");
        Self(Arc::new(CachePadded::new(Inner {
            head: AtomicU64::new(pack(real, 0)),
            tail: AtomicU32::new(real as u32),
            marked: AtomicU64::new(UNMARKED),
            owned: AtomicBool::new(false),
            exclusive,
            #[cfg(feature = "loom")]
            round_down: false,
            slots: (0..CAPACITY)
                .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
                .collect(),
        })))
    }

    /// Fewest values an unclaimed backlog needs for a claim to take any:
    /// [`STEALABLE`], or two for a queue that rounds down under loom.
    // Loom's handles cannot be read in a const fn.
    #[allow(clippy::missing_const_for_fn)]
    #[inline]
    fn stealable(&self) -> u32 {
        #[cfg(feature = "loom")]
        if self.0.round_down {
            return 2;
        }
        STEALABLE as u32
    }

    /// Values a claim takes from an unclaimed backlog of `available`: half
    /// rounded up, or rounded down for a queue that rounds down under loom.
    // Loom's handles cannot be read in a const fn.
    #[allow(clippy::missing_const_for_fn)]
    #[inline]
    fn claim_count(&self, available: u32) -> u32 {
        #[cfg(feature = "loom")]
        if self.0.round_down {
            return available / 2;
        }
        available.div_ceil(2)
    }

    /// Take the owner, panicking if it was already taken, even if it has since
    /// been dropped.
    pub fn owner(&self) -> Owner<T> {
        assert!(
            !self.0.owned.swap(true, Ordering::AcqRel),
            "queue owner must be taken at most once"
        );
        Owner(self.0.clone(), PhantomData)
    }

    /// Whether the value at the 55-bit count `real` is the newest one pushed
    /// marked. Read after an acquiring tail load that shows the value, so its
    /// own mark is visible. A later marked push can replace it, which needs
    /// the value to be no longer the newest one queued.
    #[inline]
    fn is_marked(&self, real: u64) -> bool {
        self.0.marked.load(Ordering::Relaxed) == real
    }

    /// What a snapshot offers a thief: nothing while a claim is held or below
    /// [`STEALABLE`] values, the 55-bit count of a lone value and whether it
    /// was pushed marked, or more. Concurrent changes can make this hint stale
    /// before a steal claims them.
    pub fn backlog(&self) -> Backlog {
        // Shared head updates release the tail they observed. Acquire the
        // head first so the tail cannot lag behind it and turn the wrapping
        // distance into a false backlog.
        let (real, gap) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Acquire);
        let available = tail.wrapping_sub(real as u32);
        if gap != 0 || available < self.stealable() {
            Backlog::None
        } else if available == 1 {
            Backlog::Lone(real, self.is_marked(real))
        } else {
            Backlog::More
        }
    }

    /// Move half the unclaimed backlog, rounded up, into `into`, returning
    /// how many values moved. A backlog of exactly one value is claimed only
    /// if `lone` accepts its 55-bit count and whether it was pushed marked.
    ///
    /// Moves none when the backlog is empty, while another thief holds a
    /// claim, when `into` has fewer than half its slots free, or when `lone`
    /// refuses. `lone` is called only for a lone value, on the head snapshot
    /// the claim's exchange compares, so a successful lone claim takes the
    /// value at the count it accepted. A retried claim calls it again with
    /// the count it sees then. The claim is released before the values are
    /// published in `into` with one tail store. Panics if `into` belongs to
    /// this queue or this queue is exclusive.
    #[must_use]
    pub fn steal_into_if(&self, into: &mut Owner<T>, lone: impl FnMut(u64, bool) -> bool) -> usize {
        assert!(!self.0.exclusive, "steal source must be a shared queue");
        assert!(
            !Arc::ptr_eq(&into.0, &self.0),
            "steal destination must differ from the source queue"
        );

        // Only this owner writes the destination tail. Acquiring its head
        // observes completed claim reads before their slots are reused.
        let tail = into.0.tail.load(Ordering::Relaxed);
        let (real, gap) = unpack(into.0.head.load(Ordering::Acquire));
        if tail.wrapping_sub(steal(real, gap)) > HALF {
            return 0;
        }

        let Some((first, count)) = self.claim(lone) else {
            return 0;
        };
        for offset in 0..count {
            // SAFETY: the source claim owns this initialized slot.
            let value = unsafe { self.0.read((first as u32).wrapping_add(offset)) };

            // SAFETY: the destination had half its slots free before the
            // claim, the owner is borrowed, and thieves only add room.
            unsafe { into.0.write(tail.wrapping_add(offset), value) };
        }

        self.release_claim(first, count);
        into.0
            .tail
            .store(tail.wrapping_add(count), Ordering::Release);
        Widen::widen(count)
    }

    /// Claim half the published backlog, rounded up, returning the first
    /// claimed position as a 55-bit count and the count claimed, or `None`
    /// while another claim is held or no value is published, or when `lone`
    /// refuses the count of a lone value. Every bound is checked before the
    /// exchange, so the caller can move and release the claimed values
    /// without further bound checks.
    fn claim(&self, mut lone: impl FnMut(u64, bool) -> bool) -> Option<(u64, u32)> {
        let mut head = self.0.head.load(Ordering::Acquire);
        loop {
            let (real, gap) = unpack(head);
            if gap != 0 {
                return None;
            }

            // Acquire the owner's release publication before reading any
            // slot that a successful claim grants us.
            let tail = self.0.tail.load(Ordering::Acquire);
            let available = tail.wrapping_sub(real as u32);

            // An overflow can pair an old head with the republished tail. That
            // head cannot be claimed, so refresh it before checking bounds.
            if available > CAPACITY as u32 {
                head = self.0.head.load(Ordering::Acquire);
                continue;
            }

            // At most `CAPACITY` values are available here, so rounding up
            // claims at most half the queue as well.
            let count = self.claim_count(available);
            if count == 0 {
                return None;
            }

            // The exchange below compares this head, so a lone claim takes
            // the value at the count the caller accepted, or none. The tail
            // load above shows that value, so its mark is visible as well.
            if available == 1 && !lone(real, self.is_marked(real)) {
                return None;
            }
            assert!(count <= HALF, "claim must not exceed half the queue");
            let claimed = pack(real.wrapping_add(u64::from(count)), count);

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

    /// Release a claim once its slots have been read, clearing the gap to lift
    /// `steal` to the current `real`. Owner pops may have moved `real` past the
    /// claim. The caller must hold exactly this claim, starting at the 55-bit
    /// count `first`, and have read every claimed slot.
    fn release_claim(&self, first: u64, count: u32) {
        let mut head = pack(first.wrapping_add(u64::from(count)), count);
        loop {
            let (real, _) = unpack(head);

            // Release lets an owner that acquires this head reuse the read
            // slots.
            match self.0.head.compare_exchange(
                head,
                pack(real, 0),
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
        let (real, _) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Relaxed);
        Widen::widen(tail.wrapping_sub(real as u32))
    }

    /// Slots free for publication. A pending claim holds its slots, and those
    /// the owner popped past it, until it is released.
    pub fn room(&self) -> usize {
        let (real, gap) = unpack(self.0.head.load(Ordering::Acquire));
        let tail = self.0.tail.load(Ordering::Relaxed);
        CAPACITY - Widen::widen(tail.wrapping_sub(steal(real, gap)))
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
        self.push_with(value, false, || {})
    }

    /// Publish a value marked, as [`Self::push`] does otherwise. While it is
    /// the only value queued, [`Queue::backlog`] and the decision of
    /// [`Queue::steal_into_if`] report it marked. A value handed back is not
    /// marked.
    pub fn push_marked(&mut self, value: T) -> Push<'_, T> {
        self.push_with(value, true, || {})
    }

    /// Publish as [`Self::push`] does, marked if `mark` is set, running
    /// `after_snapshot` after each attempt's head snapshot, where a test
    /// pauses the owner.
    fn push_with(&mut self, value: T, mark: bool, mut after_snapshot: impl FnMut()) -> Push<'_, T> {
        loop {
            // Acquire completed claim reads before writing a freed slot.
            let head = self.0.head.load(Ordering::Acquire);
            let (real, gap) = unpack(head);
            let tail = self.0.tail.load(Ordering::Relaxed);
            after_snapshot();

            if tail.wrapping_sub(steal(real, gap)) < CAPACITY as u32 {
                // SAFETY: the acquired head excludes pending readers, and the
                // unpublished tail slot is free.
                unsafe { self.0.write(tail, value) };

                // Before the tail store, so a thief that sees the value sees
                // its mark. The count is the full 55-bit one, so a stale mark
                // matches a later value only once the head's count repeats.
                if mark {
                    self.0.marked.store(count_at(real, tail), Ordering::Relaxed);
                }

                let tail = tail.wrapping_add(1);
                self.0.tail.store(tail, Ordering::Release);
                return Push::Pushed(Widen::widen(tail.wrapping_sub(real as u32)));
            }

            if gap != 0 {
                return Push::Claimed(value);
            }

            assert_eq!(
                tail.wrapping_sub(real as u32),
                CAPACITY as u32,
                "queue must be full to overflow"
            );

            // The exchange arbitrates against a claim and releases the
            // owner's preceding tail publications to later head readers. The
            // queue is full, so `real` moves to the tail.
            if self
                .0
                .head
                .compare_exchange(
                    head,
                    pack(real.wrapping_add(Widen::widen(CAPACITY)), 0),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            // The `HALF` positions after the old tail map onto the oldest
            // half's slots, so publishing them republishes that half.
            self.0
                .tail
                .store(tail.wrapping_add(HALF), Ordering::Release);

            return Push::Overflow(
                Overflow {
                    owner: self,
                    next: (real as u32).wrapping_add(HALF),
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
            let (real, _) = unpack(self.0.head.load(Ordering::Relaxed));
            let tail = self.0.tail.load(Ordering::Relaxed);
            if real as u32 == tail {
                return None;
            }

            self.0
                .head
                .store(pack(real.wrapping_add(1), 0), Ordering::Relaxed);

            // SAFETY: an exclusive queue has no reader but its owner, so this
            // initialized slot is the owner's alone, and the mutable borrow
            // excludes writes.
            return Some(unsafe { self.0.read(real as u32) });
        }

        let mut head = self.0.head.load(Ordering::Acquire);
        loop {
            let (real, gap) = unpack(head);
            let position = real as u32;
            let tail = self.0.tail.load(Ordering::Relaxed);
            if position == tail {
                return None;
            }

            // A held claim keeps `steal` in place, so the gap grows with
            // `real`.
            let next = pack(real.wrapping_add(1), if gap == 0 { 0 } else { gap + 1 });

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
                    return Some(unsafe { self.0.read(position) });
                }
                Err(actual) => head = actual,
            }
        }
    }

    /// Publish a batch with one tail store. Panics if it exceeds
    /// [`Self::room`] or the iterator misreports its length.
    pub fn push_batch(&mut self, mut values: impl ExactSizeIterator<Item = T>) {
        let count = values.len();
        assert!(count <= self.room(), "batch must fit the queue's room");

        let tail = self.0.tail.load(Ordering::Relaxed);
        for offset in 0..count {
            let value = values
                .next()
                .expect("batch must yield at least its reported length");

            // SAFETY: room bounds this unpublished span, the owner is
            // borrowed, and pending claims cannot overlap it.
            unsafe { self.0.write(tail.wrapping_add(offset as u32), value) };
        }

        assert!(
            values.next().is_none(),
            "batch must yield at most its reported length"
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
        self.slots[Widen::widen(position) & MASK].with_mut(|ptr| {
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
        self.slots[Widen::widen(position) & MASK].with_mut(|ptr| {
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
        let count = Widen::widen(self.end.wrapping_sub(self.next));
        (count, Some(count))
    }
}

impl<T> ExactSizeIterator for Overflow<'_, T> {}

impl<T> Drop for Overflow<'_, T> {
    fn drop(&mut self) {
        // An unread value would leak, so an unexhausted overflow panics on
        // drop. During an unwind the values leak silently, since a second
        // panic would abort.
        if !thread::panicking() {
            assert_eq!(
                self.next, self.end,
                "overflow must be exhausted before it drops"
            );
        }
    }
}

impl<T> Drop for Owner<T> {
    fn drop(&mut self) {
        // Unclaimed values must be removed before the owner drops. Catch an
        // undrained queue on its owner's thread rather than wherever the last
        // shared handle drops. Pending claims belong to their thieves.
        if !thread::panicking() {
            assert!(self.is_empty(), "owner must be empty when it drops");
        }
    }
}

impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        // A claim or value still here when the last handle drops was leaked.
        if !thread::panicking() {
            let (real, gap) = unpack(self.head.load(Ordering::Relaxed));
            assert_eq!(gap, 0, "queue must have no pending claim when it drops");
            assert_eq!(
                real as u32,
                self.tail.load(Ordering::Relaxed),
                "queue must be empty when it drops"
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

    /// Queues built for models, and claims held by a test in place of a
    /// paused thief.
    impl<T> Queue<T> {
        /// Whether a snapshot shows no claim and at least [`STEALABLE`]
        /// values.
        pub fn is_stealable(&self) -> bool {
            self.backlog() != Backlog::None
        }

        /// Steal as [`Self::steal_into_if`] does, taking a lone value too.
        #[must_use]
        pub fn steal_into(&self, into: &mut Owner<T>) -> usize {
            self.steal_into_if(into, |_, _| true)
        }

        /// Move an empty, unclaimed queue's head and tail to the 55-bit count
        /// `real`, as if values had been pushed and popped up to it.
        pub(crate) fn skip_to(&self, real: u64) {
            let (_, gap) = unpack(self.0.head.load(Ordering::Acquire));
            assert_eq!(gap, 0);
            assert_eq!(self.backlog(), Backlog::None);
            self.0.head.store(pack(real, 0), Ordering::Release);
            self.0.tail.store(real as u32, Ordering::Release);
        }

        /// An empty shared queue whose claims take half the backlog rounded
        /// down, so a lone value is never claimed or reported stealable. Its
        /// owner pops as every shared owner does. Without lone claims, broad
        /// models of the idle protocol have far fewer interleavings and stay
        /// within their preemption bounds, while focused models cover lone
        /// claims on ordinary queues.
        #[cfg(feature = "loom")]
        pub(crate) fn shared_rounding_down() -> Self {
            Self(Arc::new(CachePadded::new(Inner {
                head: AtomicU64::new(pack(0, 0)),
                tail: AtomicU32::new(0),
                marked: AtomicU64::new(UNMARKED),
                owned: AtomicBool::new(false),
                exclusive: false,
                round_down: true,
                slots: (0..CAPACITY)
                    .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
                    .collect(),
            })))
        }

        /// Claim the oldest `count` values as a thief paused after its claim
        /// exchange would hold them. Panics unless no claim is held and `count`
        /// is positive, at most [`HALF`], and within the available values, or if
        /// another head update wins the exchange. The caller must read and release
        /// the returned claim exactly once through [`Self::finish_claim`].
        pub(crate) fn hold_claim(&self, count: u32) -> (u64, u32) {
            let head = self.0.head.load(Ordering::Acquire);
            let (real, gap) = unpack(head);
            let tail = self.0.tail.load(Ordering::Acquire);
            assert_eq!(gap, 0);
            assert!(count > 0 && count <= HALF && count <= tail.wrapping_sub(real as u32));

            assert!(
                self.0
                    .head
                    .compare_exchange(
                        head,
                        pack(real + u64::from(count), count),
                        Ordering::AcqRel,
                        Ordering::Acquire
                    )
                    .is_ok()
            );
            (real, count)
        }

        /// Read a held claim's values and release it, as the paused thief would.
        /// The caller must own the unread claim returned by [`Self::hold_claim`].
        pub(crate) fn finish_claim(&self, claim: (u64, u32)) -> Vec<T> {
            let (first, count) = claim;
            let values = (0..count)
                .map(|offset| {
                    // SAFETY: hold_claim gave the caller exclusive ownership of this
                    // initialized slot, and the release follows every read.
                    unsafe { self.0.read((first as u32).wrapping_add(offset)) }
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

    /// Check the physical head, including the count's bits above its position.
    fn assert_head<T>(queue: &Queue<T>, real: u64, gap: u32) {
        assert_eq!(
            queue.0.head.load(Ordering::Acquire),
            (u64::from(gap) << REAL_BITS) | (real & REAL_MASK)
        );
    }

    /// Take every value from a queue whose owner is gone.
    fn take_unowned<T>(queue: &Queue<T>) -> Vec<T> {
        // A held claim would belong to its thief, so none may be pending.
        let (real, gap) = unpack(queue.0.head.load(Ordering::Acquire));
        assert_eq!(gap, 0);
        let tail = queue.0.tail.load(Ordering::Acquire);
        let count = tail.wrapping_sub(real as u32);

        let values = (0..count)
            .map(|offset| {
                // SAFETY: the owner is gone and no claim is held, so this test
                // is the only reader of the queue's initialized values.
                unsafe { queue.0.read((real as u32).wrapping_add(offset)) }
            })
            .collect();

        // Moving the head to the tail marks the values taken, so the queue drops empty.
        queue
            .0
            .head
            .store(pack(real + u64::from(count), 0), Ordering::Release);
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

    /// Head counts whose positions wrap one past them: at `u32::MAX` the
    /// position wraps and carries into the head's higher bits, and at the
    /// 55-bit maximum the whole count wraps to zero as well.
    const WRAPS: [u64; 2] = [u32::MAX as u64, REAL_MASK];

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
                    _ => panic!("push below capacity must publish"),
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
    /// past `u32::MAX`, and while the head's count wraps past its 55 bits.
    #[test]
    fn test_positions_wrap_across_the_maximum() {
        for (end, exclusive) in WRAPS
            .into_iter()
            .flat_map(|end| [(end, false), (end, true)])
        {
            // Start eight positions before the wrap, so a full ring wraps past it.
            let queue = Queue::at(end - 7, exclusive);
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
                _ => panic!("full wrapping queue must overflow"),
            }

            // The oldest half stays queued in order.
            assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
        }
    }

    /// A lone value in a shared queue is stealable, and its owner pops it with
    /// the exchange, here at zero and across the maximum, leaving the queue
    /// empty and unclaimed. A pop after a steal took the lone value finds
    /// nothing.
    #[test]
    fn test_lone_value_pops_or_is_stolen_across_the_maximum() {
        for start in [0, u64::from(u32::MAX), REAL_MASK] {
            let queue = Queue::at(start, false);
            let mut owner = queue.owner();

            // A steal takes half rounded up, so a lone value is stealable.
            push(&mut owner, 7);
            assert!(queue.is_stealable());

            // The pop moves steal and real together, so no claim appears held.
            assert_eq!(owner.pop(), Some(7));
            let next = (start + 1) & REAL_MASK;
            assert_eq!(unpack(queue.0.head.load(Ordering::Acquire)), (next, 0));
            assert!(!queue.is_stealable());
            assert!(owner.pop().is_none());

            // A steal takes the next lone value, leaving the owner nothing.
            push(&mut owner, 8);
            let destination = Queue::shared();
            let mut into = destination.owner();
            assert_eq!(queue.steal_into(&mut into), 1);
            assert!(owner.pop().is_none());
            assert!(owner.is_empty());
            assert!(!queue.is_stealable());
            assert_eq!(drain(&mut into), [8]);
        }
    }

    /// A held claim of a lone value leaves the owner nothing to pop and blocks
    /// every other steal, even of a value pushed behind it, and its release
    /// hands the claimed value to the thief only.
    #[test]
    fn test_held_claim_of_a_lone_value_excludes_the_owner_and_thieves() {
        for start in [0, u64::from(u32::MAX), REAL_MASK] {
            let queue = Queue::at(start, false);
            let destination = Queue::shared();
            let mut owner = queue.owner();
            let mut into = destination.owner();
            push(&mut owner, 7);

            // The claim takes the only value, so the owner finds the queue empty.
            let claim = queue.hold_claim(1);
            assert!(owner.pop().is_none());
            assert!(owner.is_empty());
            assert!(!queue.is_stealable());
            assert_eq!(queue.steal_into(&mut into), 0);

            // A push behind the claim is the owner's alone until the release.
            push(&mut owner, 8);
            assert!(!queue.is_stealable());
            assert_eq!(queue.steal_into(&mut into), 0);
            assert_eq!(queue.finish_claim(claim), [7]);

            // The release exposes the owner's lone value, which a steal takes.
            assert!(queue.is_stealable());
            assert_eq!(queue.steal_into(&mut into), 1);
            assert!(owner.pop().is_none());
            assert_eq!(drain(&mut into), [8]);
        }
    }

    /// A held claim of part of an odd backlog lets the owner pop the rest,
    /// including a lone value past the claim, which the release then skips.
    #[test]
    fn test_owner_pops_past_a_held_claim() {
        for start in [0, u64::from(u32::MAX), REAL_MASK] {
            let queue = Queue::at(start, false);
            let destination = Queue::shared();
            let mut owner = queue.owner();
            let mut into = destination.owner();
            owner.push_batch(0..3);

            // A claim of the oldest value leaves two, so the owner pops both with
            // the exchange, the second one lone and past the claim.
            let claim = queue.hold_claim(1);
            assert_eq!(queue.steal_into(&mut into), 0);
            assert_eq!(owner.pop(), Some(1));
            assert_eq!(owner.pop(), Some(2));
            assert!(owner.pop().is_none());

            // The release lifts steal past the owner's pops, leaving the queue empty.
            assert_eq!(queue.finish_claim(claim), [0]);
            assert!(!queue.is_stealable());
            assert_eq!(queue.steal_into(&mut into), 0);
            let (real, gap) = unpack(queue.0.head.load(Ordering::Acquire));
            assert_eq!(gap, 0);
            assert_eq!(real, (start + 3) & REAL_MASK);
            assert_eq!(real as u32, queue.0.tail.load(Ordering::Acquire));
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
                _ => panic!("full queue must overflow"),
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
    /// `u32::MAX`, or whose head counts wrap past their 55 bits.
    #[test]
    fn test_steal_wraps_across_the_maximum() {
        for end in WRAPS {
            // Both queues start near the wrap, so the source's backlog and the
            // destination's slots wrap past it.
            let source = Queue::at(end - 7, false);
            let destination = Queue::at(end - 3, false);
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..CAPACITY);

            // The steal takes the oldest half across the wrap.
            assert_eq!(source.steal_into(&mut into), CAPACITY / 2);

            // The stolen half, then the owner's remaining half, restore the
            // push order.
            let mut values = drain(&mut into);
            values.extend(drain(&mut owner));
            assert_eq!(values, (0..CAPACITY).collect::<Vec<_>>());
        }
    }

    /// A claim held while the owner pops past it and across a wrap keeps its
    /// slots, and its release frees every one.
    #[test]
    fn test_claim_and_pops_across_the_maximum() {
        for end in WRAPS {
            // The claim ends before the wrap, and the owner's half crosses it.
            let queue = Queue::at(end - u64::from(HALF) - 7, false);
            let mut owner = queue.owner();
            owner.push_batch(0..CAPACITY);
            let claim = queue.hold_claim(HALF);

            // The claim leaves the owner the newest half and no room, so a push
            // hands back only the new value.
            assert_eq!(owner.len(), CAPACITY / 2);
            assert_eq!(owner.room(), 0);
            assert!(matches!(owner.push(CAPACITY), Push::Claimed(value) if value == CAPACITY));

            // The exchange pops past the claim carry the count across the wrap
            // and widen the gap to the whole capacity, so the room stays zero
            // and no steal is offered.
            let popped = drain(&mut owner);
            assert_eq!(popped, (CAPACITY / 2..CAPACITY).collect::<Vec<_>>());
            assert_head(&queue, end + u64::from(HALF) - 7, CAPACITY as u32);
            assert_eq!(owner.room(), 0);
            assert!(!queue.is_stealable());

            // Releasing the claim frees every slot, and the claim and the pops
            // together hand out every value in push order.
            let mut seen = queue.finish_claim(claim);
            assert_eq!(owner.room(), CAPACITY);
            seen.extend(popped);
            assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
        }
    }

    /// Every head update retains the count above its position and carries
    /// across both wraps, including a claim release after an owner pop.
    #[test]
    fn test_every_head_update_preserves_the_widened_count() {
        for start in [
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
            (1u64 << 32) + 7,
            REAL_MASK - 1,
            REAL_MASK,
        ] {
            for exclusive in [false, true] {
                // Two values exercise shared exchanges or exclusive stores,
                // the second pop taking a lone value.
                let queue = Queue::at(start, exclusive);
                let mut owner = queue.owner();
                owner.push_batch(0..2);

                // Each pop advances the full count, even when the position wraps.
                assert_eq!(owner.pop(), Some(0));
                assert_head(&queue, start + 1, 0);
                assert_eq!(owner.pop(), Some(1));
                assert_head(&queue, start + 2, 0);
            }

            for exclusive in [false, true] {
                // Fill a fresh queue so the overflow itself crosses the wrap.
                let queue = Queue::at(start, exclusive);
                let mut owner = queue.owner();
                owner.push_batch(0..CAPACITY);

                // Overflow advances the full count by the capacity.
                match owner.push(CAPACITY) {
                    Push::Overflow(batch, value) => {
                        assert_eq!(
                            batch.collect::<Vec<_>>(),
                            (CAPACITY / 2..CAPACITY).collect::<Vec<_>>()
                        );
                        assert_eq!(value, CAPACITY);
                    }
                    _ => panic!("full queue must overflow"),
                }
                assert_head(&queue, start + Widen::widen(CAPACITY), 0);

                // The retained oldest half still drains in order.
                assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
            }

            for pop_past_claim in [false, true] {
                // A real claim advances across the wrap and pins its source slots.
                let queue = Queue::at(start, false);
                let mut owner = queue.owner();
                owner.push_batch(0..CAPACITY);
                let claim = queue
                    .claim(|_, _| true)
                    .expect("full queue must be claimable");
                assert_eq!(claim, (start, HALF));
                assert_head(&queue, start + u64::from(HALF), HALF);

                // An owner pop changes the head that release first expects.
                let mut seen = Vec::new();
                let advance = if pop_past_claim {
                    seen.push(owner.pop().expect("owner must retain half the values"));
                    assert_head(&queue, start + u64::from(HALF) + 1, HALF + 1);
                    u64::from(HALF) + 1
                } else {
                    u64::from(HALF)
                };

                // Both release paths clear the gap while retaining the full count.
                seen.extend(queue.finish_claim(claim));
                assert_head(&queue, start + advance, 0);

                // The claim and owner return every value exactly once.
                seen.extend(drain(&mut owner));
                seen.sort_unstable();
                assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
            }
        }
    }

    /// The head encoding repeats only after a full `2^55` positions: the head
    /// a stalled thief loaded differs from the head after any shorter advance,
    /// `2^32` included, so its claim exchange would fail.
    #[test]
    fn test_stale_head_matches_only_after_a_full_period() {
        // The head a thief loads from a queue holding two values, starting at
        // a count.
        let head = |start: u64| {
            let queue = Queue::at(start & REAL_MASK, false);
            let mut owner = queue.owner();
            owner.push_batch(0..2);
            let head = queue.0.head.load(Ordering::Acquire);
            drain(&mut owner);
            head
        };
        let stale = head(3);

        // Shorter advances leave a different head, so the stale exchange fails.
        for count in [1, Widen::widen(CAPACITY), 1 << 32, 1 << 54, REAL_MASK] {
            assert_ne!(head(3 + count), stale);
        }

        // A full period brings the same head back.
        assert_eq!(head(3 + REAL_MASK + 1), stale);
    }

    /// A lone value reports its 55-bit count and whether it was pushed marked,
    /// to the backlog hint and to the steal's decision, here at zero and
    /// across both wraps. A fresh queue's first value is unmarked, an unmarked
    /// push behind a marked value leaves only the newest value's mark to
    /// report once it is alone, and a marked value handed back by a full queue
    /// marks nothing.
    #[test]
    fn test_lone_value_reports_its_mark() {
        for start in [0, u64::from(u32::MAX), REAL_MASK] {
            let queue = Queue::at(start, false);
            let mut owner = queue.owner();
            let count = |offset: u64| (start + offset) & REAL_MASK;

            // The first value of a fresh queue is not marked.
            push(&mut owner, 0);
            assert_eq!(queue.backlog(), Backlog::Lone(count(0), false));
            assert_eq!(owner.pop(), Some(0));

            // A marked value is reported marked while alone, and an unmarked
            // one behind it is not once it is alone.
            assert!(matches!(owner.push_marked(1), Push::Pushed(1)));
            assert_eq!(queue.backlog(), Backlog::Lone(count(1), true));
            push(&mut owner, 2);
            assert_eq!(queue.backlog(), Backlog::More);
            assert_eq!(owner.pop(), Some(1));
            assert_eq!(queue.backlog(), Backlog::Lone(count(2), false));

            // The steal's decision sees the same mark it is refused for, then
            // the mark of the next marked value it accepts.
            let destination = Queue::shared();
            let mut into = destination.owner();
            let mut asked = Vec::new();
            let mut decide = |real, marked| {
                asked.push((real, marked));
                marked
            };
            assert_eq!(queue.steal_into_if(&mut into, &mut decide), 0);
            assert_eq!(owner.pop(), Some(2));
            assert!(matches!(owner.push_marked(3), Push::Pushed(1)));
            assert_eq!(queue.steal_into_if(&mut into, &mut decide), 1);
            assert_eq!(asked, [(count(2), false), (count(3), true)]);
            assert_eq!(drain(&mut into), [3]);

            // A marked push into a full queue hands the value back, and the
            // value left alone after the drain is not marked.
            owner.push_batch(0..CAPACITY);
            match owner.push_marked(CAPACITY) {
                Push::Overflow(batch, value) => {
                    assert_eq!(batch.count(), CAPACITY / 2);
                    assert_eq!(value, CAPACITY);
                }
                _ => panic!("a full queue overflows"),
            }
            for _ in 1..CAPACITY / 2 {
                assert!(owner.pop().is_some());
            }
            assert!(matches!(queue.backlog(), Backlog::Lone(_, false)));
            assert!(owner.pop().is_some());
        }
    }

    /// The mark keeps the full 55-bit count, so an unmarked lone value whose
    /// count shares the marked one's low 24 bits, or its `u32` position, is
    /// not reported marked, to the backlog hint or to the steal's decision.
    /// Only a full period of the head's count brings the marked count back.
    #[test]
    fn test_stale_mark_matches_only_after_a_full_period() {
        let start = 5;
        for (advance, marked) in [
            (1 << 24, false),
            (1 << 32, false),
            (1 << 54, false),
            (REAL_MASK, false),
            (REAL_MASK + 1, true),
        ] {
            let queue = Queue::at(start, false);
            let mut owner = queue.owner();
            assert!(matches!(owner.push_marked(0), Push::Pushed(1)));
            assert_eq!(queue.backlog(), Backlog::Lone(start, true));
            assert_eq!(owner.pop(), Some(0));

            // Move on without marking, then queue an unmarked value alone.
            let later = (start + advance) & REAL_MASK;
            queue.skip_to(later);
            push(&mut owner, 1);
            assert_eq!(queue.backlog(), Backlog::Lone(later, marked));
            let destination = Queue::shared();
            let mut into = destination.owner();
            let mut asked = None;
            let stolen = queue.steal_into_if(&mut into, |real, marked| {
                asked = Some((real, marked));
                false
            });
            assert_eq!(stolen, 0);
            assert_eq!(asked, Some((later, marked)));
            assert_eq!(owner.pop(), Some(1));
        }
    }

    /// A steal takes half the backlog rounded up, so a lone value is stolen,
    /// and `is_stealable` agrees.
    #[test]
    fn test_steal_takes_half_rounded_up() {
        for available in [1usize, 2, 3, 7, 8, 255, 256] {
            let source = Queue::shared();
            let destination = Queue::shared();
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..available);

            // The hint agrees with the steal, which takes half the backlog rounded up.
            let count = available.div_ceil(2);
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
        for (held, moved) in [
            (Widen::widen(HALF), CAPACITY / 2),
            (Widen::widen(HALF) + 1, 0),
        ] {
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

    /// A steal's claim records its count in the head, so until the release
    /// the owner has no room, a push into the full queue hands back only the
    /// new value, and a second claim backs off.
    #[test]
    fn test_claim_records_its_count_until_released() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY);

        // The claim takes the oldest half and leaves the owner the newest half
        // with no room, since the claim still holds its slots.
        let claim = queue
            .claim(|_, _| true)
            .expect("full queue must be claimable");
        assert_eq!(claim, (0, HALF));
        assert_eq!(owner.len(), CAPACITY / 2);
        assert_eq!(owner.room(), 0);

        // While the claim is held, a second claim backs off, the hint agrees,
        // and a push hands back only the new value.
        assert!(queue.claim(|_, _| true).is_none());
        assert!(!queue.is_stealable());
        assert!(matches!(owner.push(CAPACITY), Push::Claimed(value) if value == CAPACITY));

        // Reading and releasing the claim frees its slots.
        let mut seen = queue.finish_claim(claim);
        assert_eq!(owner.room(), CAPACITY / 2);

        // The claim and the owner together hold every value, in push order.
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A held claim does not block a push while the queue has a free slot.
    #[test]
    fn test_pending_claim_with_room_allows_a_push() {
        let queue = Queue::shared();
        let mut owner = queue.owner();
        owner.push_batch(0..CAPACITY - 1);

        // A claim on half the capacity leaves the last slot free, so the push
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
        match owner.push_with(CAPACITY, false, || {
            attempts += 1;
            if claim.is_none() {
                claim = Some(queue.hold_claim(HALF));
            }
        }) {
            Push::Claimed(value) => assert_eq!(value, CAPACITY),
            _ => panic!("retry must hand back only the new value"),
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
        let result = owner.push_with(CAPACITY, false, || {
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

        // The claim pins the room at zero, so even one value exceeds it.
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
            _ => panic!("full queue must overflow"),
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
                    _ => panic!("full queue must overflow"),
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
        // and pop after the first push and every third push after it to race
        // the thieves.
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

    /// An owner that pops almost every value as it pushes it keeps its queue
    /// a value or two deep, so steals contend with its pops for lone values.
    /// Every value is handed out once and dropped once.
    #[test]
    fn test_lone_values_race_two_thieves_for_every_value_once() {
        let total = if cfg!(miri) { 64 } else { 20_000 };
        let queue = Arc::new(Queue::<Counted>::shared());
        let mut owner = queue.owner();
        let done = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(3));
        let drops = Arc::new(AtomicUsize::new(0));

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

                    // Steal until a steal finds nothing after the owner is done.
                    loop {
                        if queue.steal_into(&mut into) > 0 {
                            seen.extend(drain(&mut into).into_iter().map(|value| value.0));
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

        let mut seen = Vec::new();
        barrier.wait();

        // Pop after all but every fourth push, so the queue stays a value or
        // two deep and most steals contend for a lone value.
        for value in 0..total {
            match owner.push(Counted(value, drops.clone())) {
                Push::Pushed(_) => {}
                Push::Claimed(value) => seen.push(value.0),
                Push::Overflow(batch, value) => {
                    seen.extend(batch.map(|value| value.0));
                    seen.push(value.0);
                }
            }
            if value % 4 != 0
                && let Some(value) = owner.pop()
            {
                seen.push(value.0);
            }
        }
        done.store(true, Ordering::Release);

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

    /// Lone values pushed and popped, then a refill that overflows and a
    /// drain, racing two steals, hand every value out once. In one run the
    /// lone values cross the position's wrap, in the other the refill and its
    /// overflow cross the count's wrap.
    #[test]
    fn test_lone_pops_refill_and_overflow_across_the_maximum_against_a_thief() {
        // Two positions before the position's wrap, the lone values cross it.
        // Four positions before the count's wrap, the lone values come before
        // it and the refill and its overflow straddle it.
        for start in [u64::from(u32::MAX) - 1, REAL_MASK - 3] {
            let mut builder = loom::model::Builder::new();
            builder.preemption_bound = Some(3);
            builder.check(move || {
                let queue = Queue::at(start, false);
                let mut owner = queue.owner();

                // The thief steals twice while the owner works.
                let thief = thread::spawn(move || {
                    let mut seen = steal_once(&queue);
                    seen.extend(steal_once(&queue));
                    seen
                });

                // Push and pop two lone values, which a steal can take first.
                let mut seen = Vec::new();
                for value in 0..2 {
                    collect_push(&mut owner, value, &mut seen);
                    seen.extend(owner.pop());
                }

                // Push one value more than the capacity, overflowing unless a
                // steal made room, then drain the rest.
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
    }

    /// An owner that drains and drops its queue while a thief holds a claim
    /// across the wrapping position leaves the claimed values to the thief,
    /// and every value is handed out once.
    #[test]
    fn test_owner_drops_while_a_thief_holds_a_claim() {
        loom::model(|| {
            // Fill a queue whose positions wrap past the maximum.
            let queue = Queue::at(u64::from(u32::MAX) - 1, false);
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
            let queue = Queue::at(u64::from(u32::MAX) - 1, false);
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

    /// A thief racing the owner's push and pop of a lone value: the pop's
    /// exchange and the claim's arbitrate, so exactly one of them takes the
    /// value, and nothing remains.
    #[test]
    fn test_lone_value_pop_against_a_thief() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let queue = Queue::shared();
            let mut owner = queue.owner();

            // The thief steals twice, taking the lone value at most once.
            let thief = thread::spawn(move || {
                let mut seen = steal_once(&queue);
                seen.extend(steal_once(&queue));
                seen
            });

            // The owner pushes and pops one value, so the queue never holds two.
            assert!(matches!(owner.push(7), Push::Pushed(1)));
            let mut seen: Vec<_> = owner.pop().into_iter().collect();

            // The value came out once, from the owner or from the thief.
            seen.extend(thief.join().unwrap());
            assert_eq!(seen, [7]);
            assert!(owner.is_empty());
        });
    }

    /// A thief that accepts only the lone value at the queue's first count
    /// races the owner, which pops that value and then pushes another, alone
    /// at the next count, here at zero and at the 55-bit maximum. The claim
    /// and the pop arbitrate the first value, so it comes out once, and the
    /// thief never takes the second, whose count it refuses whether its claim
    /// sees it first or after a failed exchange.
    #[test]
    fn test_lone_claim_takes_only_an_accepted_count() {
        for start in [0, REAL_MASK] {
            loom::model(move || {
                let queue = Queue::at(start, false);
                let mut owner = queue.owner();
                assert!(matches!(owner.push(0), Push::Pushed(1)));

                let thief = thread::spawn(move || {
                    let destination = Queue::shared();
                    let mut into = destination.owner();
                    let moved = queue.steal_into_if(&mut into, |real, _| real == start);
                    let seen = drain(&mut into);
                    assert_eq!(seen.len(), moved);
                    seen
                });

                let mut seen: Vec<_> = owner.pop().into_iter().collect();
                assert!(matches!(owner.push(1), Push::Pushed(_)));
                let stolen = thief.join().unwrap();
                assert!(!stolen.contains(&1), "a refused lone value was claimed");
                seen.extend(stolen);
                seen.extend(drain(&mut owner));
                seen.sort_unstable();
                assert_eq!(seen, [0, 1]);
            });
        }
    }

    /// A thief that accepts only marked lone values races its owner, which
    /// pops a marked value and then pushes an unmarked one, alone at the next
    /// count. The mark names only the count it was pushed at, so the thief
    /// never takes the second value, whether its claim sees it first or after
    /// a failed exchange, and the claim and the pop arbitrate the first.
    #[test]
    fn test_marked_lone_claim_takes_only_the_marked_value() {
        loom::model(|| {
            let queue = Queue::shared();
            let mut owner = queue.owner();
            assert!(matches!(owner.push_marked(0), Push::Pushed(1)));

            let thief = thread::spawn(move || {
                let destination = Queue::shared();
                let mut into = destination.owner();
                let moved = queue.steal_into_if(&mut into, |_, marked| marked);
                let seen = drain(&mut into);
                assert_eq!(seen.len(), moved);
                seen
            });

            let mut seen: Vec<_> = owner.pop().into_iter().collect();
            assert!(matches!(owner.push(1), Push::Pushed(_)));
            let stolen = thief.join().unwrap();
            assert!(!stolen.contains(&1), "an unmarked lone value was claimed");
            seen.extend(stolen);
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, [0, 1]);
        });
    }

    /// A thief that sees a marked value through the tail sees its mark as
    /// well, in the backlog hint and in the claim's decision, since the owner
    /// stores the mark before the tail store that publishes the value. Here at
    /// zero and at the 55-bit maximum, where the mark's count wraps.
    #[test]
    fn test_marked_value_is_published_with_its_mark() {
        for start in [0, REAL_MASK] {
            loom::model(move || {
                let queue = Queue::at(start, false);
                let mut owner = queue.owner();

                let thief = thread::spawn(move || {
                    if let Backlog::Lone(real, marked) = queue.backlog() {
                        assert_eq!(real, start);
                        assert!(marked, "the backlog showed the value without its mark");
                    }
                    let destination = Queue::shared();
                    let mut into = destination.owner();
                    let moved = queue.steal_into_if(&mut into, |real, marked| {
                        assert_eq!(real, start);
                        assert!(marked, "the claim saw the value without its mark");
                        true
                    });
                    let seen = drain(&mut into);
                    assert_eq!(seen.len(), moved);
                    seen
                });

                assert!(matches!(owner.push_marked(0), Push::Pushed(1)));
                let mut seen = thief.join().unwrap();
                seen.extend(drain(&mut owner));
                assert_eq!(seen, [0]);
            });
        }
    }

    /// A push into a full queue racing a steal overflows, retries, or moves
    /// only the new value, and every value is handed out once.
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
            match owner.push_with(CAPACITY, false, thread::yield_now) {
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

    /// A batch published into the room a released claim frees, as a take from
    /// the global queue publishes its share, writes the slots the thief read
    /// only after those reads, and every value comes out once.
    #[test]
    fn test_batch_after_a_release_reuses_the_claimed_slots() {
        loom::model(|| {
            let queue = Queue::shared();
            let mut owner = queue.owner();
            owner.push_batch(0..CAPACITY);

            // One steal claims the oldest half while the owner drains the rest.
            let thief = thread::spawn(move || steal_once(&queue));
            let mut seen = drain(&mut owner);

            // Fill the room the owner sees. Once the claim is released, that
            // room includes the slots the thief read.
            let room = owner.room();
            owner.push_batch(CAPACITY..CAPACITY + room);
            seen.extend(drain(&mut owner));

            // Every value comes out once, from the thief or from the owner.
            seen.extend(thief.join().unwrap());
            seen.sort_unstable();
            assert_eq!(seen, (0..CAPACITY + room).collect::<Vec<_>>());
        });
    }
}

//! A bounded ring of values in FIFO order, with one owner and shared thieves.
//!
//! Each pool worker's run queue is a [`Ring`] of its runnables. Only the
//! holder of its [`Owner`] pushes and pops. Other workers hold the shared
//! handle and steal half of an unclaimed backlog with [`Ring::steal_into`].
//!
//! # Positions
//!
//! Positions wrap as `u32` values, and a position selects its slot modulo
//! [`CAPACITY`]. The head packs `steal` in its high 32 bits and `real` in its
//! low 32 bits. The owner writes `tail`, pushes there, and pops at `real`. A
//! thief advances `real` to claim a batch, reads it, then lifts `steal` to the
//! current `real`. Owner pops may advance `real` during the claim, and a second
//! thief backs off while a claim is held.
//!
//! # Invariants
//!
//! The following invariants use wrapping distances, rather than numeric
//! comparisons of the indices:
//! - I1: `steal <= real <= tail` and `tail - steal <= CAPACITY`.
//! - I2: `[real, tail)` contains the ring's initialized values. An overflow
//!   iterator separately owns the removed newest half until it is exhausted.
//! - I3: `steal != real` means one claim holds `[steal, claim_end)`, where
//!   `claim_end` is the `real` its exchange stored. The owner's pops can move
//!   `real` beyond `claim_end` while the claim is held.
//! - I4: `[tail, steal + CAPACITY)` is free except for a live overflow's
//!   slots. Only the owner writes free slots, and a release store of `tail`
//!   publishes their values.
//! - I5: every value is read at most once, and its slot is written again
//!   only after that read.
//!
//! # Overflow
//!
//! A push into a full ring exchanges the head to `(tail, tail)`, taking every
//! value, then republishes the oldest half by storing `tail + CAPACITY / 2`:
//! in a full ring, the half ring of positions after the old tail maps onto the
//! oldest half's slots. The newest half is owned by an iterator borrowing the
//! owner, which excludes writes to those slots until it is consumed. A push
//! decides from one snapshot of the head whether it publishes, overflows, or
//! leaves the ring to a held claim, and retries when the exchange finds the
//! head moved.
//!
//! # Stealing
//!
//! A steal takes half the unclaimed backlog, rounded down, so a lone value
//! stays with its owner. It claims the values with one exchange on the head,
//! moves them into the thief's own ring, releases the claim, then publishes
//! them with one tail store. It goes only into a ring with at least half its
//! slots free, so the batch always fits. [`Ring::is_stealable`] is a hint about
//! the source's backlog. The claim checks the source again, and the steal also
//! checks the destination's room.
//!
//! Assumption A0: a thief does not stall between its head load and its claim
//! exchange while the indices advance through a full `2^32` positions, after
//! which the head could read as it did and the exchange succeed with a stale
//! count. Once the exchange succeeds the claim pins `steal`, so I1 bounds
//! further progress to `CAPACITY` positions. At one position per nanosecond,
//! the exposed window would need to exceed four seconds. An overflow advances
//! `real` by a full ring and `tail` by half a ring, so the assumption counts
//! positions rather than operations. A bound on the claim size alone would
//! not make a stale claim safe. The owner's own exchanges need no such
//! assumption: while it stalls it pushes nothing, so thieves can move `real`
//! no further than `tail`, and the head cannot return to the value the owner
//! loaded.
//!
//! # Pops without an exchange
//!
//! A ring built exclusive has no reader but its owner, so the owner pops with
//! plain loads and a store rather than an exchange, and [`Ring::steal_into`]
//! asserts that its source is shared. A pool of one worker has no other worker
//! to steal from its run queue, so its ring is exclusive.
//!
//! The owner of a shared ring also pops a lone value with a store when no claim
//! is held. A claim takes half the backlog, rounded down, so none takes a lone
//! value, and only the owner can push more, which its pop excludes. A thief
//! still expecting the pre-pop head needs a later tail publication to see two
//! values. That publication follows the head store, so acquiring the tail
//! orders the store before the thief's stale exchange, which fails under A0.
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

/// Number of slots in a ring, small under loom so models reach a full ring.
pub const CAPACITY: usize = if cfg!(feature = "loom") { 4 } else { 256 };

/// Half a ring: what an overflow keeps, as a position count.
const HALF: u32 = CAPACITY as u32 / 2;

/// Fewest values an unclaimed ring holds for a steal to take any, since a
/// steal takes half rounded down.
pub const STEALABLE: usize = 2;

/// Mask that selects a position's slot.
const MASK: usize = CAPACITY - 1;

// Positions select slots by masking, and a full ring's distance must fit in a
// wrapping `u32` comparison.
const _: () = assert!(CAPACITY.is_power_of_two() && CAPACITY < 1 << 31);

/// Shared indices and slots governed by invariants I1 through I5.
struct Inner<T> {
    /// `steal << 32 | real`: the oldest unreleased position and the next
    /// position the owner pops.
    head: AtomicU64,
    /// One past the newest published value, written only by the owner.
    tail: AtomicU32,
    /// Whether the unique owner has been taken.
    owned: AtomicBool,
    /// Whether no reader but the owner ever touches the ring, fixed at
    /// construction.
    exclusive: bool,
    /// Initialized only in the ranges owned by the ring or an overflow.
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

// SAFETY: I1 through I5 give each slot one writer and one reader, and the
// head and tail orderings transfer values between threads without overlap.
unsafe impl<T: Send> Sync for Inner<T> {}
// SAFETY: the ring owns its values and each value can move between threads.
unsafe impl<T: Send> Send for Inner<T> {}

/// Shared handle of a ring, through which thieves steal and from which its
/// owner is taken.
pub struct Ring<T>(Arc<CachePadded<Inner<T>>>);

/// Unique owner of a ring, movable between threads but never shared.
pub struct Owner<T>(Arc<CachePadded<Inner<T>>>, PhantomData<Cell<()>>);

/// Result of publishing a value into a ring.
pub enum Push<'a, T> {
    /// The value was published, with the length computed from the push's head
    /// snapshot. A concurrent claim can make this an overestimate.
    Pushed(usize),
    /// The ring was full: the newest half and the new value must be published
    /// elsewhere, in that order.
    Overflow(Overflow<'a, T>, T),
    /// No slot was free while a thief held a claim, so only the new value must
    /// move elsewhere.
    Claimed(T),
}

/// Newest half of a full ring, yielded oldest first.
///
/// The iterator must be exhausted before it is dropped. Its mutable borrow
/// excludes owner writes until every removed slot has been read.
pub struct Overflow<'a, T> {
    /// The ring's owner, borrowed until the batch is consumed.
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

impl<T> Ring<T> {
    /// An empty ring that thieves may steal from.
    pub fn shared() -> Self {
        Self::at(0, false)
    }

    /// An empty ring that no thief may steal from.
    pub fn exclusive() -> Self {
        Self::at(0, true)
    }

    /// An empty ring starting at a chosen wrapping position.
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

    /// Take the owner, panicking if it was already taken.
    pub fn owner(&self) -> Owner<T> {
        assert!(
            !self.0.owned.swap(true, Ordering::AcqRel),
            "ring already owned"
        );
        Owner(self.0.clone(), PhantomData)
    }

    /// Whether a snapshot shows no claim and at least [`STEALABLE`] values.
    /// Concurrent changes can make this hint stale before a steal claims them.
    pub fn is_stealable(&self) -> bool {
        // The head is loaded before the tail: the tail only grows, so the
        // distance cannot wrap to a huge backlog from a tail older than the
        // head.
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
    /// `into` with one tail store. Panics if `into` belongs to this ring or
    /// this ring is exclusive.
    #[must_use]
    pub fn steal_into(&self, into: &mut Owner<T>) -> usize {
        assert!(!self.0.exclusive, "cannot steal from an exclusive ring");
        assert!(
            !Arc::ptr_eq(&into.0, &self.0),
            "cannot steal into the source ring"
        );
        let tail = into.0.tail.load(Ordering::Relaxed);
        let (steal, _) = unpack(into.0.head.load(Ordering::Acquire));
        if tail.wrapping_sub(steal) > HALF {
            return 0;
        }
        let Some((first, count)) = self.claim() else {
            return 0;
        };
        for offset in 0..count {
            // SAFETY: the source claim owns this initialized slot (I3, I5).
            let value = unsafe { self.0.read(first.wrapping_add(offset)) };
            // SAFETY: the destination had half its slots free before the
            // claim, the owner is borrowed, and thieves only add room (I4).
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
            assert!(count <= HALF, "claim exceeds half a ring");
            let claimed = pack(steal, real.wrapping_add(count));
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
    /// current `real`, which owner pops may have moved past the claim.
    fn release_claim(&self, first: u32, count: u32) {
        let mut head = pack(first, first.wrapping_add(count));
        loop {
            let (_, real) = unpack(head);
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

    /// Publish a value, or hand back what a full ring cannot hold, as
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
            let head = self.0.head.load(Ordering::Acquire);
            let (steal, real) = unpack(head);
            let tail = self.0.tail.load(Ordering::Relaxed);
            after_snapshot();
            if tail.wrapping_sub(steal) < CAPACITY as u32 {
                // SAFETY: the acquired steal index excludes pending readers,
                // and the unpublished tail slot is free (I1, I4).
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
                "overflow requires a full ring"
            );
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
            // SAFETY: an exclusive ring has no reader but its owner, so this
            // initialized slot is the owner's alone, and the mutable borrow
            // excludes writes (I2, I5).
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
                // and the mutable borrow excludes writes (I2, I5).
                return Some(unsafe { self.0.read(real) });
            }
            let next = if steal == real {
                pack(next_real, next_real)
            } else {
                pack(steal, next_real)
            };
            match self
                .0
                .head
                .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    // SAFETY: the exchange gave the owner this initialized
                    // slot, and the mutable borrow excludes writes (I2, I5).
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
        assert!(count <= self.room(), "batch exceeds ring room");
        let tail = self.0.tail.load(Ordering::Relaxed);
        for offset in 0..count {
            let value = values.next().expect("batch shorter than its exact length");
            // SAFETY: room bounds this unpublished span, the owner is
            // borrowed, and pending claims cannot overlap it (I1, I4).
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
        // occupies disjoint slots (I2, I4, I5).
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
            assert!(self.is_empty(), "owner dropped a nonempty ring");
        }
    }
}

impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        // A claim or value still here when the last handle drops was leaked.
        if !thread::panicking() {
            let (steal, real) = unpack(self.head.load(Ordering::Relaxed));
            assert_eq!(steal, real, "ring dropped with a pending claim");
            assert_eq!(
                real,
                self.tail.load(Ordering::Relaxed),
                "ring dropped nonempty"
            );
        }
    }
}

/// Claims held by a test in place of a paused thief.
#[cfg(test)]
impl<T> Ring<T> {
    /// Claim the oldest `count` values as a thief paused after its claim
    /// exchange would hold them.
    pub(super) fn hold_claim(&self, count: u32) -> (u32, u32) {
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
    pub(super) fn finish_claim(&self, claim: (u32, u32)) -> Vec<T> {
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

#[cfg(all(test, not(feature = "loom")))]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Barrier, atomic::AtomicUsize, mpsc},
    };

    /// Push a value that must fit.
    fn push<T>(owner: &mut Owner<T>, value: T) {
        assert!(matches!(owner.push(value), Push::Pushed(_)));
    }

    /// Pop every value the owner holds.
    fn drain<T>(owner: &mut Owner<T>) -> Vec<T> {
        std::iter::from_fn(|| owner.pop()).collect()
    }

    /// Take every value from a ring whose owner is gone.
    fn take_unowned<T>(ring: &Ring<T>) -> Vec<T> {
        let (steal, real) = unpack(ring.0.head.load(Ordering::Acquire));
        assert_eq!(steal, real);
        let tail = ring.0.tail.load(Ordering::Acquire);
        let values = (0..tail.wrapping_sub(real))
            .map(|offset| {
                // SAFETY: the owner is gone and no claim is held, so this test
                // is the only reader of the ring's initialized values.
                unsafe { ring.0.read(real.wrapping_add(offset)) }
            })
            .collect();
        ring.0.head.store(pack(tail, tail), Ordering::Release);
        values
    }

    /// Counts its drops, so a value read twice or never shows.
    struct Counted(usize, Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Both ring kinds hold `CAPACITY` values in FIFO order, pushed one at a
    /// time or as a batch, and interleaved pops and pushes keep the order.
    #[test]
    fn test_fifo_up_to_capacity() {
        for ring in [Ring::shared(), Ring::exclusive()] {
            let mut owner = ring.owner();
            assert!(owner.is_empty());
            assert_eq!(owner.room(), CAPACITY);
            for value in 0..CAPACITY {
                match owner.push(value) {
                    Push::Pushed(len) => assert_eq!(len, value + 1),
                    _ => panic!("push before capacity overflowed"),
                }
            }
            assert_eq!(owner.len(), CAPACITY);
            assert_eq!(owner.room(), 0);
            assert_eq!(drain(&mut owner), (0..CAPACITY).collect::<Vec<_>>());
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
            let ring = Ring::at(u32::MAX - 7, exclusive);
            let mut owner = ring.owner();
            owner.push_batch(0..CAPACITY);
            assert_eq!(drain(&mut owner), (0..CAPACITY).collect::<Vec<_>>());
            owner.push_batch(0..CAPACITY);
            match owner.push(CAPACITY) {
                Push::Overflow(batch, value) => {
                    assert_eq!(
                        batch.collect::<Vec<_>>(),
                        (CAPACITY / 2..CAPACITY).collect::<Vec<_>>()
                    );
                    assert_eq!(value, CAPACITY);
                }
                _ => panic!("full wrapping ring did not overflow"),
            }
            assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
        }
    }

    /// A shared owner pops a lone value with a store, here at zero and across
    /// the maximum, leaving the ring empty and unclaimed.
    #[test]
    fn test_lone_value_pops_across_the_maximum() {
        for position in [0, u32::MAX] {
            let ring = Ring::at(position, false);
            let mut owner = ring.owner();
            push(&mut owner, 7);
            assert!(!ring.is_stealable());
            assert_eq!(owner.pop(), Some(7));
            let next = position.wrapping_add(1);
            assert_eq!(unpack(ring.0.head.load(Ordering::Acquire)), (next, next));
            assert!(!ring.is_stealable());
            assert!(owner.pop().is_none());
        }
    }

    /// An overflow hands out the newest half, then the new value, and keeps
    /// the oldest half with room for half a ring more.
    #[test]
    fn test_overflow_keeps_the_oldest_half() {
        for ring in [Ring::shared(), Ring::exclusive()] {
            let mut owner = ring.owner();
            owner.push_batch(0..CAPACITY);
            match owner.push(CAPACITY) {
                Push::Overflow(mut batch, value) => {
                    assert_eq!(batch.len(), CAPACITY / 2);
                    assert_eq!(batch.next(), Some(CAPACITY / 2));
                    assert_eq!(batch.len(), CAPACITY / 2 - 1);
                    let mut exported = vec![CAPACITY / 2];
                    exported.extend(batch);
                    exported.push(value);
                    assert_eq!(exported, (CAPACITY / 2..=CAPACITY).collect::<Vec<_>>());
                }
                _ => panic!("full ring did not overflow"),
            }
            assert_eq!(owner.len(), CAPACITY / 2);
            assert_eq!(owner.room(), CAPACITY / 2);
            owner.push_batch(CAPACITY + 1..CAPACITY + 1 + CAPACITY / 2);
            let mut expected = (0..CAPACITY / 2).collect::<Vec<_>>();
            expected.extend(CAPACITY + 1..CAPACITY + 1 + CAPACITY / 2);
            assert_eq!(drain(&mut owner), expected);
        }
    }

    /// A steal moves half a backlog between rings whose positions wrap past
    /// `u32::MAX`.
    #[test]
    fn test_steal_wraps_across_the_maximum() {
        let source = Ring::at(u32::MAX - 7, false);
        let destination = Ring::at(u32::MAX - 3, false);
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..CAPACITY);
        assert_eq!(source.steal_into(&mut into), CAPACITY / 2);
        let mut values = drain(&mut into);
        values.extend(drain(&mut owner));
        assert_eq!(values, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal takes half the backlog rounded down, so a lone value is never
    /// stolen, and `is_stealable` agrees.
    #[test]
    fn test_steal_takes_half_rounded_down() {
        for available in [1usize, 2, 3, 7, 8, 255, 256] {
            let source = Ring::shared();
            let destination = Ring::shared();
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..available);
            let count = available / 2;
            assert_eq!(source.is_stealable(), count != 0);
            assert_eq!(source.steal_into(&mut into), count);
            assert_eq!(drain(&mut into), (0..count).collect::<Vec<_>>());
            assert_eq!(drain(&mut owner), (count..available).collect::<Vec<_>>());
        }
    }

    /// A steal refuses a destination whose room a held claim pins at zero,
    /// even once its owner is empty, and proceeds after the release.
    #[test]
    fn test_steal_room_counts_a_pending_claim() {
        let source = Ring::shared();
        let destination = Ring::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(CAPACITY..2 * CAPACITY);
        into.push_batch(0..CAPACITY);
        let claim = destination.hold_claim(HALF);
        let mut seen = drain(&mut into);
        assert!(into.is_empty());
        assert_eq!(into.room(), 0);
        assert!(!destination.is_stealable());
        assert_eq!(source.steal_into(&mut into), 0);
        assert_eq!(owner.len(), CAPACITY);
        seen.extend(destination.finish_claim(claim));
        assert_eq!(into.room(), CAPACITY);
        assert_eq!(source.steal_into(&mut into), CAPACITY / 2);
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
            let source = Ring::shared();
            let destination = Ring::shared();
            let mut owner = source.owner();
            let mut into = destination.owner();
            owner.push_batch(0..CAPACITY);
            into.push_batch(CAPACITY..CAPACITY + held);
            assert_eq!(source.steal_into(&mut into), moved);
            let mut seen = drain(&mut into);
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, (0..CAPACITY + held).collect::<Vec<_>>());
        }
    }

    /// A push into a full ring under a claim hands back only the new value.
    #[test]
    fn test_full_ring_with_a_claim_moves_only_the_new_value() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY);
        let claim = ring.hold_claim(HALF);
        assert!(matches!(owner.push(CAPACITY), Push::Claimed(value) if value == CAPACITY));
        assert!(!ring.is_stealable());
        let mut seen = ring.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal takes nothing while another thief holds a claim.
    #[test]
    fn test_second_thief_backs_off_a_pending_claim() {
        let source = Ring::shared();
        let destination = Ring::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..CAPACITY);
        let claim = source.hold_claim(HALF);
        assert_eq!(source.steal_into(&mut into), 0);
        let mut seen = source.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A held claim does not block a push while the ring has a free slot.
    #[test]
    fn test_pending_claim_with_room_allows_a_push() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY - 1);
        let claim = ring.hold_claim(HALF);
        assert!(matches!(owner.push(CAPACITY - 1), Push::Pushed(len) if len == CAPACITY / 2));
        let mut seen = ring.finish_claim(claim);
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A claim taken after a full push's snapshot fails the overflow exchange,
    /// and the retry hands back only the new value.
    #[test]
    fn test_claim_between_push_snapshot_and_exchange_retries() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY);
        let mut claim = None;
        let mut attempts = 0;
        match owner.push_with(CAPACITY, || {
            attempts += 1;
            if claim.is_none() {
                claim = Some(ring.hold_claim(HALF));
            }
        }) {
            Push::Claimed(value) => assert_eq!(value, CAPACITY),
            _ => panic!("push did not retry after the new claim"),
        }
        assert_eq!(attempts, 2);
        let mut seen = ring.finish_claim(claim.unwrap());
        seen.extend(drain(&mut owner));
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// A steal that completes between a push's snapshot of a full ring and its
    /// decision makes room, so the push retries and publishes rather than
    /// overflowing from a stale snapshot.
    #[test]
    fn test_completed_steal_between_push_snapshot_and_exchange() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY);
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let thief = thread::spawn(move || {
            let destination = Ring::shared();
            let mut into = destination.owner();
            start_rx.recv().unwrap();
            assert_eq!(ring.steal_into(&mut into), CAPACITY / 2);
            let values = drain(&mut into);
            done_tx.send(()).unwrap();
            values
        });
        let mut first = true;
        let result = owner.push_with(CAPACITY, || {
            if first {
                first = false;
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            }
        });
        assert!(matches!(result, Push::Pushed(len) if len == CAPACITY / 2 + 1));
        drop(result);
        let mut seen = thief.join().unwrap();
        seen.extend(drain(&mut owner));
        seen.sort_unstable();
        assert_eq!(seen, (0..=CAPACITY).collect::<Vec<_>>());
    }

    /// A batch beyond the room panics and publishes nothing, whether queued
    /// values or a pending claim take the room.
    #[test]
    fn test_batch_asserts_room() {
        let ring = Ring::<usize>::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY - 1);
        assert!(catch_unwind(AssertUnwindSafe(|| owner.push_batch(0..2))).is_err());
        assert_eq!(drain(&mut owner), (0..CAPACITY - 1).collect::<Vec<_>>());

        // Popping past a held claim leaves the owner empty with no room.
        owner.push_batch(0..CAPACITY);
        let claim = ring.hold_claim(HALF);
        let mut seen = drain(&mut owner);
        assert!(owner.is_empty());
        assert!(
            catch_unwind(AssertUnwindSafe(
                || owner.push_batch(std::iter::once(CAPACITY))
            ))
            .is_err()
        );
        seen.extend(ring.finish_claim(claim));
        seen.sort_unstable();
        assert_eq!(seen, (0..CAPACITY).collect::<Vec<_>>());
    }

    /// Dropping an owner with a queued value panics on the owner's thread.
    #[test]
    fn test_nonempty_owner_drop_panics() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        push(&mut owner, 1);
        let result = catch_unwind(AssertUnwindSafe(|| drop(owner)));
        assert!(result.is_err());
        assert_eq!(take_unowned(&ring), [1]);
    }

    /// Dropping an overflow before it is exhausted panics.
    #[test]
    fn test_unexhausted_overflow_drop_panics() {
        let ring = Ring::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY);
        let result = catch_unwind(AssertUnwindSafe(|| match owner.push(CAPACITY) {
            Push::Overflow(batch, _) => drop(batch),
            _ => panic!("expected overflow"),
        }));
        assert!(result.is_err());
        assert_eq!(drain(&mut owner), (0..CAPACITY / 2).collect::<Vec<_>>());
    }

    /// An unwind through an unexhausted overflow and a nonempty owner does
    /// not panic again.
    #[test]
    fn test_unwinding_skips_drop_assertions() {
        assert!(
            catch_unwind(|| {
                let ring = Ring::shared();
                let mut owner = ring.owner();
                owner.push_batch(0..CAPACITY);
                let _batch = match owner.push(CAPACITY) {
                    Push::Overflow(batch, _) => batch,
                    _ => panic!("expected overflow"),
                };
                panic!("unwind with an unexhausted overflow");
            })
            .is_err()
        );
    }

    /// A ring hands out its owner once.
    #[test]
    fn test_second_owner_panics() {
        let ring = Ring::<usize>::shared();
        let _owner = ring.owner();
        assert!(catch_unwind(AssertUnwindSafe(|| ring.owner())).is_err());
    }

    /// A steal into the source ring panics.
    #[test]
    fn test_self_steal_panics() {
        let ring = Ring::<usize>::shared();
        let mut owner = ring.owner();
        assert!(catch_unwind(AssertUnwindSafe(|| ring.steal_into(&mut owner))).is_err());
    }

    /// A steal from an exclusive ring panics and leaves its values in place.
    #[test]
    fn test_steal_from_an_exclusive_ring_panics() {
        let source = Ring::exclusive();
        let destination = Ring::shared();
        let mut owner = source.owner();
        let mut into = destination.owner();
        owner.push_batch(0..4);
        assert!(catch_unwind(AssertUnwindSafe(|| source.steal_into(&mut into))).is_err());
        assert_eq!(drain(&mut owner), [0, 1, 2, 3]);
    }

    /// An owner pushing, popping and overflowing against two stealing threads
    /// hands every value out once and drops it once.
    #[test]
    fn test_owner_and_two_thieves_account_for_every_value_once() {
        let total = if cfg!(miri) { 64 } else { 4096 };
        let ring = Arc::new(Ring::<Counted>::shared());
        let mut owner = ring.owner();
        let done = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(3));
        let drops = Arc::new(AtomicUsize::new(0));
        let thieves: Vec<_> = (0..2)
            .map(|_| {
                let ring = ring.clone();
                let done = done.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let destination = Ring::shared();
                    let mut into = destination.owner();
                    let mut seen = Vec::new();
                    barrier.wait();
                    loop {
                        if ring.steal_into(&mut into) > 0 {
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
        let mut seen = Vec::new();
        barrier.wait();
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
        done.store(true, Ordering::Release);
        for thief in thieves {
            seen.extend(thief.join().unwrap());
        }
        seen.extend(drain(&mut owner).into_iter().map(|value| value.0));
        seen.sort_unstable();
        assert_eq!(seen, (0..total).collect::<Vec<_>>());
        assert_eq!(drops.load(Ordering::Relaxed), total);
    }

    /// Rings and owners move between threads, rings are shared, and owners
    /// are not.
    #[test]
    fn test_handles_are_send_and_the_owner_is_not_sync() {
        fn send<T: Send>() {}
        fn sync<T: Sync>() {}

        // Resolving the check is ambiguous exactly when the owner is Sync.
        trait AmbiguousIfSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        struct SyncMarker;
        impl<T: ?Sized + Sync> AmbiguousIfSync<SyncMarker> for T {}

        send::<Ring<Cell<usize>>>();
        sync::<Ring<Cell<usize>>>();
        send::<Owner<Cell<usize>>>();
        let _ = <Owner<usize> as AmbiguousIfSync<_>>::check;
    }
}

/// Loom models of the owner against thieves, through real rings with loom
/// cells, at a capacity of four.
#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// Pop every value the owner holds.
    fn drain<T>(owner: &mut Owner<T>) -> Vec<T> {
        std::iter::from_fn(|| owner.pop()).collect()
    }

    /// Push `value`, collecting whatever the ring hands back into `seen`.
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

    /// Steal once from `ring` into a fresh ring, returning every value taken.
    fn steal_once(ring: &Ring<usize>) -> Vec<usize> {
        let destination = Ring::shared();
        let mut into = destination.owner();
        let moved = ring.steal_into(&mut into);
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
            let ring = Ring::at(u32::MAX - 1, false);
            let mut owner = ring.owner();
            let thief = thread::spawn(move || {
                let mut seen = steal_once(&ring);
                seen.extend(steal_once(&ring));
                seen
            });
            let mut seen = Vec::new();
            for value in 0..2 {
                collect_push(&mut owner, value, &mut seen);
                seen.extend(owner.pop());
            }
            for value in 2..=CAPACITY + 2 {
                collect_push(&mut owner, value, &mut seen);
            }
            seen.extend(drain(&mut owner));
            seen.extend(thief.join().unwrap());
            seen.sort_unstable();
            assert_eq!(seen, (0..=CAPACITY + 2).collect::<Vec<_>>());
        });
    }

    /// An owner that drains and drops its ring while a thief holds a claim
    /// across the wrapping position leaves the claimed values to the thief,
    /// and every value is handed out once.
    #[test]
    fn test_owner_drops_while_a_thief_holds_a_claim() {
        loom::model(|| {
            let ring = Ring::at(u32::MAX - 1, false);
            let mut owner = ring.owner();
            owner.push_batch(0..CAPACITY);
            let claim = ring.hold_claim(HALF);
            let thief = thread::spawn(move || ring.finish_claim(claim));
            let mut seen = drain(&mut owner);
            drop(owner);
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
            let ring = Arc::new(Ring::shared());
            let mut owner = ring.owner();
            owner.push_batch(0..3);
            let thieves: Vec<_> = (0..2)
                .map(|_| {
                    let ring = ring.clone();
                    thread::spawn(move || steal_once(&ring))
                })
                .collect();
            let mut seen = Vec::new();
            seen.extend(owner.pop());
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
            let ring = Ring::at(u32::MAX - 1, false);
            let mut owner = ring.owner();
            owner.push_batch(0..2);
            let thief = thread::spawn(move || steal_once(&ring));
            let mut seen = Vec::new();
            seen.extend(owner.pop());
            seen.extend(owner.pop());
            collect_push(&mut owner, 2, &mut seen);
            collect_push(&mut owner, 3, &mut seen);
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
            let ring = Ring::shared();
            let mut owner = ring.owner();
            let thief = thread::spawn(move || {
                for _ in 0..2 {
                    assert!(!ring.is_stealable());
                    assert!(steal_once(&ring).is_empty());
                }
            });
            assert!(matches!(owner.push(7), Push::Pushed(1)));
            assert_eq!(owner.pop(), Some(7));
            thief.join().unwrap();
            assert!(owner.is_empty());
        });
    }

    /// A push into a full ring racing a steal overflows, retries, or moves
    /// only the new value, and every value is handed out once. The yield
    /// after the push's snapshot exposes the steal that completes before the
    /// push decides.
    #[test]
    fn test_full_overflow_against_a_thief() {
        loom::model(|| {
            let ring = Ring::shared();
            let mut owner = ring.owner();
            owner.push_batch(0..CAPACITY);
            let thief = thread::spawn(move || steal_once(&ring));
            let mut seen = Vec::new();
            match owner.push_with(CAPACITY, thread::yield_now) {
                Push::Pushed(_) => {}
                Push::Claimed(value) => seen.push(value),
                Push::Overflow(batch, value) => {
                    seen.extend(batch);
                    seen.push(value);
                }
            }
            seen.extend(thief.join().unwrap());
            seen.extend(drain(&mut owner));
            seen.sort_unstable();
            assert_eq!(seen, (0..=CAPACITY).collect::<Vec<_>>());
        });
    }

    /// Values a steal publishes in its own ring are visible to a third worker
    /// that steals from that ring, and the slots they vacate are reused.
    #[test]
    fn test_stolen_values_are_published_and_slots_reused() {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.check(|| {
            let sources: Vec<_> = (0..3).map(|_| Arc::new(Ring::shared())).collect();
            let mut owners: Vec<_> = sources.iter().map(|ring| ring.owner()).collect();
            for (index, owner) in owners.iter_mut().enumerate() {
                owner.push_batch(index * CAPACITY..(index + 1) * CAPACITY);
            }
            let destination = Arc::new(Ring::shared());
            let mut into = destination.owner();
            into.push_batch(100..102);
            let transferring = thread::spawn(move || {
                for ring in sources {
                    let _ = ring.steal_into(&mut into);
                }
                into
            });
            let stealing = thread::spawn(move || {
                let last = Ring::shared();
                let mut owner = last.owner();
                let mut seen = Vec::new();
                for _ in 0..3 {
                    let _ = destination.steal_into(&mut owner);
                    seen.extend(drain(&mut owner));
                }
                seen
            });
            let mut seen = stealing.join().unwrap();
            let mut into = transferring.join().unwrap();
            seen.extend(drain(&mut into));
            for owner in &mut owners {
                seen.extend(drain(owner));
            }
            seen.sort_unstable();
            let mut expected: Vec<_> = (0..3 * CAPACITY).collect();
            expected.extend(100..102);
            assert_eq!(seen, expected);
        });
    }
}

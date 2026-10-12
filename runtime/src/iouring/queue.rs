//! A bounded ring of values in FIFO order with one owner.
//!
//! Each pool worker's run queue is a [`Ring`] of its runnables. Only the
//! holder of its [`Owner`] pushes and pops.
//!
//! # Positions
//!
//! Positions wrap as `u32` values, and a position selects its slot modulo
//! [`CAPACITY`]. The owner writes `tail`, pushes there, and pops at `real`.
//! The head packs `steal` in its high 32 bits and `real` in its low 32 bits.
//! The two differ while a claim reserves the positions from `steal` for a
//! reader other than the owner, which the owner's pops and overflow respect.
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
//! # Pops without an exchange
//!
//! A ring built exclusive has no reader but its owner, so the owner pops with
//! plain loads and a store rather than an exchange. A pool of one worker has
//! no other worker to read its run queue, so its ring is exclusive.
//!
//! # Dropping handles
//!
//! The owner must remove its values before dropping. An overflow must be
//! exhausted before dropping. A nonempty owner or an unexhausted overflow
//! panics on drop unless the thread is already unwinding. These drops do not
//! destroy unread values, which may leak.

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

/// Shared handle of a ring, from which its owner is taken.
pub struct Ring<T>(Arc<CachePadded<Inner<T>>>);

/// Unique owner of a ring, movable between threads but never shared.
pub struct Owner<T>(Arc<CachePadded<Inner<T>>>, PhantomData<Cell<()>>);

/// Result of publishing a value into a ring.
pub enum Push<'a, T> {
    /// The value was published.
    Pushed,
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
    /// An empty ring that other workers may read.
    pub fn shared() -> Self {
        Self::at(0, false)
    }

    /// An empty ring that no reader but its owner ever touches.
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
                self.0.tail.store(tail.wrapping_add(1), Ordering::Release);
                return Push::Pushed;
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

#[cfg(all(test, not(feature = "loom")))]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Push a value that must fit.
    fn push<T>(owner: &mut Owner<T>, value: T) {
        assert!(matches!(owner.push(value), Push::Pushed));
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

    /// Both ring kinds hold `CAPACITY` values in FIFO order, pushed one at a
    /// time or as a batch, and interleaved pops and pushes keep the order.
    #[test]
    fn test_fifo_up_to_capacity() {
        for ring in [Ring::shared(), Ring::exclusive()] {
            let mut owner = ring.owner();
            assert!(owner.is_empty());
            assert_eq!(owner.room(), CAPACITY);
            for value in 0..CAPACITY {
                push(&mut owner, value);
                assert_eq!(owner.len(), value + 1);
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

    /// A batch beyond the room panics and publishes nothing.
    #[test]
    fn test_batch_asserts_room() {
        let ring = Ring::<usize>::shared();
        let mut owner = ring.owner();
        owner.push_batch(0..CAPACITY - 1);
        assert!(catch_unwind(AssertUnwindSafe(|| owner.push_batch(0..2))).is_err());
        assert_eq!(drain(&mut owner), (0..CAPACITY - 1).collect::<Vec<_>>());
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

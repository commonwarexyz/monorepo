//! Indexed 4-ary min-heap for registered timers.

use super::service::{Deadline, Entry, EntryArc, NOT_IN_HEAP};
#[cfg(feature = "loom")]
use loom::sync::atomic::Ordering;
#[cfg(not(feature = "loom"))]
use std::sync::atomic::Ordering;

/// Number of children assigned to each heap item.
const ARITY: usize = 4;

/// A timer and its ordering metadata.
pub(super) struct HeapItem {
    /// Fixed monotonic deadline for the timer.
    pub(super) deadline: Deadline,
    /// Sequence used to order timers with the same deadline.
    pub(super) sequence: u64,
    /// Shared timer state.
    pub(super) entry: EntryArc<Entry>,
}

impl HeapItem {
    /// Return whether this item belongs before another item.
    fn precedes(&self, other: &Self) -> bool {
        self.deadline < other.deadline
            || (self.deadline == other.deadline && self.sequence < other.sequence)
    }
}

/// An indexed 4-ary min-heap of registered timers.
#[derive(Default)]
pub(super) struct Heap {
    /// Heap items in breadth-first order.
    items: Vec<HeapItem>,
}

impl Heap {
    /// Return the number of resident timers.
    pub(super) const fn len(&self) -> usize {
        self.items.len()
    }

    /// Return the earliest timer without removing it.
    pub(super) fn peek(&self) -> Option<&HeapItem> {
        self.items.first()
    }

    /// Insert a timer in logarithmic time.
    ///
    /// # Panics
    ///
    /// Panics if the timer entry is already resident in a heap.
    pub(super) fn push(&mut self, item: HeapItem) {
        // Every heap-index access occurs while the owning shard mutex is held.
        // Relaxed ordering is sufficient because the mutex publishes mutations.
        assert_eq!(
            item.entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP,
            "timer entry is already in a heap"
        );

        let index = self.items.len();
        self.items.push(item);
        self.items[index]
            .entry
            .heap_index
            .store(index, Ordering::Relaxed);
        self.sift_up(index);
    }

    /// Remove and return the earliest timer in logarithmic time.
    pub(super) fn pop(&mut self) -> Option<HeapItem> {
        self.remove_at(0)
    }

    /// Remove the timer at `index` if it contains `expected`.
    ///
    /// Pointer identity prevents a stale index from removing a different timer.
    pub(super) fn remove(&mut self, index: usize, expected: &EntryArc<Entry>) -> Option<HeapItem> {
        if !self
            .items
            .get(index)
            .is_some_and(|item| EntryArc::ptr_eq(&item.entry, expected))
        {
            return None;
        }
        self.remove_at(index)
    }

    /// Remove and return an item by index without checking its identity.
    fn remove_at(&mut self, index: usize) -> Option<HeapItem> {
        if index >= self.items.len() {
            return None;
        }

        let removed = self.items.swap_remove(index);
        if index < self.items.len() {
            // `swap_remove` moved the tail into this slot, so publish its exact
            // index before restoring heap order through further indexed swaps.
            self.items[index]
                .entry
                .heap_index
                .store(index, Ordering::Relaxed);
            if parent_index(index)
                .is_some_and(|parent| self.items[index].precedes(&self.items[parent]))
            {
                self.sift_up(index);
            } else {
                self.sift_down(index);
            }
        }
        removed
            .entry
            .heap_index
            .store(NOT_IN_HEAP, Ordering::Relaxed);
        Some(removed)
    }

    /// Restore heap order by moving one item toward the root.
    fn sift_up(&mut self, mut index: usize) {
        while let Some(parent) = parent_index(index) {
            if !self.items[index].precedes(&self.items[parent]) {
                break;
            }
            self.swap(index, parent);
            index = parent;
        }
    }

    /// Restore heap order by moving one item toward the leaves.
    fn sift_down(&mut self, mut index: usize) {
        loop {
            let mut earliest = index;
            for offset in 0..ARITY {
                let Some(child) = child_index(index, offset) else {
                    break;
                };
                if child >= self.items.len() {
                    break;
                }
                if self.items[child].precedes(&self.items[earliest]) {
                    earliest = child;
                }
            }
            if earliest == index {
                break;
            }
            self.swap(index, earliest);
            index = earliest;
        }
    }

    /// Swap two items and publish both resulting indices.
    fn swap(&mut self, first: usize, second: usize) {
        self.items.swap(first, second);
        // The owning shard mutex orders these relaxed stores with cancellation.
        self.items[first]
            .entry
            .heap_index
            .store(first, Ordering::Relaxed);
        self.items[second]
            .entry
            .heap_index
            .store(second, Ordering::Relaxed);
    }
}

/// Return the parent index or `None` for the root.
const fn parent_index(index: usize) -> Option<usize> {
    match index.checked_sub(1) {
        Some(previous) => Some(previous / ARITY),
        None => None,
    }
}

/// Return one child index or `None` if the arithmetic would overflow.
const fn child_index(index: usize, offset: usize) -> Option<usize> {
    if offset >= ARITY {
        return None;
    }
    let Some(base) = index.checked_mul(ARITY) else {
        return None;
    };
    base.checked_add(offset + 1)
}

/// Unit tests for heap ordering and indexed removal.
#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use commonware_utils::TestRng;
    use rand::RngExt;
    use std::{sync::Arc, time::Duration};

    /// A timer retained by the reference model.
    struct LiveTimer {
        /// Deadline expressed as nanoseconds for convenient comparison.
        deadline: u64,
        /// Sequence used by the heap tie breaker.
        sequence: u64,
        /// Entry whose identity ties the model to the heap.
        entry: Arc<Entry>,
    }

    /// Create a deadline from a compact test value.
    const fn deadline(nanos: u64) -> Deadline {
        Deadline::from_duration(Duration::from_nanos(nanos))
    }

    /// Create a fresh heap item and return its shared entry.
    fn item(deadline_nanos: u64, sequence: u64) -> (Arc<Entry>, HeapItem) {
        let entry = Arc::new(Entry::new());
        let item = HeapItem {
            deadline: deadline(deadline_nanos),
            sequence,
            entry: Arc::clone(&entry),
        };
        (entry, item)
    }

    /// Return the comparable key of a heap item.
    const fn key(item: &HeapItem) -> (Duration, u64) {
        (item.deadline.as_duration(), item.sequence)
    }

    /// Assert heap order and every stored resident index.
    fn assert_invariants(heap: &Heap) {
        for (index, item) in heap.items.iter().enumerate() {
            assert_eq!(item.entry.heap_index.load(Ordering::Relaxed), index);
            for offset in 0..ARITY {
                let Some(child) = child_index(index, offset) else {
                    break;
                };
                if child >= heap.items.len() {
                    break;
                }
                assert!(!heap.items[child].precedes(item));
            }
        }
    }

    /// Remove the entry at `index` and verify its identity and resulting state.
    fn assert_remove_at(heap: &mut Heap, index: usize) {
        let expected_entry = Arc::clone(&heap.items[index].entry);
        let expected_key = key(&heap.items[index]);
        let removed = heap.remove(index, &expected_entry).expect("resident entry");

        assert!(Arc::ptr_eq(&removed.entry, &expected_entry));
        assert_eq!(key(&removed), expected_key);
        assert_eq!(
            expected_entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP
        );
        assert_invariants(heap);
    }

    /// Insert keys, verify every intermediate state, and verify pop order.
    fn assert_ordered(keys: &[(u64, u64)]) {
        let mut expected = keys.to_vec();
        expected.sort_unstable();

        let mut heap = Heap::default();
        for &(deadline, sequence) in keys {
            heap.push(item(deadline, sequence).1);
            assert_invariants(&heap);
        }

        for expected in expected {
            let popped = heap.pop().expect("expected a timer");
            assert_eq!(key(&popped), (Duration::from_nanos(expected.0), expected.1));
            assert_eq!(popped.entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
            assert_invariants(&heap);
        }
        assert_eq!(heap.len(), 0);
    }

    /// Basic inspection, popping, and positional removal preserve heap state.
    #[test]
    fn basic_operations_and_positional_removal() {
        // An empty heap has no head and accepts no removal.
        let mut heap = Heap::default();
        let missing = Arc::new(Entry::new());
        assert_eq!(heap.len(), 0);
        assert!(heap.peek().is_none());
        assert!(heap.pop().is_none());
        assert!(heap.remove(0, &missing).is_none());
        assert_eq!(missing.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);

        // Push and pop a singleton, checking its key, identity, and index.
        let (entry, singleton) = item(7, 11);
        heap.push(singleton);
        let head = heap.peek().expect("expected a head");
        assert!(Arc::ptr_eq(&head.entry, &entry));
        assert_eq!(key(head), (Duration::from_nanos(7), 11));
        assert_eq!(entry.heap_index.load(Ordering::Relaxed), 0);
        assert_invariants(&heap);

        let popped = heap.pop().expect("expected a timer");
        assert!(Arc::ptr_eq(&popped.entry, &entry));
        assert_eq!(key(&popped), (Duration::from_nanos(7), 11));
        assert_eq!(entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
        assert_invariants(&heap);

        // Remove a singleton by index, then remove three positions from a larger heap.
        heap.push(item(1, 0).1);
        assert_remove_at(&mut heap, 0);
        assert_eq!(heap.len(), 0);
        for value in (0..64).rev() {
            heap.push(item(value, value).1);
        }
        assert_invariants(&heap);

        assert_remove_at(&mut heap, 0);
        let middle_index = heap.len() / 2;
        assert_remove_at(&mut heap, middle_index);
        let final_index = heap.len() - 1;
        assert_remove_at(&mut heap, final_index);
    }

    /// Ascending, descending, equal, and wrapping insertions pop in order.
    #[test]
    fn insertion_shapes_and_pop_order() {
        // Exercise already ordered input, the worst insertion direction, and
        // equal deadlines whose order depends only on sequence.
        let ascending = (0..128).map(|value| (value, value)).collect::<Vec<_>>();
        assert_ordered(&ascending);

        let descending = (0..128)
            .rev()
            .map(|value| (value, value))
            .collect::<Vec<_>>();
        assert_ordered(&descending);

        let equal = (0..128)
            .rev()
            .map(|sequence| (42, sequence))
            .collect::<Vec<_>>();
        assert_ordered(&equal);

        // Place equal deadlines on both sides of u64 wrap plus distinct
        // deadlines that must still dominate the numeric sequence tie breaker.
        let wrapping = [
            (9, u64::MAX - 1),
            (9, u64::MAX),
            (9, 0),
            (9, 1),
            (8, 0),
            (10, u64::MAX),
        ];
        assert_ordered(&wrapping);
    }

    /// Replacing an arbitrary item with an earlier tail item sifts upward.
    #[test]
    fn removal_sifts_up() {
        // Arrange a heap where removing index five moves deadline ten beneath a
        // later parent, forcing the replacement toward the root.
        let mut heap = Heap::default();
        for value in [0, 100, 1, 2, 3, 101, 102, 103, 104, 10] {
            heap.push(item(value, value).1);
        }
        assert_invariants(&heap);

        let removed_entry = Arc::clone(&heap.items[5].entry);
        let tail_entry = Arc::clone(&heap.items[9].entry);
        assert!(heap.items[9].precedes(&heap.items[1]));

        // The replacement must settle at index one while all other indices and
        // parent ordering remain valid.
        let removed = heap
            .remove(5, &removed_entry)
            .expect("expected arbitrary entry");
        assert!(Arc::ptr_eq(&removed.entry, &removed_entry));
        assert_eq!(
            removed_entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP
        );
        assert_eq!(tail_entry.heap_index.load(Ordering::Relaxed), 1);
        assert_invariants(&heap);
    }

    /// Replacing the root with a later tail item sifts downward.
    #[test]
    fn removal_sifts_down() {
        // Ascending insertion leaves the final entry later than the root's
        // children, so root removal must move that replacement toward a leaf.
        let mut heap = Heap::default();
        for value in 0..10 {
            heap.push(item(value, value).1);
        }
        assert_invariants(&heap);

        let removed_entry = Arc::clone(&heap.items[0].entry);
        let tail_entry = Arc::clone(&heap.items[9].entry);
        assert!(heap.items[1].precedes(&heap.items[9]));

        // Verify the removed sentinel and that the replacement no longer
        // occupies the root after sift-down.
        let removed = heap.remove(0, &removed_entry).expect("expected root entry");
        assert!(Arc::ptr_eq(&removed.entry, &removed_entry));
        assert_eq!(
            removed_entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP
        );
        assert!(tail_entry.heap_index.load(Ordering::Relaxed) > 0);
        assert_invariants(&heap);
    }

    /// Stale, out-of-range, and identity-mismatched indices remove nothing.
    #[test]
    fn stale_and_mismatched_indices_are_rejected() {
        // Retain a valid index but pair it with the wrong identity, then prepare
        // out-of-range and sentinel indices for the same resident entry.
        let mut heap = Heap::default();
        for value in 0..16 {
            heap.push(item(value, value).1);
        }
        let original_len = heap.len();
        let victim = Arc::clone(&heap.items[5].entry);
        let stale_index = victim.heap_index.load(Ordering::Relaxed);
        let mismatched = Arc::new(Entry::new());

        // Invalid removal requests must not change length, ordering, or indices.
        assert!(heap.remove(stale_index, &mismatched).is_none());
        assert!(heap.remove(heap.len(), &victim).is_none());
        assert!(heap.remove(NOT_IN_HEAP, &victim).is_none());
        assert_eq!(heap.len(), original_len);
        assert_invariants(&heap);

        // A valid identity removes once. Reusing its stale index cannot remove
        // whichever entry later occupies that array slot.
        assert!(heap.remove(stale_index, &victim).is_some());
        assert_eq!(victim.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
        assert!(heap.remove(stale_index, &victim).is_none());
        assert_eq!(heap.len(), original_len - 1);
        assert_invariants(&heap);
    }

    /// Randomized operations match a simple identity-based reference model.
    #[test]
    fn randomized_operations_match_reference_model() {
        // Use deterministic randomness and begin near sequence wrap so the trace
        // combines insert, pop, indexed removal, and wrapping tie breakers.
        let mut rng = TestRng::new(0xb3bd_c9d9);
        let mut heap = Heap::default();
        let mut model = Vec::<LiveTimer>::new();
        let mut sequence = u64::MAX - 64;

        for _ in 0..20_000 {
            let insert = model.is_empty() || (model.len() < 128 && rng.random_bool(0.55));
            if insert {
                let deadline = rng.random_range(0..257);
                let (entry, item) = item(deadline, sequence);
                heap.push(item);
                model.push(LiveTimer {
                    deadline,
                    sequence,
                    entry,
                });
                sequence = sequence.wrapping_add(1);
            } else if rng.random_bool(0.5) {
                let expected_index = model
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, timer)| (timer.deadline, timer.sequence))
                    .map(|(index, _)| index)
                    .expect("reference model is not empty");
                let expected = model.swap_remove(expected_index);
                let popped = heap.pop().expect("heap matches reference length");
                assert!(Arc::ptr_eq(&popped.entry, &expected.entry));
                assert_eq!(
                    expected.entry.heap_index.load(Ordering::Relaxed),
                    NOT_IN_HEAP
                );
            } else {
                let model_index = rng.random_range(0..model.len());
                let expected = model.swap_remove(model_index);
                let heap_index = expected.entry.heap_index.load(Ordering::Relaxed);
                let removed = heap
                    .remove(heap_index, &expected.entry)
                    .expect("reference entry is resident");
                assert!(Arc::ptr_eq(&removed.entry, &expected.entry));
                assert_eq!(
                    expected.entry.heap_index.load(Ordering::Relaxed),
                    NOT_IN_HEAP
                );
            }

            // Every operation must preserve exact occupancy, parent ordering,
            // and each entry's published array index.
            assert_eq!(heap.len(), model.len());
            assert_invariants(&heap);
        }

        // Drain the remaining entries against the model to prove final pop order
        // and nonresident sentinel cleanup.
        while !model.is_empty() {
            let expected_index = model
                .iter()
                .enumerate()
                .min_by_key(|(_, timer)| (timer.deadline, timer.sequence))
                .map(|(index, _)| index)
                .expect("reference model is not empty");
            let expected = model.swap_remove(expected_index);
            let popped = heap.pop().expect("heap matches reference length");
            assert!(Arc::ptr_eq(&popped.entry, &expected.entry));
            assert_eq!(
                expected.entry.heap_index.load(Ordering::Relaxed),
                NOT_IN_HEAP
            );
            assert_invariants(&heap);
        }
        assert_eq!(heap.len(), 0);
    }

    /// Parent and child arithmetic handles roots and integer boundaries.
    #[test]
    fn index_arithmetic_boundaries() {
        // Cover the root, the first 4-ary boundary, and the integer limit.
        for (index, expected) in [
            (0, None),
            (1, Some(0)),
            (4, Some(0)),
            (5, Some(1)),
            (usize::MAX, Some((usize::MAX - 1) / ARITY)),
        ] {
            assert_eq!(parent_index(index), expected);
        }

        // Cover all root children, an invalid offset, and each overflow boundary.
        let edge_parent = usize::MAX / ARITY;
        for (index, offset, expected) in [
            (0, 0, Some(1)),
            (0, 1, Some(2)),
            (0, 2, Some(3)),
            (0, 3, Some(4)),
            (0, ARITY, None),
            (edge_parent, 0, Some(usize::MAX - 2)),
            (edge_parent, 1, Some(usize::MAX - 1)),
            (edge_parent, 2, Some(usize::MAX)),
            (edge_parent, 3, None),
            (edge_parent + 1, 0, None),
        ] {
            assert_eq!(child_index(index, offset), expected);
        }
    }

    /// Inserting one shared entry twice violates the resident-index invariant.
    #[test]
    #[should_panic(expected = "timer entry is already in a heap")]
    fn duplicate_entry_is_rejected() {
        // Insert one shared identity normally, then attempt to register the same
        // entry again under a different key.
        let mut heap = Heap::default();
        let entry = Arc::new(Entry::new());
        heap.push(HeapItem {
            deadline: deadline(1),
            sequence: 0,
            entry: Arc::clone(&entry),
        });
        heap.push(HeapItem {
            deadline: deadline(2),
            sequence: 1,
            entry,
        });
    }
}

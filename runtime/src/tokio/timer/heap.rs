//! Indexed 4-ary minimum heap owned by one timer shard.
//!
//! The heap is not internally synchronized. Its owning `ShardState`
//! mutex serializes every production operation and every residency use of
//! [`super::scheduler::Entry::heap_index`]. At each lock boundary, every resident
//! entry points to its exact vector slot, every nonresident entry stores
//! [`super::scheduler::NOT_IN_HEAP`], and no child precedes its parent.
//!
//! Insertion, minimum removal, and indexed removal take O(log n). Each swap
//! updates the reverse indices of the entries it moves. Indexed removal also
//! checks pointer identity, so a stale index cannot remove a different timer
//! that later occupies the same slot. Equal deadlines have no stable order.
//! Relaxed index atomics are sufficient because the shard mutex publishes all
//! residency changes.

use super::{
    scheduler::{Deadline, Entry, NOT_IN_HEAP},
    sync::EntryArc,
};
#[cfg(feature = "loom")]
use loom::sync::atomic::Ordering;
#[cfg(not(feature = "loom"))]
use std::sync::atomic::Ordering;

/// Number of children assigned to each heap item.
const ARITY: usize = 4;

/// A timer and its deadline.
struct Item {
    /// Fixed monotonic deadline for the timer.
    deadline: Deadline,
    /// Shared timer state.
    entry: EntryArc<Entry>,
}

impl Item {
    /// Return whether this item belongs before another item.
    fn precedes(&self, other: &Self) -> bool {
        self.deadline < other.deadline
    }
}

/// An indexed 4-ary min-heap of registered timers.
#[derive(Default)]
pub(super) struct Heap {
    /// Heap items in breadth-first order.
    items: Vec<Item>,
}

impl Heap {
    /// Return the number of resident timers.
    pub(super) const fn len(&self) -> usize {
        self.items.len()
    }

    /// Return the earliest deadline without removing its timer.
    pub(super) fn peek(&self) -> Option<Deadline> {
        self.items.first().map(|item| item.deadline)
    }

    /// Insert a timer.
    ///
    /// # Panics
    ///
    /// Panics if the timer entry is already resident in a heap.
    pub(super) fn push(&mut self, deadline: Deadline, entry: EntryArc<Entry>) {
        // Every heap-index access occurs while the owning shard mutex is held.
        // Relaxed ordering is sufficient because the mutex publishes mutations.
        assert_eq!(
            entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP,
            "timer entry is already in a heap"
        );

        let index = self.items.len();
        self.items.push(Item { deadline, entry });
        self.items[index]
            .entry
            .heap_index
            .store(index, Ordering::Relaxed);
        self.sift_up(index);
    }

    /// Remove and return the earliest timer entry.
    pub(super) fn pop(&mut self) -> Option<EntryArc<Entry>> {
        self.remove_at(0).map(|item| item.entry)
    }

    /// Remove the timer at `index` if it contains `expected`.
    ///
    /// Return true if the expected entry was removed and false otherwise.
    pub(super) fn remove(&mut self, index: usize, expected: &EntryArc<Entry>) -> bool {
        if !self.items.get(index).is_some_and(|item| {
            // Pointer identity prevents a stale index from removing a different timer.
            EntryArc::ptr_eq(&item.entry, expected)
        }) {
            return false;
        }

        self.remove_at(index)
            .expect("validated timer heap index disappeared");

        true
    }

    /// Remove and return an item by index without checking its identity.
    fn remove_at(&mut self, index: usize) -> Option<Item> {
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

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use commonware_utils::test_rng;
    use rand::RngExt;
    use std::{sync::Arc, time::Duration};

    /// A timer retained by the reference model.
    struct ModelItem {
        /// Deadline expressed as nanoseconds for convenient comparison.
        deadline: u64,
        /// Entry whose identity ties the model to the heap.
        entry: Arc<Entry>,
    }

    /// Create a deadline from a compact test value.
    const fn deadline(nanos: u64) -> Deadline {
        Deadline::from_duration(Duration::from_nanos(nanos))
    }

    /// Insert a fresh entry and return its shared identity.
    fn insert(heap: &mut Heap, deadline_nanos: u64) -> Arc<Entry> {
        let entry = Arc::new(Entry::new());
        heap.push(deadline(deadline_nanos), Arc::clone(&entry));
        entry
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

    /// Pops and verifies the minimum retained by the reference model.
    fn assert_pop_matches_model(heap: &mut Heap, model: &mut Vec<ModelItem>) {
        let expected_deadline = model
            .iter()
            .map(|timer| timer.deadline)
            .min()
            .expect("reference model is not empty");
        let popped = heap.pop().expect("heap matches reference length");
        let popped_index = model
            .iter()
            .position(|timer| Arc::ptr_eq(&popped, &timer.entry))
            .expect("popped entry is retained by the reference model");
        assert_eq!(model[popped_index].deadline, expected_deadline);
        let expected = model.swap_remove(popped_index);
        assert_eq!(
            expected.entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP
        );
    }

    /// Remove the entry at `index` and verify its identity and resulting state.
    fn assert_remove_at(heap: &mut Heap, index: usize) {
        let expected_entry = Arc::clone(&heap.items[index].entry);
        assert!(heap.remove(index, &expected_entry));
        assert_eq!(
            expected_entry.heap_index.load(Ordering::Relaxed),
            NOT_IN_HEAP
        );
        assert_invariants(heap);
    }

    /// Insert keys, verify every intermediate state, and verify pop order.
    fn assert_ordered(keys: &[u64]) {
        let mut expected = keys.to_vec();
        expected.sort_unstable();

        let mut heap = Heap::default();
        for &deadline in keys {
            insert(&mut heap, deadline);
            assert_invariants(&heap);
        }

        for expected in expected {
            assert_eq!(
                heap.items.first().map(|item| item.deadline.as_duration()),
                Some(Duration::from_nanos(expected))
            );
            let popped = heap.pop().expect("expected a timer");
            assert_eq!(popped.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
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
        assert!(!heap.remove(0, &missing));
        assert_eq!(missing.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);

        // Push and pop a singleton, checking its key, identity, and index.
        let entry = insert(&mut heap, 7);
        assert_eq!(heap.peek(), Some(deadline(7)));
        assert!(Arc::ptr_eq(&heap.items[0].entry, &entry));
        assert_eq!(
            heap.items[0].deadline.as_duration(),
            Duration::from_nanos(7)
        );
        assert_eq!(entry.heap_index.load(Ordering::Relaxed), 0);
        assert_invariants(&heap);

        let popped = heap.pop().expect("expected a timer");
        assert!(Arc::ptr_eq(&popped, &entry));
        assert_eq!(entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
        assert_invariants(&heap);

        // Remove a singleton by index, then remove three positions from a larger heap.
        insert(&mut heap, 1);
        assert_remove_at(&mut heap, 0);
        assert_eq!(heap.len(), 0);
        for value in (0..64).rev() {
            insert(&mut heap, value);
        }
        assert_invariants(&heap);

        assert_remove_at(&mut heap, 0);
        let middle_index = heap.len() / 2;
        assert_remove_at(&mut heap, middle_index);
        let final_index = heap.len() - 1;
        assert_remove_at(&mut heap, final_index);
    }

    /// Ascending, descending, and equal insertions pop in deadline order.
    #[test]
    fn insertion_shapes_and_pop_order() {
        // Exercise already ordered input, the worst insertion direction, and
        // equal deadlines that may pop in any identity order.
        let ascending = (0..128).collect::<Vec<_>>();
        assert_ordered(&ascending);

        let descending = (0..128).rev().collect::<Vec<_>>();
        assert_ordered(&descending);

        let equal = vec![42; 128];
        assert_ordered(&equal);

        let interleaved = [9, 9, 9, 9, 8, 10];
        assert_ordered(&interleaved);
    }

    /// Replacing an arbitrary item with an earlier tail item sifts upward.
    #[test]
    fn removal_sifts_up() {
        // Arrange a heap where removing index five moves deadline ten beneath a
        // later parent, forcing the replacement toward the root.
        let mut heap = Heap::default();
        for value in [0, 100, 1, 2, 3, 101, 102, 103, 104, 10] {
            insert(&mut heap, value);
        }
        assert_invariants(&heap);

        let removed_entry = Arc::clone(&heap.items[5].entry);
        let tail_entry = Arc::clone(&heap.items[9].entry);
        assert!(heap.items[9].precedes(&heap.items[1]));

        // The replacement must settle at index one while all other indices and
        // parent ordering remain valid.
        assert!(heap.remove(5, &removed_entry));
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
            insert(&mut heap, value);
        }
        assert_invariants(&heap);

        let removed_entry = Arc::clone(&heap.items[0].entry);
        let tail_entry = Arc::clone(&heap.items[9].entry);
        assert!(heap.items[1].precedes(&heap.items[9]));

        // Verify the removed sentinel and that the replacement no longer
        // occupies the root after sift-down.
        assert!(heap.remove(0, &removed_entry));
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
            insert(&mut heap, value);
        }
        let original_len = heap.len();
        let victim = Arc::clone(&heap.items[5].entry);
        let stale_index = victim.heap_index.load(Ordering::Relaxed);
        let mismatched = Arc::new(Entry::new());

        // Invalid removal requests must not change length, ordering, or indices.
        assert!(!heap.remove(stale_index, &mismatched));
        assert!(!heap.remove(heap.len(), &victim));
        assert!(!heap.remove(NOT_IN_HEAP, &victim));
        assert_eq!(heap.len(), original_len);
        assert_invariants(&heap);

        // A valid identity removes once. Reusing its stale index cannot remove
        // whichever entry later occupies that array slot.
        assert!(heap.remove(stale_index, &victim));
        assert_eq!(victim.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
        assert!(!heap.remove(stale_index, &victim));
        assert_eq!(heap.len(), original_len - 1);
        assert_invariants(&heap);
    }

    /// Randomized operations match a simple identity-based reference model.
    #[test]
    fn randomized_operations_match_reference_model() {
        // Use deterministic randomness so the trace combines insert, pop, and
        // indexed removal with many equal deadlines.
        let mut rng = test_rng();
        let mut heap = Heap::default();
        let mut model = Vec::<ModelItem>::new();

        for _ in 0..20_000 {
            let should_insert = model.is_empty() || (model.len() < 128 && rng.random_bool(0.55));
            if should_insert {
                let deadline = rng.random_range(0..257);
                let entry = insert(&mut heap, deadline);
                model.push(ModelItem { deadline, entry });
            } else if rng.random_bool(0.5) {
                assert_pop_matches_model(&mut heap, &mut model);
            } else {
                let model_index = rng.random_range(0..model.len());
                let expected = model.swap_remove(model_index);
                let heap_index = expected.entry.heap_index.load(Ordering::Relaxed);
                assert!(heap.remove(heap_index, &expected.entry));
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
            assert_pop_matches_model(&mut heap, &mut model);
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
        heap.push(deadline(1), Arc::clone(&entry));
        heap.push(deadline(2), entry);
    }
}

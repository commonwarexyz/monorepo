use super::*;
use commonware_utils::TestRng;
use rand::RngExt;
use std::time::Duration;

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
fn deadline(nanos: u64) -> Deadline {
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
fn key(item: &HeapItem) -> (Duration, u64) {
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

/// An empty heap has no head and accepts no removal.
#[test]
fn empty_heap_behavior() {
    // Start with no resident entries and an unrelated identity used for
    // removal attempts.
    let mut heap = Heap::default();
    let expected = Arc::new(Entry::new());

    // Empty inspection and every removal form must leave both the heap and
    // unrelated entry unchanged.
    assert_eq!(heap.len(), 0);
    assert!(heap.peek().is_none());
    assert!(heap.pop().is_none());
    assert!(heap.remove(0, &expected).is_none());
    assert!(heap.remove(NOT_IN_HEAP, &expected).is_none());
    assert_eq!(expected.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
}

/// One entry becomes the head and becomes nonresident when popped.
#[test]
fn one_entry() {
    // Insert a single entry so it must occupy both the head and index zero.
    let mut heap = Heap::default();
    let (entry, item) = item(7, 11);

    heap.push(item);
    assert_eq!(heap.len(), 1);
    assert!(Arc::ptr_eq(
        &heap.peek().expect("expected a head").entry,
        &entry
    ));
    assert_eq!(entry.heap_index.load(Ordering::Relaxed), 0);
    assert_invariants(&heap);

    // Popping the only entry must restore the nonresident sentinel exactly.
    let popped = heap.pop().expect("expected a timer");
    assert!(Arc::ptr_eq(&popped.entry, &entry));
    assert_eq!(entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    assert_eq!(heap.len(), 0);
}

/// Ascending, descending, equal, and randomized insertions pop in order.
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

    // Compare a larger deterministic random shape against sorted keys.
    let mut rng = TestRng::new(0x48ea_4f2d);
    let randomized = (0..1_000)
        .map(|sequence| (rng.random_range(0..257), sequence))
        .collect::<Vec<_>>();
    assert_ordered(&randomized);
}

/// Root, middle, final, and only-entry removal preserve all invariants.
#[test]
fn remove_positions() {
    // Verify the one-entry case independently because no tail replacement
    // or sift operation is available.
    let mut only = Heap::default();
    let (only_entry, only_item) = item(1, 0);
    only.push(only_item);
    let removed = only.remove(0, &only_entry).expect("expected only entry");
    assert!(Arc::ptr_eq(&removed.entry, &only_entry));
    assert_eq!(only_entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    assert_eq!(only.len(), 0);

    // Build a nontrivial shape, then remove root, interior, and tail entries.
    // Each removal must update the removed sentinel and every resident index.
    let mut heap = Heap::default();
    for value in (0..64).rev() {
        heap.push(item(value, value).1);
    }
    assert_invariants(&heap);

    let root = Arc::clone(&heap.items[0].entry);
    let removed = heap.remove(0, &root).expect("expected root");
    assert!(Arc::ptr_eq(&removed.entry, &root));
    assert_eq!(root.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    assert_invariants(&heap);

    let middle_index = heap.len() / 2;
    let middle = Arc::clone(&heap.items[middle_index].entry);
    let removed = heap
        .remove(middle_index, &middle)
        .expect("expected middle entry");
    assert!(Arc::ptr_eq(&removed.entry, &middle));
    assert_eq!(middle.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    assert_invariants(&heap);

    let final_index = heap.len() - 1;
    let final_entry = Arc::clone(&heap.items[final_index].entry);
    let removed = heap
        .remove(final_index, &final_entry)
        .expect("expected final entry");
    assert!(Arc::ptr_eq(&removed.entry, &final_entry));
    assert_eq!(final_entry.heap_index.load(Ordering::Relaxed), NOT_IN_HEAP);
    assert_invariants(&heap);
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

/// The numeric tie breaker remains a total order when a counter wraps.
#[test]
fn sequence_wrap_behavior() {
    // Place equal deadlines on both sides of u64 wrap plus distinct
    // deadlines that must still dominate the tie breaker.
    let keys = [
        (9, u64::MAX - 1),
        (9, u64::MAX),
        (9, 0),
        (9, 1),
        (8, 0),
        (10, u64::MAX),
    ];

    // Numeric sequence ordering may restart after wrap but must remain a
    // valid total heap order without corrupting indices.
    assert_ordered(&keys);
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
    // Check the root and both sides of the first 4-ary parent boundary.
    assert_eq!(parent_index(0), None);
    assert_eq!(parent_index(1), Some(0));
    assert_eq!(parent_index(4), Some(0));
    assert_eq!(parent_index(5), Some(1));
    assert_eq!(parent_index(usize::MAX), Some((usize::MAX - 1) / ARITY));

    // Check all four root children and reject an invalid child offset.
    assert_eq!(child_index(0, 0), Some(1));
    assert_eq!(child_index(0, 1), Some(2));
    assert_eq!(child_index(0, 2), Some(3));
    assert_eq!(child_index(0, 3), Some(4));
    assert_eq!(child_index(0, ARITY), None);

    // At the integer boundary, representable children succeed and every
    // overflowing multiplication or addition returns `None`.
    let edge_parent = usize::MAX / ARITY;
    assert_eq!(child_index(edge_parent, 0), Some(usize::MAX - 2));
    assert_eq!(child_index(edge_parent, 1), Some(usize::MAX - 1));
    assert_eq!(child_index(edge_parent, 2), Some(usize::MAX));
    assert_eq!(child_index(edge_parent, 3), None);
    assert_eq!(child_index(edge_parent + 1, 0), None);
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

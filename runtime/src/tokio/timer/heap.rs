//! Indexed 4-ary min-heap for registered timers.

use super::service::{Deadline, Entry, NOT_IN_HEAP};
use std::sync::{Arc, atomic::Ordering};

/// Number of children assigned to each heap item.
const ARITY: usize = 4;

/// A timer and its ordering metadata.
pub(super) struct HeapItem {
    /// Fixed monotonic deadline for the timer.
    pub(super) deadline: Deadline,
    /// Sequence used to order timers with the same deadline.
    pub(super) sequence: u64,
    /// Shared timer state.
    pub(super) entry: Arc<Entry>,
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
    pub(super) fn remove(&mut self, index: usize, expected: &Arc<Entry>) -> Option<HeapItem> {
        if !self
            .items
            .get(index)
            .is_some_and(|item| Arc::ptr_eq(&item.entry, expected))
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
#[cfg(test)]
mod tests;

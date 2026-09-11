//! Finalized blocks awaiting application dispatch.

use crate::types::Height;
use std::collections::BTreeMap;

/// Bounded staging that rejects heights below a monotonic retention minimum.
pub(super) struct Staged<B> {
    entries: BTreeMap<Height, B>,
    min: Height,
    max: usize,
}

impl<B> Staged<B> {
    /// Creates empty staging that holds at most `max` blocks.
    pub(super) const fn new(max: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            min: Height::zero(),
            max,
        }
    }

    /// Stages a block if its height is retained and capacity is available.
    /// Duplicate heights keep their existing block.
    pub(super) fn insert(&mut self, height: Height, block: B) {
        if height < self.min || self.entries.len() >= self.max {
            return;
        }
        self.entries.entry(height).or_insert(block);
    }

    /// Removes the staged block at `height` for dispatch.
    pub(super) fn remove(&mut self, height: Height) -> Option<B> {
        self.entries.remove(&height)
    }

    /// Retains entries at or above `min` and rejects future inserts below it.
    /// The retention minimum never decreases.
    pub(super) fn retain(&mut self, min: Height) {
        if min <= self.min {
            return;
        }
        self.min = min;
        while let Some(entry) = self.entries.first_entry()
            && *entry.key() < min
        {
            entry.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn insert_keeps_first_block_and_rejects_overflow() {
        let mut staged = Staged::new(2);
        let first = Arc::new(());
        staged.insert(Height::new(5), Arc::clone(&first));
        staged.insert(Height::new(5), Arc::new(()));
        staged.insert(Height::new(6), Arc::new(()));
        staged.insert(Height::new(7), Arc::new(()));
        assert!(staged.remove(Height::new(7)).is_none());
        assert!(
            staged
                .remove(Height::new(5))
                .is_some_and(|block| Arc::ptr_eq(&block, &first))
        );
        assert!(staged.remove(Height::new(6)).is_some());
    }

    #[test]
    fn retained_minimum_never_decreases() {
        let mut staged = Staged::new(2);
        let first = Arc::new(());
        let second = Arc::new(());
        staged.insert(Height::new(5), Arc::clone(&first));
        staged.insert(Height::new(6), Arc::clone(&second));

        staged.retain(Height::new(6));
        assert!(staged.remove(Height::new(5)).is_none());
        assert!(
            staged
                .remove(Height::new(6))
                .is_some_and(|block| Arc::ptr_eq(&block, &second))
        );

        // A stale retain cannot restore eligibility after all entries are removed
        staged.retain(Height::new(4));
        staged.insert(Height::new(5), first);
        staged.insert(Height::new(6), second);
        assert!(staged.remove(Height::new(5)).is_none());
        assert!(staged.remove(Height::new(6)).is_some());

        // Advancing an empty staging map still rejects late inserts
        staged.retain(Height::new(8));
        staged.insert(Height::new(7), Arc::new(()));
        staged.insert(Height::new(8), Arc::new(()));
        assert!(staged.remove(Height::new(7)).is_none());
        assert!(staged.remove(Height::new(8)).is_some());
    }
}

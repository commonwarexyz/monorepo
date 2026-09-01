//! Callers that share one unit of work, keyed by the work they wait for.

use commonware_utils::channel::oneshot;
use std::collections::{BTreeMap, btree_map::Entry};

/// Callers that share one unit of work per key.
///
/// Each key also holds state `S` created when its first caller arrives, such as a handle that
/// cancels the work when dropped. Removing a key drops its state.
pub(crate) struct Waiters<K, T, S = ()> {
    entries: BTreeMap<K, (Vec<oneshot::Sender<T>>, S)>,
    pending: usize,
}

impl<K: Ord, T, S> Waiters<K, T, S> {
    /// Returns an empty set of waiters.
    pub(crate) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            pending: 0,
        }
    }

    /// Returns the number of keys with at least one caller.
    pub(crate) fn keys(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of waiting callers across every key.
    pub(crate) const fn pending(&self) -> usize {
        self.pending
    }

    /// Adds a caller for `key` and returns whether `key` was new.
    ///
    /// For a new key, `start` creates the key's state.
    pub(crate) fn insert(
        &mut self,
        key: K,
        reply: oneshot::Sender<T>,
        start: impl FnOnce() -> S,
    ) -> bool {
        self.pending += 1;
        match self.entries.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.push(reply);
                false
            }
            Entry::Vacant(entry) => {
                entry.insert((vec![reply], start()));
                true
            }
        }
    }

    /// Drops closed callers of `key` and returns whether any caller remains, or `None` when `key`
    /// has no entry.
    ///
    /// A key left without callers is removed with its state.
    pub(crate) fn retain_open(&mut self, key: &K) -> Option<bool> {
        let (replies, _) = self.entries.get_mut(key)?;
        let before = replies.len();
        replies.retain(|reply| !reply.is_closed());
        let remaining = replies.len();
        self.pending = self
            .pending
            .checked_sub(before - remaining)
            .expect("dropped waiters were counted as pending");
        if remaining == 0 {
            self.entries.remove(key);
        }
        Some(remaining > 0)
    }

    /// Removes `key` and returns its callers.
    pub(crate) fn remove(&mut self, key: &K) -> Option<Vec<oneshot::Sender<T>>> {
        let (replies, _) = self.entries.remove(key)?;
        self.pending = self
            .pending
            .checked_sub(replies.len())
            .expect("removed waiters were counted as pending");
        Some(replies)
    }
}

impl<K: Ord, T: Clone, S> Waiters<K, T, S> {
    /// Removes `key` and sends `value` to each of its callers.
    pub(crate) fn complete(&mut self, key: &K, value: T) {
        for reply in self.remove(key).into_iter().flatten() {
            drop(reply.send(value.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callers_share_a_key_and_complete_together() {
        let mut waiters = Waiters::<u8, u32, u8>::new();
        let mut started = 0;
        let (first, mut first_receiver) = oneshot::channel();
        let (second, mut second_receiver) = oneshot::channel();
        let (other, mut other_receiver) = oneshot::channel();
        assert!(waiters.insert(1, first, || {
            started += 1;
            started
        }));
        assert!(!waiters.insert(1, second, || unreachable!("key 1 is already started")));
        assert!(waiters.insert(2, other, || 9));
        assert_eq!(waiters.keys(), 2);
        assert_eq!(waiters.pending(), 3);

        waiters.complete(&1, 7);
        assert_eq!(first_receiver.try_recv(), Ok(7));
        assert_eq!(second_receiver.try_recv(), Ok(7));
        assert_eq!(waiters.keys(), 1);
        assert_eq!(waiters.pending(), 1);

        let removed = waiters.remove(&2).expect("key 2 is registered");
        assert_eq!(removed.len(), 1);
        drop(removed);
        assert!(other_receiver.try_recv().is_err());
        assert_eq!(waiters.pending(), 0);
        assert!(waiters.remove(&2).is_none());
    }

    #[test]
    fn retain_open_drops_closed_callers_and_empty_keys() {
        let mut waiters = Waiters::<u8, u32>::new();
        let (first, first_receiver) = oneshot::channel();
        let (second, second_receiver) = oneshot::channel();
        waiters.insert(1, first, || ());
        waiters.insert(1, second, || ());
        drop(first_receiver);
        assert_eq!(waiters.retain_open(&1), Some(true));
        assert_eq!(waiters.pending(), 1);

        drop(second_receiver);
        assert_eq!(waiters.retain_open(&1), Some(false));
        assert_eq!(waiters.keys(), 0);
        assert_eq!(waiters.pending(), 0);
        assert_eq!(waiters.retain_open(&1), None);
    }
}

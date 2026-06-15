//! Track retained subscribers for keyed resolver demand.
//!
//! Resolver implementations commonly coalesce many local subscribers behind one
//! peer-visible key. This module owns the subscriber set bookkeeping while the
//! resolver decides how keys are fetched, retried, and delivered.

use commonware_utils::vec::NonEmptyVec;
use std::collections::{btree_map::Entry as BTreeMapEntry, BTreeMap, BTreeSet};

/// Retained subscribers for a key plus the span of the fetch that opened it.
#[derive(Clone, Debug)]
struct Entry<S> {
    span: tracing::Span,
    subscribers: BTreeSet<S>,
}

/// Tracks retained subscribers by resolver key.
#[derive(Clone, Debug)]
pub struct Tracker<K, S> {
    entries: BTreeMap<K, Entry<S>>,
}

impl<K, S> Default for Tracker<K, S> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K, S> Tracker<K, S>
where
    K: Clone + Ord,
    S: Clone + Ord,
{
    /// Create an empty subscriber tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if any subscriber is retained for the key.
    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Add subscribers for a key, deduplicating subscribers already retained.
    ///
    /// The span is retained only when the key entry is created; later fetches for
    /// the same key keep the original span.
    ///
    /// Returns `true` if this created a new key entry.
    pub fn insert(&mut self, key: K, subscribers: NonEmptyVec<S>, span: tracing::Span) -> bool {
        match self.entries.entry(key) {
            BTreeMapEntry::Vacant(entry) => {
                entry.insert(Entry {
                    span,
                    subscribers: subscribers.into_iter().collect(),
                });
                true
            }
            BTreeMapEntry::Occupied(mut entry) => {
                entry.get_mut().subscribers.extend(subscribers);
                false
            }
        }
    }

    /// Returns the span of the fetch that opened the key, or a disabled span if
    /// the key is not tracked.
    pub fn span(&self, key: &K) -> tracing::Span {
        self.entries
            .get(key)
            .map_or_else(tracing::Span::none, |entry| entry.span.clone())
    }

    /// Remove all subscribers for a key.
    ///
    /// Returns true if the key was present.
    pub fn remove(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Remove every tracked key.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Retain only subscribers for which the predicate returns true.
    ///
    /// Returns keys whose subscriber sets became empty and were removed.
    pub fn retain<F>(&mut self, mut predicate: F) -> Vec<K>
    where
        F: FnMut(&K, &S) -> bool,
    {
        let mut removed = Vec::new();
        self.entries.retain(|key, entry| {
            entry
                .subscribers
                .retain(|subscriber| predicate(key, subscriber));
            let keep = !entry.subscribers.is_empty();
            if !keep {
                removed.push(key.clone());
            }
            keep
        });
        removed
    }

    /// Return the subscribers currently waiting on a key.
    pub fn pending(&self, key: &K) -> Option<NonEmptyVec<S>> {
        self.entries
            .get(key)
            .and_then(|entry| Self::non_empty(&entry.subscribers))
    }

    /// Remove subscribers that just received a valid delivery.
    ///
    /// Returns remaining subscribers for the key, or `None` if the key is now
    /// complete or was not tracked.
    pub fn remove_delivered(
        &mut self,
        key: &K,
        delivered: NonEmptyVec<S>,
    ) -> Option<NonEmptyVec<S>> {
        let entry = self.entries.get_mut(key)?;
        for subscriber in delivered {
            entry.subscribers.remove(&subscriber);
        }
        if entry.subscribers.is_empty() {
            self.entries.remove(key);
            return None;
        }
        self.pending(key)
    }

    fn non_empty(subscribers: &BTreeSet<S>) -> Option<NonEmptyVec<S>> {
        NonEmptyVec::try_from(subscribers.iter().cloned().collect::<Vec<_>>()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::non_empty_vec;

    #[test]
    fn insert_merges_and_deduplicates_subscribers() {
        let mut tracker = Tracker::new();

        assert!(tracker.insert(1, non_empty_vec![10, 11], tracing::Span::none()));
        assert!(!tracker.insert(1, non_empty_vec![11, 12], tracing::Span::none()));

        assert_eq!(
            tracker.pending(&1).map(NonEmptyVec::into_vec),
            Some(vec![10, 11, 12])
        );
    }

    #[test]
    fn retain_prunes_subscribers_and_reports_removed_keys() {
        let mut tracker = Tracker::new();
        tracker.insert(1, non_empty_vec![11], tracing::Span::none());
        tracker.insert(2, non_empty_vec![20], tracing::Span::none());

        let removed = tracker.retain(|_, subscriber| *subscriber % 2 == 0);

        assert_eq!(removed, vec![1]);
        assert!(!tracker.contains(&1));
        assert_eq!(
            tracker.pending(&2).map(NonEmptyVec::into_vec),
            Some(vec![20])
        );
    }

    #[test]
    fn remove_delivered_returns_remaining_subscribers() {
        let mut tracker = Tracker::new();
        tracker.insert(1, non_empty_vec![10, 11, 12], tracing::Span::none());

        let remaining = tracker.remove_delivered(&1, non_empty_vec![10, 12]);

        assert_eq!(remaining.map(NonEmptyVec::into_vec), Some(vec![11]));
        assert!(tracker.contains(&1));
    }

    #[test]
    fn remove_delivered_removes_completed_key() {
        let mut tracker = Tracker::new();
        tracker.insert(1, non_empty_vec![10, 11], tracing::Span::none());

        assert!(tracker
            .remove_delivered(&1, non_empty_vec![10, 11])
            .is_none());
        assert!(!tracker.contains(&1));
    }

    #[test]
    fn span_retains_first_fetch_and_untracked_returns_disabled() {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry());

        let first = tracing::info_span!("test.first_fetch");
        let second = tracing::info_span!("test.second_fetch");
        let first_id = first.id();
        assert!(first_id.is_some());
        assert_ne!(first.id(), second.id());

        let mut tracker = Tracker::new();
        assert!(tracker.insert(1, non_empty_vec![10], first));
        assert!(!tracker.insert(1, non_empty_vec![11], second));

        assert_eq!(tracker.span(&1).id(), first_id);
        assert!(tracker.span(&2).is_disabled());
    }
}

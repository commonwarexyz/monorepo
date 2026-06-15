//! Track retained subscribers for keyed resolver demand.
//!
//! Resolver implementations commonly coalesce many local subscribers behind one
//! peer-visible key. This module owns the subscriber set bookkeeping while the
//! resolver decides how keys are fetched, retried, and delivered.

use commonware_utils::vec::NonEmptyVec;
use std::collections::{btree_map::Entry as BTreeMapEntry, BTreeMap};

/// Tracks retained subscribers by resolver key, each paired with the span of the
/// fetch that introduced it.
#[derive(Clone, Debug)]
pub struct Tracker<K, S> {
    entries: BTreeMap<K, BTreeMap<S, tracing::Span>>,
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

    /// Add subscribers for a key, each paired with the span of the fetch.
    ///
    /// A subscriber's span is retained only when the subscriber is first seen;
    /// later fetches for an already-tracked subscriber keep the original span.
    ///
    /// Returns `true` if this created a new key entry.
    pub fn insert(&mut self, key: K, subscribers: NonEmptyVec<S>, span: tracing::Span) -> bool {
        match self.entries.entry(key) {
            BTreeMapEntry::Vacant(entry) => {
                let subscribers = subscribers
                    .into_iter()
                    .map(|subscriber| (subscriber, span.clone()))
                    .collect();
                entry.insert(subscribers);
                true
            }
            BTreeMapEntry::Occupied(mut entry) => {
                let entry = entry.get_mut();
                for subscriber in subscribers {
                    entry.entry(subscriber).or_insert_with(|| span.clone());
                }
                false
            }
        }
    }

    /// Remove all subscribers for a key, closing their spans.
    ///
    /// Returns true if the key was present.
    pub fn remove(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Remove every tracked key, closing all spans.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Retain only subscribers for which the predicate returns true, closing the
    /// spans of the dropped subscribers.
    ///
    /// Returns keys whose subscriber sets became empty and were removed.
    pub fn retain<F>(&mut self, mut predicate: F) -> Vec<K>
    where
        F: FnMut(&K, &S) -> bool,
    {
        let mut removed = Vec::new();
        self.entries.retain(|key, subscribers| {
            subscribers.retain(|subscriber, _| predicate(key, subscriber));
            let keep = !subscribers.is_empty();
            if !keep {
                removed.push(key.clone());
            }
            keep
        });
        removed
    }

    /// Return the subscribers currently waiting on a key, each paired with the
    /// span of the fetch that introduced it.
    pub fn pending(&self, key: &K) -> Option<NonEmptyVec<(S, tracing::Span)>> {
        self.entries.get(key).and_then(Self::non_empty)
    }

    /// Remove subscribers that just received a valid delivery, closing their
    /// spans.
    ///
    /// Returns the remaining subscribers (with spans) for the key, or `None` if
    /// the key is now complete or was not tracked.
    pub fn remove_delivered(
        &mut self,
        key: &K,
        delivered: NonEmptyVec<S>,
    ) -> Option<NonEmptyVec<(S, tracing::Span)>> {
        let entry = self.entries.get_mut(key)?;
        for subscriber in delivered {
            entry.remove(&subscriber);
        }
        if entry.is_empty() {
            self.entries.remove(key);
            return None;
        }
        self.pending(key)
    }

    fn non_empty(
        subscribers: &BTreeMap<S, tracing::Span>,
    ) -> Option<NonEmptyVec<(S, tracing::Span)>> {
        NonEmptyVec::try_from(
            subscribers
                .iter()
                .map(|(subscriber, span)| (subscriber.clone(), span.clone()))
                .collect::<Vec<_>>(),
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::non_empty_vec;

    fn subscribers<S: Clone>(pending: Option<NonEmptyVec<(S, tracing::Span)>>) -> Option<Vec<S>> {
        pending.map(|pending| {
            pending
                .into_iter()
                .map(|(subscriber, _)| subscriber)
                .collect()
        })
    }

    #[test]
    fn insert_merges_and_deduplicates_subscribers() {
        let mut tracker = Tracker::new();

        assert!(tracker.insert(1, non_empty_vec![10, 11], tracing::Span::none()));
        assert!(!tracker.insert(1, non_empty_vec![11, 12], tracing::Span::none()));

        assert_eq!(subscribers(tracker.pending(&1)), Some(vec![10, 11, 12]));
    }

    #[test]
    fn retain_prunes_subscribers_and_reports_removed_keys() {
        let mut tracker = Tracker::new();
        tracker.insert(1, non_empty_vec![11], tracing::Span::none());
        tracker.insert(2, non_empty_vec![20], tracing::Span::none());

        let removed = tracker.retain(|_, subscriber| *subscriber % 2 == 0);

        assert_eq!(removed, vec![1]);
        assert!(!tracker.contains(&1));
        assert_eq!(subscribers(tracker.pending(&2)), Some(vec![20]));
    }

    #[test]
    fn remove_delivered_returns_remaining_subscribers() {
        let mut tracker = Tracker::new();
        tracker.insert(1, non_empty_vec![10, 11, 12], tracing::Span::none());

        let remaining = tracker.remove_delivered(&1, non_empty_vec![10, 12]);

        assert_eq!(subscribers(remaining), Some(vec![11]));
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
    fn each_subscriber_keeps_its_own_fetch_span() {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry());

        let first = tracing::info_span!("test.first_fetch");
        let second = tracing::info_span!("test.second_fetch");
        let first_id = first.id();
        let second_id = second.id();
        assert!(first_id.is_some());
        assert_ne!(first_id, second_id);

        let mut tracker = Tracker::new();
        assert!(tracker.insert(1, non_empty_vec![10], first));
        // The second fetch joins subscriber 11 under its own span and re-requests
        // 10, which keeps its original span.
        assert!(!tracker.insert(1, non_empty_vec![10, 11], second));

        let spans: BTreeMap<i32, Option<tracing::Id>> = tracker
            .pending(&1)
            .unwrap()
            .into_iter()
            .map(|(subscriber, span)| (subscriber, span.id()))
            .collect();
        assert_eq!(spans.get(&10), Some(&first_id));
        assert_eq!(spans.get(&11), Some(&second_id));

        assert!(tracker.pending(&2).is_none());
    }
}

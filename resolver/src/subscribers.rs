//! Track demand by key, metadata, and response channel identity.

use crate::Subscriber;
use commonware_utils::vec::NonEmptyVec;
use std::collections::BTreeMap;

/// The response receivers own the lifetime of these demand entries.
pub struct Tracker<K, S, R> {
    entries: BTreeMap<K, Vec<Subscriber<S, R>>>,
}

impl<K, S, R> Default for Tracker<K, S, R> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Clone + Ord, S: Clone + Eq, R> Tracker<K, S, R> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> Vec<K> {
        self.entries.keys().cloned().collect()
    }

    /// Add open response routes, retaining each route's original fetch span.
    /// Returns true only when a new key with live demand was inserted.
    pub fn insert(&mut self, key: K, subscribers: NonEmptyVec<Subscriber<S, R>>) -> bool {
        let new = !self.entries.contains_key(&key);
        for subscriber in subscribers {
            if subscriber.response.is_closed() {
                continue;
            }
            let entry = self.entries.entry(key.clone()).or_default();
            if !entry.contains(&subscriber) {
                entry.push(subscriber);
            }
        }
        new && self.entries.contains_key(&key)
    }

    pub fn remove(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Remove closed routes at this key and report whether demand remains.
    pub fn prune(&mut self, key: &K) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        entry.retain(|subscriber| !subscriber.response.is_closed());
        if entry.is_empty() {
            self.entries.remove(key);
            return false;
        }
        true
    }

    /// Return the open response routes at this key.
    pub fn pending(&mut self, key: &K) -> Option<NonEmptyVec<Subscriber<S, R>>> {
        if !self.prune(key) {
            return None;
        }
        Some(NonEmptyVec::from_unchecked(
            self.entries.get(key).expect("live key").clone(),
        ))
    }

    /// Reclaim abandoned keys during the resolver's periodic idle sweep.
    pub fn prune_closed(&mut self) -> Vec<K> {
        let mut removed = Vec::new();
        self.entries.retain(|key, entry| {
            entry.retain(|subscriber| !subscriber.response.is_closed());
            if entry.is_empty() {
                removed.push(key.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// Retire only the exact delivered routes, preserving replacement channels.
    pub fn remove_delivered(
        &mut self,
        key: &K,
        delivered: NonEmptyVec<Subscriber<S, R>>,
    ) -> Option<NonEmptyVec<Subscriber<S, R>>> {
        self.entries
            .get_mut(key)?
            .retain(|subscriber| !delivered.contains(subscriber));
        self.pending(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{channel::mpsc, non_empty_vec};

    fn subscriber(value: u16) -> (Subscriber<u16, u8>, mpsc::Receiver<u8>) {
        subscriber_with_span(value, tracing::Span::none())
    }

    fn subscriber_with_span(
        value: u16,
        span: tracing::Span,
    ) -> (Subscriber<u16, u8>, mpsc::Receiver<u8>) {
        let (response, receiver) = mpsc::channel(1);
        (
            Subscriber {
                subscriber: value,
                response,
                span,
            },
            receiver,
        )
    }

    fn values(pending: Option<NonEmptyVec<Subscriber<u16, u8>>>) -> Option<Vec<u16>> {
        pending.map(|pending| {
            pending
                .into_iter()
                .map(|subscriber| subscriber.subscriber)
                .collect()
        })
    }

    #[test]
    fn insert_merges_and_deduplicates_exact_routes() {
        let mut tracker = Tracker::new();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(11);

        assert!(tracker.insert(1, non_empty_vec![first.clone(), second.clone()]));
        assert!(!tracker.insert(1, non_empty_vec![first, second]));

        assert_eq!(values(tracker.pending(&1)), Some(vec![10, 11]));
    }

    #[test]
    fn equal_metadata_on_independent_channels_is_not_deduplicated() {
        let mut tracker = Tracker::new();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(10);

        assert!(tracker.insert(1, non_empty_vec![first]));
        assert!(!tracker.insert(1, non_empty_vec![second]));

        let pending = tracker.pending(&1).unwrap();
        assert_eq!(pending.len().get(), 2);
        assert!(!pending[0].response.same_channel(&pending[1].response));
    }

    #[test]
    fn different_metadata_on_the_same_channel_is_not_deduplicated() {
        let mut tracker = Tracker::new();
        let (first, _receiver) = subscriber(10);
        let second = Subscriber {
            subscriber: 11,
            response: first.response.clone(),
            span: tracing::Span::none(),
        };

        assert!(tracker.insert(1, non_empty_vec![first]));
        assert!(!tracker.insert(1, non_empty_vec![second]));

        assert_eq!(values(tracker.pending(&1)), Some(vec![10, 11]));
    }

    #[test]
    fn receiver_drop_prunes_routes_and_reports_abandoned_keys() {
        let mut tracker = Tracker::new();
        let (closed, closed_receiver) = subscriber(11);
        let (live, _live_receiver) = subscriber(20);
        tracker.insert(1, non_empty_vec![closed]);
        tracker.insert(2, non_empty_vec![live]);
        drop(closed_receiver);

        assert_eq!(tracker.prune_closed(), vec![1]);
        assert!(!tracker.contains(&1));
        assert_eq!(values(tracker.pending(&2)), Some(vec![20]));
    }

    #[test]
    fn pending_prunes_only_closed_routes() {
        let mut tracker = Tracker::new();
        let (closed, closed_receiver) = subscriber(10);
        let (live, _live_receiver) = subscriber(11);
        tracker.insert(1, non_empty_vec![closed, live]);
        drop(closed_receiver);

        assert_eq!(values(tracker.pending(&1)), Some(vec![11]));
        assert!(tracker.prune(&1));
    }

    #[test]
    fn remove_delivered_returns_remaining_routes() {
        let mut tracker = Tracker::new();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(11);
        let (third, _third_receiver) = subscriber(12);
        tracker.insert(1, non_empty_vec![first.clone(), second, third.clone()]);

        let remaining = tracker.remove_delivered(&1, non_empty_vec![first, third]);

        assert_eq!(values(remaining), Some(vec![11]));
        assert!(tracker.contains(&1));
    }

    #[test]
    fn remove_delivered_removes_completed_key() {
        let mut tracker = Tracker::new();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(11);
        tracker.insert(1, non_empty_vec![first.clone(), second.clone()]);

        assert!(
            tracker
                .remove_delivered(&1, non_empty_vec![first, second])
                .is_none()
        );
        assert!(!tracker.contains(&1));
    }

    #[test]
    fn replacement_with_same_metadata_survives_old_completion() {
        let mut tracker = Tracker::new();
        let (old, _old_receiver) = subscriber(10);
        tracker.insert(1, non_empty_vec![old]);
        let delivered = tracker.pending(&1).unwrap();

        let (replacement, _replacement_receiver) = subscriber(10);
        let replacement_response = replacement.response.clone();
        tracker.insert(1, non_empty_vec![replacement]);

        let remaining = tracker.remove_delivered(&1, delivered).unwrap();
        assert_eq!(remaining.len().get(), 1);
        assert!(remaining[0].response.same_channel(&replacement_response));
    }

    #[test]
    fn each_route_keeps_its_own_fetch_span() {
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry());

        let first_span = tracing::info_span!("test.first_fetch");
        let second_span = tracing::info_span!("test.second_fetch");
        let first_id = first_span.id();
        let second_id = second_span.id();
        assert!(first_id.is_some());
        assert_ne!(first_id, second_id);

        let (first, _first_receiver) = subscriber_with_span(10, first_span);
        let first_again = Subscriber {
            subscriber: first.subscriber,
            response: first.response.clone(),
            span: second_span.clone(),
        };
        let (second, _second_receiver) = subscriber_with_span(11, second_span);

        let mut tracker = Tracker::new();
        assert!(tracker.insert(1, non_empty_vec![first]));
        assert!(!tracker.insert(1, non_empty_vec![first_again, second]));

        let spans: BTreeMap<u16, Option<tracing::Id>> = tracker
            .pending(&1)
            .unwrap()
            .into_iter()
            .map(|subscriber| (subscriber.subscriber, subscriber.span.id()))
            .collect();
        assert_eq!(spans.get(&10), Some(&first_id));
        assert_eq!(spans.get(&11), Some(&second_id));
        assert!(tracker.pending(&2).is_none());
    }
}

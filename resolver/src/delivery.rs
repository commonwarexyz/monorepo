//! Track pending consumer deliveries for resolver implementations.
//!
//! Resolvers often need the same delivery lifecycle: keep a fetch alive while
//! `Consumer::deliver` validates a response, abort that validation if the fetch
//! is pruned, and reuse an accepted response for subscribers that were added
//! while validation was in progress. This module owns that lifecycle without
//! making assumptions about how data is fetched.

use crate::{Consumer, Delivery};
use commonware_utils::futures::{AbortablePool, Aborter};
use futures::future::Aborted;
use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap},
};

/// Completed consumer validation for a delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion<K, S, Context = ()> {
    /// Resolver-specific context associated with the delivery attempt.
    pub context: Context,

    /// Key and subscribers that were passed to the consumer.
    pub delivery: Delivery<K, S>,

    /// Whether the consumer accepted the response as valid for the key.
    pub valid: bool,
}

struct Response<Context, V> {
    context: Context,
    value: V,
    accepted: bool,
}

struct Entry<Context, V> {
    delivery: Option<Aborter>,
    response: Option<Response<Context, V>>,
}

impl<Context, V> Entry<Context, V> {
    const fn new() -> Self {
        Self {
            delivery: None,
            response: None,
        }
    }
}

/// Tracks in-flight consumer deliveries keyed by resolver key.
///
/// `Context` carries resolver-specific metadata back to the caller when
/// validation completes. A P2P resolver can use it for the peer that sent the
/// response; another resolver can use it for a local attempt identifier.
pub struct Tracker<Con, Context = ()>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    Context: Clone + Send + 'static,
{
    entries: HashMap<Con::Key, Entry<Context, Con::Value>>,
    deliveries: AbortablePool<Completion<Con::Key, Con::Subscriber, Context>>,
    consumer: Con,
}

impl<Con, Context> Tracker<Con, Context>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    Context: Clone + Send + 'static,
{
    /// Create an empty tracker backed by the provided consumer.
    pub fn new(consumer: Con) -> Self {
        Self {
            entries: HashMap::new(),
            deliveries: AbortablePool::default(),
            consumer,
        }
    }

    /// Returns true when the key has an active tracked fetch.
    pub fn contains(&self, key: &Con::Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Start tracking a key.
    ///
    /// Returns `true` when the key was inserted. If the key is already tracked,
    /// this leaves the existing entry untouched and returns `false`.
    pub fn insert(&mut self, key: Con::Key) -> bool {
        match self.entries.entry(key) {
            HashMapEntry::Vacant(entry) => {
                entry.insert(Entry::new());
                true
            }
            HashMapEntry::Occupied(_) => false,
        }
    }

    /// Remove a key and abort any in-progress delivery for it.
    ///
    /// Returns true if the key was present. Any completion produced by an
    /// aborted delivery is discarded by [`next_completion`](Self::next_completion).
    pub fn remove(&mut self, key: &Con::Key) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Retain only entries for which the predicate returns true.
    ///
    /// Dropped entries abort in-progress deliveries. Returns the number of
    /// removed entries.
    pub fn retain<F: FnMut(&Con::Key) -> bool>(&mut self, mut predicate: F) -> usize {
        let removed: Vec<_> = self
            .entries
            .extract_if(|key, _| !predicate(key))
            .collect();
        removed.len()
    }

    /// Remove all entries and abort all in-progress deliveries.
    ///
    /// Returns the number of entries removed.
    pub fn drain(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    /// Deliver a newly received response to the consumer.
    ///
    /// The response is cached so that, after the consumer accepts it, later
    /// retained subscribers can be redelivered the same bytes with
    /// [`redeliver`](Self::redeliver). Panics if the key is not tracked.
    pub fn deliver(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        context: Context,
        value: Con::Value,
    ) {
        let key = delivery.key.clone();
        let entry = self.entries.get_mut(&key).expect("delivery entry");
        entry.response = Some(Response {
            context: context.clone(),
            value: value.clone(),
            accepted: false,
        });
        self.push_delivery(delivery, context, value);
    }

    /// Deliver the cached response to another set of subscribers.
    ///
    /// This is intended for subscribers added while the first validation was still
    /// pending. Panics if the key is not tracked, no response is cached, or the
    /// cached response has not yet been accepted.
    pub fn redeliver(&mut self, delivery: Delivery<Con::Key, Con::Subscriber>) {
        let key = delivery.key.clone();
        let context = {
            let entry = self.entries.get(&key).expect("delivery entry");
            let response = entry.response.as_ref().expect("response");
            response.context.clone()
        };
        self.redeliver_with_context(delivery, context);
    }

    /// Deliver the cached response with new completion metadata.
    ///
    /// Use this when each local delivery attempt needs a fresh identifier even
    /// though every attempt uses the same cached response bytes.
    pub fn redeliver_with_context(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        context: Context,
    ) {
        let key = delivery.key.clone();
        let value = {
            let entry = self.entries.get(&key).expect("delivery entry");
            let response = entry.response.as_ref().expect("response");
            assert!(response.accepted, "accepted response");
            response.value.clone()
        };
        self.push_delivery(delivery, context, value);
    }

    /// Returns true if the cached response for this key has been accepted.
    pub fn response_accepted(&self, key: &Con::Key) -> bool {
        self.entries
            .get(key)
            .and_then(|entry| entry.response.as_ref())
            .is_some_and(|response| response.accepted)
    }

    /// Mark the cached response accepted by the consumer.
    ///
    /// Panics if the key is not tracked or no response is cached.
    pub fn accept_response(&mut self, key: &Con::Key) {
        let entry = self.entries.get_mut(key).expect("delivery entry");
        let response = entry.response.as_mut().expect("response");
        response.accepted = true;
    }

    /// Drop the cached response without removing the tracked key.
    ///
    /// Use this after a consumer rejects a response and the resolver wants to
    /// retry the same key with different bytes or metadata.
    pub fn discard_response(&mut self, key: &Con::Key) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.response = None;
        }
    }

    /// Wait for the next consumer validation result.
    ///
    /// Returns [`Aborted`] when the delivery was canceled before completion.
    /// Successful completions clear the active delivery slot for that key so it
    /// can be retried or redelivered.
    pub async fn next_completion(
        &mut self,
    ) -> Result<Completion<Con::Key, Con::Subscriber, Context>, Aborted> {
        let completed = self.deliveries.next_completed().await?;
        let Some(entry) = self.entries.get_mut(&completed.delivery.key) else {
            return Err(Aborted);
        };
        entry.delivery = None;
        Ok(completed)
    }

    fn push_delivery(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        context: Context,
        value: Con::Value,
    ) {
        let key = delivery.key.clone();
        let completed = delivery.clone();
        let mut consumer = self.consumer.clone();
        let receiver = consumer.deliver(delivery, value);
        let aborter = self.deliveries.push(async move {
            Completion {
                context,
                delivery: completed,
                valid: receiver.await.unwrap_or(false),
            }
        });
        let entry = self.entries.get_mut(&key).expect("delivery entry");
        assert!(entry.delivery.replace(aborter).is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::{Consumer as MockConsumer, Key as MockKey};
    use bytes::Bytes;
    use commonware_runtime::{deterministic::Runner, Runner as _};
    use commonware_utils::non_empty_vec;

    type TestTracker = Tracker<MockConsumer<MockKey, Bytes>, u8>;

    fn delivery(key: MockKey) -> Delivery<MockKey, ()> {
        Delivery {
            key,
            subscribers: non_empty_vec![()],
        }
    }

    #[test]
    fn test_insert_contains_remove_round_trip() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let mut tracker = TestTracker::new(MockConsumer::dummy());

            assert!(!tracker.contains(&MockKey(1)));
            assert!(tracker.insert(MockKey(1)));
            assert!(tracker.contains(&MockKey(1)));

            assert!(!tracker.insert(MockKey(1)));
            assert!(tracker.remove(&MockKey(1)));
            assert!(!tracker.contains(&MockKey(1)));
            assert!(!tracker.remove(&MockKey(1)));
        });
    }

    #[test]
    fn test_deliver_completes_with_context_and_consumer_result() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(7);
            let value = Bytes::from("data");

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 9, value.clone());

            let completed = tracker
                .next_completion()
                .await
                .expect("delivery should complete");
            assert_eq!(completed.context, 9);
            assert_eq!(completed.delivery.key, key);
            assert!(completed.valid);

            let (delivered_key, delivered_value) = events.recv().await.unwrap();
            assert_eq!(delivered_key, key);
            assert_eq!(delivered_value, value);
        });
    }

    #[test]
    fn test_remove_aborts_in_flight_delivery() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(1);

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 2, Bytes::from("v"));
            assert!(tracker.remove(&key));

            assert!(matches!(tracker.next_completion().await, Err(Aborted)));
        });
    }

    #[test]
    fn test_redeliver_reuses_accepted_response_for_new_subscribers() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(5);
            let value = Bytes::from("first");

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 3, value.clone());

            let completed = tracker
                .next_completion()
                .await
                .expect("first delivery should complete");
            assert!(completed.valid);
            tracker.accept_response(&key);
            assert!(tracker.response_accepted(&key));

            tracker.redeliver(delivery(key.clone()));
            let redelivered = tracker
                .next_completion()
                .await
                .expect("redelivery should complete");
            assert_eq!(redelivered.context, 3);
            assert_eq!(redelivered.delivery.key, key);
            assert!(redelivered.valid);

            let first = events.recv().await.unwrap();
            let second = events.recv().await.unwrap();
            assert_eq!(first, (key.clone(), value.clone()));
            assert_eq!(second, (key, value));
        });
    }

    #[test]
    fn test_redeliver_with_context_overrides_completion_context() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(6);

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 3, Bytes::from("first"));
            let completed = tracker
                .next_completion()
                .await
                .expect("first delivery should complete");
            assert_eq!(completed.context, 3);
            tracker.accept_response(&key);

            tracker.redeliver_with_context(delivery(key), 4);
            let redelivered = tracker
                .next_completion()
                .await
                .expect("redelivery should complete");
            assert_eq!(redelivered.context, 4);
        });
    }

    #[test]
    #[should_panic(expected = "accepted response")]
    fn test_redeliver_requires_accepted_response() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(7);

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 3, Bytes::from("first"));
            let completed = tracker
                .next_completion()
                .await
                .expect("first delivery should complete");
            assert!(completed.valid);

            tracker.redeliver(delivery(key));
        });
    }

    #[test]
    fn test_rejected_response_can_be_discarded_and_replaced() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (mut consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let key = MockKey(8);
            consumer.add_expected(key.clone(), Bytes::from("good"));
            let mut tracker = TestTracker::new(consumer);

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone()), 1, Bytes::from("bad"));
            let rejected = tracker
                .next_completion()
                .await
                .expect("rejected delivery should complete");
            assert!(!rejected.valid);

            tracker.discard_response(&key);
            assert!(!tracker.response_accepted(&key));
            tracker.deliver(delivery(key.clone()), 2, Bytes::from("good"));

            let accepted = tracker
                .next_completion()
                .await
                .expect("accepted delivery should complete");
            assert_eq!(accepted.context, 2);
            assert!(accepted.valid);
        });
    }
}

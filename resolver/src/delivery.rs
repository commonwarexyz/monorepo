//! Track pending consumer deliveries for resolver implementations.
//!
//! Resolvers often need the same delivery lifecycle: keep a fetch alive while
//! `Consumer::deliver` validates a response, abort that validation if the fetch
//! is pruned, and reuse a cached response for subscribers that were added
//! while validation was in progress. This module owns that lifecycle without
//! making assumptions about how data is fetched.

use crate::{Consumer, Delivery, Outcome};
use commonware_utils::{
    channel::mpsc,
    futures::{AbortablePool, Aborter},
};
use futures::future::Aborted;
use std::collections::{HashMap, hash_map::Entry as HashMapEntry};

/// Completed consumer validation for a delivery.
pub struct Completion<K, S, R, Context = ()> {
    /// Resolver-specific context associated with the delivery attempt.
    pub context: Context,

    /// Key and subscribers that were passed to the consumer.
    pub delivery: Delivery<K, S, R>,

    /// Consumer disposition for the delivered response, or `None` if the
    /// consumer abstained.
    pub outcome: Option<Outcome>,
}

// Cached response that can be redelivered while it is accepted or still unjudged.
struct Response<Context, V> {
    context: Context,
    value: V,
    accepted: bool,
}

// Active validation attempt for a key.
struct ActiveDelivery<R> {
    responses: Vec<mpsc::Sender<R>>,
    generation: u64,
    _aborter: Aborter,
}

// Pooled validation result tagged with the attempt that produced it.
struct PooledCompletion<Con: Consumer, Context> {
    generation: u64,
    completion: Completion<Con::Key, Con::Subscriber, Con::Response, Context>,
}

// Per-key delivery state retained while a resolver fetch is active.
struct Entry<Con: Consumer, Context, State> {
    delivery: Option<ActiveDelivery<Con::Response>>,
    response: Option<Response<Context, Con::Value>>,
    state: Option<State>,
}

impl<Con: Consumer, Context, State> Entry<Con, Context, State> {
    const fn new(state: State) -> Self {
        Self {
            delivery: None,
            response: None,
            state: Some(state),
        }
    }
}

/// Tracks in-flight consumer deliveries keyed by resolver key.
///
/// `Context` carries resolver-specific metadata back to the caller when
/// validation completes.
///
/// `State` holds per-key resolver state that should be dropped when the key is
/// pruned, or explicitly taken when the resolver completes the fetch.
pub struct Tracker<Con, Context = (), State = ()>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    Context: Clone + Send + 'static,
{
    entries: HashMap<Con::Key, Entry<Con, Context, State>>,
    deliveries: AbortablePool<'static, PooledCompletion<Con, Context>>,
    next_generation: u64,
    consumer: Con,
}

impl<Con, Context, State> Tracker<Con, Context, State>
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
            next_generation: 0,
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
    pub(crate) fn insert_with_state(&mut self, key: Con::Key, state: State) -> bool {
        match self.entries.entry(key) {
            HashMapEntry::Vacant(entry) => {
                entry.insert(Entry::new(state));
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

    /// Remove a key, aborting any in-progress delivery, and return its state.
    ///
    /// Returns `None` if the key was absent. The inner `Option` is `None` if the
    /// state was already taken while the key stayed active.
    pub(crate) fn remove_with_state(&mut self, key: &Con::Key) -> Option<Option<State>> {
        self.entries.remove(key).map(|entry| entry.state)
    }

    /// Take the key's state without removing the tracked key.
    ///
    /// Returns `None` when the key is absent or the state was already taken.
    pub(crate) fn take_state(&mut self, key: &Con::Key) -> Option<State> {
        self.entries
            .get_mut(key)
            .and_then(|entry| entry.state.take())
    }

    /// Abort an abandoned delivery snapshot while keeping its cached response.
    /// Later live routes can receive that response under a fresh generation.
    pub fn cancel_closed_delivery(&mut self, key: &Con::Key) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        if entry
            .delivery
            .as_ref()
            .is_some_and(|delivery| delivery.responses.iter().all(mpsc::Sender::is_closed))
        {
            entry.delivery = None;
            return true;
        }
        false
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
    /// The response is cached so that later retained subscribers can be
    /// redelivered the same bytes with [`redeliver`](Self::redeliver) once the
    /// consumer accepts it or drops its verdict. Panics if the key is not tracked.
    pub fn deliver(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber, Con::Response>,
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
    /// This is intended for subscribers added while an earlier validation was
    /// still pending. The cached response is either accepted or still unjudged
    /// because the consumer dropped the earlier verdict. Panics if the key is not
    /// tracked or no response is cached.
    pub fn redeliver(&mut self, delivery: Delivery<Con::Key, Con::Subscriber, Con::Response>) {
        let key = delivery.key.clone();
        let (context, value) = {
            let entry = self.entries.get(&key).expect("delivery entry");
            let response = entry.response.as_ref().expect("response");
            (response.context.clone(), response.value.clone())
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
    /// Use this when a response is invalid or does not satisfy every delivered
    /// subscriber and the resolver wants to retry the key.
    pub fn discard_response(&mut self, key: &Con::Key) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.response = None;
        }
    }

    /// Wait for the next consumer validation result.
    ///
    /// Returns [`Aborted`] when the delivery was canceled before completion. A
    /// consumer that abstains completes with no outcome.
    /// Successful completions clear the active delivery slot for that key so it
    /// can be retried or redelivered. Completions for an older same-key delivery
    /// are treated as aborted.
    pub async fn next_completion(
        &mut self,
    ) -> Result<Completion<Con::Key, Con::Subscriber, Con::Response, Context>, Aborted> {
        let completed = self.deliveries.next_completed().await?;
        let Some(entry) = self.entries.get_mut(&completed.completion.delivery.key) else {
            return Err(Aborted);
        };
        if entry
            .delivery
            .as_ref()
            .is_none_or(|delivery| delivery.generation != completed.generation)
        {
            return Err(Aborted);
        }
        entry.delivery = None;
        Ok(completed.completion)
    }

    // Start a consumer validation attempt and record its abort handle.
    fn push_delivery(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber, Con::Response>,
        context: Context,
        value: Con::Value,
    ) {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("delivery generation overflow");
        let key = delivery.key.clone();
        let responses = delivery
            .subscribers
            .iter()
            .map(|subscriber| subscriber.response.clone())
            .collect();
        let completed = delivery.clone();
        let mut consumer = self.consumer.clone();
        let receiver = consumer.deliver(delivery, value);
        let aborter = self.deliveries.push(async move {
            let outcome = receiver.await.map(Into::into);
            PooledCompletion {
                generation,
                completion: Completion {
                    context,
                    delivery: completed,
                    outcome,
                },
            }
        });
        let entry = self.entries.get_mut(&key).expect("delivery entry");
        assert!(
            entry
                .delivery
                .replace(ActiveDelivery {
                    responses,
                    generation,
                    _aborter: aborter,
                })
                .is_none()
        );
    }
}

impl<Con, Context> Tracker<Con, Context>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    Context: Clone + Send + 'static,
{
    /// Start tracking a key without any resolver-specific state.
    ///
    /// Returns `true` when the key was inserted. If the key is already tracked,
    /// this leaves the existing entry untouched and returns `false`.
    pub fn insert(&mut self, key: Con::Key) -> bool {
        self.insert_with_state(key, ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::{Consumer as MockConsumer, Key as MockKey};
    use bytes::Bytes;
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{
        channel::{fallible::FallibleExt, mpsc, oneshot},
        non_empty_vec,
    };
    use std::future::Future;

    type TestTracker = Tracker<MockConsumer<MockKey, Bytes>, u8>;

    fn delivery(
        key: MockKey,
        responses: &mut Vec<mpsc::Receiver<()>>,
    ) -> Delivery<MockKey, (), ()> {
        let (response, receiver) = mpsc::channel(1);
        responses.push(receiver);
        Delivery {
            key,
            subscribers: non_empty_vec![crate::Subscriber {
                subscriber: (),
                response,
                span: tracing::Span::none(),
            }],
        }
    }

    #[derive(Clone)]
    struct PendingConsumer {
        sender: mpsc::UnboundedSender<oneshot::Sender<bool>>,
    }

    impl PendingConsumer {
        fn new() -> (Self, mpsc::UnboundedReceiver<oneshot::Sender<bool>>) {
            let (sender, receiver) = mpsc::unbounded_channel();
            (Self { sender }, receiver)
        }
    }

    impl Consumer for PendingConsumer {
        type Key = MockKey;
        type Value = Bytes;
        type Subscriber = ();
        type Response = ();
        type Outcome = bool;

        fn deliver(
            &mut self,
            _delivery: Delivery<Self::Key, Self::Subscriber, Self::Response>,
            _value: Self::Value,
        ) -> impl Future<Output = Option<bool>> + Send + 'static {
            let (sender, receiver) = oneshot::channel();
            self.sender.send_lossy(sender);
            async move { receiver.await.ok() }
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
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 9, value.clone());

            let completed = tracker
                .next_completion()
                .await
                .expect("delivery should complete");
            assert_eq!(completed.context, 9);
            assert_eq!(completed.delivery.key, key);
            assert_eq!(completed.outcome, Some(Outcome::Complete));

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
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 2, Bytes::from("v"));
            assert!(tracker.remove(&key));

            assert!(matches!(tracker.next_completion().await, Err(Aborted)));
        });
    }

    #[test]
    fn test_stale_same_key_completion_does_not_clear_new_delivery() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut senders) = PendingConsumer::new();
            let mut tracker = Tracker::<PendingConsumer, u8>::new(consumer);
            let key = MockKey(1);
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 1, Bytes::from("old"));
            let old_sender = senders.recv().await.unwrap();
            old_sender.send(true).unwrap();
            let stale = tracker.deliveries.next_completed().await.unwrap();

            assert!(tracker.remove(&key));
            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 2, Bytes::from("new"));
            let new_sender = senders.recv().await.unwrap();

            let _stale_aborter = tracker.deliveries.push(async move { stale });
            assert!(matches!(tracker.next_completion().await, Err(Aborted)));

            new_sender.send(true).unwrap();
            let completed = tracker
                .next_completion()
                .await
                .expect("new delivery should complete");
            assert_eq!(completed.context, 2);
            assert_eq!(completed.delivery.key, key);
            assert_eq!(completed.outcome, Some(Outcome::Complete));
        });
    }

    #[test]
    fn test_cancel_closed_delivery_preserves_cache_and_rejects_stale_completion() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut verdicts) = PendingConsumer::new();
            let mut tracker = Tracker::<PendingConsumer, u8>::new(consumer);
            let key = MockKey(2);
            let mut old_responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(
                delivery(key.clone(), &mut old_responses),
                1,
                Bytes::from("cached"),
            );
            let old_verdict = verdicts.recv().await.unwrap();
            drop(old_responses);
            old_verdict.send(true).unwrap();
            let stale = tracker.deliveries.next_completed().await.unwrap();

            assert!(tracker.cancel_closed_delivery(&key));
            let mut live_responses = Vec::new();
            tracker.redeliver(delivery(key.clone(), &mut live_responses));
            let new_verdict = verdicts.recv().await.unwrap();

            let _stale_aborter = tracker.deliveries.push(async move { stale });
            assert!(matches!(tracker.next_completion().await, Err(Aborted)));

            new_verdict.send(true).unwrap();
            let completed = tracker
                .next_completion()
                .await
                .expect("new cached delivery should complete");
            assert_eq!(completed.context, 1);
            assert_eq!(completed.delivery.key, key);
            assert_eq!(completed.outcome, Some(Outcome::Complete));
            drop(live_responses);
        });
    }

    #[test]
    fn test_cancel_closed_delivery_keeps_partially_live_snapshot() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut verdicts) = PendingConsumer::new();
            let mut tracker = Tracker::<PendingConsumer, u8>::new(consumer);
            let key = MockKey(4);
            let (first_response, first_receiver) = mpsc::channel(1);
            let (second_response, second_receiver) = mpsc::channel(1);

            tracker.insert(key.clone());
            tracker.deliver(
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![
                        crate::Subscriber {
                            subscriber: (),
                            response: first_response,
                            span: tracing::Span::none(),
                        },
                        crate::Subscriber {
                            subscriber: (),
                            response: second_response,
                            span: tracing::Span::none(),
                        }
                    ],
                },
                5,
                Bytes::from("value"),
            );
            let verdict = verdicts.recv().await.unwrap();
            drop(first_receiver);

            assert!(!tracker.cancel_closed_delivery(&key));
            verdict.send(true).unwrap();
            let completed = tracker
                .next_completion()
                .await
                .expect("partially live delivery should complete");
            assert_eq!(completed.context, 5);
            assert_eq!(completed.outcome, Some(Outcome::Complete));
            drop(second_receiver);
        });
    }

    #[test]
    fn test_dropped_verdict_completes_without_outcome_and_redelivers() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, mut senders) = PendingConsumer::new();
            let mut tracker = Tracker::<PendingConsumer, u8>::new(consumer);
            let key = MockKey(3);
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(
                delivery(key.clone(), &mut responses),
                4,
                Bytes::from("unjudged"),
            );
            drop(senders.recv().await.unwrap());

            let completed = tracker
                .next_completion()
                .await
                .expect("dropped verdict should complete");
            assert_eq!(completed.context, 4);
            assert_eq!(completed.delivery.key, key);
            assert_eq!(completed.outcome, None);
            assert!(!tracker.response_accepted(&key));

            // The unjudged response can still be handed to other subscribers.
            tracker.redeliver(delivery(key.clone(), &mut responses));
            senders.recv().await.unwrap().send(true).unwrap();
            let judged = tracker
                .next_completion()
                .await
                .expect("redelivery should complete");
            assert_eq!(judged.context, 4);
            assert_eq!(judged.outcome, Some(Outcome::Complete));
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
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 3, value.clone());

            let completed = tracker
                .next_completion()
                .await
                .expect("first delivery should complete");
            assert_eq!(completed.outcome, Some(Outcome::Complete));
            tracker.accept_response(&key);
            assert!(tracker.response_accepted(&key));

            tracker.redeliver(delivery(key.clone(), &mut responses));
            let redelivered = tracker
                .next_completion()
                .await
                .expect("redelivery should complete");
            assert_eq!(redelivered.context, 3);
            assert_eq!(redelivered.delivery.key, key);
            assert_eq!(redelivered.outcome, Some(Outcome::Complete));

            let first = events.recv().await.unwrap();
            let second = events.recv().await.unwrap();
            assert_eq!(first, (key.clone(), value.clone()));
            assert_eq!(second, (key, value));
        });
    }

    #[test]
    #[should_panic(expected = "response")]
    fn test_redeliver_requires_cached_response() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut tracker = TestTracker::new(consumer);
            let key = MockKey(7);
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(
                delivery(key.clone(), &mut responses),
                3,
                Bytes::from("first"),
            );
            let completed = tracker
                .next_completion()
                .await
                .expect("first delivery should complete");
            assert_eq!(completed.outcome, Some(Outcome::Complete));

            tracker.discard_response(&key);
            tracker.redeliver(delivery(key, &mut responses));
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
            let mut responses = Vec::new();

            tracker.insert(key.clone());
            tracker.deliver(delivery(key.clone(), &mut responses), 1, Bytes::from("bad"));
            let rejected = tracker
                .next_completion()
                .await
                .expect("rejected delivery should complete");
            assert_eq!(rejected.outcome, Some(Outcome::Invalid));

            tracker.discard_response(&key);
            assert!(!tracker.response_accepted(&key));
            tracker.deliver(
                delivery(key.clone(), &mut responses),
                2,
                Bytes::from("good"),
            );

            let accepted = tracker
                .next_completion()
                .await
                .expect("accepted delivery should complete");
            assert_eq!(accepted.context, 2);
            assert_eq!(accepted.outcome, Some(Outcome::Complete));
        });
    }
}

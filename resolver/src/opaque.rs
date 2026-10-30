//! Resolve keys from an opaque asynchronous fetcher.
//!
//! This module owns the generic resolver actor used when fetching data only
//! requires asking an application-provided source for raw bytes or objects.
//! Implementations provide [`Fetcher::fetch`]; this module handles request
//! coalescing, retain pruning, retry scheduling, consumer delivery, and
//! cached-response redelivery. An ignored consumer outcome retires the key
//! without accepting the value or retrying the source. A verdict the consumer
//! drops without answering hands the response to the remaining subscribers, or
//! retires the key when none remain.
//!
//! Target hints supplied through [`crate::TargetedResolver::fetch_targeted`] and
//! [`crate::TargetedResolver::fetch_all_targeted`] are ignored because opaque
//! fetchers do not have peer-specific routing.

use crate::{
    Consumer, Delivery, Fetch, Outcome, Resolution, TargetedResolver,
    delivery::{Completion as DeliveryCompletion, Tracker as DeliveryTracker},
    ingress::{self, FetchKey, Message},
    subscribers,
};
use commonware_actor::{Feedback, mailbox};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{MetricsExt as _, status, status::Status},
};
use commonware_utils::{
    Span,
    futures::{AbortablePool, Aborter},
    vec::NonEmptyVec,
};
use futures::future::{self, Either};
use std::{
    collections::BTreeSet,
    future::Future,
    marker::PhantomData,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Fetches raw values for resolver keys.
pub trait Fetcher {
    /// Key requested by the resolver.
    type Key: Span;

    /// Raw value delivered to the consumer for validation.
    type Value;

    /// Fetch the value for `key`.
    ///
    /// Return `None` for transient failures, missing data, or unexpected source
    /// responses. The resolver will retry while the key still has retained
    /// subscribers.
    fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send;
}

/// Handle to an opaque-fetcher resolver actor.
pub struct Resolver<K, S, P>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    P: PublicKey,
{
    mailbox: mailbox::Sender<Message<K, S>>,
    _peer: PhantomData<P>,
}

impl<K, S, P> Clone for Resolver<K, S, P>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            _peer: PhantomData,
        }
    }
}

impl<K, S, P> crate::Resolver for Resolver<K, S, P>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    P: PublicKey,
{
    type Key = K;
    type Subscriber = S;

    fn fetch<F>(&mut self, fetch: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.send(Message::Fetch(vec![FetchKey::from(fetch.into())]))
    }

    fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.send(Message::Fetch(
            fetches
                .into_iter()
                .map(|fetch| FetchKey::from(fetch.into()))
                .collect(),
        ))
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.send(Message::Retain {
            predicate: Box::new(predicate),
        })
    }
}

impl<K, S, P> TargetedResolver for Resolver<K, S, P>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    P: PublicKey,
{
    type PublicKey = P;

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        <Self as crate::Resolver>::fetch(self, fetch)
    }

    fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        <Self as crate::Resolver>::fetch_all(
            self,
            fetches.into_iter().map(|(fetch, _)| fetch).collect(),
        )
    }
}

impl<K, S, P> Resolver<K, S, P>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    P: PublicKey,
{
    const fn new(mailbox: mailbox::Sender<Message<K, S>>) -> Self {
        Self {
            mailbox,
            _peer: PhantomData,
        }
    }

    fn send(&self, message: Message<K, S>) -> Feedback {
        self.mailbox.enqueue(message)
    }
}

/// Spawn an opaque-fetcher resolver actor.
pub fn init<E, F, Con, P>(
    context: E,
    fetcher: F,
    consumer: Con,
    mailbox_size: NonZeroUsize,
    fetch_retry_timeout: Duration,
) -> Resolver<F::Key, Con::Subscriber, P>
where
    E: Clock + Spawner + Metrics,
    F: Fetcher + Clone + Send + 'static,
    F::Value: Clone + Send + 'static,
    Con: Consumer<Key = F::Key, Value = F::Value>,
    Con::Subscriber: Ord,
    P: PublicKey,
{
    let (mailbox_tx, mailbox_rx) = mailbox::new(context.child("mailbox"), mailbox_size);
    Actor::new(
        context.child("actor"),
        fetcher,
        mailbox_rx,
        consumer,
        fetch_retry_timeout,
    )
    .start();
    Resolver::new(mailbox_tx)
}

/// Actor that coalesces opaque fetches, retries failures, and delivers accepted values.
struct Actor<E, F, Con>
where
    E: Clock + Spawner + Metrics,
    F: Fetcher,
    F::Value: Clone + Send + 'static,
    Con: Consumer<Key = F::Key, Value = F::Value>,
    Con::Subscriber: Ord,
{
    context: ContextCell<E>,
    fetcher: F,
    mailbox: mailbox::Receiver<Message<F::Key, Con::Subscriber>>,
    fetches: AbortablePool<'static, FetchCompletion<F::Key, F::Value>>,
    deliveries: DeliveryTracker<Con, (), Attempt>,
    subscribers: subscribers::Tracker<F::Key, Con::Subscriber>,
    fetch: status::Counter,
    retry_schedule: BTreeSet<(SystemTime, F::Key)>,
    fetch_retry_timeout: Duration,
}

/// Current attempt for a tracked key.
///
/// The delivery tracker holds it as the key's state, so removing the key's
/// delivery entry drops the attempt and aborts any active fetch.
enum Attempt {
    /// Fetch future is active for this key.
    Fetching { _aborter: Aborter },

    /// Consumer validation is active for this key.
    Delivering,

    /// Fetch is sleeping until the retry deadline.
    Scheduled(SystemTime),
}

struct FetchCompletion<K, V> {
    key: K,
    value: Option<V>,
}

impl<E, F, Con> Actor<E, F, Con>
where
    E: Clock + Spawner + Metrics,
    F: Fetcher + Clone + Send + 'static,
    F::Value: Clone + Send + 'static,
    Con: Consumer<Key = F::Key, Value = F::Value>,
    Con::Subscriber: Ord,
{
    fn new(
        context: E,
        fetcher: F,
        mailbox: mailbox::Receiver<Message<F::Key, Con::Subscriber>>,
        consumer: Con,
        fetch_retry_timeout: Duration,
    ) -> Self {
        let fetch = context.family("fetch", "Number of fetches by status");
        Self {
            context: ContextCell::new(context),
            fetcher,
            mailbox,
            fetches: AbortablePool::default(),
            deliveries: DeliveryTracker::new(consumer),
            subscribers: subscribers::Tracker::new(),
            fetch,
            retry_schedule: BTreeSet::new(),
            fetch_retry_timeout,
        }
    }

    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            Ok(FetchCompletion { key, value }) = self.fetches.next_completed() else continue => {
                self.handle_fetched(key, value);
            },
            Ok(DeliveryCompletion {
                delivery: Delivery {
                    key,
                    subscribers: delivered,
                },
                outcome,
                ..
            }) = self.deliveries.next_completion() else continue => {
                self.handle_delivered(key, delivered, outcome);
            },
            _ = match self.retry_schedule.first() {
                Some((deadline, _)) => Either::Left(self.context.sleep_until(*deadline)),
                None => Either::Right(future::pending()),
            } => {
                self.process_retries();
            },
            Some(message) = self.mailbox.recv() else break => {
                self.handle_message(message);
            },
        }
    }

    /// Apply a mailbox message to active resolver state.
    fn handle_message(&mut self, message: Message<F::Key, Con::Subscriber>) {
        match message {
            Message::Fetch(fetches) => {
                for fetch in fetches {
                    self.add_fetch(fetch);
                }
            }
            Message::Retain { predicate } => self.retain(predicate),
        }
    }

    /// Add subscribers for a key and start the first fetch if needed.
    fn add_fetch(&mut self, fetch: FetchKey<F::Key, Con::Subscriber>) {
        let FetchKey {
            key, subscribers, ..
        } = fetch;
        let is_new = self.subscribers.insert(key.clone(), subscribers);

        if is_new {
            let attempt = self.start_fetch(key.clone());
            assert!(
                self.deliveries.insert_with_state(key, attempt),
                "new key must not have a delivery entry"
            );
        }
    }

    /// Prune subscribers, deliveries, active fetches, and scheduled retries.
    fn retain(&mut self, predicate: ingress::Predicate<F::Key, Con::Subscriber>) {
        for key in self
            .subscribers
            .retain(|key, subscriber| predicate(key, subscriber))
        {
            if let Some(Some(Attempt::Scheduled(deadline))) =
                self.deliveries.remove_with_state(&key)
            {
                self.retry_schedule.remove(&(deadline, key));
            }
        }
    }

    /// Spawn one fetch for `key` and return the attempt that owns it.
    fn start_fetch(&mut self, key: F::Key) -> Attempt {
        let future = Self::fetch(key, self.fetcher.clone());
        let aborter = self.fetches.push(future);
        Attempt::Fetching { _aborter: aborter }
    }

    /// Deliver a fetched value to currently retained subscribers.
    fn start_delivery(
        &mut self,
        key: F::Key,
        value: F::Value,
        delivered: NonEmptyVec<(Con::Subscriber, tracing::Span)>,
    ) {
        *self
            .deliveries
            .state_mut(&key)
            .expect("key must have an attempt") = Attempt::Delivering;
        self.deliveries.deliver(
            Delivery {
                key,
                subscribers: delivered,
            },
            (),
            value,
        );
    }

    /// Deliver the cached response to subscribers that arrived later.
    fn redeliver(&mut self, key: F::Key, delivered: NonEmptyVec<(Con::Subscriber, tracing::Span)>) {
        self.deliveries.redeliver(Delivery {
            key,
            subscribers: delivered,
        });
    }

    /// Deliver fetched values or schedule a retry when the source had no data.
    fn handle_fetched(&mut self, key: F::Key, value: Option<F::Value>) {
        match value {
            None => self.schedule_retry(key),
            Some(value) => {
                if let Some(subscribers) = self.subscribers.pending(&key) {
                    self.start_delivery(key, value, subscribers);
                } else {
                    self.subscribers.remove(&key);
                    self.deliveries.remove(&key);
                }
            }
        }
    }

    /// Complete, redeliver, or retry a key after consumer validation.
    fn handle_delivered(
        &mut self,
        key: F::Key,
        delivered: NonEmptyVec<(Con::Subscriber, tracing::Span)>,
        outcome: Option<Outcome>,
    ) {
        let accepted = self.deliveries.response_accepted(&key);

        // A dropped verdict says nothing about the response, only that the consumer
        // did not judge it for these subscribers. Hand the response to the
        // remaining subscribers, or retire the key when none remain.
        let Some(outcome) = outcome else {
            let remaining = self
                .subscribers
                .remove_delivered(&key, delivered.map_into(|(subscriber, _)| subscriber));
            if let Some(subscribers) = remaining {
                self.redeliver(key, subscribers);
                return;
            }
            if !accepted {
                self.fetch.inc(Status::Dropped);
            }
            self.deliveries.remove(&key);
            return;
        };

        match outcome {
            Outcome::Resolved(Resolution::All) => {
                let remaining = self
                    .subscribers
                    .remove_delivered(&key, delivered.map_into(|(subscriber, _)| subscriber));

                // The first accepted response is reused for subscribers that joined
                // while validation was pending, avoiding a duplicate source fetch
                // for the same key.
                if let Some(subscribers) = remaining {
                    if !accepted {
                        self.deliveries.accept_response(&key);
                    }
                    self.redeliver(key, subscribers);
                } else {
                    self.subscribers.remove(&key);
                    self.deliveries.remove(&key);
                }
            }
            Outcome::Resolved(Resolution::Some | Resolution::None) => {
                // The fetcher returned one of multiple valid responses, but this response did not
                // satisfy every subscriber. Discard it and retain the fetch so another response
                // can be tried.
                self.fetch.inc(Status::Ambiguous);
                self.deliveries.discard_response(&key);
                self.schedule_retry(key);
            }
            Outcome::Invalid => {
                // A cached response already satisfied at least one subscriber. Treat a
                // later rejection during redelivery as stale application feedback rather
                // than re-fetching data that was accepted once.
                if accepted {
                    warn!(
                        ?key,
                        "previously accepted resolver response rejected during opaque redelivery"
                    );
                    self.subscribers.remove(&key);
                    self.deliveries.remove(&key);
                    return;
                }

                warn!(?key, "consumer rejected opaque resolver delivery");
                self.deliveries.discard_response(&key);
                self.schedule_retry(key);
            }
            Outcome::Ignored => {
                // The consumer no longer needs this key. Retire it without accepting the
                // response or scheduling another source fetch.
                self.fetch.inc(Status::Dropped);
                self.subscribers.remove(&key);
                self.deliveries.remove(&key);
            }
        }
    }

    /// Schedule the next fetch attempt for `key`.
    fn schedule_retry(&mut self, key: F::Key) {
        let deadline = self.context.current() + self.fetch_retry_timeout;
        let Some(attempt) = self.deliveries.state_mut(&key) else {
            return;
        };
        *attempt = Attempt::Scheduled(deadline);
        debug!(?key, ?deadline, "scheduled opaque resolver retry");
        self.retry_schedule.insert((deadline, key));
    }

    /// Start all retry attempts whose deadlines have passed.
    fn process_retries(&mut self) {
        let now = self.context.current();
        while let Some((deadline, key)) = self.retry_schedule.pop_first() {
            if deadline > now {
                self.retry_schedule.insert((deadline, key));
                break;
            }

            let Some(state) = self.deliveries.state(&key) else {
                continue;
            };
            match state {
                Attempt::Scheduled(state_deadline) if *state_deadline == deadline => {
                    debug!(?key, "retrying opaque resolver fetch");
                    let attempt = self.start_fetch(key.clone());
                    *self
                        .deliveries
                        .state_mut(&key)
                        .expect("key must have an attempt") = attempt;
                }
                Attempt::Scheduled(_) | Attempt::Fetching { .. } | Attempt::Delivering => {}
            }
        }
    }

    /// Run the user-supplied fetcher and tag the result with its key.
    async fn fetch(key: F::Key, fetcher: F) -> FetchCompletion<F::Key, F::Value> {
        let value = fetcher.fetch(key.clone()).await;
        FetchCompletion { key, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Resolver as _;
    use bytes::Bytes;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic, deterministic::Runner};
    use commonware_utils::{channel::oneshot, non_empty_vec, sync::Mutex};
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
    };

    const RETRY_TIMEOUT: Duration = Duration::from_millis(100);

    #[derive(Clone, Default)]
    struct MockFetcher {
        responses: Arc<Mutex<HashMap<u8, VecDeque<Option<Bytes>>>>>,
        calls: Arc<AtomicU32>,
    }

    impl MockFetcher {
        fn push(&self, key: u8, response: Option<Bytes>) {
            self.responses
                .lock()
                .entry(key)
                .or_default()
                .push_back(response);
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Fetcher for MockFetcher {
        type Key = u8;
        type Value = Bytes;

        fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send {
            let responses = self.responses.clone();
            let calls = self.calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                responses
                    .lock()
                    .get_mut(&key)
                    .and_then(VecDeque::pop_front)
                    .flatten()
            }
        }
    }

    #[derive(Clone)]
    struct BlockingFetcher {
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        response: Arc<Mutex<Option<oneshot::Receiver<Option<Bytes>>>>>,
    }

    impl BlockingFetcher {
        fn new() -> (Self, oneshot::Receiver<()>, oneshot::Sender<Option<Bytes>>) {
            let (started_tx, started_rx) = oneshot::channel();
            let (response_tx, response_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    response: Arc::new(Mutex::new(Some(response_rx))),
                },
                started_rx,
                response_tx,
            )
        }
    }

    impl Fetcher for BlockingFetcher {
        type Key = u8;
        type Value = Bytes;

        fn fetch(&self, _key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send {
            let started = self.started.clone();
            let response = self.response.clone();
            async move {
                if let Some(started) = started.lock().take() {
                    let _ = started.send(());
                }
                let response = response.lock().take().expect("missing response");
                response.await.unwrap_or(None)
            }
        }
    }

    struct CapturedDelivery {
        delivery: Delivery<u8, u16>,
        value: Bytes,
        response: oneshot::Sender<Outcome>,
    }

    #[derive(Clone, Default)]
    struct MockConsumer {
        deliveries: Arc<Mutex<VecDeque<CapturedDelivery>>>,
    }

    impl MockConsumer {
        fn pop(&self) -> Option<CapturedDelivery> {
            self.deliveries.lock().pop_front()
        }

        fn len(&self) -> usize {
            self.deliveries.lock().len()
        }
    }

    impl Consumer for MockConsumer {
        type Key = u8;
        type Value = Bytes;
        type Subscriber = u16;
        type Outcome = Outcome;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<Self::Outcome> {
            let (response, receiver) = oneshot::channel();
            self.deliveries.lock().push_back(CapturedDelivery {
                delivery,
                value,
                response,
            });
            receiver
        }
    }

    fn start_resolver<F>(
        context: deterministic::Context,
        fetcher: F,
        consumer: MockConsumer,
    ) -> Resolver<u8, u16, PublicKey>
    where
        F: Fetcher<Key = u8, Value = Bytes> + Clone + Send + 'static,
    {
        init(
            context,
            fetcher,
            consumer,
            NonZeroUsize::new(16).unwrap(),
            RETRY_TIMEOUT,
        )
    }

    async fn wait_for_delivery(
        context: &deterministic::Context,
        consumer: &MockConsumer,
    ) -> CapturedDelivery {
        for _ in 0..50 {
            if let Some(delivery) = consumer.pop() {
                return delivery;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for delivery");
    }

    #[test]
    fn fetch_during_validation_reuses_response_after_success() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let first = wait_for_delivery(&context, &consumer).await;
            assert_eq!(first.value, Bytes::from_static(b"value"));

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 11,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            context.sleep(Duration::from_millis(10)).await;
            first
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");

            let second = wait_for_delivery(&context, &consumer).await;
            assert_eq!(second.value, Bytes::from_static(b"value"));
            assert_eq!(
                second
                    .delivery
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| *subscriber)
                    .collect::<Vec<_>>(),
                vec![11]
            );
            second
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");

            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(fetcher.calls(), 1);
        });
    }

    #[test]
    fn missing_fetch_retries_until_value_is_available() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, None);
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );

            // The first attempt finds nothing, so the retry waits for its deadline.
            context
                .sleep(RETRY_TIMEOUT - Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);

            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"value"));
            delivery
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
            assert_eq!(fetcher.calls(), 2);
        });
    }

    #[test]
    fn unresolved_delivery_retries_without_retiring_subscriber() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"ambiguous")));
            fetcher.push(1, Some(Bytes::from_static(b"complete")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );

            let first = wait_for_delivery(&context, &consumer).await;
            assert_eq!(first.value, Bytes::from_static(b"ambiguous"));
            assert_eq!(
                first
                    .delivery
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| *subscriber)
                    .collect::<Vec<_>>(),
                vec![10]
            );
            first
                .response
                .send(Outcome::Resolved(Resolution::None))
                .expect("response dropped");

            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            let second = wait_for_delivery(&context, &consumer).await;
            assert_eq!(second.value, Bytes::from_static(b"complete"));
            assert_eq!(
                second
                    .delivery
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| *subscriber)
                    .collect::<Vec<_>>(),
                vec![10]
            );
            assert_eq!(fetcher.calls(), 2);

            second
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(consumer.len(), 0);
            assert_eq!(fetcher.calls(), 2);
            assert!(
                context
                    .encode()
                    .contains("resolver_actor_fetch_total{status=\"Ambiguous\"} 1")
            );
        });
    }

    #[test]
    fn ignored_delivery_retires_without_retry() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"obsolete")));
            fetcher.push(1, Some(Bytes::from_static(b"fresh")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"obsolete"));
            delivery
                .response
                .send(Outcome::Ignored)
                .expect("response dropped");

            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);
            assert!(
                context
                    .encode()
                    .contains("resolver_actor_fetch_total{status=\"Dropped\"} 1")
            );

            // Ignoring retires the old fetch rather than leaving a tombstone.
            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"fresh"));
            delivery
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
            assert_eq!(fetcher.calls(), 2);
        });
    }

    #[test]
    fn dropped_verdict_retires_without_retry() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"unjudged")));
            fetcher.push(1, Some(Bytes::from_static(b"fresh")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"unjudged"));

            // Drop the verdict, as a consumer does when it stops with the delivery
            // still queued. No one is waiting on the key, so the fetch is retired
            // rather than retried.
            drop(delivery);

            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);
            assert!(
                context
                    .encode()
                    .contains("resolver_actor_fetch_total{status=\"Dropped\"} 1")
            );

            // The retired key is not deduplicated against, so a fresh fetch runs.
            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"fresh"));
            delivery
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
            assert_eq!(fetcher.calls(), 2);
        });
    }

    #[test]
    fn dropped_verdict_hands_response_to_late_subscriber() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"unjudged")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let first = wait_for_delivery(&context, &consumer).await;
            assert_eq!(first.value, Bytes::from_static(b"unjudged"));

            // A late subscriber joins while the first delivery is unjudged, then
            // that delivery's verdict is dropped. The late subscriber is handed
            // the same response without another source fetch.
            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 11,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            context.sleep(Duration::from_millis(10)).await;
            drop(first);
            let second = wait_for_delivery(&context, &consumer).await;
            assert_eq!(
                second
                    .delivery
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| *subscriber)
                    .collect::<Vec<_>>(),
                vec![11]
            );
            assert_eq!(second.value, Bytes::from_static(b"unjudged"));
            second
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");

            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);
        });
    }

    #[test]
    fn accepted_redelivery_rejection_does_not_refetch() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let first = wait_for_delivery(&context, &consumer).await;

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 11,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            context.sleep(Duration::from_millis(10)).await;
            first
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");

            let second = wait_for_delivery(&context, &consumer).await;
            second
                .response
                .send(Outcome::Invalid)
                .expect("response dropped");

            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);
        });
    }

    #[test]
    fn retain_prunes_active_fetch_subscribers() {
        Runner::default().start(|context| async move {
            let (fetcher, started, response) = BlockingFetcher::new();
            let consumer = MockConsumer::default();
            let mut resolver = start_resolver(context.child("resolver"), fetcher, consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 11,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            started.await.expect("fetch did not start");
            assert!(
                resolver
                    .retain(|_, subscriber| *subscriber == 11)
                    .accepted()
            );
            context.sleep(Duration::from_millis(10)).await;
            response
                .send(Some(Bytes::from_static(b"value")))
                .expect("fetcher dropped");

            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(
                delivery
                    .delivery
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| *subscriber)
                    .collect::<Vec<_>>(),
                vec![11]
            );
            delivery
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
        });
    }

    #[test]
    fn retain_drops_last_subscriber_aborts_active_fetch() {
        Runner::default().start(|context| async move {
            let (fetcher, started, response) = BlockingFetcher::new();
            let consumer = MockConsumer::default();
            let mut resolver = start_resolver(context.child("resolver"), fetcher, consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            started.await.expect("fetch did not start");
            assert!(resolver.retain(|_, _| false).accepted());
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                response.send(Some(Bytes::from_static(b"value"))).is_err(),
                "fetch future should be aborted after its last subscriber is pruned"
            );
            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(consumer.len(), 0);
        });
    }

    #[test]
    fn retain_drops_last_subscriber_aborts_active_delivery() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(
                resolver
                    .fetch(Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    })
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert!(resolver.retain(|_, _| false).accepted());
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                delivery.response.send(Outcome::Invalid).is_err(),
                "delivery future should be aborted after its last subscriber is pruned"
            );
            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;
            assert_eq!(fetcher.calls(), 1);
            assert_eq!(consumer.len(), 0);
        });
    }

    #[test]
    fn targeted_fetch_uses_same_opaque_fetch_path() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver =
                start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());
            let target = PrivateKey::from_seed(0).public_key();

            assert!(
                resolver
                    .fetch_targeted(
                        Fetch {
                            key: 1,
                            subscriber: 10,
                            span: tracing::Span::none(),
                        },
                        non_empty_vec![target]
                    )
                    .accepted()
            );
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"value"));
            delivery
                .response
                .send(Outcome::Resolved(Resolution::All))
                .expect("response dropped");
            assert_eq!(fetcher.calls(), 1);
        });
    }
}

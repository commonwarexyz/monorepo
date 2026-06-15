//! Resolve keys from an opaque asynchronous fetcher.
//!
//! This module owns the generic resolver actor used when fetching data only
//! requires asking an application-provided source for raw bytes or objects.
//! Implementations provide [`Fetcher::fetch`]; this module handles request
//! coalescing, retain pruning, retry scheduling, consumer delivery, and
//! accepted-response redelivery.
//!
//! Target hints supplied through [`crate::TargetedResolver::fetch_targeted`] and
//! [`crate::TargetedResolver::fetch_all_targeted`] are ignored because opaque
//! fetchers do not have peer-specific routing.

use crate::{
    delivery::{Completion as DeliveryCompletion, Tracker as DeliveryTracker},
    ingress::{self, FetchKey, Message},
    subscribers, Consumer, Delivery, Fetch, TargetedResolver,
};
use commonware_actor::{mailbox, Feedback};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{
    futures::{AbortablePool, Aborter},
    vec::NonEmptyVec,
    Span,
};
use futures::future::{self, Either};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    marker::PhantomData,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, trace, warn};

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
    E: Clock + Spawner,
    F: Fetcher,
    F::Value: Clone + Send + 'static,
    Con: Consumer<Key = F::Key, Value = F::Value>,
    Con::Subscriber: Ord,
{
    context: ContextCell<E>,
    fetcher: F,
    mailbox: mailbox::Receiver<Message<F::Key, Con::Subscriber>>,
    fetches: AbortablePool<FetchCompletion<F::Key, F::Value>>,
    deliveries: DeliveryTracker<Con, u64>,
    requests: BTreeMap<F::Key, Attempt>,
    subscribers: subscribers::Tracker<F::Key, Con::Subscriber>,
    retry_schedule: BTreeSet<(SystemTime, F::Key)>,
    fetch_retry_timeout: Duration,
    next_id: u64,
}

enum Attempt {
    /// Fetch future is active for this key.
    Fetching { id: u64, _aborter: Aborter },

    /// Consumer validation is active for this key.
    Delivering { id: u64 },

    /// Fetch is sleeping until the retry deadline.
    Scheduled(SystemTime),
}

struct FetchCompletion<K, V> {
    key: K,
    id: u64,
    value: Option<V>,
}

impl<E, F, Con> Actor<E, F, Con>
where
    E: Clock + Spawner,
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
        Self {
            context: ContextCell::new(context),
            fetcher,
            mailbox,
            fetches: AbortablePool::default(),
            deliveries: DeliveryTracker::new(consumer),
            requests: BTreeMap::new(),
            subscribers: subscribers::Tracker::new(),
            retry_schedule: BTreeSet::new(),
            fetch_retry_timeout,
            next_id: 0,
        }
    }

    fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            Ok(result) = self.fetches.next_completed() else continue => {
                self.handle_fetch_completed(result);
            },
            delivery = self.deliveries.next_completion() => {
                let delivery = match delivery {
                    Ok(delivery) => delivery,
                    Err(_) => continue,
                };
                self.handle_delivery_completed(delivery);
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
            key,
            subscribers,
            span,
            ..
        } = fetch;
        let is_new = self.subscribers.insert(key.clone(), subscribers, span);

        if is_new {
            assert!(self.deliveries.insert(key.clone()), "delivery entry");
            self.requests
                .insert(key.clone(), Attempt::Scheduled(self.context.current()));
            self.start_fetch(key);
        }
    }

    /// Prune subscribers, deliveries, active fetches, and scheduled retries.
    fn retain(&mut self, predicate: ingress::Predicate<F::Key, Con::Subscriber>) {
        for key in self
            .subscribers
            .retain(|key, subscriber| predicate(key, subscriber))
        {
            self.deliveries.remove(&key);
            if let Some(attempt) = self.requests.remove(&key) {
                match attempt {
                    Attempt::Fetching { .. } | Attempt::Delivering { .. } => {}
                    Attempt::Scheduled(deadline) => {
                        self.retry_schedule.remove(&(deadline, key));
                    }
                }
            }
        }
    }

    /// Spawn one fetch attempt for `key`.
    fn start_fetch(&mut self, key: F::Key) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let future = Self::fetch(key.clone(), id, self.fetcher.clone());
        let aborter = self.fetches.push(future);
        self.requests.insert(
            key,
            Attempt::Fetching {
                id,
                _aborter: aborter,
            },
        );
    }

    /// Deliver a fetched value to currently retained subscribers.
    fn start_delivery(
        &mut self,
        key: F::Key,
        value: F::Value,
        delivered: NonEmptyVec<(Con::Subscriber, tracing::Span)>,
    ) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.deliveries.deliver(
            Delivery {
                key: key.clone(),
                subscribers: delivered,
            },
            id,
            value,
        );
        self.requests.insert(key, Attempt::Delivering { id });
    }

    /// Deliver an already accepted response to subscribers that arrived later.
    fn redeliver(&mut self, key: F::Key, delivered: NonEmptyVec<(Con::Subscriber, tracing::Span)>) {
        self.deliveries.redeliver(Delivery {
            key,
            subscribers: delivered,
        });
    }

    /// Handle a completed fetch future if it is still the active attempt.
    fn handle_fetch_completed(&mut self, completion: FetchCompletion<F::Key, F::Value>) {
        let FetchCompletion { key, id, value } = completion;
        if !self.current_fetch(&key, id) {
            return;
        }
        self.handle_fetched(key, value);
    }

    /// Handle a completed consumer delivery if it is still the active attempt.
    fn handle_delivery_completed(
        &mut self,
        completion: DeliveryCompletion<F::Key, Con::Subscriber, u64>,
    ) {
        let DeliveryCompletion {
            context: id,
            delivery,
            valid,
        } = completion;
        let Delivery {
            key,
            subscribers: delivered,
            ..
        } = delivery;
        if !self.current_delivery(&key, id) {
            return;
        }
        self.handle_delivered(key, delivered, valid);
    }

    /// Return whether a fetch completion matches the current attempt id.
    fn current_fetch(&self, key: &F::Key, id: u64) -> bool {
        let Some(attempt) = self.requests.get(key) else {
            trace!(?key, id, "ignoring stale fetch completion");
            return false;
        };
        match attempt {
            Attempt::Fetching { id: active_id, .. } if *active_id == id => true,
            Attempt::Fetching { id: active_id, .. } => {
                trace!(
                    ?key,
                    completed_id = id,
                    active_id,
                    "ignoring replaced fetch completion",
                );
                false
            }
            Attempt::Delivering { id: active_id } => {
                trace!(
                    ?key,
                    completed_id = id,
                    active_id,
                    "ignoring fetch completion for delivery attempt",
                );
                false
            }
            Attempt::Scheduled(deadline) => {
                trace!(?key, id, ?deadline, "ignoring scheduled fetch completion");
                false
            }
        }
    }

    /// Return whether a delivery completion matches the current attempt id.
    fn current_delivery(&self, key: &F::Key, id: u64) -> bool {
        let Some(attempt) = self.requests.get(key) else {
            trace!(?key, id, "ignoring stale delivery completion");
            return false;
        };
        match attempt {
            Attempt::Delivering { id: active_id } if *active_id == id => true,
            Attempt::Delivering { id: active_id } => {
                trace!(
                    ?key,
                    completed_id = id,
                    active_id,
                    "ignoring replaced delivery completion",
                );
                false
            }
            Attempt::Fetching { id: active_id, .. } => {
                trace!(
                    ?key,
                    completed_id = id,
                    active_id,
                    "ignoring delivery completion for fetch attempt",
                );
                false
            }
            Attempt::Scheduled(deadline) => {
                trace!(
                    ?key,
                    id,
                    ?deadline,
                    "ignoring scheduled delivery completion"
                );
                false
            }
        }
    }

    /// Deliver fetched values or schedule a retry when the source had no data.
    fn handle_fetched(&mut self, key: F::Key, value: Option<F::Value>) {
        match value {
            None => self.schedule_retry(key),
            Some(value) => {
                if let Some(subscribers) = self.subscribers.pending(&key) {
                    self.start_delivery(key, value, subscribers);
                } else {
                    self.requests.remove(&key);
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
        valid: bool,
    ) {
        let accepted = self.deliveries.response_accepted(&key);

        if valid {
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
                self.requests.remove(&key);
                self.subscribers.remove(&key);
                self.deliveries.remove(&key);
            }
            return;
        }

        // A cached response already satisfied at least one subscriber. Treat a
        // later rejection during redelivery as stale application feedback rather
        // than re-fetching data that was accepted once.
        if accepted {
            warn!(
                ?key,
                "previously accepted resolver response rejected during opaque redelivery"
            );
            self.requests.remove(&key);
            self.subscribers.remove(&key);
            self.deliveries.remove(&key);
            return;
        }

        warn!(?key, "consumer rejected opaque resolver delivery");
        self.deliveries.discard_response(&key);
        self.schedule_retry(key);
    }

    /// Schedule the next fetch attempt for `key`.
    fn schedule_retry(&mut self, key: F::Key) {
        let deadline = self.context.current() + self.fetch_retry_timeout;
        let Some(attempt) = self.requests.get_mut(&key) else {
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

            let Some(state) = self.requests.get(&key) else {
                continue;
            };
            match state {
                Attempt::Scheduled(state_deadline) if *state_deadline == deadline => {
                    debug!(?key, "retrying opaque resolver fetch");
                    self.start_fetch(key);
                }
                Attempt::Scheduled(_) | Attempt::Fetching { .. } | Attempt::Delivering { .. } => {}
            }
        }
    }

    /// Run the user-supplied fetcher and preserve the attempt id.
    async fn fetch(key: F::Key, id: u64, fetcher: F) -> FetchCompletion<F::Key, F::Value> {
        let value = fetcher.fetch(key.clone()).await;
        FetchCompletion { key, id, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Resolver as _;
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{deterministic, deterministic::Runner, Runner as _, Supervisor as _};
    use commonware_utils::{channel::oneshot, non_empty_vec, sync::Mutex};
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
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
        response: oneshot::Sender<bool>,
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

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<bool> {
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

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
            let first = wait_for_delivery(&context, &consumer).await;
            assert_eq!(first.value, Bytes::from_static(b"value"));

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 11,
                    span: tracing::Span::none(),
                })
                .accepted());
            context.sleep(Duration::from_millis(10)).await;
            first.response.send(true).expect("response dropped");

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
            second.response.send(true).expect("response dropped");

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

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
            context
                .sleep(RETRY_TIMEOUT + Duration::from_millis(10))
                .await;

            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"value"));
            delivery.response.send(true).expect("response dropped");
            assert_eq!(fetcher.calls(), 2);
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

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
            let first = wait_for_delivery(&context, &consumer).await;

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 11,
                    span: tracing::Span::none(),
                })
                .accepted());
            context.sleep(Duration::from_millis(10)).await;
            first.response.send(true).expect("response dropped");

            let second = wait_for_delivery(&context, &consumer).await;
            second.response.send(false).expect("response dropped");

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

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 11,
                    span: tracing::Span::none(),
                })
                .accepted());
            started.await.expect("fetch did not start");
            assert!(resolver
                .retain(|_, subscriber| *subscriber == 11)
                .accepted());
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
            delivery.response.send(true).expect("response dropped");
        });
    }

    #[test]
    fn retain_drops_last_subscriber_aborts_active_fetch() {
        Runner::default().start(|context| async move {
            let (fetcher, started, response) = BlockingFetcher::new();
            let consumer = MockConsumer::default();
            let mut resolver = start_resolver(context.child("resolver"), fetcher, consumer.clone());

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
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

            assert!(resolver
                .fetch(Fetch {
                    key: 1,
                    subscriber: 10,
                    span: tracing::Span::none(),
                })
                .accepted());
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert!(resolver.retain(|_, _| false).accepted());
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                delivery.response.send(false).is_err(),
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

            assert!(resolver
                .fetch_targeted(
                    Fetch {
                        key: 1,
                        subscriber: 10,
                        span: tracing::Span::none(),
                    },
                    non_empty_vec![target]
                )
                .accepted());
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"value"));
            delivery.response.send(true).expect("response dropped");
            assert_eq!(fetcher.calls(), 1);
        });
    }
}

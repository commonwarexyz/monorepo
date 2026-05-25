//! Resolve keys from a direct asynchronous fetcher.
//!
//! This module owns the generic resolver actor used when fetching data only
//! requires directly asking some source for raw bytes or objects. Implementations
//! provide [`Fetcher::fetch`]; this module handles request coalescing, retain
//! pruning, retry scheduling, consumer delivery, and accepted-response
//! redelivery.

use crate::{
    delivery::{Completion as DeliveryCompletion, Tracker as DeliveryTracker},
    ingress::{self, FetchKey, Message},
    subscribers::Tracker as SubscriberTracker,
    Consumer, Delivery, Fetch,
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
pub trait Fetcher: Clone + Send + 'static {
    /// Key requested by the resolver.
    type Key: Span;

    /// Raw value delivered to the consumer for validation.
    type Value: Clone + Send + 'static;

    /// Fetch the value for `key`.
    ///
    /// Return `None` for transient failures, missing data, or unexpected source
    /// responses. The resolver will retry while the key still has retained
    /// subscribers.
    fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send;
}

/// Handle to a direct-fetcher resolver actor.
pub struct Resolver<K, S, P>
where
    K: Span,
    S: Clone + Ord + Send + 'static,
    P: PublicKey,
{
    mailbox: mailbox::Sender<Message<K, S>>,
    _peer: PhantomData<P>,
}

impl<K, S, P> Clone for Resolver<K, S, P>
where
    K: Span,
    S: Clone + Ord + Send + 'static,
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
    S: Clone + Ord + Send + 'static,
    P: PublicKey,
{
    type Key = K;
    type Subscriber = S;
    type PublicKey = P;

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

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.fetch(fetch)
    }

    fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.fetch_all(fetches.into_iter().map(|(fetch, _)| fetch).collect())
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

impl<K, S, P> Resolver<K, S, P>
where
    K: Span,
    S: Clone + Ord + Send + 'static,
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

/// Spawn a direct-fetcher resolver actor.
pub fn init<E, F, Con, P>(
    context: E,
    fetcher: F,
    consumer: Con,
    mailbox_size: NonZeroUsize,
    fetch_retry_timeout: Duration,
) -> Resolver<F::Key, Con::Subscriber, P>
where
    E: Clock + Spawner + Metrics,
    F: Fetcher,
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

struct Actor<E, F, Con>
where
    E: Clock + Spawner,
    F: Fetcher,
    Con: Consumer<Key = F::Key, Value = F::Value>,
    Con::Subscriber: Ord,
{
    context: ContextCell<E>,
    fetcher: F,
    mailbox: mailbox::Receiver<Message<F::Key, Con::Subscriber>>,
    fetches: AbortablePool<FetchCompletion<F::Key, F::Value>>,
    deliveries: DeliveryTracker<Con, u64>,
    requests: BTreeMap<F::Key, Attempt>,
    subscribers: SubscriberTracker<F::Key, Con::Subscriber>,
    retry_schedule: BTreeSet<(SystemTime, F::Key)>,
    fetch_retry_timeout: Duration,
    next_id: u64,
}

enum Attempt {
    Fetching { id: u64, _aborter: Aborter },
    Delivering { id: u64 },
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
    F: Fetcher,
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
            subscribers: SubscriberTracker::new(),
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

    fn add_fetch(&mut self, fetch: FetchKey<F::Key, Con::Subscriber>) {
        let FetchKey { key, subscribers } = fetch;
        let is_new = self.subscribers.insert(key.clone(), subscribers);

        if is_new {
            assert!(self.deliveries.insert(key.clone()), "delivery entry");
            self.requests
                .insert(key.clone(), Attempt::Scheduled(self.context.current()));
            self.start_fetch(key);
        }
    }

    fn retain(&mut self, predicate: ingress::Predicate<F::Key, Con::Subscriber>) {
        for key in self
            .subscribers
            .retain(|key, subscriber| predicate(key, subscriber))
        {
            self.deliveries.remove(&key);
            // Removing the request drops any active fetch aborter or marks any
            // active delivery completion as stale. Scheduled retries also need
            // their timer entry removed explicitly.
            if let Some(Attempt::Scheduled(deadline)) = self.requests.remove(&key) {
                self.retry_schedule.remove(&(deadline, key));
            }
        }
    }

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

    fn start_delivery(
        &mut self,
        key: F::Key,
        value: F::Value,
        delivered: NonEmptyVec<Con::Subscriber>,
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

    fn redeliver(&mut self, key: F::Key, delivered: NonEmptyVec<Con::Subscriber>) {
        self.deliveries.redeliver(Delivery {
            key,
            subscribers: delivered,
        });
    }

    fn handle_fetch_completed(&mut self, completion: FetchCompletion<F::Key, F::Value>) {
        let FetchCompletion { key, id, value } = completion;
        if !self.current_fetch(&key, id) {
            return;
        }
        self.handle_fetched(key, value);
    }

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
        } = delivery;
        if !self.current_delivery(&key, id) {
            return;
        }
        self.handle_delivered(key, delivered, valid);
    }

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
                trace!(?key, id, ?deadline, "ignoring scheduled delivery completion");
                false
            }
        }
    }

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

    fn handle_delivered(
        &mut self,
        key: F::Key,
        delivered: NonEmptyVec<Con::Subscriber>,
        valid: bool,
    ) {
        let accepted = self.deliveries.response_accepted(&key);

        if valid {
            let remaining = self.subscribers.remove_delivered(&key, delivered);

            if let Some(subscribers) = remaining {
                // The first accepted response is reused for subscribers that
                // joined while validation was pending, avoiding a duplicate
                // source fetch for the same key.
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

        if accepted {
            // A cached response already satisfied at least one subscriber.
            // Treat a later rejection during redelivery as stale application
            // feedback rather than re-fetching data that was accepted once.
            warn!(?key, "previously accepted resolver response rejected during direct redelivery");
            self.requests.remove(&key);
            self.subscribers.remove(&key);
            self.deliveries.remove(&key);
            return;
        }

        warn!(?key, "consumer rejected direct resolver delivery");
        self.deliveries.discard_response(&key);
        self.schedule_retry(key);
    }

    fn schedule_retry(&mut self, key: F::Key) {
        let deadline = self.context.current() + self.fetch_retry_timeout;
        let Some(attempt) = self.requests.get_mut(&key) else {
            return;
        };
        *attempt = Attempt::Scheduled(deadline);
        debug!(?key, ?deadline, "scheduled direct resolver retry");
        self.retry_schedule.insert((deadline, key));
    }

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
                    debug!(?key, "retrying direct resolver fetch");
                    self.start_fetch(key);
                }
                Attempt::Scheduled(_) | Attempt::Fetching { .. } | Attempt::Delivering { .. } => {}
            }
        }
    }

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
        F: Fetcher<Key = u8, Value = Bytes>,
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
            let mut resolver = start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 10 }).accepted());
            let first = wait_for_delivery(&context, &consumer).await;
            assert_eq!(first.value, Bytes::from_static(b"value"));

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 11 }).accepted());
            context.sleep(Duration::from_millis(10)).await;
            first.response.send(true).expect("response dropped");

            let second = wait_for_delivery(&context, &consumer).await;
            assert_eq!(second.value, Bytes::from_static(b"value"));
            assert_eq!(second.delivery.subscribers, non_empty_vec![11]);
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
            let mut resolver = start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 10 }).accepted());
            context.sleep(RETRY_TIMEOUT + Duration::from_millis(10)).await;

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
            let mut resolver = start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 10 }).accepted());
            let first = wait_for_delivery(&context, &consumer).await;

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 11 }).accepted());
            context.sleep(Duration::from_millis(10)).await;
            first.response.send(true).expect("response dropped");

            let second = wait_for_delivery(&context, &consumer).await;
            second.response.send(false).expect("response dropped");

            context.sleep(RETRY_TIMEOUT + Duration::from_millis(10)).await;
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

            assert!(resolver.fetch(Fetch { key: 1, subscriber: 10 }).accepted());
            assert!(resolver.fetch(Fetch { key: 1, subscriber: 11 }).accepted());
            started.await.expect("fetch did not start");
            assert!(resolver.retain(|_, subscriber| *subscriber == 11).accepted());
            context.sleep(Duration::from_millis(10)).await;
            response
                .send(Some(Bytes::from_static(b"value")))
                .expect("fetcher dropped");

            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.delivery.subscribers, non_empty_vec![11]);
            delivery.response.send(true).expect("response dropped");
        });
    }

    #[test]
    fn targeted_fetch_uses_same_direct_fetch_path() {
        Runner::default().start(|context| async move {
            let fetcher = MockFetcher::default();
            fetcher.push(1, Some(Bytes::from_static(b"value")));
            let consumer = MockConsumer::default();
            let mut resolver = start_resolver(context.child("resolver"), fetcher.clone(), consumer.clone());
            let target = PrivateKey::from_seed(0).public_key();

            assert!(resolver
                .fetch_targeted(Fetch { key: 1, subscriber: 10 }, non_empty_vec![target])
                .accepted());
            let delivery = wait_for_delivery(&context, &consumer).await;
            assert_eq!(delivery.value, Bytes::from_static(b"value"));
            delivery.response.send(true).expect("response dropped");
            assert_eq!(fetcher.calls(), 1);
        });
    }
}

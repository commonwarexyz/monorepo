//! Coordinate local callers sharing resolver requests.
//!
//! A [`Tracker`] owns one exclusive [`Id`] domain for the full lifetime of one
//! underlying resolver engine. Do not create another tracker over the same engine
//! or replace a tracker while that engine remains alive. Route every delivery for
//! that ID domain through the same tracker.
//!
//! This adapter requires the resolver to serialize validation attempts for each
//! key, as the P2P and opaque resolvers do. In particular, a newer delivery for a
//! key must not complete while an older delivery for that key is still being
//! validated.
//!
//! [`Tracker`] owns the resolver verdicts queued by [`Tracker::deliver`]. Poll
//! [`Tracker::next_completed`] continuously to drive approval aggregation and
//! rejection cleanup. Dropping the tracker drops every queued verdict unjudged. A
//! `false` approval means the response is invalid for the key itself, not merely
//! unsuitable for one local caller.
//!
//! # Examples
//!
//! ```no_run
//! use commonware_resolver::{Resolver, request::{Id, Tracker}};
//! use commonware_utils::channel::oneshot;
//!
//! fn fetch<R, V>(tracker: &mut Tracker<R, V>, key: R::Key)
//!     -> oneshot::Receiver<(V, oneshot::Sender<bool>)>
//! where
//!     R: Resolver<Subscriber = Id>,
//!     V: Clone + Send + 'static,
//! {
//!     let (response, receiver) = oneshot::channel();
//!     let _ = tracker.fetch(key, tracing::Span::current(), response);
//!     receiver
//! }
//! ```

use crate::{Delivery, Fetch, Resolver};
use commonware_actor::Feedback;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::Pool,
};
use std::collections::{BTreeMap, btree_map::Entry};

/// Identifies one local group of callers sharing a resolver request.
///
/// IDs are allocated by [`Tracker`] and are meaningful only to the resolver
/// engine exclusively owned by that tracker.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Id(u64);

struct Group<V> {
    id: Id,
    responses: Vec<oneshot::Sender<(V, oneshot::Sender<bool>)>>,
}

struct Completion<K> {
    key: K,
    id: Id,
    verdict: Option<bool>,
}

/// Coordinates coalescing, cancellation, delivery, and verdict aggregation for
/// local callers of a resolver.
///
/// See the [module-level documentation](crate::request) for the ownership,
/// completion polling, and verdict contract.
pub struct Tracker<R, V>
where
    R: Resolver<Subscriber = Id>,
{
    resolver: R,
    pending: BTreeMap<R::Key, Group<V>>,
    approvals: Pool<'static, Completion<R::Key>>,
    next_id: u64,
}

impl<R, V> Tracker<R, V>
where
    R: Resolver<Subscriber = Id>,
    V: Clone + Send + 'static,
{
    /// Creates an empty request tracker backed by `resolver`.
    ///
    /// Reserve the resolver's [`Id`] domain and all its deliveries for this tracker
    /// until the engine shuts down.
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            pending: BTreeMap::new(),
            approvals: Pool::default(),
            next_id: 0,
        }
    }

    /// Adds a local caller waiting for `key`.
    ///
    /// Callers for an existing key share its ID and resolver fetch, even when all
    /// older response receivers have closed. A new key gets a fresh ID and
    /// submits a resolver fetch. The returned feedback describes only that
    /// submission; `None` means the caller joined an existing group.
    ///
    /// If a new submission reports [`Feedback::Closed`], its newly created group
    /// is removed and its response sender is dropped.
    /// Notify the tracker through [`cancel_closed`](Self::cancel_closed) when a
    /// caller stops waiting so an empty group can be retired.
    ///
    /// # Panics
    ///
    /// Panics before reusing an ID if the ID space is exhausted.
    pub fn fetch(
        &mut self,
        key: R::Key,
        span: tracing::Span,
        response: oneshot::Sender<(V, oneshot::Sender<bool>)>,
    ) -> Option<Feedback> {
        if let Some(group) = self.pending.get_mut(&key) {
            group.responses.retain(|response| !response.is_closed());
            group.responses.push(response);
            return None;
        }

        let id = Id(self.next_id);
        self.next_id = self.next_id.checked_add(1).expect("request ID overflow");
        self.pending.insert(
            key.clone(),
            Group {
                id,
                responses: vec![response],
            },
        );

        let feedback = self.resolver.fetch(Fetch {
            key: key.clone(),
            subscriber: id,
            span,
        });
        if feedback == Feedback::Closed {
            let _ = self.pending.remove(&key);
        }
        Some(feedback)
    }

    /// Cancels the current request for `key` when none of its callers remain.
    ///
    /// Closed response senders are pruned first. A cancellation retains every
    /// resolver subscription except the exact `(key, ID)` owned by the now-empty
    /// group. The returned feedback describes that retain submission; `None`
    /// means no group existed or at least one caller remains live.
    pub fn cancel_closed(&mut self, key: &R::Key) -> Option<Feedback> {
        let group = self.pending.get_mut(key)?;
        group.responses.retain(|response| !response.is_closed());
        if !group.responses.is_empty() {
            return None;
        }

        let id = self
            .pending
            .remove(key)
            .expect("pending group disappeared")
            .id;
        let key = key.clone();
        Some(
            self.resolver
                .retain(move |candidate, candidate_id| candidate != &key || candidate_id != &id),
        )
    }

    /// Prepares and delivers a resolver response to the matching local callers.
    ///
    /// Membership is checked before `prepare` runs. A stale or unrelated delivery
    /// is left unjudged and returns `Ok(false)`. If `prepare` fails, the resolver is
    /// told the response is invalid while the waiting group and its ID remain for
    /// retry.
    ///
    /// After successful preparation, the waiting group is removed and each live
    /// caller receives a cloned value and an individual approval sender. If no
    /// send succeeds, the resolver verdict is dropped and `Ok(false)` is returned.
    /// Otherwise, approval work is queued and `Ok(true)` is returned. Queued work
    /// sequentially aggregates approvals: dropped approvals are ignored, the first
    /// observed `false` is decisive, and any observed `true` succeeds when no
    /// `false` is observed. If every approval is dropped, the resolver verdict is
    /// dropped.
    ///
    /// [`next_completed`](Self::next_completed) reports each aggregate result for
    /// metrics. On rejection, queued work reports `false` before completion, and
    /// `next_completed` then prunes strictly older IDs for the same key. It retains
    /// the rejecting ID because verdict submission is not an acknowledgement that
    /// the resolver consumed it.
    pub fn deliver<E>(
        &mut self,
        delivery: Delivery<R::Key, Id>,
        feedback: oneshot::Sender<bool>,
        prepare: impl FnOnce() -> Result<V, E>,
    ) -> Result<bool, E> {
        let entry = match self.pending.entry(delivery.key) {
            Entry::Occupied(entry)
                if delivery
                    .subscribers
                    .iter()
                    .any(|(subscriber, _)| subscriber == &entry.get().id) =>
            {
                entry
            }
            _ => return Ok(false),
        };

        let value = match prepare() {
            Ok(value) => value,
            Err(error) => {
                feedback.send_lossy(false);
                return Err(error);
            }
        };
        let (key, group) = entry.remove_entry();
        let id = group.id;
        let mut approvals = Vec::with_capacity(group.responses.len());
        for response in group.responses {
            let (approval, receiver) = oneshot::channel();
            if response.send((value.clone(), approval)).is_ok() {
                approvals.push(receiver);
            }
        }

        if approvals.is_empty() {
            return Ok(false);
        }

        self.approvals.push(async move {
            let mut verdict = None;
            for approval in approvals {
                match approval.await {
                    Ok(true) => verdict = Some(true),
                    Ok(false) => {
                        verdict = Some(false);
                        break;
                    }
                    Err(_) => {}
                }
            }

            if let Some(verdict) = verdict {
                feedback.send_lossy(verdict);
            }
            Completion { key, id, verdict }
        });
        Ok(true)
    }

    /// Waits for the next queued approval group to complete.
    ///
    /// The returned key identifies the delivered response and the optional verdict
    /// is intended for metrics. `None` means every approval sender was dropped. On
    /// `Some(false)`, this method synchronously submits cleanup that retains the
    /// rejecting ID and every newer ID for the same key before returning.
    ///
    /// If no approval work is queued, this method remains pending.
    pub async fn next_completed(&mut self) -> (R::Key, Option<bool>) {
        let Completion { key, id, verdict } = self.approvals.next_completed().await;
        if verdict == Some(false) {
            let rejected_key = key.clone();
            let _ = self.resolver.retain(move |candidate, candidate_id| {
                candidate != &rejected_key || candidate_id >= &id
            });
        }
        (key, verdict)
    }

    /// Returns the number of keys with callers still waiting for delivery.
    ///
    /// Queued approval groups are not included.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns `true` when no callers are waiting for delivery.
    ///
    /// Queued approval groups are not included.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Consumer, p2p};
    use bytes::Bytes;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_p2p::{
        Blocker,
        simulated::{Link, Network},
    };
    use commonware_runtime::{
        Handle, Quota, Runner as _, Supervisor as _,
        deterministic::{self, Runner},
    };
    use commonware_utils::{
        NZU32, NZUsize,
        channel::{mpsc, ring},
        probability,
        sync::Mutex,
        vec::NonEmptyVec,
    };
    use std::{cell::Cell, collections::VecDeque, sync::Arc, time::Duration};

    /// Resolver whose accepted submissions and retain effects remain observable.
    #[derive(Clone)]
    struct MockResolver {
        /// Shared recorder state across resolver handle clones.
        state: Arc<Mutex<State>>,
    }

    /// Mutable state recorded by [`MockResolver`].
    struct State {
        /// Feedback returned by every resolver submission.
        feedback: Feedback,
        /// Fetch keys and their allocated request identities in submission order.
        fetches: Vec<(u64, Id)>,
        /// Resolver subscriptions surviving the applied retain predicates.
        subscriptions: BTreeMap<u64, Vec<Id>>,
        /// Number of retain predicates submitted by the helper.
        retains: usize,
    }

    impl MockResolver {
        fn new(feedback: Feedback) -> Self {
            Self {
                state: Arc::new(Mutex::new(State {
                    feedback,
                    fetches: Vec::new(),
                    subscriptions: BTreeMap::new(),
                    retains: 0,
                })),
            }
        }

        fn fetches(&self) -> Vec<(u64, Id)> {
            self.state.lock().fetches.clone()
        }

        fn subscriptions(&self, key: u64) -> Vec<Id> {
            self.state
                .lock()
                .subscriptions
                .get(&key)
                .cloned()
                .unwrap_or_default()
        }

        fn retains(&self) -> usize {
            self.state.lock().retains
        }
    }

    impl Resolver for MockResolver {
        type Key = u64;
        type Subscriber = Id;

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let fetch = fetch.into();
            let mut state = self.state.lock();
            state.fetches.push((fetch.key, fetch.subscriber));
            if state.feedback.accepted() {
                state
                    .subscriptions
                    .entry(fetch.key)
                    .or_default()
                    .push(fetch.subscriber);
            }
            state.feedback
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let mut feedback = Feedback::Ok;
            for fetch in fetches {
                feedback = self.fetch(fetch);
            }
            feedback
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            let mut state = self.state.lock();
            state.retains += 1;
            state.subscriptions.retain(|key, subscribers| {
                subscribers.retain(|subscriber| predicate(key, subscriber));
                !subscribers.is_empty()
            });
            state.feedback
        }
    }

    fn delivery(key: u64, ids: &[Id]) -> Delivery<u64, Id> {
        Delivery {
            key,
            subscribers: NonEmptyVec::from_unchecked(
                ids.iter()
                    .copied()
                    .map(|id| (id, tracing::Span::none()))
                    .collect(),
            ),
        }
    }

    const REQUEST: u8 = 1;
    const UNRELATED: u8 = 2;
    const VALUE: &[u8] = b"response";

    /// The cleanup closure emitted by the request tracker, retained without modification.
    type Predicate = Box<dyn Fn(&u8, &Id) -> bool + Send>;

    /// A caller waiting for bytes and its independent verification channel.
    type Response = oneshot::Receiver<(Bytes, oneshot::Sender<bool>)>;

    /// Resolver delivery whose verdict remains controlled by the test.
    struct Delivered {
        /// The actual subscriber snapshot taken by the resolver.
        delivery: Delivery<u8, Id>,
        /// Bytes returned by the peer.
        value: Bytes,
        /// The engine's original verdict sender.
        feedback: oneshot::Sender<bool>,
    }

    /// Forwards deliveries so the test can gate verdict consumption explicitly.
    #[derive(Clone)]
    struct RecordingConsumer {
        /// Deliveries awaiting local fanout and a resolver verdict.
        sender: mpsc::UnboundedSender<Delivered>,
    }

    impl Consumer for RecordingConsumer {
        type Key = u8;
        type Value = Bytes;
        type Subscriber = Id;
        type Outcome = bool;

        fn deliver(&mut self, delivery: Delivery<u8, Id>, value: Bytes) -> oneshot::Receiver<bool> {
            let (feedback, receiver) = oneshot::channel();
            let _ = self.sender.send(Delivered {
                delivery,
                value,
                feedback,
            });
            receiver
        }
    }

    /// Gates responses for the tested key while answering ordering-fence keys immediately.
    #[derive(Clone)]
    struct GatedProducer {
        /// Pending peer requests released only after subscriber admission is fenced.
        requests: mpsc::UnboundedSender<oneshot::Sender<Bytes>>,
    }

    impl p2p::Producer for GatedProducer {
        type Key = u8;

        fn produce(&mut self, key: u8) -> oneshot::Receiver<Bytes> {
            let (sender, receiver) = oneshot::channel();
            if key == REQUEST {
                let _ = self.requests.send(sender);
            } else {
                let _ = sender.send(Bytes::from_static(VALUE));
            }
            receiver
        }
    }

    /// Observes invalid-verdict consumption without disconnecting the source needed for retries.
    #[derive(Clone)]
    struct RecordingBlocker {
        /// Peer-block decisions made by the real resolver engine.
        sender: mpsc::UnboundedSender<PublicKey>,
    }

    impl Blocker for RecordingBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, peer: PublicKey) -> Feedback {
            let _ = self.sender.send(peer);
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<PublicKey> {
            let (_, receiver) = ring::channel(NZUsize!(1));
            receiver
        }
    }

    /// Records generated identities and holds the helper's original retain closures.
    #[derive(Clone)]
    struct RecordingResolver {
        /// Real engine mailbox used to admit fetches and apply retained cleanup.
        inner: p2p::Mailbox<u8, PublicKey, Id>,
        /// Fetches issued by the helper, including their opaque generated identities.
        fetches: Arc<Mutex<VecDeque<Fetch<u8, Id>>>>,
        /// Cleanup waiting for the test's chosen consumption ordering.
        retains: Arc<Mutex<VecDeque<Predicate>>>,
    }

    impl Resolver for RecordingResolver {
        type Key = u8;
        type Subscriber = Id;

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<u8, Id>> + Send,
        {
            let fetch = fetch.into();
            self.fetches.lock().push_back(fetch.clone());
            self.inner.fetch(fetch)
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<u8, Id>> + Send,
        {
            let fetches: Vec<_> = fetches.into_iter().map(Into::into).collect();
            self.fetches.lock().extend(fetches.iter().cloned());
            self.inner.fetch_all(fetches)
        }

        fn retain(&mut self, predicate: impl Fn(&u8, &Id) -> bool + Send + 'static) -> Feedback {
            self.retains.lock().push_back(Box::new(predicate));
            Feedback::Ok
        }
    }

    /// A caller-side tracker connected to two real resolver engines over simulated links.
    struct Harness {
        /// The production helper under test.
        tracker: Tracker<RecordingResolver, Bytes>,
        /// Test control over the exact fetches and cleanup emitted by the helper.
        resolver: RecordingResolver,
        /// Actual consumer callbacks from the client engine.
        deliveries: mpsc::UnboundedReceiver<Delivered>,
        /// Callbacks for other keys preserved while waiting for a particular key.
        buffered: BTreeMap<u8, Delivered>,
        /// Source requests whose responses are released after each ordering fence.
        requests: mpsc::UnboundedReceiver<oneshot::Sender<Bytes>>,
        /// A block event proves that the engine consumed an invalid verdict.
        blocks: mpsc::UnboundedReceiver<PublicKey>,
        /// The sole serving peer, checked against every block event.
        source: PublicKey,
        /// Fresh keys used to fence engine mailbox consumption.
        next_fence: u8,
        /// Keeps the source engine's mailbox open for the test lifetime.
        _source_mailbox: p2p::Mailbox<u8, PublicKey, Id>,
        /// Both resolver actors and their simulated network, stopped at test completion.
        handles: [Handle<()>; 3],
    }

    impl Harness {
        async fn new(context: deterministic::Context) -> Self {
            // Connect a client and source over reliable simulated links.
            let peers = [11, 12].map(|seed| PrivateKey::from_seed(seed).public_key());
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: false,
                    tracked_peer_sets: NZUsize!(1),
                },
                peers.clone(),
            )
            .await;
            let network_handle = network.start();
            let manager = oracle.manager();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::ZERO,
                success_rate: probability!(1.0),
            };
            oracle
                .add_link(peers[0].clone(), peers[1].clone(), link.clone())
                .await
                .unwrap();
            oracle
                .add_link(peers[1].clone(), peers[0].clone(), link)
                .await
                .unwrap();
            let client_net = oracle
                .control(peers[0].clone())
                .register(0, Quota::per_second(NZU32!(1000)))
                .await
                .unwrap();
            let source_net = oracle
                .control(peers[1].clone())
                .register(0, Quota::per_second(NZU32!(1000)))
                .await
                .unwrap();

            // Forward deliveries and gate response bytes so tests control admission and verdict order.
            let (delivery_tx, deliveries) = mpsc::unbounded_channel();
            let (request_tx, requests) = mpsc::unbounded_channel();
            let (block_tx, blocks) = mpsc::unbounded_channel();
            let config = |me| p2p::Config {
                peer_provider: manager.clone(),
                blocker: RecordingBlocker {
                    sender: block_tx.clone(),
                },
                consumer: RecordingConsumer {
                    sender: delivery_tx.clone(),
                },
                producer: GatedProducer {
                    requests: request_tx.clone(),
                },
                mailbox_size: NZUsize!(1),
                me: Some(me),
                timeout: Duration::from_secs(1),
                fetch_retry_timeout: Duration::from_millis(10),
                priority_requests: false,
                priority_responses: false,
            };
            let (client, mailbox) =
                p2p::Engine::new(context.child("client"), config(peers[0].clone()));
            let (source, source_mailbox) =
                p2p::Engine::new(context.child("source"), config(peers[1].clone()));
            let resolver = RecordingResolver {
                inner: mailbox,
                fetches: Arc::new(Mutex::new(VecDeque::new())),
                retains: Arc::new(Mutex::new(VecDeque::new())),
            };
            Self {
                tracker: Tracker::new(resolver.clone()),
                resolver,
                deliveries,
                buffered: BTreeMap::new(),
                requests,
                blocks,
                source: peers[1].clone(),
                next_fence: 10,
                _source_mailbox: source_mailbox,
                handles: [
                    client.start(client_net),
                    source.start(source_net),
                    network_handle,
                ],
            }
        }

        fn fetch(&mut self, key: u8) -> (Id, Response, Feedback) {
            let (sender, receiver) = oneshot::channel();
            let feedback = self
                .tracker
                .fetch(key, tracing::Span::none(), sender)
                .expect("new waiting group must issue a fetch");
            assert!(feedback.accepted());
            let fetch = self.resolver.fetches.lock().pop_front().unwrap();
            assert_eq!(fetch.key, key);
            (fetch.subscriber, receiver, feedback)
        }

        /// Wait for one key while retaining deliveries for all other keys.
        async fn receive(&mut self, key: u8) -> Delivered {
            if let Some(delivered) = self.buffered.remove(&key) {
                return delivered;
            }
            loop {
                let delivered = self.deliveries.recv().await.unwrap();
                if delivered.delivery.key == key {
                    return delivered;
                }
                assert!(
                    self.buffered
                        .insert(delivered.delivery.key, delivered)
                        .is_none()
                );
            }
        }

        /// Release a peer response and check the resolver's exact subscriber snapshot.
        async fn respond(&mut self, expected: &[Id]) -> Delivered {
            self.requests
                .recv()
                .await
                .unwrap()
                .send(Bytes::from_static(VALUE))
                .unwrap();
            let delivered = self.receive(REQUEST).await;
            let subscribers: Vec<_> = delivered
                .delivery
                .subscribers
                .iter()
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(subscribers, expected);
            delivered
        }

        async fn accept(&mut self, delivered: Delivered, caller: Response) {
            let key = delivered.delivery.key;
            assert!(
                self.tracker
                    .deliver(delivered.delivery, delivered.feedback, || {
                        Ok::<_, ()>(delivered.value)
                    })
                    .unwrap(),
                "delivery must include the waiting group"
            );
            let (value, approval) = caller.await.unwrap();
            assert_eq!(value, VALUE);
            approval.send(true).unwrap();
            assert_eq!(self.tracker.next_completed().await, (key, Some(true)));
        }

        /// Obtain rejection cleanup while keeping the engine's original verdict sender gated.
        async fn reject(
            &mut self,
            delivered: Delivered,
            caller: Response,
        ) -> (oneshot::Sender<bool>, Predicate) {
            let (feedback, verdict) = oneshot::channel();
            let key = delivered.delivery.key;
            assert!(
                self.tracker
                    .deliver(delivered.delivery, feedback, || {
                        Ok::<_, ()>(delivered.value)
                    })
                    .unwrap(),
                "delivery must include the rejecting group"
            );
            let (value, approval) = caller.await.unwrap();
            assert_eq!(value, VALUE);
            approval.send(false).unwrap();
            assert_eq!(self.tracker.next_completed().await, (key, Some(false)));
            assert!(!verdict.await.unwrap());
            let predicate = self.resolver.retains.lock().pop_front().unwrap();
            assert!(self.resolver.retains.lock().is_empty());
            (delivered.feedback, predicate)
        }

        fn queue_fence(&mut self) -> (u8, Response) {
            let key = self.next_fence;
            self.next_fence = self.next_fence.checked_add(1).unwrap();
            let (_, caller, _) = self.fetch(key);
            (key, caller)
        }

        async fn finish_fence(&mut self, (key, caller): (u8, Response)) {
            let delivered = self.receive(key).await;
            self.accept(delivered, caller).await;
        }

        async fn fence(&mut self) {
            let fence = self.queue_fence();
            self.finish_fence(fence).await;
        }

        /// Apply captured cleanup through a full mailbox and fence its consumption.
        async fn apply_cutoff(
            &mut self,
            predicate: Predicate,
            successor: bool,
        ) -> Option<(Id, Response)> {
            // Fill the ready slot so cleanup must cross overflow and overtake any queued successor.
            let filler = self.queue_fence();
            let successor = successor.then(|| {
                let (id, caller, feedback) = self.fetch(REQUEST);
                assert_eq!(feedback, Feedback::Backoff);
                (id, caller)
            });
            assert_eq!(self.resolver.inner.retain(predicate), Feedback::Backoff);
            let fence = self.queue_fence();

            // Both fence deliveries prove that cleanup and surviving demand reached the engine.
            self.finish_fence(filler).await;
            self.finish_fence(fence).await;
            successor
        }

        async fn consume_rejection(&mut self, feedback: oneshot::Sender<bool>) {
            feedback
                .send(false)
                .expect("cleanup must preserve the verdict receiver");
            assert_eq!(self.blocks.recv().await.unwrap(), self.source);
        }

        async fn finish_rejection(
            &mut self,
            feedback: oneshot::Sender<bool>,
            predicate: Predicate,
            retain_before_verdict: bool,
            successor: bool,
        ) -> Option<(Id, Response)> {
            if retain_before_verdict {
                let successor = self.apply_cutoff(predicate, successor).await;
                self.consume_rejection(feedback).await;
                successor
            } else {
                self.consume_rejection(feedback).await;
                self.apply_cutoff(predicate, successor).await
            }
        }

        async fn shutdown(self) {
            for handle in &self.handles {
                handle.abort();
            }
            for handle in self.handles {
                let _ = handle.await;
            }
        }
    }

    #[test]
    fn coalesces_callers_and_reuses_id_after_closed_callers() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());

            // Establish one request, close its only caller, and add fresh demand
            // before cancellation can retire the group.
            let (first, first_rx) = oneshot::channel();
            assert_eq!(
                tracker.fetch(7, tracing::Span::none(), first),
                Some(Feedback::Ok)
            );
            drop(first_rx);
            let (second, second_rx) = oneshot::channel();
            assert_eq!(tracker.fetch(7, tracing::Span::none(), second), None);
            assert_eq!(tracker.cancel_closed(&7), None);

            // The fresh caller shares the original resolver identity and is the
            // only caller that receives the response.
            let fetches = resolver.fetches();
            assert_eq!(fetches.len(), 1);
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(7, &[fetches[0].1]), verdict, || Ok::<_, ()>(11))
                    .unwrap()
            );
            let (value, approval) = second_rx.await.unwrap();
            assert_eq!(value, 11);
            approval.send(true).unwrap();
            assert_eq!(tracker.next_completed().await, (7, Some(true)));
            assert!(verdict_rx.await.unwrap());
        });
    }

    #[test]
    fn successful_fanout_allows_a_fresh_group() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());

            // Fan out the first group while leaving its approval work pending.
            let (first, first_rx) = oneshot::channel();
            let _ = tracker.fetch(3, tracing::Span::none(), first);
            let first_id = resolver.fetches()[0].1;
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(3, &[first_id]), verdict, || Ok::<_, ()>(5))
                    .unwrap()
            );
            let (_value, approval) = first_rx.await.unwrap();
            assert!(tracker.is_empty());

            // Demand arriving after fanout owns a distinct, monotonic identity
            // even before the old group reports its verdict.
            let (second, _second_rx) = oneshot::channel();
            assert_eq!(
                tracker.fetch(3, tracing::Span::none(), second),
                Some(Feedback::Ok)
            );
            let fetches = resolver.fetches();
            assert_eq!(fetches.len(), 2);
            assert!(fetches[1].1 > first_id);
            approval.send(true).unwrap();
            assert_eq!(tracker.next_completed().await, (3, Some(true)));
            assert!(verdict_rx.await.unwrap());
        });
    }

    #[test]
    fn cancellation_is_exact_and_requires_all_callers_closed() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());

            // Two callers share one group, so closing only one cannot authorize
            // cancellation of the resolver subscription.
            let (first, first_rx) = oneshot::channel();
            let (second, second_rx) = oneshot::channel();
            let _ = tracker.fetch(1, tracing::Span::none(), first);
            let _ = tracker.fetch(1, tracing::Span::none(), second);
            drop(first_rx);
            assert_eq!(tracker.cancel_closed(&1), None);
            assert_eq!(resolver.retains(), 0);

            // Once every caller closes, only the exact current identity is
            // removed and an absent group cannot submit another cancellation.
            drop(second_rx);
            assert_eq!(tracker.cancel_closed(&1), Some(Feedback::Ok));
            assert_eq!(tracker.cancel_closed(&1), None);
            assert_eq!(resolver.subscriptions(1), Vec::<Id>::new());
            assert_eq!(resolver.retains(), 1);
            assert!(tracker.is_empty());
        });
    }

    #[test]
    fn stale_delivery_does_not_prepare_or_consume_new_demand() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());

            // Cancel one generation, reopen the key, and retain the stale ID for
            // a delivery that races with the new group.
            let (old, old_rx) = oneshot::channel();
            let _ = tracker.fetch(9, tracing::Span::none(), old);
            let old_id = resolver.fetches()[0].1;
            drop(old_rx);
            let _ = tracker.cancel_closed(&9);
            let (fresh, _fresh_rx) = oneshot::channel();
            let _ = tracker.fetch(9, tracing::Span::none(), fresh);
            let prepared = Cell::new(false);

            // Membership is resolved before preparation, preserving both the new
            // group and an unjudged resolver verdict.
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                !tracker
                    .deliver(delivery(9, &[old_id]), verdict, || {
                        prepared.set(true);
                        Ok::<_, ()>(4)
                    })
                    .unwrap()
            );
            assert!(!prepared.get());
            assert!(verdict_rx.await.is_err());
            assert_eq!(tracker.len(), 1);
        });
    }

    #[test]
    fn preparation_error_keeps_the_waiting_identity() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (response, response_rx) = oneshot::channel();
            let _ = tracker.fetch(4, tracing::Span::none(), response);
            let id = resolver.fetches()[0].1;

            // Invalid preparation reports rejection without detaching the local
            // group, allowing the resolver to retry the same identity.
            let (invalid, invalid_rx) = oneshot::channel();
            assert!(matches!(
                tracker.deliver(delivery(4, &[id]), invalid, || Err::<u64, _>("invalid")),
                Err("invalid")
            ));
            assert!(!invalid_rx.await.unwrap());
            assert_eq!(tracker.len(), 1);

            // A later valid delivery for that ID reaches the original caller.
            let (valid, valid_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(4, &[id]), valid, || Ok::<_, &str>(8))
                    .unwrap()
            );
            let (value, approval) = response_rx.await.unwrap();
            assert_eq!(value, 8);
            approval.send(true).unwrap();
            assert_eq!(tracker.next_completed().await, (4, Some(true)));
            assert!(valid_rx.await.unwrap());
        });
    }

    #[test]
    fn absent_receivers_and_all_dropped_approvals_are_unjudged() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());

            // A group whose receiver closes before fanout produces no approval
            // work and therefore no resolver verdict.
            let (closed, closed_rx) = oneshot::channel();
            let _ = tracker.fetch(2, tracing::Span::none(), closed);
            let closed_id = resolver.fetches()[0].1;
            drop(closed_rx);
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                !tracker
                    .deliver(delivery(2, &[closed_id]), verdict, || Ok::<_, ()>(6))
                    .unwrap()
            );
            assert!(verdict_rx.await.is_err());

            // When every caller abandons verification, completion reports no verdict.
            let (abstain, abstain_rx) = oneshot::channel();
            let _ = tracker.fetch(2, tracing::Span::none(), abstain);
            let abstain_id = resolver.fetches()[1].1;
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(2, &[abstain_id]), verdict, || Ok::<_, ()>(8))
                    .unwrap()
            );
            drop(abstain_rx.await.unwrap().1);
            assert_eq!(tracker.next_completed().await, (2, None));
            assert!(verdict_rx.await.is_err());
            assert_eq!(resolver.retains(), 0);
        });
    }

    #[test]
    fn dropping_tracker_leaves_queued_approval_unjudged() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (response, response_rx) = oneshot::channel();
            let _ = tracker.fetch(2, tracing::Span::none(), response);
            let id = resolver.fetches()[0].1;

            // Tracker owns queued approval work, so dropping it closes the
            // downstream approval and resolver verdict without cleanup.
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(2, &[id]), verdict, || Ok::<_, ()>(7))
                    .unwrap()
            );
            let (_value, approval) = response_rx.await.unwrap();
            drop(tracker);
            assert!(approval.is_closed());
            assert!(verdict_rx.await.is_err());
            assert_eq!(resolver.retains(), 0);
        });
    }

    #[test]
    fn mixed_dropped_and_true_approvals_accept() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (first, first_rx) = oneshot::channel();
            let (second, second_rx) = oneshot::channel();
            let _ = tracker.fetch(5, tracing::Span::none(), first);
            let _ = tracker.fetch(5, tracing::Span::none(), second);
            let id = resolver.fetches()[0].1;

            // One caller abstains while another approves, so the aggregate has a
            // positive verdict and requires no rejection cleanup.
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(5, &[id]), verdict, || Ok::<_, ()>(10))
                    .unwrap()
            );
            drop(first_rx.await.unwrap().1);
            second_rx.await.unwrap().1.send(true).unwrap();
            assert_eq!(tracker.next_completed().await, (5, Some(true)));
            assert!(verdict_rx.await.unwrap());
            assert_eq!(resolver.retains(), 0);
        });
    }

    #[test]
    fn observed_false_is_decisive_and_closes_later_approvals() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (first, first_rx) = oneshot::channel();
            let (second, second_rx) = oneshot::channel();
            let (third, third_rx) = oneshot::channel();
            let _ = tracker.fetch(6, tracing::Span::none(), first);
            let _ = tracker.fetch(6, tracing::Span::none(), second);
            let _ = tracker.fetch(6, tracing::Span::none(), third);
            let id = resolver.fetches()[0].1;

            // Sequential aggregation observes an approval, then a rejection, and
            // does not wait for or interpret the later caller.
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(6, &[id]), verdict, || Ok::<_, ()>(12))
                    .unwrap()
            );
            first_rx.await.unwrap().1.send(true).unwrap();
            second_rx.await.unwrap().1.send(false).unwrap();
            let later = third_rx.await.unwrap().1;
            assert_eq!(tracker.next_completed().await, (6, Some(false)));
            assert!(!verdict_rx.await.unwrap());
            assert!(later.is_closed());
            assert_eq!(resolver.retains(), 1);
            assert_eq!(resolver.subscriptions(6), vec![id]);
        });
    }

    #[test]
    fn rejection_cleanup_is_key_scoped() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Ok);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (rejected, rejected_rx) = oneshot::channel();
            let (other, _other_rx) = oneshot::channel();
            let _ = tracker.fetch(20, tracing::Span::none(), rejected);
            let _ = tracker.fetch(21, tracing::Span::none(), other);
            let fetches = resolver.fetches();

            // Rejection prunes only older identities for its own key, preserving
            // both its verdict owner and unrelated demand.
            let (verdict, verdict_rx) = oneshot::channel();
            assert!(
                tracker
                    .deliver(delivery(20, &[fetches[0].1]), verdict, || Ok::<_, ()>(1))
                    .unwrap()
            );
            rejected_rx.await.unwrap().1.send(false).unwrap();
            assert_eq!(tracker.next_completed().await, (20, Some(false)));
            assert!(!verdict_rx.await.unwrap());
            assert_eq!(resolver.subscriptions(20), vec![fetches[0].1]);
            assert_eq!(resolver.subscriptions(21), vec![fetches[1].1]);
            assert_eq!(tracker.len(), 1);
        });
    }

    #[test]
    fn id_exhaustion_panics_before_submission_or_reuse() {
        let resolver = MockResolver::new(Feedback::Ok);
        let mut tracker = Tracker::<_, u64>::new(resolver.clone());
        tracker.next_id = u64::MAX;
        let (response, _receiver) = oneshot::channel();

        // Exhaustion is detected before the group is inserted or the resolver
        // can observe a reused identity.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracker.fetch(30, tracing::Span::none(), response)
        }));
        assert!(result.is_err());
        assert!(tracker.is_empty());
        assert!(resolver.fetches().is_empty());
    }

    #[test]
    fn closed_initial_submission_removes_the_group() {
        let runner = Runner::default();
        runner.start(|_| async move {
            let resolver = MockResolver::new(Feedback::Closed);
            let mut tracker = Tracker::<_, u64>::new(resolver.clone());
            let (response, receiver) = oneshot::channel();

            // A closed resolver endpoint cannot own pending local demand, so the
            // newly created group and its response sender are dropped together.
            assert_eq!(
                tracker.fetch(40, tracing::Span::none(), response),
                Some(Feedback::Closed)
            );
            assert!(tracker.is_empty());
            assert!(receiver.await.is_err());
            assert_eq!(resolver.fetches().len(), 1);
            assert!(resolver.subscriptions(40).is_empty());
        });
    }

    #[test]
    fn repeated_rejections_preserve_verdict_and_bound_spent_groups() {
        for retain_before_verdict in [true, false] {
            deterministic::Runner::timed(Duration::from_secs(10)).start(
                move |context| async move {
                    let mut harness = Harness::new(context).await;

                    // Older demand for another key must remain live across every generated cutoff.
                    let (_, unrelated_caller, _) = harness.fetch(UNRELATED);
                    let unrelated = harness.receive(UNRELATED).await;
                    let (first_id, first_caller, _) = harness.fetch(REQUEST);
                    let first = harness.respond(&[first_id]).await;

                    // With no same-key successor, removing the current ID would abort this false verdict.
                    let (feedback, cutoff) = harness.reject(first, first_caller).await;
                    assert!(
                        harness
                            .finish_rejection(feedback, cutoff, retain_before_verdict, false)
                            .await
                            .is_none()
                    );
                    assert!(!unrelated.feedback.is_closed());

                    // Admit fresh demand before releasing the retry's bytes and inspect its real snapshot.
                    let (mut current_id, mut current_caller, _) = harness.fetch(REQUEST);
                    harness.fence().await;
                    let mut delivered = harness.respond(&[first_id, current_id]).await;

                    // Each new rejecting group must reclaim spent history while preserving its successor.
                    for _ in 0..3 {
                        let (feedback, cutoff) = harness.reject(delivered, current_caller).await;
                        let (next_id, next_caller) = harness
                            .finish_rejection(feedback, cutoff, retain_before_verdict, true)
                            .await
                            .unwrap();
                        assert!(!unrelated.feedback.is_closed());
                        delivered = harness.respond(&[current_id, next_id]).await;
                        current_id = next_id;
                        current_caller = next_caller;
                    }

                    // Both the final waiting group and the independent older caller can still complete.
                    harness.accept(delivered, current_caller).await;
                    harness.accept(unrelated, unrelated_caller).await;
                    harness.fence().await;
                    assert!(harness.tracker.is_empty());
                    harness.shutdown().await;
                },
            );
        }
    }

    #[test]
    fn delayed_older_cutoffs_preserve_current_and_newer_groups() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut harness = Harness::new(context).await;

            // Keep an independent older key alive while several same-key completions await cleanup.
            let (_, unrelated_caller, _) = harness.fetch(UNRELATED);
            let unrelated = harness.receive(UNRELATED).await;
            let (first_id, first_caller, _) = harness.fetch(REQUEST);
            let first = harness.respond(&[first_id]).await;
            let (feedback, first_cutoff) = harness.reject(first, first_caller).await;
            harness.consume_rejection(feedback).await;

            // Hold the original cleanup closures so the next snapshots expose the accumulated IDs.
            let (second_id, second_caller, _) = harness.fetch(REQUEST);
            harness.fence().await;
            let second = harness.respond(&[first_id, second_id]).await;
            let (feedback, second_cutoff) = harness.reject(second, second_caller).await;
            harness.consume_rejection(feedback).await;
            let (third_id, third_caller, _) = harness.fetch(REQUEST);
            harness.fence().await;
            let third = harness.respond(&[first_id, second_id, third_id]).await;
            let (feedback, third_cutoff) = harness.reject(third, third_caller).await;

            // Apply the newest cutoff first, then deliver both older closures after new demand exists.
            let (new_id, new_caller) = harness
                .finish_rejection(feedback, third_cutoff, true, true)
                .await
                .unwrap();
            assert!(harness.apply_cutoff(second_cutoff, false).await.is_none());
            assert!(harness.apply_cutoff(first_cutoff, false).await.is_none());
            assert!(!unrelated.feedback.is_closed());
            let newest = harness.respond(&[third_id, new_id]).await;

            // Delayed cleanup neither resurrects spent groups nor consumes current or newer demand.
            harness.accept(newest, new_caller).await;
            harness.accept(unrelated, unrelated_caller).await;
            harness.fence().await;
            assert!(harness.tracker.is_empty());
            harness.shutdown().await;
        });
    }
}

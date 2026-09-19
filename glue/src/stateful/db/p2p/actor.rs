//! Resolver service actor for QMDB sync over P2P.

use super::{Mailbox, handler, mailbox, metrics::Metrics as ResolverMetrics};
use crate::stateful::db::Shared;
use commonware_actor::mailbox as actor_mailbox;
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{Delivery, Fetch, Resolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{GaugeExt, status},
};
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Request, Response, Source},
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::Pool as FuturesPool,
};
use futures::future;
use rand_core::Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

type Op<DB> = <Shared<DB> as Source>::Op;
type DatabaseRoot<DB> = <Shared<DB> as Source>::Digest;
type SyncMailbox<F, DB> = Mailbox<DB, F, Op<DB>, DatabaseRoot<DB>>;
type SyncMessage<F, DB> = mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>>;
type PendingSubs<F, DB> =
    BTreeMap<(Request<F>, u64), mailbox::ResponseTx<F, Op<DB>, DatabaseRoot<DB>>>;
type Approval<F> = (Delivery<Request<F>, u64>, Option<bool>);

/// Configuration for [`Actor`].
pub struct Config<P, D, B, DB>
where
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Provider for the current peer set.
    pub peer_provider: D,

    /// Blocker used when peers send invalid data.
    pub blocker: B,

    /// Local database used to serve incoming requests when available.
    pub database: Option<Shared<DB>>,

    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: NonZeroUsize,

    /// Local node identity if available.
    pub me: Option<P>,

    /// Request timeout.
    pub timeout: Duration,

    /// Retry cadence for pending fetches.
    pub fetch_retry_timeout: Duration,

    /// Maximum number of operations to serve in a single response.
    pub max_serve_ops: NonZeroU64,

    /// Send fetch requests with network priority.
    pub priority_requests: bool,

    /// Send responses with network priority.
    pub priority_responses: bool,
}

/// Runs a QMDB sync resolver service over `commonware_resolver::p2p::Engine`.
pub struct Actor<E, P, D, B, F, DB>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    DB: Send + Sync + 'static,
    Shared<DB>: Source<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    context: ContextCell<E>,
    config: Config<P, D, B, DB>,
    mailbox_rx: actor_mailbox::Receiver<SyncMessage<F, DB>>,
    metrics: ResolverMetrics,
    /// Callers awaiting bytes, indexed by request and resolver subscriber.
    pending: PendingSubs<F, DB>,
    /// Next identity to allocate for a caller.
    next_subscriber: u64,
    /// Verification results for the resolver's delivered subscriber snapshots.
    approvals: FuturesPool<'static, Approval<F>>,
    serves: FuturesPool<'static, ()>,
}

impl<E, P, D, B, F, DB> Actor<E, P, D, B, F, DB>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    DB: Send + Sync + 'static,
    Shared<DB>: Source<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    /// Create a new resolver actor and mailbox.
    pub fn new(context: E, cfg: Config<P, D, B, DB>) -> (Self, SyncMailbox<F, DB>) {
        let metrics = ResolverMetrics::new(&context);
        let _ = metrics
            .has_database
            .try_set(i64::from(cfg.database.is_some()));
        let (mailbox_tx, mailbox_rx) =
            actor_mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config: cfg,
            mailbox_rx,
            metrics,
            pending: BTreeMap::new(),
            next_subscriber: 0,
            approvals: FuturesPool::default(),
            serves: FuturesPool::default(),
        };
        (actor, mailbox)
    }

    /// Start the resolver service.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(net))
    }

    /// Main event loop: multiplexes mailbox messages and engine callbacks.
    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (handler_tx, mut handler_rx) =
            actor_mailbox::new(self.context.child("handler"), self.config.mailbox_size);
        let handler = handler::Handler::new(handler_tx);
        let (engine, mut resolver_mailbox) = p2p::Engine::new(
            self.context.as_present().child("resolver"),
            p2p::Config {
                peer_provider: self.config.peer_provider.clone(),
                blocker: self.config.blocker.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.config.mailbox_size,
                me: self.config.me.clone(),
                timeout: self.config.timeout,
                fetch_retry_timeout: self.config.fetch_retry_timeout,
                priority_requests: self.config.priority_requests,
                priority_responses: self.config.priority_responses,
            },
        );
        let mut resolver_task = engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_start => {
                let mailbox_message = async {
                    match self.mailbox_rx.recv().await {
                        Some(message) => Some(message),
                        None => future::pending().await,
                    }
                };
            },
            on_stopped => {
                return;
            },
            _ = &mut resolver_task => {
                return;
            },
            completion = self.approvals.next_completed() => {
                self.handle_approval(&mut resolver_mailbox, completion);
            },
            _ = self.serves.next_completed() => {
                // Polling drives the serve future and removes it on completion, freeing the slot.
                // The future sends the response and records metrics, leaving no result to handle.
            },
            Some(message) = mailbox_message else continue => {
                self.handle_mailbox_message(&mut resolver_mailbox, message);
            },
            Some(message) = handler_rx.recv() else {
                return;
            } => match message {
                handler::EngineMessage::Deliver {
                    delivery,
                    value,
                    response,
                } => {
                    self.handle_deliver(delivery, value, response);
                }
                handler::EngineMessage::Produce { key, response } => {
                    self.handle_produce(key, response);
                }
            },
        }
    }

    /// Process database attachment, local requests, and caller cancellation.
    fn handle_mailbox_message<R>(&mut self, resolver: &mut R, message: SyncMessage<F, DB>)
    where
        R: Resolver<Key = Request<F>, Subscriber = u64>,
    {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                // Future serves use this handle; an active serve keeps its captured database.
                let replacing_existing = self.config.database.replace(db).is_some();
                info!(replacing_existing, "attached resolver database");
                let _ = self.metrics.has_database.try_set(1i64);
            }
            mailbox::Message::GetOperations { request, response } => {
                // Each caller owns a subscription. The resolver coalesces same-key fetches
                // and redelivers cached responses to callers that join during verification.
                let subscriber = self.next_subscriber;
                self.next_subscriber = self
                    .next_subscriber
                    .checked_add(1)
                    .expect("request ID overflow");
                self.pending.insert((request, subscriber), response);
                resolver.fetch(Fetch {
                    key: request,
                    subscriber,
                    span: tracing::Span::none(),
                });
                self.metrics.fetch_requests.inc();
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
            }
            mailbox::Message::CancelOperations { request } => {
                // Notices can lag behind new callers. Closed response channels identify
                // exactly which subscriptions no longer have a waiting caller.
                let canceled: BTreeSet<_> = self
                    .pending
                    .extract_if((request, 0)..=(request, u64::MAX), |_, response| {
                        response.is_closed()
                    })
                    .map(|((_, subscriber), _)| subscriber)
                    .collect();
                if canceled.is_empty() {
                    return;
                }

                // Retire canceled subscriptions from the resolver while preserving callers
                // still waiting for a response or verifying one.
                self.metrics.cancel_requests.inc_by(canceled.len() as u64);
                resolver.retain(move |key, id| key != &request || !canceled.contains(id));
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
            }
        }
    }

    /// Deliver a decoded response to waiting callers and collect verification feedback.
    fn handle_deliver(
        &mut self,
        delivery: Delivery<Request<F>, u64>,
        value: bytes::Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        // Queued deliveries can outlive their callers. Only IDs in this snapshot
        // may consume a response; later subscribers remain with the resolver.
        let key = delivery.key;
        if !delivery
            .subscribers
            .iter()
            .any(|(subscriber, _)| self.pending.contains_key(&(key, *subscriber)))
        {
            self.metrics.deliveries.inc(status::Status::Dropped);
            return;
        }

        // Retain waiting callers until decoding and response shape checks succeed,
        // so invalid bytes leave their subscriptions available for resolver retry.
        let cfg = (key.max_ops().get() as usize, ());
        let response = match Response::<F, Op<DB>, DatabaseRoot<DB>>::decode_cfg(value, &cfg) {
            Ok(response)
                if matches!(
                    (&key, &response),
                    (Request::Operations { .. }, Response::Operations { .. })
                        | (Request::Boundary { .. }, Response::Boundary { .. })
                ) =>
            {
                response
            }
            _ => {
                self.metrics.deliveries.inc(status::Status::Invalid);
                feedback_tx.send_lossy(false);
                return;
            }
        };

        // Give every matching caller its response before processing any verdict.
        let mut approvals = Vec::with_capacity(delivery.subscribers.len().get());
        for (subscriber, _) in delivery.subscribers.iter() {
            let Some(caller) = self.pending.remove(&(key, *subscriber)) else {
                continue;
            };
            let (approval, receiver) = oneshot::channel();
            if caller.send((response.clone(), approval)).is_ok() {
                approvals.push(receiver);
            }
        }
        let _ = self.metrics.pending_requests.try_set(self.pending.len());
        if approvals.is_empty() {
            self.metrics.deliveries.inc(status::Status::Dropped);
            return;
        }

        // Callers verify the same response against the same QMDB history, so
        // one explicit verdict is enough. Dropped feedback is neutral.
        self.approvals.push(async move {
            for approval in approvals {
                if let Ok(verdict) = approval.await {
                    feedback_tx.send_lossy(verdict);
                    return (delivery, Some(verdict));
                }
            }
            (delivery, None)
        });
    }

    /// Retire rejected deliveries' subscriptions and record verification results.
    fn handle_approval<R>(&mut self, resolver: &mut R, (delivery, verdict): Approval<F>)
    where
        R: Resolver<Key = Request<F>, Subscriber = u64>,
    {
        match verdict {
            Some(true) => self.metrics.deliveries.inc(status::Status::Success),
            Some(false) => {
                // These callers have received their responses or departed. Retire the
                // entire snapshot so resolver retry serves only remaining subscribers.
                let key = delivery.key;
                let delivered: BTreeSet<_> = delivery
                    .subscribers
                    .into_iter()
                    .map(|(subscriber, _)| subscriber)
                    .collect();
                resolver.retain(move |candidate, id| candidate != &key || !delivered.contains(id));
                self.metrics.deliveries.inc(status::Status::Failure);
                debug!(?key, "downstream marked response as peer-invalid");
            }
            None => self.metrics.deliveries.inc(status::Status::Dropped),
        }
    }

    /// Serve a peer's request by querying the local database.
    fn handle_produce(&mut self, key: Request<F>, response_tx: oneshot::Sender<bytes::Bytes>) {
        // Keep one database read active while the event loop continues handling
        // local requests and deliveries. Busy peers can retry elsewhere.
        if !self.serves.is_empty() {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        }
        let Some(database) = &self.config.database else {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        };
        if let Request::Operations { max_ops, .. } = key
            && max_ops > self.config.max_serve_ops
        {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        }
        let database = database.clone();
        let serve_requests = self.metrics.serve_requests.clone();

        self.serves.push(async move {
            let result = database.serve(key).await;

            let Ok((response, _feedback_tx)) = result else {
                serve_requests.inc(status::Status::Failure);
                return;
            };

            response_tx.send_lossy(response.encode());
            serve_requests.inc(status::Status::Success);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_actor::Feedback;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519, sha256};
    use commonware_macros::select;
    use commonware_p2p::{
        Provider, TrackedPeers,
        simulated::{Link, Network, Oracle},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
        reschedule, telemetry::metrics::count_running_tasks,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, Location, Proof, full::Config as MmrJournalConfig},
        qmdb::any::{FixedConfig, unordered::fixed},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU32, NZU64, NZUsize, channel::oneshot, probability};
    use futures::FutureExt as _;
    use std::time::Duration;

    #[derive(Clone, Debug)]
    struct DummyProvider;

    impl Provider for DummyProvider {
        type PublicKey = ed25519::PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
            let (_tx, rx) = commonware_utils::channel::mpsc::unbounded_channel();
            rx
        }
    }

    #[derive(Clone)]
    struct DummyBlocker;

    impl commonware_p2p::Blocker for DummyBlocker {
        type PublicKey = ed25519::PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    type TestDb = fixed::Db<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;
    type TestOp = <Shared<TestDb> as Source>::Op;

    type TestActor = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        mmr::Family,
        TestDb,
    >;

    /// Resolver that records accepted fetches and retain effects.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        /// Fetch keys and subscriber IDs in submission order.
        fetches: Vec<(Request<mmr::Family>, u64)>,
        /// Resolver subscriptions surviving submitted retain predicates.
        subscriptions: BTreeMap<Request<mmr::Family>, Vec<u64>>,
        /// Number of retain predicates submitted by the actor.
        retains: usize,
    }

    impl Resolver for RecordingResolver {
        type Key = Request<mmr::Family>;
        type Subscriber = u64;

        fn fetch<T>(&mut self, fetch: T) -> Feedback
        where
            T: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let fetch = fetch.into();
            self.fetches.push((fetch.key, fetch.subscriber));
            self.subscriptions
                .entry(fetch.key)
                .or_default()
                .push(fetch.subscriber);
            Feedback::Ok
        }

        fn fetch_all<T>(&mut self, fetches: Vec<T>) -> Feedback
        where
            T: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            for fetch in fetches {
                self.fetch(fetch);
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            self.retains += 1;
            self.subscriptions.retain(|key, subscribers| {
                subscribers.retain(|subscriber| predicate(key, subscriber));
                !subscribers.is_empty()
            });
            Feedback::Ok
        }
    }

    fn test_delivery(
        key: Request<mmr::Family>,
        subscribers: impl IntoIterator<Item = u64>,
    ) -> Delivery<Request<mmr::Family>, u64> {
        Delivery {
            key,
            subscribers: subscribers
                .into_iter()
                .map(|subscriber| (subscriber, tracing::Span::none()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }

    fn test_config(
        database: Option<Shared<TestDb>>,
    ) -> Config<ed25519::PublicKey, DummyProvider, DummyBlocker, TestDb> {
        Config {
            peer_provider: DummyProvider,
            blocker: DummyBlocker,
            database,
            mailbox_size: NZUsize!(16),
            me: None,
            timeout: Duration::from_millis(10),
            fetch_retry_timeout: Duration::from_millis(10),
            max_serve_ops: NZU64!(16),
            priority_requests: false,
            priority_responses: false,
        }
    }

    fn test_request_at(size: Location) -> Request<mmr::Family> {
        Request::Operations {
            size,
            start: Location::new(0),
            max_ops: NZU64!(1),
        }
    }

    fn db_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, NZU16!(101), NZUsize!(11));
        FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{suffix}-mmr-journal"),
                metadata_partition: format!("{suffix}-mmr-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{suffix}-log-journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    async fn init_db(context: deterministic::Context, suffix: &str) -> Shared<TestDb> {
        let db = TestDb::init(context.child("db"), db_config(suffix, &context))
            .await
            .expect("db init should succeed");
        Shared::new("test", db)
    }

    /// Create a database with one committed update so responses contain real operations.
    async fn init_seeded_db(context: deterministic::Context, suffix: &str) -> Shared<TestDb> {
        let db = TestDb::init(context.child("db"), db_config(suffix, &context))
            .await
            .expect("db init should succeed");
        let key = Sha256::hash(&[suffix.as_bytes(), b"-key"]);
        let value = Sha256::hash(&[suffix.as_bytes(), b"-value"]);
        let batch = db
            .new_batch()
            .write(key, Some(value))
            .merkleize(&db, None)
            .await
            .expect("batch should merkleize");
        let (db, _) = db.apply_batch(batch).await.expect("batch should apply");
        Shared::new("test", db)
    }

    type LiveMailbox = SyncMailbox<mmr::Family, TestDb>;

    /// Two connected resolver services with distinct databases, indexed by peer.
    struct LivePair {
        /// Local data each peer can serve, also available for expected-response checks.
        databases: [Shared<TestDb>; 2],
        /// Local fetch entry points for each resolver service.
        mailboxes: [LiveMailbox; 2],
        /// Actor counters used to observe admission and cancellation.
        metrics: [ResolverMetrics; 2],
        /// Network state used to observe peer blocking.
        oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
        /// Actor handles used to verify that shutdown releases their child tasks.
        handles: Vec<Handle<()>>,
    }

    /// Connect two database-backed actors over reliable deterministic links.
    async fn spawn_live_pair(context: &deterministic::Context, prefix: &str) -> LivePair {
        // Reliable links isolate actor scheduling and database availability from packet loss.
        let peers = [1, 2].map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(2),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers.clone(),
        )
        .await;
        network.start();

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

        // Distinct data identifies which peer supplied each response.
        let databases = [
            init_seeded_db(context.child("database_0"), &format!("{prefix}-0")).await,
            init_seeded_db(context.child("database_1"), &format!("{prefix}-1")).await,
        ];

        // Keep each actor's admission counters and handle alongside its local fetch interface.
        let mut mailboxes = Vec::new();
        let mut metrics = Vec::new();
        let mut handles = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let control = oracle.control(peer.clone());
            let net = control
                .register(0, Quota::per_second(NZU32!(100)))
                .await
                .unwrap();
            let (actor, mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb>::new(
                context.child(if index == 0 { "actor_0" } else { "actor_1" }),
                Config {
                    peer_provider: manager.clone(),
                    blocker: control,
                    database: Some(databases[index].clone()),
                    mailbox_size: NZUsize!(16),
                    me: Some(peer.clone()),
                    timeout: Duration::from_millis(20),
                    fetch_retry_timeout: Duration::from_millis(10),
                    max_serve_ops: NZU64!(16),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            metrics.push(actor.metrics.clone());
            mailboxes.push(mailbox);
            handles.push(actor.start(net));
        }

        LivePair {
            databases,
            mailboxes: mailboxes.try_into().ok().unwrap(),
            metrics: metrics.try_into().ok().unwrap(),
            oracle,
            handles,
        }
    }

    /// Wait for actor admission; resolver consumption requires a separate ordering barrier.
    async fn wait_for_fetches(
        context: &deterministic::Context,
        metrics: &ResolverMetrics,
        expected: u64,
    ) {
        select! {
            _ = async {
                while metrics.fetch_requests.get() < expected {
                    reschedule().await;
                }
            } => {},
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("actor did not process {expected} fetch requests");
            },
        }
    }

    /// Wait for the actor to retire canceled caller subscriptions.
    async fn wait_for_cancels(
        context: &deterministic::Context,
        metrics: &ResolverMetrics,
        expected: u64,
    ) {
        select! {
            _ = async {
                while metrics.cancel_requests.get() < expected {
                    reschedule().await;
                }
            } => {},
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("actor did not process {expected} cancellations");
            },
        }
    }

    /// Stop both actors and verify their previously live task prefix drains completely.
    async fn shutdown_pair(
        context: &deterministic::Context,
        prefix: &str,
        handles: Vec<Handle<()>>,
    ) {
        // Establish that the selected prefix covers live work before testing its cleanup.
        let actor_prefix = format!("{prefix}_actor");
        assert!(
            count_running_tasks(context, &actor_prefix) > 0,
            "selected actor prefix should be running before abort"
        );

        // Stop both actor trees and wait for their resolver descendants to exit.
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
        select! {
            _ = async {
                while count_running_tasks(context, &actor_prefix) != 0 {
                    reschedule().await;
                }
            } => {},
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("selected actor prefix remained after abort");
            },
        }
        assert_eq!(count_running_tasks(context, &actor_prefix), 0);
    }

    /// Obtain the response directly from its database for comparison with the P2P result.
    async fn expected_payload(db: &Shared<TestDb>, request: Request<mmr::Family>) -> Bytes {
        let (response, feedback) = db.serve(request).await.unwrap();
        assert!(feedback.is_none());
        response.encode()
    }

    fn assert_operations_response(
        response: &Response<mmr::Family, TestOp, sha256::Digest>,
        request: Request<mmr::Family>,
        expected: &Bytes,
    ) {
        assert_eq!(&response.encode(), expected);
        let Response::Operations { proof, operations } = response else {
            panic!("operations request returned a boundary response");
        };
        assert_eq!(proof.leaves, request.size());
        assert!(!operations.is_empty());
    }

    /// A decodable operations response for testing request/response shape checks.
    fn encoded_fetch_payload() -> Bytes {
        Response::<mmr::Family, TestOp, sha256::Digest>::Operations {
            proof: Proof {
                leaves: Location::new(0),
                inactive_peaks: 0,
                digests: Vec::new(),
            },
            operations: Vec::new(),
        }
        .encode()
    }

    #[test]
    fn produce_denied_before_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));

            // An unattached actor must release the peer request without waiting for a database.
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(Location::new(1)), response_tx);
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn same_request_served_after_attach() {
        deterministic::Runner::default().start(|context| async move {
            // Attaching a database makes an initially unavailable actor able to serve.
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let db = init_db(context.child("resolver_db"), "resolver-after-attach").await;
            let size = db.read().await.bounds().end;
            let mut resolver = RecordingResolver::default();
            actor.handle_mailbox_message(&mut resolver, mailbox::Message::AttachDatabase(db));

            // Drive the queued read to completion and check that the peer receives encoded data.
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(size), response_tx);
            actor.serves.next_completed().await;

            let payload = response_rx
                .await
                .expect("response should be available after attach");
            assert!(!payload.is_empty());
        });
    }

    #[test]
    fn produce_rejects_request_above_max_serve_ops() {
        deterministic::Runner::default().start(|context| async move {
            // Attach a usable database so the configured request bound is the only rejection cause.
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let db = init_db(context.child("resolver_db"), "resolver-unbounded-max-ops").await;
            let size = db.read().await.bounds().end;
            let mut resolver = RecordingResolver::default();
            actor.handle_mailbox_message(&mut resolver, mailbox::Message::AttachDatabase(db));

            // Oversized requests must release their response channel before starting a read.
            let request = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(1_000),
            };
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx);

            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn get_operations_registers_each_caller_and_cancels_exact_ids() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));

            // A delayed cancellation notice must preserve a fresh caller for the same key.
            let (old, old_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: old,
                },
            );
            let old_id = resolver.fetches[0].1;
            drop(old_rx);
            let (fresh, fresh_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.fetches[1].1;
            assert_ne!(fresh_id, old_id);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert_eq!(resolver.fetches.len(), 2);
            assert_eq!(resolver.retains, 1);
            assert_eq!(resolver.subscriptions[&request], [fresh_id]);
            assert_eq!(actor.pending.len(), 1);
            assert!(actor.pending.contains_key(&(request, fresh_id)));

            // Each closed caller is retired once; repeated notices are harmless.
            drop(fresh_rx);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert_eq!(resolver.retains, 2);
            assert!(!resolver.subscriptions.contains_key(&request));
            assert!(actor.pending.is_empty());
        });
    }

    #[test]
    fn partial_caller_cancellation_preserves_live_subscriber() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (canceled, canceled_rx) = oneshot::channel();
            let (live, live_rx) = oneshot::channel();
            for response in [canceled, live] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            assert_eq!(resolver.fetches.len(), 2);
            let subscriber = resolver.fetches[1].1;

            drop(canceled_rx);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert_eq!(resolver.retains, 1);
            assert_eq!(resolver.subscriptions[&request], [subscriber]);
            assert_eq!(actor.pending.len(), 1);
            assert!(actor.pending.contains_key(&(request, subscriber)));
            assert_eq!(actor.metrics.pending_requests.get(), 1);
            assert_eq!(actor.metrics.cancel_requests.get(), 1);

            let payload = encoded_fetch_payload();
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [subscriber]),
                payload.clone(),
                feedback,
            );
            let (response, approval) = live_rx.await.unwrap();
            assert_eq!(response.encode(), payload);
            approval.send(true).unwrap();
            let completion = actor.approvals.next_completed().await;
            actor.handle_approval(&mut resolver, completion);
            assert!(verdict.await.unwrap());
            assert!(actor.pending.is_empty());
        });
    }

    #[test]
    fn request_id_exhaustion_precedes_submission() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (existing, _existing_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: existing,
                },
            );
            let existing_id = resolver.fetches[0].1;
            actor.next_subscriber = u64::MAX;
            let (response, receiver) = oneshot::channel();

            // Exhaustion panics before insertion or resolver submission can reuse an ID.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }));
            assert!(result.is_err());
            assert!(receiver.await.is_err());
            assert_eq!(actor.pending.len(), 1);
            assert!(actor.pending.contains_key(&(request, existing_id)));
            assert_eq!(resolver.fetches, [(request, existing_id)]);
        });
    }

    #[test]
    fn malformed_or_mismatched_delivery_preserves_waiting_caller() {
        deterministic::Runner::default().start(|context| async move {
            // Keep a boundary requester waiting across responses it cannot consume.
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = Request::Boundary {
                size: Location::new(1),
                start: Location::new(0),
            };
            let (response, mut receiver) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let subscriber = resolver.fetches[0].1;
            let delivery = test_delivery(request, [subscriber]);

            // Both failures must judge the original subscription and leave its caller waiting.
            for payload in [
                Bytes::from_static(b"malformed-response"),
                encoded_fetch_payload(),
            ] {
                let (feedback, validity) = oneshot::channel();
                actor.handle_deliver(delivery.clone(), payload, feedback);

                assert!(!validity.await.unwrap());
                assert_eq!(actor.pending.len(), 1);
                assert!(actor.pending.contains_key(&(request, subscriber)));
                assert!(matches!(
                    receiver.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
            }
        });
    }

    #[test]
    fn cancel_reopens_with_new_id_and_stale_delivery_cannot_drain_it() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));

            // Cancel the first caller, then admit two new callers for the same key.
            let (old, old_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: old,
                },
            );
            let old_id = resolver.fetches[0].1;
            drop(old_rx);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            let (fresh, mut fresh_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.fetches[1].1;
            assert!(fresh_id > old_id);
            let (later, mut later_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: later,
                },
            );
            let later_id = resolver.fetches[2].1;

            // The stale delivery is unjudged and cannot consume either new caller.
            let (stale_feedback, stale_verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [old_id]),
                encoded_fetch_payload(),
                stale_feedback,
            );
            assert!(stale_verdict.await.is_err());
            assert_eq!(actor.pending.len(), 2);
            assert!(matches!(
                fresh_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // A queued snapshot reaches only its named caller, even after later admission.
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [fresh_id]),
                encoded_fetch_payload(),
                feedback,
            );
            let (_response, approval) = fresh_rx.await.unwrap();
            approval.send(true).unwrap();
            let completion = actor.approvals.next_completed().await;
            assert_eq!(completion, (test_delivery(request, [fresh_id]), Some(true)));
            actor.handle_approval(&mut resolver, completion);
            assert!(verdict.await.unwrap());
            assert!(matches!(
                later_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(actor.pending.len(), 1);
            assert!(actor.pending.contains_key(&(request, later_id)));

            // The remaining subscriber receives its own delivery and finishes independently.
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [later_id]),
                encoded_fetch_payload(),
                feedback,
            );
            later_rx.await.unwrap().1.send(true).unwrap();
            let completion = actor.approvals.next_completed().await;
            actor.handle_approval(&mut resolver, completion);
            assert!(verdict.await.unwrap());
            assert!(actor.pending.is_empty());
        });
    }

    #[test]
    fn delivery_without_live_recipient_is_unjudged() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (response, receiver) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let subscriber = resolver.fetches[0].1;
            drop(receiver);

            // Successful decoding with no recipient drops the verdict and queues no approval.
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [subscriber]),
                encoded_fetch_payload(),
                feedback,
            );
            assert!(verdict.await.is_err());
            assert!(actor.pending.is_empty());
            assert!(actor.approvals.is_empty());
        });
    }

    #[test]
    fn dropped_approvals_are_neutral() {
        for expected in [None, Some(true)] {
            deterministic::Runner::default().start(|context| async move {
                let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
                let mut resolver = RecordingResolver::default();
                let request = test_request_at(Location::new(1));
                let (first, first_rx) = oneshot::channel();
                let (second, second_rx) = oneshot::channel();
                for response in [first, second] {
                    actor.handle_mailbox_message(
                        &mut resolver,
                        mailbox::Message::GetOperations { request, response },
                    );
                }
                let delivery = test_delivery(request, resolver.fetches.iter().map(|(_, id)| *id));

                // One caller abstains; the other either accepts or also leaves the data unjudged.
                let (feedback, verdict) = oneshot::channel();
                actor.handle_deliver(delivery.clone(), encoded_fetch_payload(), feedback);
                drop(first_rx.await.unwrap().1);
                let approval = second_rx.await.unwrap().1;
                if let Some(verdict) = expected {
                    approval.send(verdict).unwrap();
                } else {
                    drop(approval);
                }

                // An abstention neither overrides an explicit acceptance nor creates one.
                let completion = actor.approvals.next_completed().await;
                assert_eq!(completion, (delivery, expected));
                actor.handle_approval(&mut resolver, completion);
                assert_eq!(verdict.await.ok(), expected);
                assert_eq!(resolver.retains, 0);
            });
        }
    }

    #[test]
    fn false_approval_retires_snapshot_but_preserves_newer_demand() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let unrelated = Request::Operations {
                size: Location::new(1),
                start: Location::new(0),
                max_ops: NZU64!(2),
            };

            // A delivery can include a caller whose cancellation notice has not arrived yet.
            let (rejecting, rejecting_rx) = oneshot::channel();
            let (later, later_rx) = oneshot::channel();
            let (departed, departed_rx) = oneshot::channel();
            for response in [rejecting, later, departed] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let delivery = test_delivery(request, resolver.fetches.iter().map(|(_, id)| *id));
            drop(departed_rx);
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery.clone(), encoded_fetch_payload(), feedback);
            let (_response, rejection) = rejecting_rx.await.unwrap();
            let (_response, later_approval) = later_rx.await.unwrap();

            // New same-key and unrelated callers must survive retirement of this snapshot.
            let (fresh, _fresh_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.fetches[3].1;
            let (other, _other_rx) = oneshot::channel();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request: unrelated,
                    response: other,
                },
            );
            let unrelated_id = resolver.fetches[4].1;

            // Rejection retires every delivered ID, including the failed handoff.
            rejection.send(false).unwrap();
            let completion = actor.approvals.next_completed().await;
            assert_eq!(completion, (delivery, Some(false)));
            actor.handle_approval(&mut resolver, completion);
            assert!(!verdict.await.unwrap());
            assert!(later_approval.is_closed());
            assert_eq!(
                resolver.subscriptions.get(&request).unwrap().as_slice(),
                &[fresh_id]
            );
            assert_eq!(
                resolver.subscriptions.get(&unrelated).unwrap().as_slice(),
                &[unrelated_id]
            );
            assert_eq!(resolver.retains, 1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert_eq!(resolver.retains, 1);
            assert_eq!(actor.pending.len(), 2);
        });
    }

    #[test]
    fn produce_keeps_one_busy_serve_slot() {
        deterministic::Runner::default().start(|context| async move {
            // Hold database access so the first serve cannot finish and free its slot.
            let db = init_seeded_db(context.child("resolver_db"), "bounded-serve").await;
            let size = db.read().await.bounds().end;
            let actor_db = db.clone();
            let (slot, database) = db.write().await;
            let (mut actor, _mailbox) =
                TestActor::new(context.child("actor"), test_config(Some(actor_db)));

            // Admit one serve and check that a second request is dropped immediately.
            let (first_tx, mut first_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(size), first_tx);
            assert!(matches!(
                first_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            let (extra_tx, extra_rx) = oneshot::channel();
            actor.handle_produce(
                Request::Operations {
                    size,
                    start: Location::new(0),
                    max_ops: NZU64!(2),
                },
                extra_tx,
            );
            let extra_was_dropped = matches!(extra_rx.now_or_never(), Some(Err(_)));

            // Release the database and actor before reporting the admission-bound assertion.
            slot.put(database);
            drop(actor);
            assert!(
                extra_was_dropped,
                "a busy actor retained more than one database serve"
            );
        });
    }

    #[test]
    fn busy_serve_preserves_actor_progress_and_reuses_slot() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Distinct request keys distinguish the active read from a request that must retry.
            const PREFIX: &str = "busy_serve_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[0].read().await.bounds().end;
            let request_1 = test_request_at(size);
            let request_2 = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(2),
            };
            let expected_1 = expected_payload(&pair.databases[0], request_1).await;
            let expected_2 = expected_payload(&pair.databases[0], request_2).await;
            let peer_expected = expected_payload(&pair.databases[1], request_1).await;

            // Keep one peer's database unavailable while the other peer requests its data.
            let (slot, database) = pair.databases[0].write().await;
            let blocked_1 = pair.mailboxes[1].serve(request_1);
            futures::pin_mut!(blocked_1);
            assert!(futures::poll!(blocked_1.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[1], 1).await;
            context.sleep(Duration::from_millis(5)).await;
            assert!(blocked_1.as_mut().now_or_never().is_none());

            // A second request reaches the busy peer and must remain eligible for retry.
            let blocked_2 = pair.mailboxes[1].serve(request_2);
            futures::pin_mut!(blocked_2);
            assert!(futures::poll!(blocked_2.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[1], 2).await;
            context.sleep(Duration::from_millis(5)).await;
            assert!(blocked_2.as_mut().now_or_never().is_none());

            // The busy actor must still fetch and validate data from the other peer.
            let (response, feedback) = select! {
                result = pair.mailboxes[0].serve(request_1) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("busy serve blocked an unrelated local fetch");
                },
            };
            assert_operations_response(&response, request_1, &peer_expected);
            feedback.unwrap().send(true).unwrap();

            // Restoring the database lets the active request and the dropped request finish.
            slot.put(database);
            let (response_1, feedback_1) = select! {
                result = blocked_1 => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first serve did not resume"),
            };
            assert_operations_response(&response_1, request_1, &expected_1);
            feedback_1.unwrap().send(true).unwrap();
            let (response_2, feedback_2) = select! {
                result = blocked_2 => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("retried serve did not resume"),
            };
            assert_operations_response(&response_2, request_2, &expected_2);
            feedback_2.unwrap().send(true).unwrap();

            // Both actor trees must release their work on shutdown.
            shutdown_pair(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn late_same_key_subscribers_complete_after_one_approval() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // A distinct key provides an ordering barrier through the same resolver mailbox.
            const PREFIX: &str = "late_subscriber_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[1].read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&pair.databases[1], request).await;
            let barrier_request = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(2),
            };
            let barrier_expected = expected_payload(&pair.databases[1], barrier_request).await;

            // Hold the first delivery's verdict while later subscribers join the same key.
            let (first, delayed) = futures::future::join(
                pair.mailboxes[0].serve(request),
                pair.mailboxes[0].serve(request),
            )
            .await;
            let (first, first_feedback) = first.unwrap();
            let (delayed_response, delayed_feedback) = delayed.unwrap();
            assert_operations_response(&first, request, &expected);
            assert_eq!(pair.metrics[0].fetch_requests.get(), 2);

            let second = pair.mailboxes[0].serve(request);
            futures::pin_mut!(second);
            assert!(futures::poll!(second.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[0], 3).await;
            let third = pair.mailboxes[0].serve(request);
            futures::pin_mut!(third);
            assert!(futures::poll!(third.as_mut()).is_pending());

            // Barrier completion proves the late fetch reached the resolver before acceptance.
            let (barrier, barrier_feedback) = select! {
                result = pair.mailboxes[0].serve(barrier_request) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("resolver did not process the post-subscriber barrier");
                },
            };
            assert_operations_response(&barrier, barrier_request, &barrier_expected);
            barrier_feedback.unwrap().send(true).unwrap();
            first_feedback.unwrap().send(true).unwrap();

            // Both late callers must receive the retained response and can approve it independently.
            let mut late_results = select! {
                results = futures::future::join(second, third) => Some(results),
                _ = context.sleep(Duration::from_secs(1)) => None,
            };
            if let Some((
                Ok((second_response, second_feedback)),
                Ok((third_response, third_feedback)),
            )) = late_results.as_mut()
            {
                assert_operations_response(second_response, request, &expected);
                assert_operations_response(third_response, request, &expected);
                second_feedback.take().unwrap().send_lossy(true);
                third_feedback.take().unwrap().send_lossy(true);
            }

            // Validation of the retained response belongs to the delayed caller.
            assert_operations_response(&delayed_response, request, &expected);
            delayed_feedback.unwrap().send_lossy(true);

            // Check task cleanup even when late delivery times out.
            shutdown_pair(&context, PREFIX, pair.handles).await;
            assert!(
                matches!(late_results, Some((Ok(_), Ok(_)))),
                "late same-key subscribers did not receive the approved response"
            );
        });
    }

    #[test]
    fn cancel_late_subscriber_preserves_prior_feedback_and_fresh_demand() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Separate barrier keys establish resolver consumption before and after cancellation.
            const PREFIX: &str = "cancel_late_subscriber_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[1].read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&pair.databases[1], request).await;
            let barrier_request = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(2),
            };
            let barrier_expected = expected_payload(&pair.databases[1], barrier_request).await;
            let post_cancel_barrier = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(3),
            };
            let post_cancel_expected =
                expected_payload(&pair.databases[1], post_cancel_barrier).await;

            // Keep the first caller's approval open throughout cancellation of a later subscriber.
            let (first, first_feedback) = pair.mailboxes[0].serve(request).await.unwrap();
            assert_operations_response(&first, request, &expected);

            // Admit the late subscriber into the resolver, then drop its caller.
            {
                let late = pair.mailboxes[0].serve(request);
                futures::pin_mut!(late);
                assert!(futures::poll!(late.as_mut()).is_pending());
                wait_for_fetches(&context, &pair.metrics[0], 2).await;

                let (barrier, barrier_feedback) = select! {
                    result = pair.mailboxes[0].serve(barrier_request) => result.unwrap(),
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("resolver did not process the late subscriber before cancellation");
                    },
                };
                assert_operations_response(&barrier, barrier_request, &barrier_expected);
                barrier_feedback.unwrap().send(true).unwrap();
            }
            wait_for_cancels(&context, &pair.metrics[0], 1).await;

            // Reopen the key and fence its admission before releasing the original approval.
            let fresh = pair.mailboxes[0].serve(request);
            futures::pin_mut!(fresh);
            assert!(futures::poll!(fresh.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[0], 4).await;
            let (barrier, barrier_feedback) = select! {
                result = pair.mailboxes[0].serve(post_cancel_barrier) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("resolver did not process fresh demand after cancellation");
                },
            };
            assert_operations_response(&barrier, post_cancel_barrier, &post_cancel_expected);
            barrier_feedback.unwrap().send(true).unwrap();
            first_feedback.unwrap().send(true).unwrap();

            // Canceling the intermediate subscriber must preserve cached data for the fresh caller.
            let (fresh, fresh_feedback) = select! {
                result = fresh => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("fresh subscriber did not receive the retained response");
                },
            };
            assert_operations_response(&fresh, request, &expected);
            fresh_feedback.unwrap().send(true).unwrap();

            // The cancellation and redelivery paths must leave no actor tasks after shutdown.
            shutdown_pair(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn rejected_response_does_not_outlive_canceled_successor() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            const PREFIX: &str = "rejected_then_canceled";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[1].read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&pair.databases[1], request).await;
            let barrier = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(2),
            };
            let fetch_counts = || {
                let metrics = context.encode();
                let count = |name| {
                    let prefix = format!("{PREFIX}_actor_0_resolver_{name} ");
                    metrics
                        .lines()
                        .find_map(|line| line.strip_prefix(&prefix))
                        .expect("resolver fetch metric missing")
                        .parse::<u64>()
                        .unwrap()
                };
                (count("fetch_pending"), count("fetch_active"))
            };

            // Admit a successor while the first caller still owns the response's verdict.
            // A distinct-key delivery fences its admission into the same resolver.
            let (first, feedback) = pair.mailboxes[0].serve(request).await.unwrap();
            assert_operations_response(&first, request, &expected);
            {
                let successor = pair.mailboxes[0].serve(request);
                futures::pin_mut!(successor);
                assert!(futures::poll!(successor.as_mut()).is_pending());
                wait_for_fetches(&context, &pair.metrics[0], 2).await;
                let (_, barrier_feedback) = pair.mailboxes[0].serve(barrier).await.unwrap();
                barrier_feedback.unwrap().send(true).unwrap();
                feedback.unwrap().send(false).unwrap();

                // Rejection must be consumed while the successor remains live. With the only
                // source blocked, the successor's request stays pending until it is canceled.
                while pair.oracle.blocked().await.unwrap().is_empty() {
                    context.sleep(Duration::from_millis(1)).await;
                }
                assert!(futures::poll!(successor.as_mut()).is_pending());
                while fetch_counts() != (1, 0) {
                    context.sleep(Duration::from_millis(1)).await;
                }
            }
            wait_for_cancels(&context, &pair.metrics[0], 1).await;
            assert_eq!(pair.metrics[0].pending_requests.get(), 0);

            // No local caller remains, so resolver demand must drain without another response.
            let drained = select! {
                _ = async {
                    while fetch_counts() != (0, 0) {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                } => true,
                _ = context.sleep(Duration::from_secs(1)) => false,
            };
            let remaining = fetch_counts();
            shutdown_pair(&context, PREFIX, pair.handles).await;
            assert!(drained, "orphaned resolver fetches: {remaining:?}");
        });
    }
}

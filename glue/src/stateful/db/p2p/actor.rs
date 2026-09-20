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
    qmdb::sync::{Identity, Request, Response, Source, Verifier},
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
type SyncMailbox<F, DB, V> = Mailbox<DB, F, Op<DB>, DatabaseRoot<DB>, V>;
type SyncMessage<F, DB, V> = mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>, V>;
type PendingSubs<F, DB, V> =
    BTreeMap<(Request<F>, u64), mailbox::Reply<Response<F, Op<DB>, DatabaseRoot<DB>>, V>>;

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
pub struct Actor<E, P, D, B, F, DB, V>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    DB: Send + Sync + 'static,
    Shared<DB>: Source<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
    V: Verifier<Response<F, Op<DB>, DatabaseRoot<DB>>>,
{
    context: ContextCell<E>,
    config: Config<P, D, B, DB>,
    mailbox_rx: actor_mailbox::Receiver<SyncMessage<F, DB, V>>,
    metrics: ResolverMetrics,
    /// Pending replies, keyed by request and subscriber ID.
    pending: PendingSubs<F, DB, V>,
    next_id: u64,
    /// At most one active database read for a peer.
    serves: FuturesPool<'static, ()>,
}

impl<E, P, D, B, F, DB, V> Actor<E, P, D, B, F, DB, V>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    DB: Send + Sync + 'static,
    Shared<DB>: Source<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
    V: Verifier<Response<F, Op<DB>, DatabaseRoot<DB>>>,
{
    /// Create a new resolver actor and mailbox.
    pub fn new(context: E, cfg: Config<P, D, B, DB>) -> (Self, SyncMailbox<F, DB, V>) {
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
            next_id: 0,
            serves: FuturesPool::default(),
        };
        (actor, mailbox)
    }

    /// Start the resolver service.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()>
    where
        V: 'static,
        V::Output: 'static,
    {
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
            // Drive the serve future and free its slot on completion.
            // The future sends the response and records metrics.
            _ = self.serves.next_completed() => {},
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

    /// Process database attachment, fetch requests, and cancellations.
    fn handle_mailbox_message<R>(&mut self, resolver: &mut R, message: SyncMessage<F, DB, V>)
    where
        R: Resolver<Key = Request<F>, Subscriber = u64>,
    {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                // Active reads keep the database handle they started with.
                let replacing_existing = self.config.database.replace(db).is_some();
                info!(replacing_existing, "attached resolver database");
                let _ = self.metrics.has_database.try_set(1i64);
            }
            mailbox::Message::GetOperations { request, response } => {
                // Give each caller a subscription that can be canceled independently.
                let subscriber = self.next_id;
                self.next_id = self.next_id.checked_add(1).expect("request ID overflow");
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
                // Cancellation can arrive after a new caller, so remove only closed replies.
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
                // still waiting for a verified response.
                self.metrics.cancel_requests.inc_by(canceled.len() as u64);
                resolver.retain(move |_, id| !canceled.contains(id));
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
            }
        }
    }

    /// Verify a candidate for waiting callers and report its validity to the resolver.
    fn handle_deliver(
        &mut self,
        delivery: Delivery<Request<F>, u64>,
        value: bytes::Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        // Queued deliveries can outlive their callers.
        let key = delivery.key;
        if !delivery.subscribers.iter().any(|(subscriber, _)| {
            self.pending
                .get(&(key, *subscriber))
                .is_some_and(|caller| !caller.is_closed())
        }) {
            self.metrics.deliveries.inc(status::Status::Dropped);
            return;
        }

        // Leave subscriptions intact on invalid data so the resolver can retry.
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

        // Rejected callers stay subscribed for retries. Closed replies stay indexed until
        // cancellation retracts their resolver IDs. Callers verify the same QMDB history,
        // so one explicit verdict classifies the response.
        let mut verdict = None;
        for (subscriber, _) in delivery.subscribers.iter() {
            let Some(caller) = self.pending.get_mut(&(key, *subscriber)) else {
                continue;
            };
            let outcome = caller.deliver(response.clone());
            verdict = verdict.or(outcome);
            if outcome == Some(true) {
                self.pending.remove(&(key, *subscriber));
            }
        }
        let _ = self.metrics.pending_requests.try_set(self.pending.len());
        match verdict {
            Some(true) => self.metrics.deliveries.inc(status::Status::Success),
            Some(false) => {
                self.metrics.deliveries.inc(status::Status::Failure);
                debug!(?key, "response failed verification");
            }
            None => self.metrics.deliveries.inc(status::Status::Dropped),
        }
        if let Some(verdict) = verdict {
            feedback_tx.send_lossy(verdict);
        }
    }

    /// Serve a peer's request by querying the local database.
    fn handle_produce(&mut self, key: Request<F>, response_tx: oneshot::Sender<bytes::Bytes>) {
        // Peers can retry while the current database read finishes.
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
            let result = database.serve(key, Identity).await;

            let Ok(Some(response)) = result else {
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
        simulated::{Link, Network},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
        reschedule, telemetry::metrics::count_running_tasks,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, Location, Proof, full::Config as MmrJournalConfig},
        qmdb::{
            any::{FixedConfig, unordered::fixed},
            sync,
        },
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

    type TestActor<V = Identity> = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        mmr::Family,
        TestDb,
        V,
    >;

    /// Records fetches and cancellations.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        /// Fetch keys and subscriber IDs in submission order.
        fetches: Vec<(Request<mmr::Family>, u64)>,
        /// Current subscriptions, grouped by request.
        subscriptions: BTreeMap<Request<mmr::Family>, Vec<u64>>,
        /// Number of calls to `retain`.
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

    /// Create a database with one applied update.
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

    type LiveMailbox = SyncMailbox<mmr::Family, TestDb, Identity>;

    /// Two connected resolver services with distinct databases, indexed by peer.
    struct LivePair {
        /// Databases served by each peer.
        databases: [Shared<TestDb>; 2],
        /// Mailboxes for requesting data from peers.
        mailboxes: [LiveMailbox; 2],
        /// Actor counters used to observe admission and cancellation.
        metrics: [ResolverMetrics; 2],
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

        // Start both actors and retain their task handles for cleanup.
        let mut mailboxes = Vec::new();
        let mut metrics = Vec::new();
        let mut handles = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let control = oracle.control(peer.clone());
            let net = control
                .register(0, Quota::per_second(NZU32!(100)))
                .await
                .unwrap();
            let (actor, mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb, Identity>::new(
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
            handles,
        }
    }

    /// Wait for the actor to accept fetches. The resolver may still have them queued.
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

    /// Stop the actors and wait for their child tasks to exit.
    async fn shutdown_actors(
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

        // Stop all actor trees and wait for their resolver descendants to exit.
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
        db.serve(request, Some).await.unwrap().unwrap().encode()
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

    type TestResponse = Response<mmr::Family, TestOp, sha256::Digest>;
    type TestReply<V = Identity> = mailbox::Reply<TestResponse, V>;

    fn test_reply<V>(verify: V) -> (TestReply<V>, oneshot::Receiver<V::Output>)
    where
        V: Verifier<TestResponse>,
    {
        let (response, receiver) = oneshot::channel();
        (mailbox::Reply::new(verify, response), receiver)
    }

    fn identity_reply() -> (TestReply, oneshot::Receiver<TestResponse>) {
        test_reply(Identity)
    }

    fn rejecting_verifier() -> impl Fn(TestResponse) -> Option<()> {
        |_| None
    }

    fn transforming_verifier(
        adjustment: u64,
        transforms: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl Fn(TestResponse) -> Option<Location> {
        move |response| {
            transforms.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Response::Operations { proof, .. } = response else {
                return None;
            };
            proof.leaves.checked_add(adjustment)
        }
    }

    /// A decodable operations response for testing request/response shape checks.
    fn encoded_fetch_payload_at(leaves: Location) -> Bytes {
        Response::<mmr::Family, TestOp, sha256::Digest>::Operations {
            proof: Proof {
                leaves,
                inactive_peaks: 0,
                digests: Vec::new(),
            },
            operations: Vec::new(),
        }
        .encode()
    }

    fn encoded_fetch_payload() -> Bytes {
        encoded_fetch_payload_at(Location::new(0))
    }

    #[test]
    fn produce_denied_before_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) =
                TestActor::<Identity>::new(context.child("actor"), test_config(None));

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
            let (mut actor, _mailbox) =
                TestActor::<Identity>::new(context.child("actor"), test_config(None));
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
            let (mut actor, _mailbox) =
                TestActor::<Identity>::new(context.child("actor"), test_config(None));
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
            let (old, old_rx) = identity_reply();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: old,
                },
            );
            let old_id = resolver.fetches[0].1;
            drop(old_rx);
            let (fresh, fresh_rx) = identity_reply();
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

            // Each closed caller is retired once. Repeated notices are harmless.
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
            let (canceled, canceled_rx) = identity_reply();
            let (live, mut live_rx) = identity_reply();
            for response in [canceled, live] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            assert_eq!(resolver.fetches.len(), 2);
            let subscriber = resolver.fetches[1].1;
            let delivery = test_delivery(request, resolver.fetches.iter().map(|(_, id)| *id));

            // Cancellation can be processed after the resolver captures a delivery snapshot.
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
            actor.handle_deliver(delivery, payload.clone(), feedback);
            let response = live_rx.try_recv().unwrap();
            assert_eq!(response.encode(), payload);
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
            let (existing, _existing_rx) = identity_reply();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: existing,
                },
            );
            let existing_id = resolver.fetches[0].1;
            actor.next_id = u64::MAX;
            let (response, receiver) = identity_reply();

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
            let (response, mut receiver) = identity_reply();
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
            let (old, old_rx) = identity_reply();
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
            let (fresh, mut fresh_rx) = identity_reply();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.fetches[1].1;
            assert!(fresh_id > old_id);
            let (later, mut later_rx) = identity_reply();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: later,
                },
            );
            let later_id = resolver.fetches[2].1;

            // A stale malformed delivery stays unjudged and cannot consume either new caller.
            let (stale_feedback, stale_verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [old_id]),
                Bytes::new(),
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
            let response = fresh_rx.await.unwrap();
            assert_eq!(response.encode(), encoded_fetch_payload());
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
            assert_eq!(later_rx.await.unwrap().encode(), encoded_fetch_payload());
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
            let (response, receiver) = identity_reply();
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let subscriber = resolver.fetches[0].1;
            drop(receiver);

            // A delivery with no live recipient creates no validity judgment.
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [subscriber]),
                encoded_fetch_payload(),
                feedback,
            );
            assert!(verdict.await.is_err());
            assert_eq!(actor.pending.len(), 1);

            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert!(actor.pending.is_empty());
        });
    }

    #[test]
    fn same_verifier_type_uses_distinct_per_call_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let transforms = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let (first, first_rx) = test_reply(transforming_verifier(1, transforms.clone()));
            let (second, second_rx) = test_reply(transforming_verifier(2, transforms.clone()));
            let (mut actor, _mailbox) = TestActor::<_>::new(context, test_config(None));
            for response in [first, second] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }

            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, resolver.fetches.iter().map(|(_, id)| *id)),
                encoded_fetch_payload_at(Location::new(7)),
                feedback,
            );

            assert!(verdict.await.unwrap());
            assert_eq!(first_rx.await.unwrap(), Location::new(8));
            assert_eq!(second_rx.await.unwrap(), Location::new(9));
            assert_eq!(transforms.load(std::sync::atomic::Ordering::Relaxed), 2);
            assert!(actor.pending.is_empty());
        });
    }

    #[test]
    fn rejected_candidate_keeps_same_reply_until_valid_candidate() {
        deterministic::Runner::default().start(|context| async move {
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (response, mut receiver) = test_reply(|response: TestResponse| {
                let Response::Operations { proof, .. } = response else {
                    return None;
                };
                (proof.leaves == Location::new(1)).then_some(proof.leaves)
            });
            let (mut actor, _mailbox) = TestActor::<_>::new(context, test_config(None));
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let subscriber = resolver.fetches[0].1;
            let delivery = test_delivery(request, [subscriber]);

            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                delivery.clone(),
                encoded_fetch_payload_at(Location::new(0)),
                feedback,
            );
            assert!(!verdict.await.unwrap());
            assert!(actor.pending.contains_key(&(request, subscriber)));
            assert_eq!(resolver.subscriptions[&request], [subscriber]);
            assert!(matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                delivery,
                encoded_fetch_payload_at(Location::new(1)),
                feedback,
            );
            assert!(verdict.await.unwrap());
            assert_eq!(receiver.await.unwrap(), Location::new(1));
            assert!(actor.pending.is_empty());
            assert_eq!(resolver.fetches, [(request, subscriber)]);
        });
    }

    #[test]
    fn cancel_after_rejection_preserves_other_same_key_demand() {
        deterministic::Runner::default().start(|context| async move {
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));

            let (canceled, canceled_rx) = test_reply(rejecting_verifier());
            let (waiting, _waiting_rx) = test_reply(rejecting_verifier());
            let (mut actor, _mailbox) = TestActor::<_>::new(context, test_config(None));
            for response in [canceled, waiting] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let [canceled_id, waiting_id] = [resolver.fetches[0].1, resolver.fetches[1].1];
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, [canceled_id, waiting_id]),
                encoded_fetch_payload(),
                feedback,
            );
            assert!(!verdict.await.unwrap());
            assert_eq!(actor.pending.len(), 2);

            drop(canceled_rx);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            let (fresh, _fresh_rx) = test_reply(rejecting_verifier());
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.fetches[2].1;

            assert_eq!(resolver.retains, 1);
            assert_eq!(resolver.subscriptions[&request], [waiting_id, fresh_id]);
            assert_eq!(actor.pending.len(), 2);
            assert!(!actor.pending.contains_key(&(request, canceled_id)));
        });
    }

    #[test]
    fn invalid_snapshot_keeps_closed_reply_for_exact_cancellation() {
        deterministic::Runner::default().start(|context| async move {
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));

            let (first, first_rx) = test_reply(rejecting_verifier());
            let (closed, closed_rx) = test_reply(rejecting_verifier());
            let (mut actor, _mailbox) = TestActor::<_>::new(context, test_config(None));
            for response in [first, closed] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let delivery = test_delivery(request, resolver.fetches.iter().map(|(_, id)| *id));

            // The delivery still names both callers when one stops waiting before rejection.
            drop(closed_rx);
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);
            assert!(!verdict.await.unwrap());

            // Rejection keeps both resolver subscriptions, so cancellation must remove both IDs.
            drop(first_rx);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::CancelOperations { request },
            );
            assert!(actor.pending.is_empty());
            assert!(!resolver.subscriptions.contains_key(&request));
            assert_eq!(actor.metrics.cancel_requests.get(), 2);
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
                TestActor::<Identity>::new(context.child("actor"), test_config(Some(actor_db)));

            // Start the first serve while database access is blocked, then try to admit a second.
            let (first_tx, mut first_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(size), first_tx);
            assert!(actor.serves.next_completed().now_or_never().is_none());
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

            // Release the database and actor before asserting.
            slot.put(database);
            drop(actor);
            assert!(
                extra_was_dropped,
                "a busy actor retained more than one database serve"
            );
        });
    }

    #[test]
    fn failed_serve_releases_slot() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let db = init_seeded_db(context.child("resolver_db"), "failed-serve").await;
            let size = db.read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&db, request).await;
            let (mut actor, _mailbox) =
                TestActor::<Identity>::new(context.child("actor"), test_config(Some(db)));

            // A well-formed request can name a history larger than the local database.
            let (failed_tx, failed_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(size + 1), failed_tx);
            actor.serves.next_completed().await;
            assert!(failed_rx.await.is_err());
            assert!(actor.serves.is_empty());

            // The failed read must release capacity for a request the database can serve.
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx);
            actor.serves.next_completed().await;
            assert_eq!(response_rx.await.unwrap(), expected);
            assert!(actor.serves.is_empty());
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
            let blocked_1 = pair.mailboxes[1].serve(request_1, Identity);
            futures::pin_mut!(blocked_1);
            assert!(futures::poll!(blocked_1.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[1], 1).await;
            context.sleep(Duration::from_millis(5)).await;
            assert!(blocked_1.as_mut().now_or_never().is_none());

            // A second request reaches the busy peer and must remain eligible for retry.
            let blocked_2 = pair.mailboxes[1].serve(request_2, Identity);
            futures::pin_mut!(blocked_2);
            assert!(futures::poll!(blocked_2.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[1], 2).await;
            context.sleep(Duration::from_millis(5)).await;
            assert!(blocked_2.as_mut().now_or_never().is_none());

            // The busy actor must still fetch and validate data from the other peer.
            let response = select! {
                result = pair.mailboxes[0].serve(request_1, Identity) => result.unwrap().unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("busy serve blocked an unrelated local fetch");
                },
            };
            assert_operations_response(&response, request_1, &peer_expected);

            // Restoring the database lets the active request and the dropped request finish.
            slot.put(database);
            let response_1 = select! {
                result = blocked_1 => result.unwrap().unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first serve did not resume"),
            };
            assert_operations_response(&response_1, request_1, &expected_1);
            let response_2 = select! {
                result = blocked_2 => result.unwrap().unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("retried serve did not resume"),
            };
            assert_operations_response(&response_2, request_2, &expected_2);

            // Both actor trees must release their work on shutdown.
            shutdown_actors(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn coalesced_same_key_live_calls_complete() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            const PREFIX: &str = "coalesced_same_key_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[1].read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&pair.databases[1], request).await;

            // Both callers register independently while the resolver coalesces their key.
            let (first, delayed) = futures::future::join(
                pair.mailboxes[0].serve(request, Identity),
                pair.mailboxes[0].serve(request, Identity),
            )
            .await;
            let first = first.unwrap().unwrap();
            let delayed = delayed.unwrap().unwrap();
            assert_operations_response(&first, request, &expected);
            assert_operations_response(&delayed, request, &expected);
            assert_eq!(pair.metrics[0].fetch_requests.get(), 2);
            shutdown_actors(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn invalid_peer_retries_same_qmdb_source_registration() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            const PREFIX: &str = "invalid_peer_same_registration";
            let test_context = context.child(PREFIX);
            let mut peers = [1, 2, 3].map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
            peers.sort();
            let bad = peers[0].clone();
            let good = peers[1].clone();
            let client = peers[2].clone();
            let (network, oracle) = Network::new_with_peers(
                test_context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                peers,
            )
            .await;
            network.start();
            for peer in [&bad, &good] {
                let link = Link {
                    latency: Duration::from_millis(1),
                    jitter: Duration::ZERO,
                    success_rate: probability!(1.0),
                };
                oracle
                    .add_link(client.clone(), peer.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(peer.clone(), client.clone(), link)
                    .await
                    .unwrap();
            }

            let bad_db = init_seeded_db(test_context.child("bad_db"), "f7-bad").await;
            let good_db = init_seeded_db(test_context.child("good_db"), "f7-good").await;
            let target = {
                let bad_db = bad_db.read().await;
                let good_db = good_db.read().await;
                assert_eq!(bad_db.bounds(), good_db.bounds());
                assert_ne!(bad_db.root(), good_db.root());
                sync::Target::new(good_db.root(), good_db.bounds().try_into().unwrap())
            };

            let manager = oracle.manager();
            let mut handles = Vec::new();
            for (label, peer, database) in [
                ("actor_0", bad.clone(), bad_db),
                ("actor_1", good.clone(), good_db),
            ] {
                let control = oracle.control(peer.clone());
                let net = control
                    .register(0, Quota::per_second(NZU32!(1_000)))
                    .await
                    .unwrap();
                let (actor, _mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb, Identity>::new(
                    test_context.child(label),
                    Config {
                        peer_provider: manager.clone(),
                        blocker: control,
                        database: Some(database),
                        mailbox_size: NZUsize!(16),
                        me: Some(peer),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(50),
                        max_serve_ops: NZU64!(16),
                        priority_requests: false,
                        priority_responses: false,
                    },
                );
                handles.push(actor.start(net));
            }

            let control = oracle.control(client.clone());
            let net = control
                .register(0, Quota::per_second(NZU32!(1_000)))
                .await
                .unwrap();
            let (actor, mailbox) = Actor::<
                _,
                _,
                _,
                _,
                mmr::Family,
                TestDb,
                sync::RequestVerifier<mmr::Family, Sha256>,
            >::new(
                test_context.child("actor_2"),
                Config {
                    peer_provider: manager,
                    blocker: control,
                    database: None,
                    mailbox_size: NZUsize!(16),
                    me: Some(client.clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(50),
                    max_serve_ops: NZU64!(16),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let metrics = actor.metrics.clone();
            handles.push(actor.start(net));

            let synced: TestDb = select! {
                result = sync::sync(sync::engine::Config {
                    context: test_context.child("destination"),
                    source: mailbox,
                    target: target.clone(),
                    max_outstanding_requests: 1,
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(16),
                    db_config: db_config("f7-destination", &test_context),
                    update_rx: None,
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 0,
                }) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("sync waited for the rejected peer's full request timeout");
                },
            };
            assert_eq!(synced.root(), target.root);
            assert_eq!(oracle.blocked().await.unwrap(), vec![(client, bad)]);
            assert_eq!(metrics.fetch_requests.get(), 1);
            assert_eq!(metrics.pending_requests.get(), 0);
            shutdown_actors(&context, PREFIX, handles).await;
        });
    }
}

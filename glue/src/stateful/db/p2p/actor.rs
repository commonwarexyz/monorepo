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
    iter::repeat_n,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::info;

type Op<DB> = <Shared<DB> as Source>::Op;
type DatabaseRoot<DB> = <Shared<DB> as Source>::Digest;
type SyncMailbox<F, DB> = Mailbox<DB, F, Op<DB>, DatabaseRoot<DB>>;
type SyncMessage<F, DB> = mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>>;
type Subscriber<F, DB> = handler::Subscriber<Response<F, Op<DB>, DatabaseRoot<DB>>>;

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

    /// Capacity of resolver mailboxes.
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
    next_id: u64,
    /// Outstanding database reads for peers.
    serves: FuturesPool<'static, ()>,
    /// Outstanding fanout verdicts and subscriber cancellations.
    work: FuturesPool<'static, ()>,
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
            next_id: 0,
            serves: FuturesPool::default(),
            work: FuturesPool::default(),
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
            // Drive reads and release their slots on completion.
            // Each future sends its response and records the outcome.
            _ = self.serves.next_completed() => {},
            // Drive verdicts and subscription retirement independently of database reads.
            _ = self.work.next_completed() => {},
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

    /// Process database attachment and fetch requests.
    fn handle_mailbox_message<R>(&mut self, resolver: &mut R, message: SyncMessage<F, DB>)
    where
        R: Resolver<Key = Request<F>, Subscriber = Subscriber<F, DB>>,
    {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                // Active reads keep the database handle they started with.
                let replacing_existing = self.config.database.replace(db).is_some();
                info!(replacing_existing, "attached resolver database");
                let _ = self.metrics.has_database.try_set(1i64);
            }
            mailbox::Message::GetOperations { request, response } => {
                if response.is_closed() {
                    return;
                }

                // Give each caller a subscription that can be canceled independently.
                let id = self.next_id;
                self.next_id = self.next_id.checked_add(1).expect("request ID overflow");
                resolver.fetch(Fetch {
                    key: request,
                    subscriber: handler::Subscriber {
                        id,
                        reply: response.clone(),
                    },
                    span: tracing::Span::none(),
                });
                self.metrics.fetch_requests.inc();
                self.metrics.pending_requests.inc();

                // The reply receiver stays with the caller through every rejected candidate.
                // Closing it retires this exact subscription even while a verdict is pending.
                let mut resolver = resolver.clone();
                let pending_requests = self.metrics.pending_requests.clone();
                self.work.push(async move {
                    response.closed().await;

                    // Native registrations and deliveries keep their reply sender alive.
                    if response.strong_count() > 1 {
                        resolver.retain(move |_, subscriber| subscriber.id != id);
                    }
                    pending_requests.dec();
                });
            }
        }
    }

    /// Decode a candidate and route its validity feedback to waiting callers.
    fn handle_deliver(
        &mut self,
        delivery: Delivery<Request<F>, Subscriber<F, DB>>,
        value: bytes::Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        // Queued deliveries can outlive their callers.
        let key = delivery.key;
        let mut subscribers = delivery.subscribers.into_vec();
        subscribers.retain(|(subscriber, _)| !subscriber.reply.is_closed());
        if subscribers.is_empty() {
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

        // The native resolver already waits asynchronously for this verdict.
        if let [(subscriber, _)] = subscribers.as_slice() {
            let status = if subscriber.reply.try_send((response, feedback_tx)).is_ok() {
                status::Status::Success
            } else {
                status::Status::Dropped
            };
            self.metrics.deliveries.inc(status);
            return;
        }

        // Every recipient must consume or drop this candidate before a rejection can
        // trigger another delivery into its capacity-one reply channel.
        let count = subscribers.len();
        let mut verdicts = Vec::with_capacity(count);
        for ((subscriber, _), response) in subscribers.into_iter().zip(repeat_n(response, count)) {
            let (verdict, receiver) = oneshot::channel();
            if subscriber.reply.try_send((response, verdict)).is_ok() {
                verdicts.push(receiver);
            }
        }
        if verdicts.is_empty() {
            self.metrics.deliveries.inc(status::Status::Dropped);
            return;
        }
        self.metrics.deliveries.inc(status::Status::Success);
        self.work.push(async move {
            // All callers verify the same QMDB history. Closed receipts abstain.
            let mut verdict = None;
            for receiver in verdicts {
                verdict = verdict.or(receiver.await.ok());
            }
            if let Some(verdict) = verdict {
                feedback_tx.send_lossy(verdict);
            }
        });
    }

    /// Serve a peer's request by querying the local database.
    fn handle_produce(&mut self, key: Request<F>, response_tx: oneshot::Sender<bytes::Bytes>) {
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

            let Ok((response, _feedback)) = result else {
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
    use commonware_utils::{
        NZU16, NZU32, NZU64, NZUsize,
        channel::{mpsc, oneshot},
        probability,
        sync::Mutex,
    };
    use futures::FutureExt as _;
    use std::{collections::BTreeMap, sync::Arc, time::Duration};

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

    type TestResponse = Response<mmr::Family, TestOp, sha256::Digest>;
    type TestSubscriber = handler::Subscriber<TestResponse>;

    struct FeedbackSource(Mutex<Option<(TestResponse, sync::Feedback<TestResponse>)>>);

    impl Source for FeedbackSource {
        type Family = mmr::Family;
        type Digest = sha256::Digest;
        type Op = TestOp;
        type Error = sync::ServeError<mmr::Family>;

        async fn serve(&self, _request: Request<mmr::Family>) -> sync::source::Result<Self> {
            let (response, feedback) = self
                .0
                .lock()
                .take()
                .ok_or(sync::ServeError::MissingSource)?;
            Ok((response, Some(feedback)))
        }
    }

    #[derive(Default)]
    struct Recorded {
        fetches: Vec<(Request<mmr::Family>, TestSubscriber)>,
        subscriptions: BTreeMap<Request<mmr::Family>, Vec<TestSubscriber>>,
        retains: usize,
    }

    /// Records registrations and cancellations across cloned resolver handles.
    #[derive(Clone, Default)]
    struct RecordingResolver(Arc<Mutex<Recorded>>);

    impl Resolver for RecordingResolver {
        type Key = Request<mmr::Family>;
        type Subscriber = TestSubscriber;

        fn fetch<T>(&mut self, fetch: T) -> Feedback
        where
            T: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let fetch = fetch.into();
            let mut recorded = self.0.lock();
            recorded.fetches.push((fetch.key, fetch.subscriber.clone()));
            recorded
                .subscriptions
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
            let mut recorded = self.0.lock();
            recorded.retains += 1;
            recorded.subscriptions.retain(|key, subscribers| {
                subscribers.retain(|subscriber| predicate(key, subscriber));
                !subscribers.is_empty()
            });
            Feedback::Ok
        }
    }

    fn test_delivery(
        key: Request<mmr::Family>,
        subscribers: impl IntoIterator<Item = TestSubscriber>,
    ) -> Delivery<Request<mmr::Family>, TestSubscriber> {
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

    /// Poll the actor's background work while waiting for a delivery verdict.
    async fn drive_verdict(
        actor: &mut TestActor,
        mut receiver: oneshot::Receiver<bool>,
    ) -> Result<bool, oneshot::error::RecvError> {
        loop {
            select! {
                result = &mut receiver => return result,
                _ = actor.work.next_completed() => {},
            }
        }
    }

    fn test_config<DB>(
        database: Option<Shared<DB>>,
    ) -> Config<ed25519::PublicKey, DummyProvider, DummyBlocker, DB> {
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

    type LiveMailbox = SyncMailbox<mmr::Family, TestDb>;

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

    /// Connect two replicas over reliable links, with wire timeouts beyond the
    /// one-second progress checks.
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

        // Independent replicas allow one database to serve while the other is locked.
        let databases = [
            init_db(context.child("database_0"), &format!("{prefix}-0")).await,
            init_db(context.child("database_1"), &format!("{prefix}-1")).await,
        ];
        assert_eq!(
            databases[0].read().await.root(),
            databases[1].read().await.root()
        );

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
            let (actor, mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb>::new(
                context.child(if index == 0 { "actor_0" } else { "actor_1" }),
                Config {
                    peer_provider: manager.clone(),
                    blocker: control,
                    database: Some(databases[index].clone()),
                    mailbox_size: NZUsize!(16),
                    me: Some(peer.clone()),
                    timeout: Duration::from_secs(5),
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

    /// Wait for all callers to release their reply channels.
    async fn wait_for_no_pending(context: &deterministic::Context, metrics: &ResolverMetrics) {
        select! {
            _ = async {
                while metrics.pending_requests.get() != 0 {
                    reschedule().await;
                }
            } => {},
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("actor retained a closed request");
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
        db.serve(request).await.unwrap().0.encode()
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
    fn produce_drops_source_feedback_without_judging() {
        deterministic::Runner::default().start(|context| async move {
            let db = init_seeded_db(context.child("resolver_db"), "produce-feedback").await;
            let request = test_request_at(db.read().await.bounds().end);
            let (response, _) = db.serve(request).await.unwrap();
            let expected = response.encode();
            let (verdict, verdict_rx) = oneshot::channel();
            let (_, candidates) = mpsc::channel(1);
            let source = FeedbackSource(Mutex::new(Some((
                response,
                sync::Feedback::new(verdict, candidates),
            ))));
            let (mut actor, _mailbox) = Actor::new(
                context.child("actor"),
                test_config(Some(Shared::new("feedback_source", source))),
            );

            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx);
            actor.serves.next_completed().await;
            assert_eq!(response_rx.await.unwrap(), expected);
            assert!(verdict_rx.await.is_err());
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

            // A delayed close waiter must preserve a fresh caller for the same key.
            let (old, old_rx) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: old,
                },
            );
            let old_id = resolver.0.lock().fetches[0].1.id;
            drop(old_rx);
            let (fresh, fresh_rx) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: fresh,
                },
            );
            let fresh_id = resolver.0.lock().fetches[1].1.id;
            assert_ne!(fresh_id, old_id);
            actor.work.next_completed().await;
            {
                let recorded = resolver.0.lock();
                assert_eq!(recorded.fetches.len(), 2);
                assert_eq!(recorded.retains, 1);
                assert_eq!(recorded.subscriptions[&request].len(), 1);
                assert_eq!(recorded.subscriptions[&request][0].id, fresh_id);
            }
            assert_eq!(actor.metrics.pending_requests.get(), 1);

            drop(fresh_rx);
            actor.work.next_completed().await;
            assert_eq!(resolver.0.lock().retains, 2);
            assert!(!resolver.0.lock().subscriptions.contains_key(&request));
            assert_eq!(actor.metrics.pending_requests.get(), 0);
            assert!(actor.work.is_empty());
        });
    }

    #[test]
    fn completed_native_ownership_skips_redundant_retain() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let mut fetch = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(fetch.as_mut()).is_pending());
            let message = actor.mailbox_rx.recv().await.unwrap();
            actor.handle_mailbox_message(&mut resolver, message);
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);
            let (_, feedback) = fetch.await.unwrap();
            feedback.unwrap().accept();
            assert!(verdict.await.unwrap());

            // Native completion releases every registration and snapshot before the
            // closure waiter is polled. The recorder's history also owns a sender clone.
            {
                let mut recorded = resolver.0.lock();
                recorded.subscriptions.clear();
                recorded.fetches.clear();
            }
            actor.work.next_completed().await;
            assert_eq!(resolver.0.lock().retains, 0);
            assert_eq!(actor.metrics.pending_requests.get(), 0);
            assert!(actor.work.is_empty());
        });
    }

    #[test]
    fn canceled_mailbox_request_is_skipped_before_registration() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let mut fetch = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(fetch.as_mut()).is_pending());
            drop(fetch);

            let message = actor.mailbox_rx.recv().await.unwrap();
            actor.handle_mailbox_message(&mut resolver, message);
            assert!(resolver.0.lock().fetches.is_empty());
            assert_eq!(actor.metrics.pending_requests.get(), 0);
            assert!(actor.work.is_empty());
        });
    }

    #[test]
    fn cancellation_before_native_admission_preserves_replacement() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let peer = ed25519::PrivateKey::from_seed(1).public_key();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                [peer.clone()],
            )
            .await;
            network.start();
            let control = oracle.control(peer.clone());
            let net = control
                .register(0, Quota::per_second(NZU32!(100)))
                .await
                .unwrap();
            let (handler_tx, _handler_rx) =
                actor_mailbox::new(context.child("handler"), NZUsize!(8));
            let handler = handler::Handler::<mmr::Family, TestResponse>::new(handler_tx);
            let (engine, mut resolver) = p2p::Engine::new(
                context.child("resolver"),
                p2p::Config {
                    peer_provider: oracle.manager(),
                    blocker: control,
                    consumer: handler.clone(),
                    producer: handler,
                    mailbox_size: NZUsize!(8),
                    me: Some(peer),
                    timeout: Duration::from_secs(5),
                    fetch_retry_timeout: Duration::from_millis(10),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let (mut actor, mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let request = test_request_at(Location::new(1));

            // Queue the fetch and its exact cancellation before the native actor starts.
            let mut canceled = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(canceled.as_mut()).is_pending());
            let message = actor.mailbox_rx.recv().await.unwrap();
            actor.handle_mailbox_message(&mut resolver, message);
            drop(canceled);
            actor.work.next_completed().await;

            let mut replacement = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(replacement.as_mut()).is_pending());
            let message = actor.mailbox_rx.recv().await.unwrap();
            actor.handle_mailbox_message(&mut resolver, message);

            // This ready-queue predicate runs after both registrations and the cancellation.
            // Observing only the second ID proves the native subscription has no orphan.
            let (observed, mut observations) = mpsc::unbounded_channel();
            resolver.retain(move |_, subscriber| {
                observed.send(subscriber.id).unwrap();
                true
            });
            let handle = engine.start(net);
            let retained = select! {
                retained = observations.recv() => retained.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("native resolver did not process queued cancellation");
                },
            };
            assert_eq!(retained, 1);
            assert!(observations.try_recv().is_err());
            assert_eq!(actor.metrics.pending_requests.get(), 1);

            drop(replacement);
            actor.work.next_completed().await;
            assert_eq!(actor.metrics.pending_requests.get(), 0);
            handle.abort();
            let _ = handle.await;
        });
    }

    #[test]
    fn partial_caller_cancellation_preserves_live_subscriber() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (canceled, canceled_rx) = mpsc::channel(1);
            let (live, mut live_rx) = mpsc::channel(1);
            for response in [canceled, live] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let subscribers = resolver.0.lock().subscriptions[&request].clone();
            let live_id = subscribers[1].id;
            let delivery = test_delivery(request, subscribers);

            // The native delivery still names a caller whose response receiver has closed.
            drop(canceled_rx);
            actor.work.next_completed().await;
            assert_eq!(resolver.0.lock().subscriptions[&request][0].id, live_id);
            assert_eq!(actor.metrics.pending_requests.get(), 1);

            let payload = encoded_fetch_payload();
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, payload.clone(), feedback);
            let (response, feedback) = live_rx.recv().await.unwrap();
            assert_eq!(response.encode(), payload);
            feedback.send(true).unwrap();

            // A singleton verdict reaches the native receiver without polling glue work.
            assert!(verdict.await.unwrap());
            drop(live_rx);
            actor.work.next_completed().await;
            assert!(!resolver.0.lock().subscriptions.contains_key(&request));
        });
    }

    #[test]
    fn request_id_exhaustion_precedes_submission() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (existing, _existing_rx) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: existing,
                },
            );
            let existing_id = resolver.0.lock().fetches[0].1.id;
            actor.next_id = u64::MAX;
            let (response, mut receiver) = mpsc::channel(1);

            // Exhaustion panics before resolver submission can reuse an ID.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }));
            assert!(result.is_err());
            assert!(receiver.recv().await.is_none());
            let recorded = resolver.0.lock();
            assert_eq!(recorded.fetches.len(), 1);
            assert_eq!(recorded.fetches[0].1.id, existing_id);
            assert_eq!(actor.metrics.pending_requests.get(), 1);
        });
    }

    #[test]
    fn malformed_or_mismatched_delivery_preserves_waiting_caller() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = Request::Boundary {
                size: Location::new(1),
                start: Location::new(0),
            };
            let (response, mut receiver) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());

            // Both failures judge the original subscription and leave its caller waiting.
            for payload in [
                Bytes::from_static(b"malformed-response"),
                encoded_fetch_payload(),
            ] {
                let (feedback, validity) = oneshot::channel();
                actor.handle_deliver(delivery.clone(), payload, feedback);
                assert!(!validity.await.unwrap());
                assert_eq!(resolver.0.lock().subscriptions[&request].len(), 1);
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
            }
            assert_eq!(resolver.0.lock().fetches.len(), 1);
        });
    }

    #[test]
    fn cancel_reopens_with_new_id_and_stale_delivery_cannot_drain_it() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (old, old_rx) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations {
                    request,
                    response: old,
                },
            );
            let old = resolver.0.lock().fetches[0].1.clone();
            drop(old_rx);
            actor.work.next_completed().await;

            let (fresh, mut fresh_rx) = mpsc::channel(1);
            let (later, mut later_rx) = mpsc::channel(1);
            for response in [fresh, later] {
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let fresh = resolver.0.lock().fetches[1].1.clone();
            let later = resolver.0.lock().fetches[2].1.clone();
            assert!(fresh.id > old.id);

            // A stale malformed delivery cannot consume either replacement's channel.
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, [old]), Bytes::new(), feedback);
            assert!(verdict.await.is_err());
            assert!(matches!(
                fresh_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));

            // A captured snapshot reaches only its named recipient after later admission.
            let payload = encoded_fetch_payload();
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, [fresh]), payload.clone(), feedback);
            let (response, feedback) = fresh_rx.recv().await.unwrap();
            assert_eq!(response.encode(), payload);
            feedback.send(true).unwrap();
            assert!(verdict.await.unwrap());
            assert!(matches!(
                later_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));

            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, [later]), payload.clone(), feedback);
            let (response, feedback) = later_rx.recv().await.unwrap();
            assert_eq!(response.encode(), payload);
            feedback.send(true).unwrap();
            assert!(verdict.await.unwrap());
        });
    }

    #[test]
    fn delivery_without_live_recipient_is_unjudged() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let (response, receiver) = mpsc::channel(1);
            actor.handle_mailbox_message(
                &mut resolver,
                mailbox::Message::GetOperations { request, response },
            );
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());
            drop(receiver);

            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);
            assert!(verdict.await.is_err());
            actor.work.next_completed().await;
            assert!(!resolver.0.lock().subscriptions.contains_key(&request));
        });
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(1)]
    fn fanout_waits_for_slow_receipt_and_preserves_other_demand_on_cancel(
        #[case] first_to_reject: usize,
    ) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut actor, mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let mut first = Box::pin(mailbox.serve(request));
            let mut slow = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(first.as_mut()).is_pending());
            assert!(futures::poll!(slow.as_mut()).is_pending());
            for _ in 0..2 {
                let message = actor.mailbox_rx.recv().await.unwrap();
                actor.handle_mailbox_message(&mut resolver, message);
            }
            if first_to_reject == 1 {
                std::mem::swap(&mut first, &mut slow);
            }
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());
            let (feedback, mut verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);

            let (_, feedback) = first.await.unwrap();
            let mut retry = Box::pin(feedback.unwrap().reject());
            assert!(futures::poll!(retry.as_mut()).is_pending());
            assert!(actor.work.next_completed().now_or_never().is_none());
            assert!(matches!(
                verdict.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // The rejecting caller leaves while the slow candidate is still queued.
            // A fresh registration must survive both the old closure and its verdict.
            drop(retry);
            actor.work.next_completed().await;
            let mut fresh = Box::pin(mailbox.serve(request));
            assert!(futures::poll!(fresh.as_mut()).is_pending());
            let message = actor.mailbox_rx.recv().await.unwrap();
            actor.handle_mailbox_message(&mut resolver, message);
            let (_, feedback) = slow.await.unwrap();
            let mut retry = Box::pin(feedback.unwrap().reject());
            assert!(futures::poll!(retry.as_mut()).is_pending());
            assert!(!drive_verdict(&mut actor, verdict).await.unwrap());
            {
                let recorded = resolver.0.lock();
                assert_eq!(recorded.fetches.len(), 3);
                let ids = recorded.subscriptions[&request]
                    .iter()
                    .map(|s| s.id)
                    .collect::<Vec<_>>();
                assert_eq!(
                    ids,
                    [
                        recorded.fetches[1 - first_to_reject].1.id,
                        recorded.fetches[2].1.id,
                    ]
                );
            }

            // Both channels have room for the retry, and neither surviving caller re-registers.
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);
            let (_, feedback) = retry.await.unwrap();
            feedback.accept();
            let (_, feedback) = fresh.await.unwrap();
            feedback.unwrap().accept();
            assert!(drive_verdict(&mut actor, verdict).await.unwrap());
            while actor.metrics.pending_requests.get() != 0 {
                actor.work.next_completed().await;
            }
            assert_eq!(resolver.0.lock().fetches.len(), 3);
            assert!(resolver.0.lock().subscriptions.is_empty());
        });
    }

    #[test]
    fn abandoned_fanout_is_unjudged_and_retracts_every_subscriber() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let mut resolver = RecordingResolver::default();
            let request = test_request_at(Location::new(1));
            let mut receivers = Vec::new();
            for _ in 0..2 {
                let (response, receiver) = mpsc::channel(1);
                receivers.push(receiver);
                actor.handle_mailbox_message(
                    &mut resolver,
                    mailbox::Message::GetOperations { request, response },
                );
            }
            let delivery =
                test_delivery(request, resolver.0.lock().subscriptions[&request].clone());
            let (feedback, verdict) = oneshot::channel();
            actor.handle_deliver(delivery, encoded_fetch_payload(), feedback);
            drop(receivers);
            assert!(drive_verdict(&mut actor, verdict).await.is_err());
            while actor.metrics.pending_requests.get() != 0 {
                actor.work.next_completed().await;
            }
            assert!(resolver.0.lock().subscriptions.is_empty());
        });
    }

    #[test]
    fn concurrent_serves_complete_after_database_is_available() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Distinct response sizes identify the request each reply belongs to.
            let db = init_seeded_db(context.child("resolver_db"), "concurrent-serves").await;
            let size = db.read().await.bounds().end;
            let requests = [
                test_request_at(size),
                Request::Operations {
                    size,
                    start: Location::new(0),
                    max_ops: NZU64!(2),
                },
            ];
            let expected =
                futures::future::join_all(requests.map(|request| expected_payload(&db, request)))
                    .await;
            assert_ne!(expected[0], expected[1]);

            // Block both reads so the second request arrives while the first is still pending.
            let mut config = test_config(Some(db.clone()));
            config.mailbox_size = NZUsize!(1);
            let (slot, database) = db.write().await;
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), config);
            let mut responses = requests.map(|request| {
                let (response, receiver) = oneshot::channel();
                actor.handle_produce(request, response);
                receiver
            });
            let reads_pending = actor.serves.next_completed().now_or_never().is_none();
            let replies_pending = responses.iter_mut().all(|response| {
                matches!(
                    response.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                )
            });

            // Restore database access before asserting, then finish both outstanding reads.
            slot.put(database);
            assert!(reads_pending);
            assert!(
                replies_pending,
                "a pending read caused another serve to be dropped"
            );
            for _ in requests {
                actor.serves.next_completed().await;
            }
            for (response, expected) in responses.into_iter().zip(expected) {
                assert_eq!(response.await.unwrap(), expected);
            }
            assert!(actor.serves.is_empty());
        });
    }

    #[test]
    fn failed_serve_does_not_block_another_request() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let db = init_seeded_db(context.child("resolver_db"), "failed-serve").await;
            let size = db.read().await.bounds().end;
            let request = test_request_at(size);
            let expected = expected_payload(&db, request).await;
            let (mut actor, _mailbox) =
                TestActor::new(context.child("actor"), test_config(Some(db)));

            // Queue an unavailable history beside a request the database can serve.
            let (failed_tx, failed_rx) = oneshot::channel();
            actor.handle_produce(test_request_at(size + 1), failed_tx);
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx);

            // Both reads finish independently, with only the unavailable request failing.
            for _ in 0..2 {
                actor.serves.next_completed().await;
            }
            assert!(failed_rx.await.is_err());
            assert_eq!(response_rx.await.unwrap(), expected);
            assert!(actor.serves.is_empty());
        });
    }

    #[test]
    fn concurrent_serves_preserve_actor_progress() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Distinct request types keep the two reads from being coalesced.
            const PREFIX: &str = "concurrent_serves_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[0].read().await.bounds().end;
            let request_1 = test_request_at(size);
            let request_2 = Request::Boundary {
                size,
                start: Location::new(0),
            };
            let expected_1 = expected_payload(&pair.databases[0], request_1).await;
            let expected_2 = expected_payload(&pair.databases[1], request_2).await;
            let peer_expected = expected_payload(&pair.databases[1], request_1).await;

            // Keep one peer's database unavailable while the other peer requests its data.
            let (slot, database) = pair.databases[0].write().await;
            let blocked_1 = pair.mailboxes[1].serve(request_1);
            futures::pin_mut!(blocked_1);
            assert!(futures::poll!(blocked_1.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[1], 1).await;
            context.sleep(Duration::from_millis(5)).await;
            assert!(blocked_1.as_mut().now_or_never().is_none());

            // The busy actor must still fetch data from the other peer.
            let (response, feedback) = select! {
                result = pair.mailboxes[0].serve(request_1) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("busy serve blocked an unrelated local fetch");
                },
            };
            assert_operations_response(&response, request_1, &peer_expected);
            feedback.unwrap().accept();

            // A newly attached database can serve a second request while the first read waits.
            pair.mailboxes[0].attach_database(pair.databases[1].clone());
            let response_2 = select! {
                result = pair.mailboxes[1].serve(request_2) => Some(result),
                _ = context.sleep(Duration::from_secs(1)) => None,
            };
            let first_pending = blocked_1.as_mut().now_or_never().is_none();

            // Restore access before asserting. The first read must use its original database.
            slot.put(database);
            let (response_2, feedback) = response_2
                .expect("a pending read blocked another serve")
                .unwrap();
            assert!(first_pending);
            assert_eq!(response_2.encode(), expected_2);
            feedback.unwrap().accept();
            let (response_1, feedback) = select! {
                result = blocked_1 => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first serve did not resume"),
            };
            assert_operations_response(&response_1, request_1, &expected_1);
            feedback.unwrap().accept();

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
                pair.mailboxes[0].serve(request),
                pair.mailboxes[0].serve(request),
            )
            .await;
            let (first, first_feedback) = first.unwrap();
            let (delayed, delayed_feedback) = delayed.unwrap();
            assert_operations_response(&first, request, &expected);
            assert_operations_response(&delayed, request, &expected);
            first_feedback.unwrap().accept();
            delayed_feedback.unwrap().accept();
            assert_eq!(pair.metrics[0].fetch_requests.get(), 2);
            shutdown_actors(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn pending_feedback_allows_fetches_serves_and_cancellation() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            const PREFIX: &str = "pending_feedback_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let size = pair.databases[0].read().await.bounds().end;
            let request = test_request_at(size);
            let boundary = Request::Boundary {
                size,
                start: Location::new(0),
            };
            let expected = expected_payload(&pair.databases[0], request).await;
            let expected_boundary = expected_payload(&pair.databases[1], boundary).await;
            let (response, pending) = pair.mailboxes[0].serve(request).await.unwrap();
            assert_operations_response(&response, request, &expected);

            // An undecided response must not block another fetch or an incoming peer read.
            let (response, feedback) = select! {
                result = pair.mailboxes[0].serve(boundary) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("pending verdict blocked another fetch");
                },
            };
            assert_eq!(response.encode(), expected_boundary);
            feedback.unwrap().accept();
            let (response, feedback) = select! {
                result = pair.mailboxes[1].serve(request) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("pending verdict blocked an incoming peer read");
                },
            };
            assert_operations_response(&response, request, &expected);
            feedback.unwrap().accept();

            // Closing the undecided receipt cancels it without waiting for a verdict.
            drop(pending);
            wait_for_no_pending(&context, &pair.metrics[0]).await;
            let (response, feedback) = select! {
                result = pair.mailboxes[0].serve(request) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("canceled verdict blocked a replacement fetch");
                },
            };
            assert_operations_response(&response, request, &expected);
            let feedback = feedback.unwrap();

            // Shutdown must release both a held receipt and a fetch waiting on peer storage.
            let (slot, database) = pair.databases[1].write().await;
            let mut waiting = Box::pin(pair.mailboxes[0].serve(boundary));
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[0], 4).await;
            shutdown_actors(&context, PREFIX, pair.handles).await;
            slot.put(database);
            assert!(waiting.await.is_err());
            assert!(feedback.reject().await.is_none());
        });
    }

    #[test]
    fn late_subscriber_receives_cached_response_after_verdict_or_cancellation() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            for accept in [true, false] {
                let prefix = if accept { "late_accept" } else { "late_cancel" };
                let pair_context = context.child(prefix);
                let pair = spawn_live_pair(&pair_context, prefix).await;
                let size = pair.databases[1].read().await.bounds().end;
                let request = test_request_at(size);
                let expected = expected_payload(&pair.databases[1], request).await;
                let (_, first) = pair.mailboxes[0].serve(request).await.unwrap();
                let mut late = Box::pin(pair.mailboxes[0].serve(request));
                assert!(futures::poll!(late.as_mut()).is_pending());

                // A later distinct request completes only after the native mailbox admits
                // the late subscriber. Glue admission alone would not establish this order.
                let (_, fence) = pair.mailboxes[0]
                    .serve(Request::Boundary {
                        size,
                        start: Location::new(0),
                    })
                    .await
                    .unwrap();
                fence.unwrap().accept();
                assert!(late.as_mut().now_or_never().is_none());

                // With the peer database locked, only native cached bytes can finish the
                // late call. Restore the database before asserting the bounded result.
                let (slot, database) = pair.databases[1].write().await;
                if accept {
                    first.unwrap().accept();
                } else {
                    drop(first);
                }
                let result = select! {
                    result = late => Some(result),
                    _ = context.sleep(Duration::from_secs(1)) => None,
                };
                slot.put(database);
                let (response, feedback) = result
                    .expect("late subscriber did not receive the cached response")
                    .unwrap();
                assert_operations_response(&response, request, &expected);
                feedback.unwrap().accept();
                wait_for_no_pending(&context, &pair.metrics[0]).await;
                shutdown_actors(&context, prefix, pair.handles).await;
            }
        });
    }

    #[test]
    fn multiple_batches_sync_through_live_mailbox() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            const PREFIX: &str = "multiple_batches_live";
            let pair_context = context.child(PREFIX);
            let pair = spawn_live_pair(&pair_context, PREFIX).await;
            let (slot, database) = pair.databases[1].write().await;
            let mut batch = database.new_batch();
            for index in 0u64..16 {
                let key = Sha256::hash(&[b"key", &index.to_be_bytes()]);
                let value = Sha256::hash(&[b"value", &index.to_be_bytes()]);
                batch = batch.write(key, Some(value));
            }
            let batch = batch.merkleize(&database, None).await.unwrap();
            let (database, _) = database.apply_batch(batch).await.unwrap();
            let bounds = database.bounds();
            let target = sync::Target::new(database.root(), bounds.clone().try_into().unwrap());
            slot.put(database);

            // Small fetch and apply batches exercise repeated source polling between journal
            // writes, with several candidate responses allowed to wait in parallel.
            let synced: TestDb = select! {
                result = sync::sync(sync::engine::Config {
                    context: pair_context.child("destination"),
                    source: pair.mailboxes[0].clone(),
                    target: target.clone(),
                    max_outstanding_requests: 4,
                    fetch_batch_size: NZU64!(2),
                    apply_batch_size: NZU64!(1),
                    db_config: db_config("multiple-batches-destination", &pair_context),
                    update_rx: None,
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 0,
                }) => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("multi-batch sync stopped making progress");
                },
            };
            assert_eq!(synced.root(), target.root);
            assert_eq!(synced.bounds(), bounds);
            assert!(pair.metrics[0].fetch_requests.get() > 4);
            wait_for_no_pending(&context, &pair.metrics[0]).await;
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
                let (actor, _mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb>::new(
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
            let (actor, mailbox) = Actor::<_, _, _, _, mmr::Family, TestDb>::new(
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
            wait_for_no_pending(&context, &metrics).await;
            assert_eq!(metrics.pending_requests.get(), 0);
            shutdown_actors(&context, PREFIX, handles).await;
        });
    }
}

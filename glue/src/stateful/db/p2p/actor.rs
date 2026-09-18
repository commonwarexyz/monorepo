//! Resolver service actor for QMDB sync over P2P.

use super::{Mailbox, handler, mailbox, metrics::Metrics as ResolverMetrics};
use crate::stateful::db::Shared;
use commonware_actor::mailbox as actor_mailbox;
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{Delivery, Fetch, Resolver as _, p2p};
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
    collections::{BTreeMap, btree_map::Entry},
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

type Op<DB> = <Shared<DB> as Source>::Op;
type DatabaseRoot<DB> = <Shared<DB> as Source>::Digest;
type SyncMailbox<F, DB> = Mailbox<DB, F, Op<DB>, DatabaseRoot<DB>>;
type SyncMessage<F, DB> = mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>>;
type PendingSubs<F, DB> =
    BTreeMap<Request<F>, Pending<mailbox::ResponseTx<F, Op<DB>, DatabaseRoot<DB>>>>;

/// Callers sharing one resolver subscription until their response is delivered.
struct Pending<T> {
    subscriber: u64,
    responses: Vec<T>,
}

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

/// Runtime serving state for the resolver actor.
enum State<DB> {
    /// Database is not attached yet.
    NoDb,
    /// Database is attached and can serve incoming requests.
    HasDb(Shared<DB>),
}

/// An action dispatched by incoming mailbox messages.
enum MailboxAction<F: Family> {
    None,
    Fetch(Fetch<Request<F>, u64>),
    Cancel(Request<F>, u64),
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
    state: State<DB>,
    metrics: ResolverMetrics,
    pending: PendingSubs<F, DB>,
    next_subscriber: u64,
    tasks: FuturesPool<'static, Option<(Request<F>, u64)>>,
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
    pub fn new(context: E, mut cfg: Config<P, D, B, DB>) -> (Self, SyncMailbox<F, DB>) {
        let metrics = ResolverMetrics::new(&context);
        let state = cfg.database.take().map_or(State::NoDb, |db| {
            let _ = metrics.has_database.try_set(1i64);
            State::HasDb(db)
        });
        let (mailbox_tx, mailbox_rx) =
            actor_mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config: cfg,
            mailbox_rx,
            state,
            metrics,
            pending: BTreeMap::new(),
            next_subscriber: 0,
            tasks: FuturesPool::default(),
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
            rejected = self.tasks.next_completed() => {
                if let Some((request, subscriber)) = rejected {
                    // The current rejected subscription keeps its verdict and retry
                    // alive. Earlier groups have already finished their local work.
                    resolver_mailbox.retain(move |key, id| key != &request || *id >= subscriber);
                }
            },
            _ = self.serves.next_completed() => {},
            Some(message) = mailbox_message else continue => {
                match self.handle_mailbox_message(message) {
                    MailboxAction::None => {}
                    MailboxAction::Fetch(request) => {
                        resolver_mailbox.fetch(request);
                    }
                    MailboxAction::Cancel(request, subscriber) => {
                        resolver_mailbox.retain(move |key, id| key != &request || *id != subscriber);
                    }
                }
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

    /// Process a mailbox message and return any change to resolver demand.
    fn handle_mailbox_message(&mut self, message: SyncMessage<F, DB>) -> MailboxAction<F> {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached resolver database");
                self.state = State::HasDb(db);
                let _ = self.metrics.has_database.try_set(1i64);
                MailboxAction::None
            }
            mailbox::Message::GetOperations { request, response } => {
                if let Some(pending) = self.pending.get_mut(&request) {
                    pending.responses.retain(|response| !response.is_closed());
                    pending.responses.push(response);
                    return MailboxAction::None;
                }
                let subscriber = self.next_subscriber;
                self.next_subscriber = self
                    .next_subscriber
                    .checked_add(1)
                    .expect("subscriber ID overflow");
                self.pending.insert(
                    request,
                    Pending {
                        subscriber,
                        responses: vec![response],
                    },
                );
                self.metrics.fetch_requests.inc();
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
                MailboxAction::Fetch(Fetch {
                    key: request,
                    subscriber,
                    span: tracing::Span::none(),
                })
            }
            mailbox::Message::CancelOperations { request } => {
                let Some(pending) = self.pending.get_mut(&request) else {
                    return MailboxAction::None;
                };
                pending.responses.retain(|response| !response.is_closed());
                if !pending.responses.is_empty() {
                    return MailboxAction::None;
                }
                let subscriber = self.pending.remove(&request).unwrap().subscriber;
                self.metrics.cancel_requests.inc();
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
                MailboxAction::Cancel(request, subscriber)
            }
        }
    }

    /// Decode a peer's response, fan it out to pending subscribers, and aggregate approvals.
    fn handle_deliver(
        &mut self,
        delivery: Delivery<Request<F>, u64>,
        value: bytes::Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        // A queued delivery can outlive its callers. Consume a waiting group only
        // when its subscription is included in the delivery.
        let key = delivery.key;
        let entry = match self.pending.entry(key) {
            Entry::Occupied(entry)
                if delivery
                    .subscribers
                    .iter()
                    .any(|(subscriber, _)| *subscriber == entry.get().subscriber) =>
            {
                entry
            }
            _ => {
                self.metrics.deliveries.inc(status::Status::Dropped);
                return;
            }
        };

        // Keep the waiting group intact until decoding and response shape checks succeed.
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

        let pending = entry.remove();
        let _ = self.metrics.pending_requests.try_set(self.pending.len());
        let subscriber = pending.subscriber;
        let mut approvals = Vec::new();
        for subscriber in pending.responses {
            let (success_tx, success_rx) = oneshot::channel();
            if subscriber
                .send((response.clone(), Some(success_tx)))
                .is_err()
            {
                continue;
            }
            approvals.push(success_rx);
        }

        if approvals.is_empty() {
            self.metrics.deliveries.inc(status::Status::Dropped);
            return;
        }

        let deliveries = self.metrics.deliveries.clone();
        self.tasks.push(async move {
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

            let Some(peer_valid) = verdict else {
                deliveries.inc(status::Status::Dropped);
                return None;
            };
            if peer_valid {
                deliveries.inc(status::Status::Success);
            } else {
                deliveries.inc(status::Status::Failure);
                debug!(?key, "downstream marked response as peer-invalid");
            }
            feedback_tx.send_lossy(peer_valid);
            (!peer_valid).then_some((key, subscriber))
        });
    }

    /// Serve a peer's request by querying the local database.
    fn handle_produce(&mut self, key: Request<F>, response_tx: oneshot::Sender<bytes::Bytes>) {
        // Keep one database read active while the event loop continues handling
        // local requests and deliveries. Busy peers can retry elsewhere.
        if !self.serves.is_empty() {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        }
        let State::HasDb(database) = &self.state else {
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
        qmdb::any::{FixedConfig, unordered::fixed},
        translator::TwoCap,
    };
    use commonware_utils::{
        NZU16, NZU32, NZU64, NZUsize,
        channel::{mpsc, oneshot},
        non_empty_vec, probability,
    };
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

    /// Reports peer-block requests so tests can observe resolver rejection handling.
    #[derive(Clone)]
    struct RecordingBlocker(mpsc::UnboundedSender<ed25519::PublicKey>);

    impl commonware_p2p::Blocker for RecordingBlocker {
        type PublicKey = ed25519::PublicKey;

        fn block(&mut self, peer: Self::PublicKey) -> commonware_actor::Feedback {
            let _ = self.0.send(peer);
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

    type TestPending = mailbox::ResponseTx<mmr::Family, TestOp, sha256::Digest>;
    type TestPendingResult = oneshot::Receiver<(
        Response<mmr::Family, TestOp, sha256::Digest>,
        commonware_storage::qmdb::sync::FeedbackTx,
    )>;

    fn test_subscriber() -> (TestPending, TestPendingResult) {
        oneshot::channel()
    }

    fn test_delivery(
        key: Request<mmr::Family>,
        subscriber: u64,
    ) -> Delivery<Request<mmr::Family>, u64> {
        Delivery {
            key,
            subscribers: non_empty_vec![(subscriber, tracing::Span::none())],
        }
    }

    fn test_fetch(
        action: MailboxAction<mmr::Family>,
        expected: Request<mmr::Family>,
    ) -> Fetch<Request<mmr::Family>, u64> {
        let MailboxAction::Fetch(fetch) = action else {
            panic!("expected fetch action");
        };
        assert_eq!(fetch.key, expected);
        fetch
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

    /// Wait for the actor to retire a waiting group after its last caller leaves.
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

    /// A decodable response for tests that control downstream approval explicitly.
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
            actor.handle_mailbox_message(mailbox::Message::AttachDatabase(db));

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
            actor.handle_mailbox_message(mailbox::Message::AttachDatabase(db));

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
    fn deliver_with_no_live_recipient_is_unjudged() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // The caller leaves while its delivery is still queued.
            let (subscriber_tx, subscriber_rx) = test_subscriber();
            drop(subscriber_rx);
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![subscriber_tx],
                },
            );

            // With nobody to verify the response, the peer receives no validity judgment.
            let (ack_tx, ack_rx) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, 7), encoded_fetch_payload(), ack_tx);

            assert!(ack_rx.await.is_err());
        });
    }

    #[test]
    fn deliver_with_rejected_subscriber_blocks_peer() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // Both callers receive the response, but the second leaves its approval pending.
            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![sub1_tx, sub2_tx],
                },
            );

            let (ack_tx, ack_rx) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, 7), encoded_fetch_payload(), ack_tx);
            let (_response, second_feedback) = sub2_rx.await.unwrap();

            // One explicit rejection is decisive even when another caller has not replied.
            futures::join!(
                async {
                    let _ = actor.tasks.next_completed().await;
                },
                async {
                    let (_response, feedback_tx) = sub1_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(false)
                        .unwrap();
                }
            );

            // Rejection closes the remaining approval receiver instead of waiting for it.
            assert!(!ack_rx.await.unwrap());
            assert!(!second_feedback.unwrap().send_lossy(true));
        });
    }

    #[test]
    fn deliver_ignores_dropped_subscriber_approval() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // Two callers share one delivery and can independently abandon verification.
            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![sub1_tx, sub2_tx],
                },
            );

            let (ack_tx, ack_rx) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, 7), encoded_fetch_payload(), ack_tx);

            // A dropped approval is unjudged; the other caller's acceptance still counts.
            futures::join!(
                async {
                    let _ = actor.tasks.next_completed().await;
                },
                async {
                    let fetch = sub1_rx.await.unwrap();
                    drop(fetch);
                },
                async {
                    let (_response, feedback_tx) = sub2_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(true)
                        .unwrap();
                }
            );

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_with_all_dropped_approvals_is_unjudged() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // Both callers receive data before abandoning their approval channels.
            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![sub1_tx, sub2_tx],
                },
            );

            let (ack_tx, ack_rx) = oneshot::channel();
            actor.handle_deliver(test_delivery(request, 7), encoded_fetch_payload(), ack_tx);

            // No caller judges the response, so the resolver must not receive an acceptance.
            futures::join!(
                async {
                    let _ = actor.tasks.next_completed().await;
                },
                async {
                    drop(sub1_rx.await.unwrap());
                },
                async {
                    drop(sub2_rx.await.unwrap());
                }
            );

            assert!(ack_rx.await.is_err());
        });
    }

    #[test]
    fn unknown_delivery_is_unjudged() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));
            assert!(!actor.pending.contains_key(&request));

            // A delivery with no waiting group must not create a validity judgment.
            let (ack_tx, ack_rx) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, 7),
                Bytes::from_static(b"late-response"),
                ack_tx,
            );
            assert!(ack_rx.await.is_err());
        });
    }

    #[test]
    fn get_operations_reuses_pending_cohort_when_prior_callers_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // The caller has left, but its cancellation has not yet retired the subscription.
            let (stale_tx, stale_rx) = test_subscriber();
            drop(stale_rx);
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![stale_tx],
                },
            );

            // New demand joins that subscription while replacing the closed local response.
            let (fresh_tx, _fresh_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(mailbox::Message::GetOperations {
                request,
                response: fresh_tx,
            });

            assert!(matches!(action, MailboxAction::None));
            let pending = actor.pending.get(&request).unwrap();
            assert_eq!(pending.subscriber, 7);
            assert_eq!(pending.responses.len(), 1);
            assert!(!pending.responses[0].is_closed());
        });
    }

    #[test]
    fn malformed_or_mismatched_delivery_preserves_same_cohort() {
        deterministic::Runner::default().start(|context| async move {
            // Keep a boundary requester waiting across responses it cannot consume.
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = Request::Boundary {
                size: Location::new(1),
                start: Location::new(0),
            };
            let (sub_tx, mut sub_rx) = test_subscriber();
            actor.pending.insert(
                request,
                Pending {
                    subscriber: 7,
                    responses: vec![sub_tx],
                },
            );

            // Decode failure and a wrong response variant both reject data without losing demand.
            for payload in [
                Bytes::from_static(b"malformed-response"),
                encoded_fetch_payload(),
            ] {
                let (feedback_tx, validity_rx) = oneshot::channel();
                actor.handle_deliver(test_delivery(request, 7), payload, feedback_tx);

                assert!(!validity_rx.await.unwrap());
                let pending = actor.pending.get(&request).unwrap();
                assert_eq!(pending.subscriber, 7);
                assert_eq!(pending.responses.len(), 1);
                assert!(sub_rx.try_recv().is_err());
            }
        });
    }

    #[test]
    fn cancel_operations_without_pending_cohort_is_noop() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // A cancellation can arrive after delivery has already removed the waiting group.
            let action =
                actor.handle_mailbox_message(mailbox::Message::CancelOperations { request });

            assert!(matches!(action, MailboxAction::None));
        });
    }

    #[test]
    fn cancel_reopens_with_new_id_and_stale_delivery_cannot_drain_it() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            // Retire one subscription after its only caller leaves.
            let (old_tx, old_rx) = test_subscriber();
            let old_subscriber = test_fetch(
                actor.handle_mailbox_message(mailbox::Message::GetOperations {
                    request,
                    response: old_tx,
                }),
                request,
            )
            .subscriber;
            drop(old_rx);
            let cancel =
                actor.handle_mailbox_message(mailbox::Message::CancelOperations { request });
            assert!(matches!(cancel, MailboxAction::Cancel(key, subscriber)
                    if key == request && subscriber == old_subscriber));

            // Reopening the same key creates a distinct group while an older delivery may exist.
            let (fresh_tx, mut fresh_rx) = test_subscriber();
            let fresh_subscriber = test_fetch(
                actor.handle_mailbox_message(mailbox::Message::GetOperations {
                    request,
                    response: fresh_tx,
                }),
                request,
            )
            .subscriber;
            assert_ne!(fresh_subscriber, old_subscriber);

            // The older delivery cannot drain the new group or judge data on its behalf.
            let (stale_ack_tx, stale_ack_rx) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, old_subscriber),
                encoded_fetch_payload(),
                stale_ack_tx,
            );
            assert!(stale_ack_rx.await.is_err());
            let pending = actor.pending.get(&request).unwrap();
            assert_eq!(pending.subscriber, fresh_subscriber);
            assert_eq!(pending.responses.len(), 1);
            assert!(fresh_rx.try_recv().is_err());

            // A delivery addressed to the new group still completes and reports its approval.
            let (fresh_ack_tx, fresh_ack_rx) = oneshot::channel();
            actor.handle_deliver(
                test_delivery(request, fresh_subscriber),
                encoded_fetch_payload(),
                fresh_ack_tx,
            );
            let (_response, feedback) = fresh_rx.await.unwrap();
            feedback.unwrap().send(true).unwrap();
            let _ = actor.tasks.next_completed().await;
            assert!(fresh_ack_rx.await.unwrap());
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
    fn late_same_key_subscriber_completes_after_approval() {
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

            // Hold the first delivery's verdict while a new waiting group forms for its key.
            let (first, first_feedback) = pair.mailboxes[0].serve(request).await.unwrap();
            assert_operations_response(&first, request, &expected);

            let second = pair.mailboxes[0].serve(request);
            futures::pin_mut!(second);
            assert!(futures::poll!(second.as_mut()).is_pending());
            wait_for_fetches(&context, &pair.metrics[0], 2).await;
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

            // Check task cleanup even when late delivery times out.
            shutdown_pair(&context, PREFIX, pair.handles).await;
            assert!(
                matches!(late_results, Some((Ok(_), Ok(_)))),
                "late same-key subscribers did not receive the approved response"
            );
        });
    }

    #[test]
    fn cancel_late_cohort_preserves_prior_feedback_and_fresh_demand() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Separate barrier keys establish resolver consumption before and after cancellation.
            const PREFIX: &str = "cancel_late_cohort_live";
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

            // Keep the first group's approval open throughout cancellation of a later group.
            let (first, first_feedback) = pair.mailboxes[0].serve(request).await.unwrap();
            assert_operations_response(&first, request, &expected);

            // Admit the late group into the resolver, then drop its last caller.
            {
                let late = pair.mailboxes[0].serve(request);
                futures::pin_mut!(late);
                assert!(futures::poll!(late.as_mut()).is_pending());
                wait_for_fetches(&context, &pair.metrics[0], 2).await;

                let (barrier, barrier_feedback) = select! {
                    result = pair.mailboxes[0].serve(barrier_request) => result.unwrap(),
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("resolver did not process the late cohort before cancellation");
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

            // Cancelling the intermediate group must preserve cached data for the fresh caller.
            let (fresh, fresh_feedback) = select! {
                result = fresh => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("fresh cohort did not receive the retained response");
                },
            };
            assert_operations_response(&fresh, request, &expected);
            fresh_feedback.unwrap().send(true).unwrap();

            // The cancellation and redelivery paths must leave no actor tasks after shutdown.
            shutdown_pair(&context, PREFIX, pair.handles).await;
        });
    }

    #[test]
    fn repeated_rejections_prune_older_cohorts() {
        // Retention and verdict completion can reach the resolver in either order.
        for retain_before_false in [false, true] {
            deterministic::Runner::timed(Duration::from_secs(10)).start(move |context| async move {
                // Keep the honest source reachable after synthetic rejection so retries stay live.
                let peers = [11, 12].map(|seed| ed25519::PrivateKey::from_seed(seed).public_key());
                let (network, oracle) = Network::new_with_peers(
                    context.child("rejection_network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                        max_peers_per_set: NZUsize!(2),
                        disconnect_on_block: false,
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

                let client_control = oracle.control(peers[0].clone());
                let client_net = client_control
                    .register(0, Quota::per_second(NZU32!(100)))
                    .await
                    .unwrap();
                let source_control = oracle.control(peers[1].clone());
                let source_net = source_control
                    .register(0, Quota::per_second(NZU32!(100)))
                    .await
                    .unwrap();

                // Serve real database responses, with a distinct key available as a mailbox fence.
                let database =
                    init_seeded_db(context.child("rejection_source_db"), "rejection-source").await;
                let size = database.read().await.bounds().end;
                let request = test_request_at(size);
                let barrier_request = Request::Operations {
                    size,
                    start: Location::new(0),
                    max_ops: NZU64!(2),
                };
                let (source, _source_mailbox) =
                    Actor::<_, _, _, _, mmr::Family, TestDb>::new(
                        context.child("rejection_source"),
                        Config {
                            peer_provider: manager.clone(),
                            blocker: source_control,
                            database: Some(database),
                            mailbox_size: NZUsize!(16),
                            me: Some(peers[1].clone()),
                            timeout: Duration::from_millis(20),
                            fetch_retry_timeout: Duration::from_millis(1),
                            max_serve_ops: NZU64!(16),
                            priority_requests: false,
                            priority_responses: false,
                        },
                    );
                let source_handle = source.start(source_net);

                // Drive the client actor manually to inspect real resolver subscription snapshots.
                let (handler_tx, mut handler_rx) = commonware_actor::mailbox::new(
                    context.child("rejection_handler"),
                    NZUsize!(16),
                );
                let handler = handler::Handler::new(handler_tx);
                let (blocked_tx, mut blocked_rx) = mpsc::unbounded_channel();
                let (engine, mut resolver_mailbox) = p2p::Engine::new(
                    context.child("rejection_resolver"),
                    p2p::Config {
                        peer_provider: manager,
                        blocker: RecordingBlocker(blocked_tx),
                        consumer: handler.clone(),
                        producer: handler,
                        mailbox_size: NZUsize!(16),
                        me: Some(peers[0].clone()),
                        timeout: Duration::from_millis(20),
                        fetch_retry_timeout: Duration::from_millis(1),
                        priority_requests: false,
                        priority_responses: false,
                    },
                );
                let resolver_handle = engine.start(client_net);
                let (mut actor, _mailbox) =
                    TestActor::new(context.child("rejection_client"), test_config(None));

                // Leave the first group's approval pending while subsequent demand is admitted.
                let (first_tx, first_rx) = test_subscriber();
                let first_fetch = test_fetch(
                    actor.handle_mailbox_message(mailbox::Message::GetOperations {
                        request,
                        response: first_tx,
                    }),
                    request,
                );
                let mut current_id = first_fetch.subscriber;
                resolver_mailbox.fetch(first_fetch);

                let first = select! {
                    message = handler_rx.recv() => message.unwrap(),
                    _ = context.sleep(Duration::from_secs(1)) => panic!("first delivery missing"),
                };
                let handler::EngineMessage::Deliver {
                    delivery,
                    value,
                    response,
                } = first
                else {
                    panic!("unexpected produce request");
                };
                assert_eq!(delivery.key, request);
                assert_eq!(
                    delivery
                        .subscribers
                        .iter()
                        .map(|(subscriber, _)| *subscriber)
                        .collect::<Vec<_>>(),
                    vec![current_id]
                );
                actor.handle_deliver(delivery, value, response);
                let (_response, first_feedback) = first_rx.await.unwrap();
                let mut current_feedback = Some(first_feedback.unwrap());

                // A second rejection reveals whether already-spent older identities accumulate.
                for round in 0..2 {
                    // The successor must survive cleanup of the group whose verdict is pending.
                    let (successor_tx, successor_rx) = test_subscriber();
                    let successor_fetch = test_fetch(
                        actor.handle_mailbox_message(mailbox::Message::GetOperations {
                            request,
                            response: successor_tx,
                        }),
                        request,
                    );
                    let successor_id = successor_fetch.subscriber;
                    resolver_mailbox.fetch(successor_fetch);

                    // A distinct-key delivery fences retention before the verdict is published.
                    if retain_before_false {
                        resolver_mailbox
                            .retain(move |key, id| key != &request || *id >= current_id);

                        let (barrier_tx, barrier_rx) = test_subscriber();
                        let barrier_fetch = test_fetch(
                            actor.handle_mailbox_message(mailbox::Message::GetOperations {
                                request: barrier_request,
                                response: barrier_tx,
                            }),
                            barrier_request,
                        );
                        resolver_mailbox.fetch(barrier_fetch);
                        let barrier = select! {
                            message = handler_rx.recv() => message.unwrap(),
                            _ = context.sleep(Duration::from_secs(1)) => {
                                panic!("post-retain barrier delivery missing");
                            },
                        };
                        let handler::EngineMessage::Deliver {
                            delivery,
                            value,
                            response,
                        } = barrier
                        else {
                            panic!("unexpected produce request");
                        };
                        assert_eq!(delivery.key, barrier_request);
                        actor.handle_deliver(delivery, value, response);
                        let (_response, feedback) = barrier_rx.await.unwrap();
                        feedback.unwrap().send(true).unwrap();
                        assert_eq!(actor.tasks.next_completed().await, None);
                    }

                    // Consume the rejection and observe the resolver's resulting block event.
                    current_feedback.take().unwrap().send(false).unwrap();
                    assert_eq!(
                        actor.tasks.next_completed().await,
                        Some((request, current_id))
                    );
                    let blocked_peer = select! {
                        peer = blocked_rx.recv() => peer.unwrap(),
                        _ = context.sleep(Duration::from_secs(1)) => {
                            panic!("resolver did not consume the invalid verdict");
                        },
                    };
                    assert_eq!(blocked_peer, peers[1]);

                    // In this ordering the block event fences verdict consumption before cleanup.
                    if !retain_before_false {
                        resolver_mailbox
                            .retain(move |key, id| key != &request || *id >= current_id);
                    }

                    // Retry carries only the current retry owner and still-live successor demand.
                    let retried = select! {
                        message = handler_rx.recv() => message.unwrap(),
                        _ = context.sleep(Duration::from_secs(1)) => panic!("retry delivery missing"),
                    };
                    let handler::EngineMessage::Deliver {
                        delivery,
                        value,
                        response,
                    } = retried
                    else {
                        panic!("unexpected produce request");
                    };
                    assert_eq!(delivery.key, request);
                    let subscribers = delivery
                        .subscribers
                        .iter()
                        .map(|(subscriber, _)| *subscriber)
                        .collect::<Vec<_>>();
                    assert_eq!(subscribers, vec![current_id, successor_id]);

                    // Let the successor become the next rejecting group to exercise reclamation.
                    if round == 0 {
                        actor.handle_deliver(delivery, value, response);
                        let (_response, feedback) = successor_rx.await.unwrap();
                        current_feedback = Some(feedback.unwrap());
                        current_id = successor_id;
                    }
                }

                // Stop the independently driven resolver and source actor after both rounds.
                resolver_handle.abort();
                let _ = resolver_handle.await;
                source_handle.abort();
                let _ = source_handle.await;
            });
        }
    }
}

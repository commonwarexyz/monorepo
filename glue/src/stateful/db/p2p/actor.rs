//! Resolver service actor for QMDB sync over P2P.

use super::{handler, mailbox, metrics::Metrics as ResolverMetrics, Mailbox};
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{p2p, Resolver as _};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::status::{self, CounterExt, GaugeExt},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_storage::{
    merkle::Family,
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc, oneshot},
    sync::AsyncRwLock,
};
use futures::future::{self, Either};
use rand::Rng;
use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc, time::Duration};
use tracing::{debug, info};

type Op<DB> = <Arc<AsyncRwLock<DB>> as SyncResolver>::Op;
type DatabaseRoot<DB> = <Arc<AsyncRwLock<DB>> as SyncResolver>::Digest;
type SyncMailbox<F, DB> = Mailbox<DB, F, Op<DB>, DatabaseRoot<DB>>;
type Pending<F, Op, D> = oneshot::Sender<Result<FetchResult<F, Op, D>, mailbox::ResponseDropped>>;
type PendingSubs<F, DB> = BTreeMap<handler::Request<F>, Vec<Pending<F, Op<DB>, DatabaseRoot<DB>>>>;

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
    pub database: Option<Arc<AsyncRwLock<DB>>>,

    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: usize,

    /// Local node identity if available.
    pub me: Option<P>,

    /// Initial expected performance for new peers.
    pub initial: Duration,

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
    HasDb(Arc<AsyncRwLock<DB>>),
}

/// An action dispatched by incoming mailbox messages.
enum MailboxAction<F: Family> {
    None,
    Fetch(handler::Request<F>),
    Cancel(handler::Request<F>),
}

/// Runs a QMDB sync resolver service over `commonware_resolver::p2p::Engine`.
pub struct Actor<E, P, D, B, F, DB>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    Arc<AsyncRwLock<DB>>: SyncResolver<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    context: ContextCell<E>,
    config: Config<P, D, B, DB>,
    mailbox_rx: mpsc::Receiver<mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>>>,
    state: State<DB>,
    metrics: ResolverMetrics,
    pending: PendingSubs<F, DB>,
}

impl<E, P, D, B, F, DB> Actor<E, P, D, B, F, DB>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    Arc<AsyncRwLock<DB>>: SyncResolver<Family = F>,
    Op<DB>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    /// Create a new resolver actor and mailbox.
    pub fn new(context: E, mut cfg: Config<P, D, B, DB>) -> (Self, SyncMailbox<F, DB>) {
        let metrics = ResolverMetrics::new(&context);
        let state = cfg.database.take().map_or(State::NoDb, |db| {
            let _ = metrics.has_database.try_set(1i64);
            State::HasDb(db)
        });
        let (mailbox_tx, mailbox_rx) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config: cfg,
            mailbox_rx,
            state,
            metrics,
            pending: BTreeMap::new(),
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
        let (handler_tx, mut handler_rx) = mpsc::channel(self.config.mailbox_size);
        let handler = handler::Handler::new(handler_tx);
        let (engine, mut resolver_mailbox) = p2p::Engine::new(
            self.context.clone().into_present().with_label("resolver"),
            p2p::Config {
                peer_provider: self.config.peer_provider.clone(),
                blocker: self.config.blocker.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.config.mailbox_size,
                me: self.config.me.clone(),
                initial: self.config.initial,
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
                self.pending.retain(|_, subs| {
                    subs.retain(|s| !s.is_closed());
                    !subs.is_empty()
                });
                let mailbox_message = if !(self.mailbox_rx.is_closed() && self.mailbox_rx.is_empty()) {
                    Either::Left(self.mailbox_rx.recv())
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                return;
            },
            _ = &mut resolver_task => {
                return;
            },
            Some(message) = mailbox_message else continue => {
                match self.handle_mailbox_message(message) {
                    MailboxAction::None => {}
                    MailboxAction::Fetch(request) => {
                        resolver_mailbox.fetch(request).await;
                    }
                    MailboxAction::Cancel(request) => {
                        resolver_mailbox.cancel(request).await;
                    }
                }
            },
            Some(message) = handler_rx.recv() else {
                return;
            } => {
                match message {
                    handler::EngineMessage::Deliver { key, value, response } => {
                        self.handle_deliver(key, value, response).await;
                    }
                    handler::EngineMessage::Produce { key, response } => {
                        self.handle_produce(key, response).await;
                    }
                }
            },
        }
    }

    /// Process a mailbox message. Returns a request to fetch if a new key was registered.
    fn handle_mailbox_message(
        &mut self,
        message: mailbox::Message<DB, F, Op<DB>, DatabaseRoot<DB>>,
    ) -> MailboxAction<F> {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached resolver database");
                self.state = State::HasDb(db);
                let _ = self.metrics.has_database.try_set(1i64);
                MailboxAction::None
            }
            mailbox::Message::GetOperations { request, response } => {
                if let Some(subscribers) = self.pending.get_mut(&request) {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    if !subscribers.is_empty() {
                        subscribers.push(response);
                        return MailboxAction::None;
                    }
                }
                self.pending.insert(request.clone(), vec![response]);
                self.metrics.fetch_requests.inc();
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
                MailboxAction::Fetch(request)
            }
            mailbox::Message::CancelOperations { request } => {
                if self.should_cancel_request(&request) {
                    self.metrics.cancel_requests.inc();
                    let _ = self.metrics.pending_requests.try_set(self.pending.len());
                    MailboxAction::Cancel(request)
                } else {
                    MailboxAction::None
                }
            }
        }
    }

    /// Returns `true` if a request should be cancelled.
    fn should_cancel_request(&mut self, request: &handler::Request<F>) -> bool {
        let Some(subscribers) = self.pending.get_mut(request) else {
            return false;
        };
        subscribers.retain(|subscriber| !subscriber.is_closed());
        if !subscribers.is_empty() {
            return false;
        }
        self.pending.remove(request);
        true
    }

    /// Decode a peer's response, fan it out to pending subscribers, and aggregate approvals.
    async fn handle_deliver(
        &mut self,
        key: handler::Request<F>,
        value: bytes::Bytes,
        response: oneshot::Sender<bool>,
    ) {
        // Only accept responses for keys we currently have in-flight.
        // Unknown keys are unsolicited/stale deliveries and are ignored.
        let Some(subscribers) = self.pending.remove(&key) else {
            self.metrics.deliveries.inc(status::Status::Dropped);
            response.send_lossy(true);
            return;
        };
        let _ = self.metrics.pending_requests.try_set(self.pending.len());

        // `max_ops` is sourced from the original local request key above.
        let max_ops = key.max_ops.get() as usize;
        let decoded =
            match handler::Response::<F, Op<DB>, DatabaseRoot<DB>>::decode_cfg(value, &max_ops) {
                Ok(decoded) => decoded,
                Err(_) => {
                    self.pending.insert(key, subscribers);
                    let _ = self.metrics.pending_requests.try_set(self.pending.len());
                    self.metrics.deliveries.inc(status::Status::Invalid);
                    response.send_lossy(false);
                    return;
                }
            };

        let mut approvals = Vec::new();
        for subscriber in subscribers {
            let (success_tx, success_rx) = oneshot::channel();
            if subscriber
                .send(Ok(FetchResult {
                    proof: decoded.proof.clone(),
                    operations: decoded.operations.clone(),
                    success_tx,
                    pinned_nodes: decoded.pinned_nodes.clone(),
                }))
                .is_err()
            {
                continue;
            }
            approvals.push(success_rx);
        }

        if approvals.is_empty() {
            self.metrics.deliveries.inc(status::Status::Success);
            response.send_lossy(true);
            return;
        }

        let mut peer_valid = true;
        for approval in approvals {
            if let Ok(approved) = approval.await {
                peer_valid &= approved;
            }
        }

        if peer_valid {
            self.metrics.deliveries.inc(status::Status::Success);
        } else {
            self.metrics.deliveries.inc(status::Status::Failure);
            debug!(?key, "downstream marked response as peer-invalid");
        }
        response.send_lossy(peer_valid);
    }

    /// Serve a peer's request by querying the local database.
    async fn handle_produce(
        &mut self,
        key: handler::Request<F>,
        response: oneshot::Sender<bytes::Bytes>,
    ) {
        let State::HasDb(database) = &self.state else {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        };
        if key.max_ops > self.config.max_serve_ops {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        }
        let (_cancel_tx, cancel_rx) = oneshot::channel();
        let result = database
            .get_operations(
                key.op_count,
                key.start_loc,
                key.max_ops,
                key.include_pinned_nodes,
                cancel_rx,
            )
            .await;

        let Ok(fetch) = result else {
            self.metrics.serve_requests.inc(status::Status::Failure);
            return;
        };

        response.send_lossy(
            handler::Response {
                proof: fetch.proof,
                operations: fetch.operations,
                pinned_nodes: fetch.pinned_nodes,
            }
            .encode(),
        );
        self.metrics.serve_requests.inc(status::Status::Success);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, sha256, Sha256};
    use commonware_p2p::{Provider, TrackedPeers};
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, journaled::Config as MmrJournalConfig, Location, Proof},
        qmdb::any::{unordered::fixed, FixedConfig},
        translator::TwoCap,
    };
    use commonware_utils::{channel::oneshot, sync::AsyncRwLock, NZUsize, NZU16, NZU64};
    use std::{num::NonZeroU64, sync::Arc, time::Duration};

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

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    type TestDb = fixed::Db<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        TwoCap,
    >;
    type TestOp = <Arc<AsyncRwLock<TestDb>> as SyncResolver>::Op;

    type TestActor = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        mmr::Family,
        TestDb,
    >;

    fn test_config(
        database: Option<Arc<AsyncRwLock<TestDb>>>,
    ) -> Config<ed25519::PublicKey, DummyProvider, DummyBlocker, TestDb> {
        Config {
            peer_provider: DummyProvider,
            blocker: DummyBlocker,
            database,
            mailbox_size: 16,
            me: None,
            initial: Duration::from_millis(10),
            timeout: Duration::from_millis(10),
            fetch_retry_timeout: Duration::from_millis(10),
            max_serve_ops: NonZeroU64::new(16).unwrap(),
            priority_requests: false,
            priority_responses: false,
        }
    }

    fn test_request_at(op_count: Location) -> handler::Request<mmr::Family> {
        handler::Request {
            op_count,
            start_loc: Location::new(0),
            max_ops: NonZeroU64::new(1).unwrap(),
            include_pinned_nodes: false,
        }
    }

    type TestPending = Pending<mmr::Family, TestOp, sha256::Digest>;
    type TestPendingResult = oneshot::Receiver<
        Result<FetchResult<mmr::Family, TestOp, sha256::Digest>, mailbox::ResponseDropped>,
    >;

    fn test_subscriber() -> (TestPending, TestPendingResult) {
        oneshot::channel()
    }

    fn db_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap> {
        let page_cache = CacheRef::from_pooler(pooler, NZU16!(101), NZUsize!(11));
        FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{suffix}-mmr-journal"),
                metadata_partition: format!("{suffix}-mmr-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{suffix}-log-journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
        }
    }

    async fn init_db(context: deterministic::Context, suffix: &str) -> Arc<AsyncRwLock<TestDb>> {
        let db = TestDb::init(context.with_label("db"), db_config(suffix, &context))
            .await
            .expect("db init should succeed");
        Arc::new(AsyncRwLock::new(db))
    }

    fn encoded_fetch_payload() -> Bytes {
        handler::Response::<mmr::Family, TestOp, sha256::Digest> {
            proof: Proof {
                leaves: Location::new(0),
                digests: Vec::new(),
            },
            operations: Vec::new(),
            pinned_nodes: None,
        }
        .encode()
    }

    #[test]
    fn produce_denied_before_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.clone(), test_config(None));

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(Location::new(1)), response_tx)
                .await;
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn same_request_served_after_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.clone(), test_config(None));
            let db = init_db(context.clone(), "resolver-after-attach").await;
            let op_count = db.read().await.bounds().await.end;
            actor.handle_mailbox_message(mailbox::Message::AttachDatabase(db));

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(op_count), response_tx)
                .await;

            let payload = response_rx
                .await
                .expect("response should be available after attach");
            assert!(!payload.is_empty());
        });
    }

    #[test]
    fn produce_rejects_request_above_max_serve_ops() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.clone(), test_config(None));
            let db = init_db(context.clone(), "resolver-unbounded-max-ops").await;
            let op_count = db.read().await.bounds().await.end;
            actor.handle_mailbox_message(mailbox::Message::AttachDatabase(db));

            let request = handler::Request {
                op_count,
                start_loc: Location::new(0),
                max_ops: NonZeroU64::new(1_000).unwrap(),
                include_pinned_nodes: false,
            };
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx).await;

            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn deliver_with_dropped_response_receiver_is_treated_as_valid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, subscriber_rx) = test_subscriber();
            drop(subscriber_rx);
            actor.pending.insert(request.clone(), vec![subscriber_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_deliver(request, encoded_fetch_payload(), ack_tx)
                .await;

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_with_rejected_subscriber_blocks_peer() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor
                .pending
                .insert(request.clone(), vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
                async {
                    let fetch = sub1_rx.await.unwrap().unwrap();
                    fetch.success_tx.send(true).unwrap();
                },
                async {
                    let fetch = sub2_rx.await.unwrap().unwrap();
                    fetch.success_tx.send(false).unwrap();
                }
            );

            assert!(!ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_ignores_dropped_subscriber_approval() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor
                .pending
                .insert(request.clone(), vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
                async {
                    let fetch = sub1_rx.await.unwrap().unwrap();
                    drop(fetch);
                },
                async {
                    let fetch = sub2_rx.await.unwrap().unwrap();
                    fetch.success_tx.send(true).unwrap();
                }
            );

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn failed_then_deliver_clears_pending_and_allows_retry() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, _subscriber_rx) = test_subscriber();
            actor.pending.insert(request.clone(), vec![subscriber_tx]);
            actor.pending.remove(&request);
            assert!(!actor.pending.contains_key(&request));

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_deliver(request, Bytes::from_static(b"late-response"), ack_tx)
                .await;
            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn get_operations_refetches_when_pending_subscribers_are_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (stale_tx, stale_rx) = test_subscriber();
            drop(stale_rx);
            actor.pending.insert(request.clone(), vec![stale_tx]);

            let (fresh_tx, _fresh_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(mailbox::Message::GetOperations {
                request: request.clone(),
                response: fresh_tx,
            });

            assert!(matches!(action, MailboxAction::Fetch(ref key) if key == &request));
            let pending = actor.pending.get(&request).unwrap();
            assert_eq!(pending.len(), 1);
            assert!(!pending[0].is_closed());
        });
    }
}

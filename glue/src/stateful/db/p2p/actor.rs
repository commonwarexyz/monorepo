//! Resolver service actor for QMDB sync over P2P.

use super::{Mailbox, handler, mailbox, metrics::Metrics as ResolverMetrics};
use crate::stateful::db::ServeSource;
use commonware_actor::mailbox as actor_mailbox;
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{Resolver as _, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{GaugeExt, status},
};
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Request, Response, Source},
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use futures::future;
use rand_core::Rng;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

type Serve<Src> = <Src as ServeSource>::Serve;
type Op<Src> = <Serve<Src> as Source>::Op;
type SourceRoot<Src> = <Serve<Src> as Source>::Digest;
type SyncMailbox<F, Src> = Mailbox<Src, F, Op<Src>, SourceRoot<Src>>;
type SyncMessage<F, Src> = mailbox::Message<Src, F, Op<Src>, SourceRoot<Src>>;
type PendingSubs<F, Src> =
    BTreeMap<Request<F>, Vec<mailbox::ResponseTx<F, Op<Src>, SourceRoot<Src>>>>;

/// Configuration for [`Actor`].
pub struct Config<P, D, B>
where
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Provider for the current peer set.
    pub peer_provider: D,

    /// Blocker used when peers send invalid data.
    pub blocker: B,

    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: NonZeroUsize,

    /// Local node identity if available.
    pub me: Option<P>,

    /// Initial expected performance for new peers.
    pub initial: Duration,

    /// Request timeout.
    pub timeout: Duration,

    /// Retry cadence for pending fetches.
    pub fetch_retry_timeout: Duration,

    /// Requests asking for more operations than this are declined.
    pub max_serve_ops: NonZeroU64,

    /// Send fetch requests with network priority.
    pub priority_requests: bool,

    /// Send responses with network priority.
    pub priority_responses: bool,
}

/// An action dispatched by incoming mailbox messages.
enum MailboxAction<F: Family> {
    None,
    Fetch(Request<F>),
    Cancel(Request<F>),
}

/// Runs a QMDB sync resolver service over `commonware_resolver::p2p::Engine`.
pub struct Actor<E, P, D, B, F, Src>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    Src: ServeSource,
    Serve<Src>: Source<Family = F>,
    Op<Src>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    context: ContextCell<E>,
    config: Config<P, D, B>,
    mailbox_rx: actor_mailbox::Receiver<SyncMessage<F, Src>>,
    /// The serving source, attached after startup.
    source: Option<Src>,
    metrics: ResolverMetrics,
    pending: PendingSubs<F, Src>,
}

impl<E, P, D, B, F, Src> Actor<E, P, D, B, F, Src>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    Src: ServeSource,
    Serve<Src>: Source<Family = F>,
    Op<Src>: Codec<Cfg = ()> + Send + Clone + 'static,
{
    /// Create a new resolver actor and mailbox.
    pub fn new(context: E, cfg: Config<P, D, B>) -> (Self, SyncMailbox<F, Src>) {
        let metrics = ResolverMetrics::new(&context);
        let (mailbox_tx, mailbox_rx) =
            actor_mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config: cfg,
            mailbox_rx,
            source: None,
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
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
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
                debug!("resolver engine stopped, shutting down");
                return;
            },
            Some(message) = mailbox_message else continue => {
                match self.handle_mailbox_message(message) {
                    MailboxAction::None => {}
                    MailboxAction::Fetch(request) => {
                        resolver_mailbox.fetch(request);
                    }
                    MailboxAction::Cancel(request) => {
                        resolver_mailbox.retain(move |key, _| key != &request);
                    }
                }
            },
            Some(message) = handler_rx.recv() else {
                debug!("resolver handler closed, shutting down");
                return;
            } => match message {
                handler::EngineMessage::Deliver {
                    key,
                    value,
                    response,
                } => {
                    self.handle_deliver(key, value, response).await;
                }
                handler::EngineMessage::Produce { key, response } => {
                    self.handle_produce(key, response).await;
                }
            },
        }
    }

    /// Process a mailbox message, returning the fetch or cancel action to forward to
    /// the resolver engine.
    fn handle_mailbox_message(&mut self, message: SyncMessage<F, Src>) -> MailboxAction<F> {
        match message {
            mailbox::Message::AttachSource(source) => {
                let replacing_existing = self.source.is_some();
                info!(replacing_existing, "attached resolver source");
                self.source = Some(source);
                let _ = self.metrics.has_source.try_set(1i64);
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
                self.pending.insert(request, vec![response]);
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
    fn should_cancel_request(&mut self, request: &Request<F>) -> bool {
        let Some(subscribers) = self.pending.get_mut(request) else {
            return true;
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
        key: Request<F>,
        value: bytes::Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        // Only accept responses for keys we currently have in-flight.
        // Unknown keys are unsolicited/stale deliveries and are ignored.
        let Some(subscribers) = self.pending.remove(&key) else {
            self.metrics.deliveries.inc(status::Status::Dropped);
            feedback_tx.send_lossy(true);
            return;
        };
        let _ = self.metrics.pending_requests.try_set(self.pending.len());

        let cfg = (key.max_ops().get() as usize, ());
        let response = match Response::<F, Op<Src>, SourceRoot<Src>>::decode_cfg(value, &cfg) {
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
                self.pending.insert(key, subscribers);
                let _ = self.metrics.pending_requests.try_set(self.pending.len());
                self.metrics.deliveries.inc(status::Status::Invalid);
                feedback_tx.send_lossy(false);
                return;
            }
        };

        let mut approvals = Vec::new();
        for subscriber in subscribers {
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
            self.metrics.deliveries.inc(status::Status::Success);
            feedback_tx.send_lossy(true);
            return;
        }

        let mut peer_valid = true;
        for approval in approvals {
            let approved = select! {
                approved = approval => approved,
                _ = self.context.stopped() => return,
            };
            if let Ok(approved) = approved {
                peer_valid &= approved;
            }
        }

        if peer_valid {
            self.metrics.deliveries.inc(status::Status::Success);
        } else {
            self.metrics.deliveries.inc(status::Status::Failure);
            debug!(?key, "downstream marked response as peer-invalid");
        }
        feedback_tx.send_lossy(peer_valid);
    }

    /// Serve a peer's request from the latest published snapshot.
    ///
    /// Serves run one at a time in the actor loop. Spawning them per-request is a
    /// possible follow-up now that the handle is an owned snapshot.
    async fn handle_produce(
        &mut self,
        key: Request<F>,
        mut response_tx: oneshot::Sender<bytes::Bytes>,
    ) {
        let Some(source) = &self.source else {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        };
        if let Request::Operations { max_ops, .. } = key
            && max_ops > self.config.max_serve_ops
        {
            self.metrics.serve_requests.inc(status::Status::Invalid);
            return;
        }
        // Declines before the first publication and after the publisher drops.
        let Some(handle) = source.latest() else {
            self.metrics.serve_requests.inc(status::Status::Dropped);
            return;
        };

        // The handle is an owned snapshot, so serving reads frozen state and never touches
        // the live database. Abandon the read when the requester or the runtime goes away.
        let serve = handle.serve(key);
        futures::pin_mut!(serve);
        let result = select! {
            result = &mut serve => result,
            _ = response_tx.closed() => {
                self.metrics.serve_cancelled.inc();
                return;
            },
            _ = self.context.stopped() => {
                self.metrics.serve_cancelled.inc();
                return;
            },
        };

        let Ok((response, _feedback_tx)) = result else {
            self.metrics.serve_requests.inc(status::Status::Failure);
            return;
        };

        if response_tx.send_lossy(response.encode()) {
            self.metrics.serve_requests.inc(status::Status::Success);
        } else {
            // The requester went away between the read and the send.
            self.metrics.serve_cancelled.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{Sha256, ed25519, sha256};
    use commonware_p2p::{Provider, TrackedPeers};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedLogConfig,
        mmr::{self, Location, Proof, full::Config as MmrJournalConfig},
        qmdb::any::{FixedConfig, unordered::fixed},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, channel::oneshot};
    use std::{sync::Arc, time::Duration};

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
    type TestOp = <TestDb as Source>::Op;

    /// A source that always serves the same frozen database handle.
    #[derive(Clone)]
    struct StaticSource(Arc<TestDb>);

    impl ServeSource for StaticSource {
        type Serve = Arc<TestDb>;

        fn latest(&self) -> Option<Arc<TestDb>> {
            Some(self.0.clone())
        }
    }

    /// A source with nothing to serve yet.
    #[derive(Clone)]
    struct EmptySource;

    impl ServeSource for EmptySource {
        type Serve = Arc<TestDb>;

        fn latest(&self) -> Option<Arc<TestDb>> {
            None
        }
    }

    type TestActor = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        mmr::Family,
        StaticSource,
    >;

    fn test_config() -> Config<ed25519::PublicKey, DummyProvider, DummyBlocker> {
        Config {
            peer_provider: DummyProvider,
            blocker: DummyBlocker,
            mailbox_size: NZUsize!(16),
            me: None,
            initial: Duration::from_millis(10),
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

    fn db_config(suffix: &str, pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
        let page_cache = CacheRef::from_pooler(pooler, NZU16!(101), NZUsize!(11));
        FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{suffix}-mmr-journal"),
                metadata_partition: format!("{suffix}-mmr-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{suffix}-log-journal"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    async fn init_source(
        context: deterministic::Context,
        suffix: &str,
    ) -> (StaticSource, Location) {
        let db = TestDb::init(context.child("db"), db_config(suffix, &context))
            .await
            .expect("db init should succeed");
        let size = db.bounds().end;
        (StaticSource(Arc::new(db)), size)
    }

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
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config());

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(Location::new(1)), response_tx)
                .await;
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn produce_denied_when_source_is_empty() {
        deterministic::Runner::default().start(|context| async move {
            type EmptyActor = Actor<
                deterministic::Context,
                ed25519::PublicKey,
                DummyProvider,
                DummyBlocker,
                mmr::Family,
                EmptySource,
            >;
            let (mut actor, _mailbox) = EmptyActor::new(context.child("actor"), test_config());
            actor.handle_mailbox_message(mailbox::Message::AttachSource(EmptySource));

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
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config());
            let (source, size) =
                init_source(context.child("resolver_db"), "resolver-after-attach").await;
            actor.handle_mailbox_message(mailbox::Message::AttachSource(source));

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(size), response_tx)
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
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config());
            let (source, size) =
                init_source(context.child("resolver_db"), "resolver-unbounded-max-ops").await;
            actor.handle_mailbox_message(mailbox::Message::AttachSource(source));

            let request = Request::Operations {
                size,
                start: Location::new(0),
                max_ops: NZU64!(1_000),
            };
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx).await;

            assert!(response_rx.await.is_err());
            let metrics = context.encode();
            assert!(
                metrics.lines().any(|line| {
                    line.contains("serve_requests_total")
                        && line.contains("status=\"Invalid\"")
                        && line.ends_with(" 1")
                }),
                "oversized request must count as a client error"
            );
        });
    }

    #[test]
    fn deliver_with_dropped_response_receiver_is_treated_as_valid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, subscriber_rx) = test_subscriber();
            drop(subscriber_rx);
            actor.pending.insert(request, vec![subscriber_tx]);

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
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor.pending.insert(request, vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
                async {
                    let (_response, feedback_tx) = sub1_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(true)
                        .unwrap();
                },
                async {
                    let (_response, feedback_tx) = sub2_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(false)
                        .unwrap();
                }
            );

            assert!(!ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_ignores_dropped_subscriber_approval() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor.pending.insert(request, vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
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
    fn failed_then_deliver_clears_pending_and_allows_retry() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, _subscriber_rx) = test_subscriber();
            actor.pending.insert(request, vec![subscriber_tx]);
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
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let (stale_tx, stale_rx) = test_subscriber();
            drop(stale_rx);
            actor.pending.insert(request, vec![stale_tx]);

            let (fresh_tx, _fresh_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(mailbox::Message::GetOperations {
                request,
                response: fresh_tx,
            });

            assert!(matches!(action, MailboxAction::Fetch(ref key) if key == &request));
            let pending = actor.pending.get(&request).unwrap();
            assert_eq!(pending.len(), 1);
            assert!(!pending[0].is_closed());
        });
    }

    #[test]
    fn deliver_rejects_answer_shaped_unlike_its_question() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = Request::Boundary {
                size: Location::new(1),
                start: Location::new(0),
            };
            let (sub_tx, mut sub_rx) = test_subscriber();
            actor.pending.insert(request, vec![sub_tx]);

            // An operations-shaped answer to a boundary request decodes but does not match.
            let (feedback_tx, validity_rx) = oneshot::channel();
            actor
                .handle_deliver(request, encoded_fetch_payload(), feedback_tx)
                .await;

            assert!(!validity_rx.await.unwrap());
            assert!(actor.pending.contains_key(&request));
            assert!(sub_rx.try_recv().is_err());
        });
    }

    #[test]
    fn cancel_operations_cancels_pruned_request() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config());
            let request = test_request_at(Location::new(1));

            let action =
                actor.handle_mailbox_message(mailbox::Message::CancelOperations { request });

            assert!(matches!(action, MailboxAction::Cancel(ref key) if key == &request));
        });
    }
}

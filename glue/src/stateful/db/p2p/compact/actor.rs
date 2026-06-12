//! Actor for compact QMDB sync over P2P.

use super::{handler, mailbox, Mailbox};
use commonware_actor::mailbox as actor_mailbox;
use commonware_codec::{Codec, Decode as _, Encode};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{p2p, Resolver as _};
use commonware_runtime::{spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_storage::{
    merkle::{Family, Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT},
    qmdb::{self, sync::compact},
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::TracedAsyncRwLock,
};
use futures::future;
use rand::Rng;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::info;

type DbResolver<DB> = Arc<TracedAsyncRwLock<DB>>;
type DbOp<DB> = <DbResolver<DB> as compact::Resolver>::Op;
type Pending<F, Op, D> =
    oneshot::Sender<Result<compact::FetchResult<F, Op, D>, mailbox::ResponseDropped>>;
type PendingSubs<F, Op, D> = BTreeMap<handler::Request<F, D>, Vec<Pending<F, Op, D>>>;

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
    pub database: Option<DbResolver<DB>>,

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

    /// Send fetch requests with network priority.
    pub priority_requests: bool,

    /// Send responses with network priority.
    pub priority_responses: bool,
}

enum State<DB> {
    NoDb,
    HasDb(DbResolver<DB>),
}

enum MailboxAction<F: Family, D: commonware_cryptography::Digest> {
    None,
    Fetch(handler::Request<F, D>),
    Cancel(handler::Request<F, D>),
}

/// Runs a compact QMDB sync resolver service over P2P.
pub struct Actor<E, P, D, B, F, DB, H>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    H: Hasher,
    DbResolver<DB>: compact::Resolver<Family = F, Digest = H::Digest>,
    DbOp<DB>: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    context: ContextCell<E>,
    config: Config<P, D, B, DB>,
    mailbox_rx: actor_mailbox::Receiver<mailbox::Message<DB, F, DbOp<DB>, H::Digest>>,
    state: State<DB>,
    pending: PendingSubs<F, DbOp<DB>, H::Digest>,
}

impl<E, P, D, B, F, DB, H> Actor<E, P, D, B, F, DB, H>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    H: Hasher,
    DbResolver<DB>: compact::Resolver<Family = F, Digest = H::Digest>,
    DbOp<DB>: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    /// Create a new compact resolver actor and mailbox.
    pub fn new(context: E, mut config: Config<P, D, B, DB>) -> (Self, Mailbox<DB, F, DbOp<DB>, H>) {
        let state = config.database.take().map_or(State::NoDb, State::HasDb);
        let (mailbox_tx, mailbox_rx) =
            actor_mailbox::new(context.child("mailbox"), config.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config,
            mailbox_rx,
            state,
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

    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (handler_tx, mut handler_rx) =
            actor_mailbox::new(self.context.child("handler"), self.config.mailbox_size);
        let handler = handler::Handler::<F, H::Digest>::new(handler_tx);
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
                self.pending.retain(|_, subscribers| {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    !subscribers.is_empty()
                });
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

    fn handle_mailbox_message(
        &mut self,
        message: mailbox::Message<DB, F, DbOp<DB>, H::Digest>,
    ) -> MailboxAction<F, H::Digest> {
        match message {
            mailbox::Message::AttachDatabase(db) => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached compact resolver database");
                self.state = State::HasDb(db);
                MailboxAction::None
            }
            mailbox::Message::GetState { request, response } => {
                if let Some(subscribers) = self.pending.get_mut(&request) {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    if !subscribers.is_empty() {
                        subscribers.push(response);
                        return MailboxAction::None;
                    }
                }
                self.pending.insert(request.clone(), vec![response]);
                MailboxAction::Fetch(request)
            }
            mailbox::Message::CancelState { request } => {
                if self.should_cancel_request(&request) {
                    MailboxAction::Cancel(request)
                } else {
                    MailboxAction::None
                }
            }
        }
    }

    fn should_cancel_request(&mut self, request: &handler::Request<F, H::Digest>) -> bool {
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

    async fn handle_deliver(
        &mut self,
        key: handler::Request<F, H::Digest>,
        value: bytes::Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Some(subscribers) = self.pending.remove(&key) else {
            response.send_lossy(true);
            return;
        };

        let cfg = (
            (..=MAX_PINNED_NODES).into(),
            (),
            MAX_PROOF_DIGESTS_PER_ELEMENT,
        );
        let state = match compact::State::<F, DbOp<DB>, H::Digest>::decode_cfg(value, &cfg) {
            Ok(state) => state,
            Err(_) => {
                self.pending.insert(key, subscribers);
                response.send_lossy(false);
                return;
            }
        };

        if !Self::valid_state_response(&key, &state) {
            self.pending.insert(key, subscribers);
            response.send_lossy(false);
            return;
        }

        let mut approvals = Vec::new();
        for subscriber in subscribers {
            let (success_tx, success_rx) = oneshot::channel();
            if subscriber
                .send(Ok(compact::FetchResult {
                    state: state.clone(),
                    callback: Some(success_tx),
                }))
                .is_err()
            {
                continue;
            }
            approvals.push(success_rx);
        }

        if approvals.is_empty() {
            response.send_lossy(true);
            return;
        }

        let mut peer_valid = true;
        for approval in approvals {
            if let Ok(approved) = approval.await {
                peer_valid &= approved;
            }
        }
        response.send_lossy(peer_valid);
    }

    fn valid_state_response(
        key: &handler::Request<F, H::Digest>,
        state: &compact::State<F, DbOp<DB>, H::Digest>,
    ) -> bool {
        let target = key.to_target();
        if state.leaf_count != target.leaf_count || state.leaf_count == Location::new(0) {
            return false;
        }
        if state.pinned_nodes.len() != F::nodes_to_pin(state.leaf_count).count() {
            return false;
        }

        let hasher = qmdb::hasher::<H>();
        qmdb::verify_proof(
            &hasher,
            &state.last_commit_proof,
            Location::new(*state.leaf_count - 1),
            std::slice::from_ref(&state.last_commit_op),
            &target.root,
        )
    }

    async fn handle_produce(
        &mut self,
        key: handler::Request<F, H::Digest>,
        response: oneshot::Sender<bytes::Bytes>,
    ) {
        let State::HasDb(database) = &self.state else {
            return;
        };
        let Ok(fetch) = compact::Resolver::get_compact_state(database, key.to_target()).await
        else {
            return;
        };
        response.send_lossy(fetch.state.encode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, sha256, Sha256};
    use commonware_p2p::{Provider, TrackedPeers};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_storage::{
        merkle::Proof,
        mmr,
        qmdb::keyless::fixed::{self as keyless_fixed, Operation as KeylessOp},
    };
    use commonware_utils::{
        channel::{mpsc, oneshot},
        sequence::U64,
        sync::TracedAsyncRwLock,
        NZUsize,
    };
    use std::{sync::Arc, time::Duration};

    #[derive(Clone, Debug)]
    struct DummyProvider;

    impl Provider for DummyProvider {
        type PublicKey = ed25519::PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
            let (_tx, rx) = mpsc::unbounded_channel();
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

    type TestDb =
        keyless_fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type TestActor = Actor<
        deterministic::Context,
        ed25519::PublicKey,
        DummyProvider,
        DummyBlocker,
        mmr::Family,
        TestDb,
        Sha256,
    >;
    type TestOp = KeylessOp<mmr::Family, U64>;

    fn test_config(
        database: Option<Arc<TracedAsyncRwLock<TestDb>>>,
    ) -> Config<ed25519::PublicKey, DummyProvider, DummyBlocker, TestDb> {
        Config {
            peer_provider: DummyProvider,
            blocker: DummyBlocker,
            database,
            mailbox_size: NZUsize!(16),
            me: None,
            initial: Duration::from_millis(10),
            timeout: Duration::from_millis(10),
            fetch_retry_timeout: Duration::from_millis(10),
            priority_requests: false,
            priority_responses: false,
        }
    }

    async fn init_db(context: deterministic::Context) -> TestDb {
        let witness = commonware_storage::journal::contiguous::variable::Config {
            partition: "compact-p2p-test-witness".into(),
            items_per_section: commonware_utils::NZU64!(64),
            compression: None,
            codec_config: (),
            page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                &context,
                commonware_utils::NZU16!(1024),
                NZUsize!(64),
            ),
            write_buffer: NZUsize!(1024),
        };
        TestDb::init(
            context,
            keyless_fixed::CompactConfig {
                strategy: Sequential,
                witness,
                commit_codec_config: (),
            },
        )
        .await
        .expect("db init should succeed")
    }

    async fn compact_state(
        context: deterministic::Context,
    ) -> (
        compact::Target<mmr::Family, sha256::Digest>,
        compact::FetchResult<mmr::Family, TestOp, sha256::Digest>,
    ) {
        let mut db = init_db(context).await;
        db.apply_batch(db.new_batch().append(U64::new(7)).merkleize(
            &db,
            None,
            db.inactivity_floor_loc(),
        ))
        .unwrap();
        db.sync().await.unwrap();

        let target = db.target();
        let fetch = compact::Resolver::get_compact_state(
            &Arc::new(TracedAsyncRwLock::new("test", db)),
            target.clone(),
        )
        .await
        .expect("compact state should be available");
        (target, fetch)
    }

    #[test]
    fn invalid_proof_is_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let target = compact::Target {
                root: sha256::Digest::from([7; 32]),
                leaf_count: mmr::Location::new(1),
            };
            let request = handler::Request::from_target(target);
            let (pending_tx, _pending_rx) = oneshot::channel();
            actor.pending.insert(request.clone(), vec![pending_tx]);

            let bad_state = compact::State::<mmr::Family, TestOp, sha256::Digest> {
                leaf_count: mmr::Location::new(1),
                pinned_nodes: Vec::new(),
                last_commit_op: TestOp::Commit(None, mmr::Location::new(0)),
                last_commit_proof: Proof {
                    leaves: mmr::Location::new(1),
                    inactive_peaks: 0,
                    digests: Vec::new(),
                },
            };

            let (valid_tx, valid_rx) = oneshot::channel();
            actor
                .handle_deliver(request.clone(), bad_state.encode(), valid_tx)
                .await;

            assert!(!valid_rx.await.expect("validation response should arrive"));
            assert!(actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn invalid_pinned_node_count_is_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, mut fetch) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);
            let (pending_tx, _pending_rx) = oneshot::channel();
            actor.pending.insert(request.clone(), vec![pending_tx]);
            fetch.state.pinned_nodes.push(sha256::Digest::from([9; 32]));

            let (valid_tx, valid_rx) = oneshot::channel();
            actor
                .handle_deliver(request.clone(), fetch.state.encode(), valid_tx)
                .await;

            assert!(!valid_rx.await.expect("validation response should arrive"));
            assert!(actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn valid_state_after_invalid_proof_completes_request() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, fetch) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);
            let (subscriber_tx, subscriber_rx) = oneshot::channel();
            actor.pending.insert(request.clone(), vec![subscriber_tx]);

            let mut bad_state = fetch.state.clone();
            bad_state.last_commit_proof = Proof {
                leaves: bad_state.leaf_count,
                inactive_peaks: 0,
                digests: Vec::new(),
            };

            let (bad_tx, bad_rx) = oneshot::channel();
            actor
                .handle_deliver(request.clone(), bad_state.encode(), bad_tx)
                .await;
            assert!(!bad_rx.await.expect("invalid response should be rejected"));
            assert!(actor.pending.contains_key(&request));

            let (good_tx, good_rx) = oneshot::channel();
            futures::join!(
                async {
                    actor
                        .handle_deliver(request.clone(), fetch.state.encode(), good_tx)
                        .await;
                },
                async {
                    let fetch = subscriber_rx
                        .await
                        .expect("subscriber should receive valid state")
                        .expect("fetch should succeed");
                    fetch
                        .callback
                        .expect("compact deliveries should include feedback")
                        .send(true)
                        .unwrap();
                }
            );

            assert!(good_rx.await.expect("valid response should be accepted"));
            assert!(!actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn produce_serves_attached_database() {
        deterministic::Runner::default().start(|context| async move {
            let db = init_db(context.child("db")).await;
            let target = db.target();
            let db = Arc::new(TracedAsyncRwLock::new("test", db));
            let (mut actor, _mailbox) = TestActor::new(context, test_config(Some(db)));
            let request = handler::Request::from_target(target.clone());
            let (response_tx, response_rx) = oneshot::channel();

            actor.handle_produce(request, response_tx).await;

            let encoded = response_rx.await.expect("response should be served");
            let cfg = (
                (..=MAX_PINNED_NODES).into(),
                (),
                MAX_PROOF_DIGESTS_PER_ELEMENT,
            );
            let state =
                compact::State::<mmr::Family, TestOp, sha256::Digest>::decode_cfg(encoded, &cfg)
                    .expect("served state should decode");
            assert_eq!(state.leaf_count, target.leaf_count);
        });
    }

    #[test]
    fn downstream_rejection_marks_peer_invalid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, fetch) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);

            let (subscriber_tx, subscriber_rx) = oneshot::channel();
            actor.pending.insert(request.clone(), vec![subscriber_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                async {
                    actor
                        .handle_deliver(request, fetch.state.encode(), ack_tx)
                        .await;
                },
                async {
                    let fetch = subscriber_rx.await.unwrap().unwrap();
                    fetch
                        .callback
                        .expect("compact deliveries should include feedback")
                        .send(false)
                        .unwrap();
                }
            );

            assert!(!ack_rx.await.unwrap());
        });
    }

    #[test]
    fn dropped_downstream_feedback_does_not_mark_peer_invalid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, fetch) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);

            let (subscriber_tx, subscriber_rx) = oneshot::channel();
            actor.pending.insert(request.clone(), vec![subscriber_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                async {
                    actor
                        .handle_deliver(request, fetch.state.encode(), ack_tx)
                        .await;
                },
                async {
                    let fetch = subscriber_rx.await.unwrap().unwrap();
                    drop(fetch);
                }
            );

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn cancel_state_cancels_last_subscriber() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, _) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);

            let (subscriber_tx, subscriber_rx) = oneshot::channel();
            drop(subscriber_rx);
            actor.pending.insert(request.clone(), vec![subscriber_tx]);

            let action = actor.handle_mailbox_message(mailbox::Message::CancelState {
                request: request.clone(),
            });

            assert!(matches!(action, MailboxAction::Cancel(ref key) if key == &request));
            assert!(!actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn cancel_state_keeps_shared_request_alive() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (target, _) = compact_state(context.child("state")).await;
            let request = handler::Request::from_target(target);

            let (stale_tx, stale_rx) = oneshot::channel();
            drop(stale_rx);
            let (live_tx, _live_rx) = oneshot::channel();
            actor
                .pending
                .insert(request.clone(), vec![stale_tx, live_tx]);

            let action = actor.handle_mailbox_message(mailbox::Message::CancelState {
                request: request.clone(),
            });

            assert!(matches!(action, MailboxAction::None));
            let subscribers = actor
                .pending
                .get(&request)
                .expect("request should remain pending");
            assert_eq!(subscribers.len(), 1);
            assert!(!subscribers[0].is_closed());
        });
    }
}

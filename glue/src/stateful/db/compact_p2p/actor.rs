//! Actor for compact QMDB sync over P2P.

use super::{handler, mailbox, Mailbox};
use commonware_codec::{Codec, Decode as _, Encode};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{p2p, Resolver as _};
use commonware_runtime::{spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_storage::{
    merkle::{Family, Location, MAX_PROOF_DIGESTS_PER_ELEMENT},
    qmdb::{self, sync::compact},
};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc, oneshot},
    sync::AsyncRwLock,
};
use futures::future::{self, Either};
use rand::Rng;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tracing::info;

const MAX_PINNED_NODES: usize = 64;

type DbResolver<DB> = Arc<AsyncRwLock<DB>>;
type DbOp<DB> = <DbResolver<DB> as compact::Resolver>::Op;
type Pending<F, Op, D> =
    oneshot::Sender<Result<compact::State<F, Op, D>, mailbox::ResponseDropped>>;
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
    pub mailbox_size: usize,

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
    mailbox_rx: mpsc::Receiver<mailbox::Message<DB, F, DbOp<DB>, H::Digest>>,
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
        let (mailbox_tx, mailbox_rx) = mpsc::channel(config.mailbox_size);
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
        let (handler_tx, mut handler_rx) = mpsc::channel(self.config.mailbox_size);
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
                }
            },
            Some(message) = handler_rx.recv() else {
                return;
            } => {
                match message {
                    handler::EngineMessage::Deliver { key, value, response } => {
                        self.handle_deliver(key, value, response);
                    }
                    handler::EngineMessage::Produce { key, response } => {
                        self.handle_produce(key, response).await;
                    }
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
        }
    }

    fn handle_deliver(
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

        for subscriber in subscribers {
            let _ = subscriber.send(Ok(state.clone()));
        }
        response.send_lossy(true);
    }

    fn valid_state_response(
        key: &handler::Request<F, H::Digest>,
        state: &compact::State<F, DbOp<DB>, H::Digest>,
    ) -> bool {
        let target = key.to_target();
        if state.leaf_count != target.leaf_count || state.leaf_count == Location::new(0) {
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
        let Ok(state) = compact::Resolver::get_compact_state(database, key.to_target()).await
        else {
            return;
        };
        response.send_lossy(state.encode());
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
    use commonware_utils::{channel::oneshot, sequence::U64, sync::AsyncRwLock};
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

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    type TestDb = keyless_fixed::CompactDb<mmr::Family, deterministic::Context, U64, Sha256>;
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
            priority_requests: false,
            priority_responses: false,
        }
    }

    async fn init_db(context: deterministic::Context) -> TestDb {
        TestDb::init(
            context,
            keyless_fixed::CompactConfig {
                merkle: commonware_storage::merkle::compact::Config {
                    partition: "compact-p2p-test".into(),
                    strategy: Sequential,
                },
                commit_codec_config: (),
            },
        )
        .await
        .expect("db init should succeed")
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
            actor.handle_deliver(request.clone(), bad_state.encode(), valid_tx);

            assert!(!valid_rx.await.expect("validation response should arrive"));
            assert!(actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn produce_serves_attached_database() {
        deterministic::Runner::default().start(|context| async move {
            let db = init_db(context.child("db")).await;
            let target = db.current_target();
            let db = Arc::new(AsyncRwLock::new(db));
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
}

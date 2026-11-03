//! The ordered mode on a Multimmit committee.
//!
//! Every validator runs the engine with an [`Inline`] producer, the marshal, an executor whose
//! application is stateful's ordered mode, aggregation over the executed chain's checkpoints, and
//! a checkpoint probe. A validator that joins late state-syncs to a checkpoint its peers certified,
//! and resumes its marshal from a floor they serve, instead of executing the chain from genesis.
//!
//! [`a_late_validator_state_syncs_to_a_certified_checkpoint`] is the end-to-end state sync example.
//! Its documentation lists each step it shows.
//!
//! [`a_late_validator_resumes_state_sync_after_a_crash`] crashes the whole runtime while a late
//! validator state-syncs, restarts every validator on the storage the crash left, and checks that
//! the late validator resumes the sync toward the newest target it persisted.

use super::{
    checkpoint_recovery::{Archive, archive as checkpoint_archive},
    common::{PAGE_CACHE_SIZE, PAGE_SIZE},
    mocks::digested,
    ordered::{Stage, State, Tally, Worth, read_counter, until_applied},
    single_db_app::{Qmdb, qmdb_config},
};
use crate::{
    executor::{
        self, Checkpoints, Execute, Executor, Halt, StoreConfig, Update,
        probe::{self, Local, Probe},
    },
    stateful::{
        PruneConfig,
        db::{AttachableResolver, Shared, SyncEngineConfig, p2p as qmdb_resolver},
        ordered,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{
    Application, Epochable as _, Heightable as _,
    aggregation::{
        self,
        types::{Certificate, RecoveryKey},
    },
    ancestry::Ancestry,
    multimmit::{
        self, Planes, Running,
        checkpoint::Scheme as CheckpointScheme,
        config::Tuning,
        marshal::{
            self as marshal, ArchiveConfig, ArchiveMode, Inline, Retention, SchemeVerifier,
            ServiceHandle, Start,
        },
        mocks::{Committee, MockBody},
        types::{Context as Producing, TransactionBlock},
    },
    types::{Epoch, Height, Participant, ViewDelta},
};
use commonware_cryptography::{
    Digested, Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    certificate::Verifier as _, ed25519, sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::p2p as resolver;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Quota, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
    telemetry::metrics::metric_sum,
};
use commonware_storage::{
    mmr,
    qmdb::{
        any::operation::Operation as QmdbOperation,
        sync::{Feedback, Request, Response, Source, source},
    },
    translator::TwoCap,
};
use commonware_utils::{
    NZDuration, NZU32, NZU64, NZUsize,
    acknowledgement::Exact,
    channel::{mpsc, oneshot, ring},
    probability,
    sync::Mutex,
};
use std::{
    collections::HashMap,
    future,
    num::{NonZeroU64, NonZeroUsize},
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_MULTIMMIT_TEST";
const CHECKPOINT_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_ORDERED_MULTIMMIT_TEST_CHECKPOINTS";
const VALIDATORS: u32 = 6;
const QUOTA: Quota = Quota::per_second(NZU32!(1_024));
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Blocks per checkpoint.
const INTERVAL: NonZeroU64 = NZU64!(8);

/// Inputs marshal delivers before one is acknowledged.
const ACK_WINDOW: NonZeroUsize = NZUsize!(16);

const DATA: u64 = 0;
const CONSENSUS: u64 = 1;
const CERTIFICATES: u64 = 2;
const ENGINE_RESOLVER: u64 = 3;
const MARSHAL_RESOLVER: u64 = 4;
const MARSHAL_BROADCAST: u64 = 5;
const AGGREGATION: u64 = 6;
const PROBE: u64 = 7;
const CHECKPOINT_RESOLVER: u64 = 9;
const QMDB: u64 = 8;

type Input = TransactionBlock<Sha256, MockBody>;
type Marshal = marshal::Mailbox<Sha256, MinPk, MockBody>;
type Scheme = CheckpointScheme<ed25519::PublicKey, MinPk>;
type Chain = executor::Mailbox<State>;
type StatefulMailbox = ordered::Mailbox<deterministic::Context, Tally<Input>, Sequential>;
type Resolver = qmdb_resolver::Mailbox<Qmdb<deterministic::Context>, mmr::Family, Op, Digest>;
type Op = <Qmdb<deterministic::Context> as Source>::Op;
type SyncResponse = Response<mmr::Family, Op, Digest>;

/// Returns the epoch and the inclusive position range of the executed chain's checkpoints.
fn checkpoint_scope(committee: &Committee<MinPk>) -> (Epoch, Height, Height) {
    (
        committee.config.epoch(),
        Height::zero(),
        Height::new(u64::MAX / INTERVAL.get() - 1),
    )
}

/// What the sync engine did with a request whose response was corrupted.
#[derive(Clone, Debug)]
struct Judged {
    /// The request the corrupted response answered.
    request: Request<mmr::Family>,
    /// The sync engine's verdict on each response to the request, the corrupted one first.
    verdicts: Vec<bool>,
    /// Once the sync engine accepts a response to the request, whether that response encodes
    /// exactly as the honest response did before it was corrupted.
    accepted_original: Option<bool>,
    /// Set if the sync engine abandoned the request before accepting a response to it, as it may
    /// when it moves to a newer target.
    abandoned: bool,
}

/// Corrupts state sync responses, one request at a time, and records what the sync engine did
/// with each corrupted request.
#[derive(Clone)]
struct Corruption {
    /// Set while the next response that updates a key should be corrupted.
    armed: Arc<AtomicBool>,
    /// Every corrupted request, in the order it was corrupted.
    judged: Arc<Mutex<Vec<Judged>>>,
}

impl Corruption {
    fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(true)),
            judged: Arc::default(),
        }
    }

    /// Records the sync engine's verdict on the corrupted response to `request`, and on every
    /// later response the resolver fetches for the same request, and passes each verdict to the
    /// resolver's `feedback`. `original` is the encoding of the response before it was corrupted.
    ///
    /// If the engine abandons the request before accepting a response to it, the next response
    /// that updates a key is corrupted instead.
    fn judge(
        &self,
        context: deterministic::Context,
        request: Request<mmr::Family>,
        original: Vec<u8>,
        feedback: Feedback<SyncResponse>,
    ) -> Feedback<SyncResponse> {
        let (verdict, mut judged) = oneshot::channel();
        let (candidates, next) = mpsc::channel(1);
        let corruption = self.clone();
        let index = {
            let mut all = self.judged.lock();
            all.push(Judged {
                request,
                verdicts: Vec::new(),
                accepted_original: None,
                abandoned: false,
            });
            all.len() - 1
        };
        context.spawn(move |_| async move {
            let mut feedback = feedback;
            // The encoding of the response being judged, or `None` for the corrupted one.
            let mut candidate: Option<Vec<u8>> = None;
            loop {
                let Ok(valid) = judged.await else {
                    corruption.abandon(index);
                    return;
                };
                corruption.judged.lock()[index].verdicts.push(valid);
                if valid {
                    let matches = candidate.as_ref() == Some(&original);
                    corruption.judged.lock()[index].accepted_original = Some(matches);
                    feedback.accept();
                    return;
                }
                let Some((response, next_feedback)) = feedback.reject().await else {
                    corruption.abandon(index);
                    return;
                };
                candidate = Some(response.encode().to_vec());
                let (verdict, next_judged) = oneshot::channel();
                if candidates.send((response, verdict)).await.is_err() {
                    corruption.abandon(index);
                    return;
                }
                feedback = next_feedback;
                judged = next_judged;
            }
        });
        Feedback::new(verdict, next)
    }

    /// Records that the engine abandoned the corrupted request at `index`, and corrupts the next
    /// response that updates a key.
    fn abandon(&self, index: usize) {
        self.judged.lock()[index].abandoned = true;
        self.armed.store(true, Ordering::SeqCst);
    }
}

/// Where a joining validator's process is cut while it state-syncs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    /// After the sync engines received one response and the executor persisted a target above
    /// its first, with every later response withheld so that the sync cannot complete.
    MidSync,
    /// After the application returned the block its state reached, which the executor has not
    /// installed as its base, and the executor persisted a target above that block.
    Synced,
}

/// Observes the state sync a joining validator's executor runs, and may hold it at a [`Cut`].
#[derive(Clone)]
struct SyncWatch {
    cut: Option<Cut>,
    /// Heights of the targets the executor offered the sync: the first target, then each update.
    offered: Arc<Mutex<Vec<u64>>>,
    /// Requests admitted for serving. Only [`Cut::MidSync`] limits it, to one.
    admitted: Arc<AtomicUsize>,
    /// Responses the resolver returned to the sync engines.
    received: Arc<AtomicUsize>,
    /// The block the application's state reached.
    reached: Arc<Mutex<Option<Digested<State>>>>,
    /// Set once the cut is reached.
    at_cut: Arc<AtomicBool>,
}

impl SyncWatch {
    fn new(cut: Option<Cut>) -> Self {
        Self {
            cut,
            offered: Arc::default(),
            admitted: Arc::default(),
            received: Arc::default(),
            reached: Arc::default(),
            at_cut: Arc::default(),
        }
    }

    /// Admits a request for serving, or returns `None` if [`Cut::MidSync`] withholds it.
    fn admit(&self) -> Option<Admission> {
        if self.cut != Some(Cut::MidSync) {
            return Some(Admission(None));
        }
        self.admitted
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Admission(Some(Arc::clone(&self.admitted))))
    }

    /// Records that the resolver returned a response to an admitted request.
    fn served(&self, admission: Admission) {
        admission.keep();
        self.received.fetch_add(1, Ordering::SeqCst);
        self.check_mid_sync();
    }

    /// Records that the executor offered the sync a target at `height`. The executor persists
    /// every target before it offers it.
    fn offer(&self, height: u64) {
        self.offered.lock().push(height);
        self.check_mid_sync();
    }

    fn check_mid_sync(&self) {
        if self.cut == Some(Cut::MidSync)
            && self.received.load(Ordering::SeqCst) > 0
            && self.offered.lock().len() > 1
        {
            self.at_cut.store(true, Ordering::SeqCst);
        }
    }

    /// Returns whether the cut was reached.
    fn cut_reached(&self) -> bool {
        self.at_cut.load(Ordering::SeqCst)
    }
}

/// A request admitted for serving. Unless the resolver returns a response to it, dropping it
/// releases the admission, so a failed or cancelled request does not hold it.
struct Admission(Option<Arc<AtomicUsize>>);

impl Admission {
    /// Keeps the admission taken, so no later request is admitted.
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(admitted) = self.0.take() {
            admitted.store(0, Ordering::SeqCst);
        }
    }
}

/// The executor's application for every validator: the ordered mode, with its state sync
/// observed by a [`SyncWatch`]. Every call passes through to the ordered mode, and only a watch
/// with a [`Cut`] changes what the executor sees.
#[derive(Clone)]
struct Watched {
    inner: StatefulMailbox,
    watch: SyncWatch,
}

impl Execute<deterministic::Context> for Watched {
    type Input = Input;
    type Block = State;

    async fn genesis(&mut self) -> State {
        self.inner.genesis().await
    }

    fn resume(&mut self, tip: Digested<State>) {
        self.inner.resume(tip);
    }

    fn certified(&mut self, block: Digested<State>) {
        self.inner.certified(block);
    }

    /// Passes the first target and every update to the ordered mode, recording their heights,
    /// then records the block the ordered mode reached.
    ///
    /// At [`Cut::Synced`], the reached block is never returned: the executor never installs it
    /// as its base. The cut is reached once the executor has offered, and so persisted, a target
    /// above that block.
    async fn sync(
        &mut self,
        target: Digested<State>,
        updates: ring::Receiver<Update<State>>,
    ) -> Digested<State> {
        let watch = self.watch.clone();
        watch.offer(target.height().get());
        let (forward, forwarded) = ring::channel(NZUsize!(1));
        let mut updates = Some(updates);
        let reached = {
            let mut sync = pin!(self.inner.sync(target, forwarded));
            loop {
                let reached = select! {
                    reached = &mut sync => Some(reached),
                    update = next_offer(&mut updates) => {
                        match update {
                            Some(update) => {
                                watch.offer(update.block.height().get());
                                forward.send_lossy(update);
                            }
                            None => updates = None,
                        }
                        None
                    },
                };
                if let Some(reached) = reached {
                    break reached;
                }
            }
        };
        *watch.reached.lock() = Some(reached.clone());
        if watch.cut != Some(Cut::Synced) {
            return reached;
        }
        let height = reached.height().get();
        let mut above = watch.offered.lock().iter().any(|&h| h > height);
        while !above {
            let Some(update) = next_offer(&mut updates).await else {
                break;
            };
            let offered = update.block.height().get();
            watch.offer(offered);
            above = offered > height;
        }
        if above {
            watch.at_cut.store(true, Ordering::SeqCst);
        }
        future::pending().await
    }

    async fn execute(
        self,
        context: (deterministic::Context, executor::Context<Digest>),
        ancestry: impl Ancestry<State>,
        input: Digested<Input>,
    ) -> Digested<State> {
        self.inner.execute(context, ancestry, input).await
    }

    async fn prepare(self, context: deterministic::Context, input: Digested<Input>) {
        self.inner.prepare(context, input).await
    }
}

/// Waits for the next target the executor offers, if it still offers any.
async fn next_offer(updates: &mut Option<ring::Receiver<Update<State>>>) -> Option<Update<State>> {
    match updates {
        Some(updates) => updates.recv().await,
        None => future::pending().await,
    }
}

/// The QMDB resolver of a validator, which may corrupt responses it fetched from a peer, and may
/// withhold responses at a [`Cut`].
///
/// The corruption happens after an honest peer's response arrives, so it stands in for a peer
/// that served a wrong response; no peer here encodes one. A corrupted response sets a different
/// value for a key it updates. It is still well formed and matches its request, so only its proof
/// against the state root of the certified block can show that it is wrong. Once the sync engine
/// rejects it, the resolver blocks the peer that served it and fetches the same request from
/// another peer.
#[derive(Clone)]
struct Snapshots {
    context: Arc<deterministic::Context>,
    resolver: Resolver,
    corruption: Option<Corruption>,
    watch: Option<SyncWatch>,
}

impl Source for Snapshots {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Op;
    type Error = <Resolver as Source>::Error;

    async fn serve(&self, request: Request<mmr::Family>) -> source::Result<Self> {
        let admission = match &self.watch {
            Some(watch) => match watch.admit() {
                Some(admission) => Some(admission),
                // The cut withholds every later response, so the sync cannot complete.
                None => return future::pending().await,
            },
            None => None,
        };
        let (mut response, feedback) = self.resolver.serve(request).await?;
        if let (Some(watch), Some(admission)) = (&self.watch, admission) {
            watch.served(admission);
        }
        let Some(corruption) = &self.corruption else {
            return Ok((response, feedback));
        };
        let Some(feedback) = feedback else {
            return Ok((response, None));
        };
        if !corruption.armed.load(Ordering::SeqCst) {
            return Ok((response, Some(feedback)));
        }
        let original = response.encode().to_vec();
        if !corrupt(&mut response) {
            return Ok((response, Some(feedback)));
        }
        corruption.armed.store(false, Ordering::SeqCst);
        let feedback = corruption.judge(self.context.child("verdict"), request, original, feedback);
        Ok((response, Some(feedback)))
    }
}

/// Changes the value of the first update in `response`, and returns whether there was one.
fn corrupt(response: &mut SyncResponse) -> bool {
    let mut ops: Vec<&mut Op> = match response {
        Response::Operations { operations, .. } => operations.iter_mut().collect(),
        Response::Boundary { op, .. } => vec![op],
    };
    let Some(update) = ops.iter_mut().find_map(|op| match op {
        QmdbOperation::Update(update) => Some(update),
        _ => None,
    }) else {
        return false;
    };
    update.1 = Sha256::hash(&[b"corrupted", update.1.as_ref()]);
    true
}

impl AttachableResolver<Qmdb<deterministic::Context>> for Snapshots {
    async fn attach_database(&self, db: Shared<Qmdb<deterministic::Context>>) {
        self.resolver.attach_database(db);
    }
}

/// Builds each producer block with a body worth its chain and height.
#[derive(Clone)]
struct Producer;

impl Application<deterministic::Context> for Producer {
    type Context = Producing<Digest>;
    type Block = Input;
    type Input = ();

    async fn propose(
        &mut self,
        (_, context): (deterministic::Context, Self::Context),
        _: impl Ancestry<Input>,
        _: (),
    ) -> Option<Digested<Input>> {
        let value = u64::from(context.chain().get()) * 1_000 + context.height().get();
        Some(digested(TransactionBlock::from_context(
            context,
            MockBody(value),
        )))
    }

    async fn verify(
        &mut self,
        _: (deterministic::Context, Self::Context),
        _: impl Ancestry<Input>,
    ) -> bool {
        true
    }
}

impl Worth for Input {
    fn worth(&self) -> u64 {
        self.body().0
    }
}

/// Asserts that every prepared input `tally` executed was prepared before it executed, and that
/// nearly every executed input was prepared.
///
/// Marshal reports inputs final before it orders them, so the executor prepares them well ahead.
/// Preparing only the inputs delivered behind others that have not executed leaves many more
/// unprepared.
fn assert_prepared_ahead(tally: &Tally<Input>) {
    let mut first: HashMap<(Stage, Digest), usize> = HashMap::new();
    for (position, entry) in tally.stages.lock().iter().enumerate() {
        first.entry(*entry).or_insert(position);
    }
    let (mut executed, mut ahead) = (0, 0);
    for (&(stage, digest), &position) in &first {
        if stage != Stage::Executed {
            continue;
        }
        executed += 1;
        if let Some(&prepared) = first.get(&(Stage::Prepared, digest)) {
            assert!(
                prepared < position,
                "an input executed before it was prepared"
            );
            ahead += 1;
        }
    }
    assert!(
        ahead * 10 >= executed * 9,
        "only {ahead} of {executed} executed inputs were prepared"
    );
}

/// A running validator.
struct Validator {
    chain: Chain,
    marshal: Marshal,
    stateful: StatefulMailbox,
    checkpoints: Checkpoints<Scheme, State>,
    archive: Archive,
    tally: Tally<Input>,
    _engine: Running<Digest>,
    _marshal: ServiceHandle,
    _handles: Vec<Handle<()>>,
    _recovery: aggregation::Recovery,
    _executor: Handle<Result<(), Halt>>,
}

impl Validator {
    /// Returns the applied counter.
    async fn counter(&self) -> u64 {
        let databases = self
            .stateful
            .subscribe_databases()
            .await
            .expect("stateful is running");
        read_counter(&databases).await
    }
}

/// A Multimmit committee on a simulated network.
struct Cluster {
    context: deterministic::Context,
    committee: Committee<MinPk>,
    oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
}

impl Cluster {
    async fn new(context: deterministic::Context) -> Self {
        let committee = Committee::<MinPk>::builder(7, VALIDATORS)
            .namespace(NAMESPACE)
            .build();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 8 * 1024 * 1024,
                max_peers_per_set: NZUsize!(committee.identities.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            committee.identities.clone(),
        )
        .await;
        network.start();
        for a in &committee.identities {
            for b in &committee.identities {
                if a != b {
                    oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
                }
            }
        }
        Self {
            context,
            committee,
            oracle,
        }
    }

    /// Starts validator `index`. A joining validator starts its executor from the newest
    /// checkpoint its peers certified, and its marshal from a floor they serve. With a
    /// `corruption`, the validator corrupts state sync responses it fetches. With a `watch`, the
    /// executor's state sync is observed, and may be held at a cut.
    async fn start(
        &self,
        index: usize,
        joining: bool,
        corruption: Option<Corruption>,
        watch: Option<SyncWatch>,
    ) -> Validator {
        let context = self
            .context
            .child("validator")
            .with_attribute("index", index);
        let identity = self.committee.identities[index].clone();
        let control = self.oracle.control(identity.clone());
        let mut channels = Vec::new();
        for channel in [
            DATA,
            CONSENSUS,
            CERTIFICATES,
            ENGINE_RESOLVER,
            MARSHAL_RESOLVER,
            MARSHAL_BROADCAST,
            AGGREGATION,
            PROBE,
            QMDB,
            CHECKPOINT_RESOLVER,
        ] {
            channels.push(Some(control.register(channel, QUOTA).await.unwrap()));
        }
        let mut channel = |id: u64| channels[id as usize].take().unwrap();
        let prefix = format!("validator_{index}");
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut handles = Vec::new();

        // Marshal disseminates, stores, and orders producer blocks.
        let (broadcast, buffer) = buffered::Engine::new(
            context.child("body_broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(256),
                deque_size: 256,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        handles.push(broadcast.start(channel(MARSHAL_BROADCAST)));
        let mut archive =
            ArchiveConfig::new(TwoCap, CacheRef::new(paged::page_size(4_096), NZUsize!(16)));
        archive.items_per_section = NZU64!(16);
        let config = marshal::Config::new(
            Start::Genesis(self.committee.config.genesis().clone()),
            prefix.clone(),
            self.committee.codec(),
            (),
            archive,
        )
        .with_max_pending_acks(ACK_WINDOW)
        .with_retention(Retention::uniform(ArchiveMode::Prunable));
        let (mut service, bridge) = marshal::open(context.child("marshal"), config, buffer)
            .await
            .expect("marshal opens");
        let (resolver_engine, resolver) = resolver::Engine::new(
            context.child("marshal_resolver"),
            resolver::Config {
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                consumer: bridge.clone(),
                producer: bridge,
                mailbox_size: NZUsize!(256),
                me: Some(identity.clone()),
                fetch_timeout: NZDuration!(Duration::from_secs(2)),
                fetch_retry_delay: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        handles.push(resolver_engine.start(channel(MARSHAL_RESOLVER)));
        let relay = service.relay(
            self.committee
                .config
                .producer_chain(Participant::from_usize(index)),
        );

        // The ordered mode is both the executor's application and its consumer.
        let (qmdb_resolver, resolvers): (_, Resolver) =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, mmr::Family, Qmdb<_>>::new(
                context.child("qmdb_resolver"),
                qmdb_resolver::Config {
                    peer_provider: self.oracle.manager(),
                    blocker: control.clone(),
                    database: None,
                    mailbox_size: NZUsize!(256),
                    me: Some(identity.clone()),
                    fetch_timeout: NZDuration!(Duration::from_secs(2)),
                    fetch_retry_delay: Duration::from_millis(100),
                    max_serve_ops: NZU64!(64),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        handles.push(qmdb_resolver.start(channel(QMDB)));
        let resolvers = Snapshots {
            context: Arc::new(context.child("snapshots")),
            resolver: resolvers,
            corruption,
            watch: watch.clone(),
        };
        let tally = Tally::default();
        let (stateful, stateful_mailbox) = ordered::Stateful::init(
            context.child("stateful"),
            ordered::Config {
                application: tally.clone(),
                db_config: qmdb_config(&prefix, page_cache.clone()),
                resolvers,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: NZUsize!(4),
                },
                mailbox_size: NZUsize!(256),
                // Multimmit finalizes several blocks a view, so peers must retain a checkpoint's
                // state for longer than a joining validator waits between sampled targets.
                prune_config: Some(PruneConfig {
                    maintenance_interval: NZUsize!(4),
                    retained_marshal_blocks: 64,
                    retained_qmdb_blocks: 64,
                }),
                strategy: Sequential,
            },
        );
        let (executor, inbox, chain) =
            Executor::<_, _, Marshal, _, TwoCap, Exact, Sequential>::init(
                context.child("executor"),
                executor::Config {
                    execute: Watched {
                        inner: stateful_mailbox.clone(),
                        watch: watch.unwrap_or_else(|| SyncWatch::new(None)),
                    },
                    consumer: stateful_mailbox.clone(),
                    ack_window: ACK_WINDOW,
                    start: if joining {
                        executor::Start::Checkpoint
                    } else {
                        executor::Start::Genesis
                    },
                    store: StoreConfig {
                        partition_prefix: prefix.clone(),
                        translator: TwoCap,
                        page_cache: page_cache.clone(),
                        items_per_section: NZU64!(16),
                        write_buffer: NZUsize!(4_096),
                        replay_buffer: NZUsize!(4_096),
                        codec_config: (),
                    },
                    mailbox_size: NZUsize!(256),
                    strategy: Sequential,
                },
            )
            .await;
        let verifier = SchemeVerifier::new(
            context.child("marshal_verifier"),
            self.committee.verifier.clone(),
            Sequential,
        );
        let (marshal, marshal_handle) = service.start(resolver, verifier, inbox);

        // Aggregation certifies the executed chain's checkpoints with the committee's
        // nullification key.
        let scheme = self.committee.signers[index].checkpoint(CHECKPOINT_NAMESPACE);
        let checkpoint_scope = checkpoint_scope(&self.committee);
        let checkpoints = Checkpoints::<Scheme, State>::new(chain.clone(), INTERVAL);
        let (reporter, archive, writer) = checkpoint_archive(
            context.child("checkpoint_archive"),
            format!("{prefix}_checkpoint_archive"),
            page_cache.clone(),
            &scheme,
            checkpoint_scope,
            checkpoints.clone(),
        )
        .await;
        handles.push(writer);
        let (coordinator, recovery, consumer) = aggregation::RecoveryCoordinator::new(
            context.child("checkpoint_recovery"),
            NZUsize!(8),
            NZUsize!(16),
        );
        let (recovery_resolver, resolver_mailbox) = resolver::Engine::new(
            context.child("checkpoint_resolver"),
            resolver::Config {
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                consumer,
                producer: archive.clone(),
                mailbox_size: NZUsize!(256),
                me: Some(identity.clone()),
                fetch_timeout: NZDuration!(Duration::from_secs(2)),
                fetch_retry_delay: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        handles.push(coordinator.start(resolver_mailbox));
        let aggregation = aggregation::Engine::new(
            context.child("aggregation"),
            aggregation::Config {
                epoch: checkpoint_scope.0,
                first: checkpoint_scope.1,
                last: checkpoint_scope.2,
                scheme: scheme.clone(),
                automaton: checkpoints.clone(),
                reporter,
                blocker: control.clone(),
                priority_acks: false,
                rebroadcast_timeout: NZDuration!(Duration::from_millis(500)),
                recovery_after_rebroadcasts: NZU64!(2),
                recoverer: recovery.clone(),
                window: NZU64!(8),
                journal_partition: format!("{prefix}_aggregation"),
                journal_write_buffer: NZUsize!(4_096),
                journal_replay_buffer: NZUsize!(4_096),
                journal_heights_per_section: NZU64!(8),
                journal_compression: None,
                journal_page_cache: page_cache.clone(),
                strategy: Sequential,
            },
        )
        .expect("checkpoint scope is not registered");
        handles.push(recovery_resolver.start(channel(CHECKPOINT_RESOLVER)));
        let aggregation = aggregation.start(channel(AGGREGATION));
        handles.push(
            context
                .child("aggregation_result")
                .spawn(move |_| async move {
                    aggregation.await.expect("aggregation runs");
                }),
        );

        // Every validator serves its newest checkpoint; a joining one also samples its peers'.
        let (probe, sampler) = Probe::new(probe::Config {
            context: context.child("probe"),
            epoch: checkpoint_scope.0,
            first: checkpoint_scope.1,
            last: checkpoint_scope.2,
            scheme,
            strategy: Sequential,
            blocker: control.clone(),
            block_codec: (),
            floor_codec: self.committee.codec(),
            retry_timeout: NZDuration!(Duration::from_millis(500)),
            max_response_size: NZUsize!(1024 * 1024),
            mailbox_size: NZUsize!(16),
        });
        handles.push(probe.start(
            channel(PROBE),
            Local {
                checkpoints: checkpoints.clone(),
                marshal: marshal.clone(),
            },
        ));

        // The engine orders the blocks the inline producer builds.
        let engine = multimmit::Engine::open(
            context.child("engine"),
            multimmit::Config::<Sha256, _, _, _, _, _, _, _, _> {
                scheme: self.committee.signers[index].clone(),
                genesis: self.committee.config.genesis().clone(),
                tuning: Tuning {
                    production_interval: Duration::from_millis(100),
                    view_retention: ViewDelta::new(16),
                    ..Tuning::new(Duration::from_millis(500))
                },
                automaton: Inline::new(context.child("producer"), Producer, marshal.clone()),
                relay,
                reporter: marshal.clone(),
                strategy: Sequential,
                critical_strategy: Sequential,
                blocker: control,
                partition_prefix: prefix,
                page_cache: CacheRef::new(paged::page_size(4_096), NZUsize!(8)),
                mailbox_size: NZUsize!(256),
            },
        )
        .await
        .expect("engine opens");
        let mut engine = engine.start(Planes {
            data: channel(DATA),
            consensus: channel(CONSENSUS),
            certificates: channel(CERTIFICATES),
            resolver: channel(ENGINE_RESOLVER),
        });

        let executor = executor.start(marshal.clone());
        handles.push(stateful.start(chain.clone()));
        if joining {
            handles.push(context.child("join").spawn({
                let (marshal, chain) = (marshal.clone(), chain.clone());
                move |context| {
                    probe::join(
                        context,
                        sampler,
                        marshal,
                        chain,
                        NZDuration!(Duration::from_millis(500)),
                    )
                }
            }));
        }
        engine.ready().await.expect("engine becomes ready");
        Validator {
            chain,
            marshal,
            stateful: stateful_mailbox,
            checkpoints,
            archive,
            tally,
            _engine: engine,
            _marshal: marshal_handle,
            _handles: handles,
            _recovery: recovery,
            _executor: executor,
        }
    }
}

#[test]
fn validators_execute_certify_and_prune_one_chain() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..VALIDATORS as usize {
            validators.push(committee.start(index, false, None, None).await);
        }
        // The run is long enough for pruning to reach blocks the engine still verifies: pruning
        // those would stall the chain.
        until_applied(&context, validators.iter().map(|v| &v.tally), 300).await;

        // Every validator executed the same chain, and certified checkpoints of it.
        let reference = validators[0]
            .chain
            .block_at(Height::new(300))
            .await
            .unwrap();
        for validator in &validators {
            let block = validator.chain.block_at(Height::new(300)).await.unwrap();
            assert_eq!(block, reference);
            let latest = validator
                .checkpoints
                .latest()
                .expect("a checkpoint is certified");
            let height = validator.checkpoints.height(latest.item.position).unwrap();
            if let Some(block) = validator.chain.block_at(height).await {
                assert_eq!(block.digest(), latest.item.digest);
            }
        }
        assert!(validators[0].counter().await > 0);

        // Each validator prepared inputs ahead of executing them.
        for validator in &validators {
            assert_prepared_ahead(&validator.tally);
        }

        // Pruning reclaimed the first executed block and, once the engine released it, the first
        // input's body, so retention stays bounded.
        for validator in &validators {
            assert!(validator.chain.block_at(Height::new(1)).await.is_none());
            let first = validator
                .tally
                .first
                .lock()
                .clone()
                .expect("an input is executed");
            let block = validator
                .marshal
                .get_block(first.reference())
                .await
                .unwrap();
            assert!(block.is_none(), "marshal retains the first input");
        }
    });
}

/// A late validator state-syncs to a recent certified checkpoint and resumes executing the chain.
///
/// This is the end-to-end state sync example of the executor stack. Run it with:
///
/// ```text
/// just test -p commonware-glue ordered_multimmit::a_late_validator_state_syncs_to_a_certified_checkpoint
/// ```
///
/// 1. Five of six validators order inputs with Multimmit and execute them into a chain of
///    blocks. Each block commits to its height, its parent, its input, and the state root after
///    the input. Aggregation certifies the digest of every [`INTERVAL`]-th block with the
///    committee's nullification key, so a certificate binds a position in the chain to a state.
/// 2. The sixth validator starts late, after its peers pruned the first input. Its probe samples
///    the peers and accepts a checkpoint only if the certificate verifies under the committee's
///    checkpoint key and scope, and the block it names is the one the certificate certifies.
/// 3. The executor offers that block to the application, which fetches the state the block
///    commits to from the peers. A fetched response is corrupted after it arrives. The sync
///    engine checks it against the certified state root and rejects it, the resolver blocks the
///    peer that served it, and another peer's response to the same request, which encodes as the
///    response did before it was corrupted, is accepted. State sync then completes.
/// 4. The late validator holds the chain only from the checkpoint it synced to, which is not the
///    first checkpoint. Its application hook receives no block at or below that checkpoint.
/// 5. It then executes the inputs after the checkpoint and produces the same blocks, and so the
///    same state roots, as the validators that executed the chain from genesis.
/// 6. Its aggregation engine recovers every checkpoint certificate through the sync base from its
///    peers, then signs new checkpoints.
#[test]
fn a_late_validator_state_syncs_to_a_certified_checkpoint() {
    deterministic::Runner::timed(Duration::from_secs(180)).start(|mut context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..VALIDATORS as usize - 1 {
            validators.push(committee.start(index, false, None, None).await);
        }
        until_applied(&context, validators.iter().map(|v| &v.tally), 48).await;

        // Peers pruned the first input, so the late validator must resume marshal from a floor.
        for validator in &validators {
            let first = validator
                .tally
                .first
                .lock()
                .clone()
                .expect("an input is executed");
            while validator
                .marshal
                .get_block(first.reference())
                .await
                .unwrap()
                .is_some()
            {
                context.sleep(Duration::from_millis(50)).await;
            }
        }

        // The late validator holds the chain only from the checkpoint it synced to. Blocks after
        // it that change no state skip the application's hook, so the first applied block may be
        // later.
        let corruption = Corruption::new();
        let late = committee
            .start(
                VALIDATORS as usize - 1,
                true,
                Some(corruption.clone()),
                None,
            )
            .await;
        until_applied(&context, [&late.tally], 1).await;
        let first = late.tally.applied.lock()[0];
        let base = first / INTERVAL.get() * INTERVAL.get() - 1;
        // Read the base block now. Once the late validator executes past it and certifies newer
        // checkpoints, pruning may remove it from the executed chain.
        let base_block = late.chain.block_at(Height::new(base)).await;
        assert!(
            base > INTERVAL.get()
                && base_block.is_some()
                && late.chain.block_at(Height::new(base - 1)).await.is_none(),
            "the late validator applied height {first}, not after a checkpoint"
        );
        let base_block = base_block.unwrap();

        // The application hook received no block at or below the checkpoint.
        assert!(
            late.tally
                .applied
                .lock()
                .iter()
                .all(|&height| height > base)
        );

        // The sync engine rejected every corrupted response it judged. For at least one corrupted
        // request, it then accepted a response that the resolver fetched for the same request,
        // and that response encodes exactly as the honest response did before it was corrupted.
        // Any other corrupted request was abandoned, as when the sync moves to a newer target,
        // and a later response was corrupted in its place.
        let judged = corruption.judged.lock().clone();
        assert!(!judged.is_empty(), "no state sync response was corrupted");
        for request in &judged {
            assert_ne!(
                request.verdicts.first(),
                Some(&true),
                "the sync engine accepted a corrupted response to {}",
                request.request
            );
        }
        let replaced: Vec<_> = judged
            .iter()
            .filter(|request| request.accepted_original.is_some())
            .collect();
        assert!(
            !replaced.is_empty(),
            "no corrupted request was answered again: {judged:?}"
        );
        for request in replaced {
            assert!(!request.abandoned);
            assert_eq!(request.verdicts.first(), Some(&false));
            assert_eq!(request.verdicts.last(), Some(&true));
            assert_eq!(
                request.accepted_original,
                Some(true),
                "the response accepted for {} differs from the honest one",
                request.request
            );
        }

        // The late validator blocked at least one peer.
        let identity = &committee.committee.identities[VALIDATORS as usize - 1];
        let blocked = committee.oracle.blocked().await.unwrap();
        assert!(
            blocked.iter().any(|(blocker, _)| blocker == identity),
            "the late validator blocked no peer"
        );

        // It then follows the chain the validators execute. Equal blocks commit to equal state
        // roots, so the state it synced and the state it then executed match its peers'.
        let target = validators[0].tally.applied() + 16;
        until_applied(&context, [&late.tally, &validators[0].tally], target).await;
        let reference = validators[0]
            .chain
            .block_at(Height::new(target))
            .await
            .unwrap();
        assert_eq!(
            late.chain.block_at(Height::new(target)).await.unwrap(),
            reference
        );
        let sync_base = base;
        loop {
            if let Some(certificate) = late.checkpoints.latest() {
                let height = late.checkpoints.height(certificate.item.position).unwrap();
                if height.get() >= sync_base {
                    break;
                }
            }
            context.sleep(Duration::from_millis(50)).await;
        }
        assert!(
            late.checkpoints
                .height(late.checkpoints.latest().unwrap().item.position)
                .unwrap()
                .get()
                >= sync_base
        );
        let recovered = late.checkpoints.latest().unwrap().item.position;
        while late.checkpoints.latest().unwrap().item.position.get() < recovered.get() + 2 {
            context.sleep(Duration::from_millis(50)).await;
        }
        // Every mandatory checkpoint through the sync base was recovered. Progress in `latest`
        // alone could hide holes below the active window's end.
        let index = (VALIDATORS - 1).to_string();
        let base_position = (sync_base + 1) / INTERVAL.get() - 1;
        while metric_sum(
            &context.encode(),
            "aggregation_frontier",
            &[("index", &index)],
        ) <= base_position as f64
        {
            context.sleep(Duration::from_millis(50)).await;
        }

        // The certificate for the sync base verifies under the committee's checkpoint key and
        // scope, and names the block the late validator synced to at that position. It does not
        // verify under another committee's key, or under a scope that excludes its position.
        let trusted = committee
            .committee
            .verifier
            .checkpoint(CHECKPOINT_NAMESPACE);
        let (epoch, lowest, highest) = checkpoint_scope(&committee.committee);
        let key = RecoveryKey {
            namespace: aggregation::scheme::Scheme::<Digest>::recovery_namespace(&trusted),
            epoch,
            position: Height::new(base_position),
        };
        let encoded = loop {
            if let Some(encoded) = late.archive.get(&key) {
                break encoded;
            }
            context.sleep(Duration::from_millis(50)).await;
        };
        let certificate =
            Certificate::<Scheme, Digest>::decode_cfg(encoded, &trusted.certificate_codec_config())
                .expect("archived certificate decodes");
        assert!(certificate.verify_for(
            &mut context,
            &trusted,
            epoch,
            lowest,
            highest,
            &Sequential
        ));
        assert_eq!(
            late.checkpoints.height(certificate.item.position),
            Some(Height::new(base))
        );
        assert_eq!(certificate.item.digest, base_block.digest());
        let other = Committee::<MinPk>::builder(8, VALIDATORS)
            .namespace(NAMESPACE)
            .build()
            .verifier
            .checkpoint(CHECKPOINT_NAMESPACE);
        assert!(!certificate.verify_for(&mut context, &other, epoch, lowest, highest, &Sequential));
        let above = Height::new(base_position + 1);
        assert!(!certificate.verify_for(
            &mut context,
            &trusted,
            epoch,
            above,
            highest,
            &Sequential
        ));

        // Only locally signed acknowledgements use the aggregation channel. The late validator
        // participates in new checkpoints after recovering its skipped history.
        let origin = committee.committee.identities[VALIDATORS as usize - 1].to_string();
        let channel = AGGREGATION.to_string();
        assert!(
            metric_sum(
                &context.encode(),
                "messages_sent_total",
                &[("origin", &origin), ("channel", &channel)],
            ) > 0.0
        );
    });
}

/// What the first run of [`a_late_validator_resumes_state_sync_after_a_crash`] saw at its cut.
struct AtCut {
    /// Height of the newest target the executor offered the sync, and so persisted, before the
    /// cut.
    newest: u64,
    /// Height of the block the application's state reached, at [`Cut::Synced`].
    reached: Option<u64>,
}

/// A late validator crashes while it state-syncs, restarts on the same storage, and resumes the
/// sync toward the newest target it persisted.
///
/// The first run starts the late validator as in
/// [`a_late_validator_state_syncs_to_a_certified_checkpoint`] and holds its state sync at `cut`.
/// Ending the run there crashes the runtime: every task is dropped, and storage keeps only what
/// was synced. Every validator then restarts with the same identity and storage.
///
/// After the restart, the late validator's executor resumes the sync toward the newest target it
/// persisted, which is above the first target and, at [`Cut::Synced`], above the block its
/// database already reached. The block the resumed sync reaches is the one the honest validators
/// executed at its height. The application hook receives no block at or below it in either run.
/// The late validator then executes the same blocks as its peers, recovers every checkpoint
/// certificate through its base, and sends checkpoint acknowledgements.
#[rstest::rstest]
#[case::mid_sync(Cut::MidSync)]
#[case::synced(Cut::Synced)]
fn a_late_validator_resumes_state_sync_after_a_crash(#[case] cut: Cut) {
    let joiner = VALIDATORS as usize - 1;
    let runner = deterministic::Runner::timed(Duration::from_secs(300));
    let (at_cut, checkpoint) = runner.start_and_recover(move |context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..joiner {
            validators.push(committee.start(index, false, None, None).await);
        }
        until_applied(&context, validators.iter().map(|v| &v.tally), 48).await;

        let watch = SyncWatch::new(Some(cut));
        let late = committee
            .start(joiner, true, None, Some(watch.clone()))
            .await;
        while !watch.cut_reached() {
            context.sleep(Duration::from_millis(50)).await;
        }

        // The executor persisted a target but installed no base, so the application hook
        // received no block.
        assert!(!late.chain.awaits_floor().await);
        assert!(!late.chain.has_base().await);
        assert!(late.tally.applied.lock().is_empty());
        let offered = watch.offered.lock().clone();
        let newest = *offered.last().expect("a target was offered");
        let reached = watch
            .reached
            .lock()
            .as_ref()
            .map(|block| block.height().get());
        match cut {
            Cut::MidSync => {
                // One response arrived and every later one is withheld, so the sync has not
                // completed.
                assert_eq!(watch.received.load(Ordering::SeqCst), 1);
                assert_eq!(reached, None, "the sync completed with one response");
                assert!(newest > offered[0]);
            }
            Cut::Synced => {
                let reached = reached.expect("the sync reached a block");
                assert!(newest > reached);
            }
        }

        // Returning ends the run here, which crashes the runtime.
        AtCut { newest, reached }
    });

    deterministic::Runner::from(checkpoint).start(move |mut context| async move {
        let committee = Cluster::new(context.child("committee")).await;
        let mut validators = Vec::new();
        for index in 0..joiner {
            validators.push(committee.start(index, false, None, None).await);
        }
        let watch = SyncWatch::new(None);
        let late = committee
            .start(joiner, true, None, Some(watch.clone()))
            .await;
        let base = loop {
            if let Some(base) = watch.reached.lock().clone() {
                break base;
            }
            context.sleep(Duration::from_millis(50)).await;
        };

        // The resumed sync started from the newest target persisted before the crash, or from a
        // later one persisted after the watch last saw an offer, and fetched from peers.
        let first = watch.offered.lock()[0];
        assert!(first >= at_cut.newest);
        if let Some(reached) = at_cut.reached {
            assert!(first > reached);
        }
        assert!(watch.received.load(Ordering::SeqCst) > 0);
        let height = base.height().get();
        assert!(height >= first);
        assert_eq!(
            (height + 1) % INTERVAL.get(),
            0,
            "the base is not a checkpoint"
        );

        // The base is the block an honest validator executed at its height, and so commits to the
        // state root it computed there. The honest validator may still be catching up after the
        // restart, so wait for the block, but fail at once if it applied past the base and no
        // longer holds it.
        let honest = loop {
            let applied_past = validators[0].tally.applied() > height;
            if let Some(block) = validators[0].chain.block_at(base.height()).await {
                break block;
            }
            assert!(
                !applied_past,
                "the honest validator applied past height {height} but no longer holds its block"
            );
            context.sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(honest.digest(), base.digest());
        assert_eq!(honest.inner().targets(), base.inner().targets());

        // Execution resumes after the base, and the application hook receives no block at or
        // below it. Equal blocks commit to equal state roots.
        let target = height + 2 * INTERVAL.get();
        until_applied(&context, [&late.tally, &validators[0].tally], target).await;
        assert!(
            late.tally
                .applied
                .lock()
                .iter()
                .all(|&applied| applied > height)
        );
        assert_eq!(
            late.chain.block_at(Height::new(target)).await.unwrap(),
            validators[0]
                .chain
                .block_at(Height::new(target))
                .await
                .unwrap()
        );

        // Every mandatory checkpoint through the base was recovered, and the certificate for the
        // base verifies under the committee's checkpoint key and scope and names the base.
        let index = joiner.to_string();
        let position = (height + 1) / INTERVAL.get() - 1;
        while metric_sum(
            &context.encode(),
            "aggregation_frontier",
            &[("index", &index)],
        ) <= position as f64
        {
            context.sleep(Duration::from_millis(50)).await;
        }
        let trusted = committee
            .committee
            .verifier
            .checkpoint(CHECKPOINT_NAMESPACE);
        let (epoch, lowest, highest) = checkpoint_scope(&committee.committee);
        let key = RecoveryKey {
            namespace: aggregation::scheme::Scheme::<Digest>::recovery_namespace(&trusted),
            epoch,
            position: Height::new(position),
        };
        let encoded = loop {
            if let Some(encoded) = late.archive.get(&key) {
                break encoded;
            }
            context.sleep(Duration::from_millis(50)).await;
        };
        let certificate =
            Certificate::<Scheme, Digest>::decode_cfg(encoded, &trusted.certificate_codec_config())
                .expect("archived certificate decodes");
        assert!(certificate.verify_for(
            &mut context,
            &trusted,
            epoch,
            lowest,
            highest,
            &Sequential
        ));
        assert_eq!(certificate.item.digest, base.digest());

        // The metrics registry is new after the restart, so these acknowledgements were sent
        // after it.
        let origin = committee.committee.identities[joiner].to_string();
        let channel = AGGREGATION.to_string();
        while metric_sum(
            &context.encode(),
            "messages_sent_total",
            &[("origin", &origin), ("channel", &channel)],
        ) <= 0.0
        {
            context.sleep(Duration::from_millis(50)).await;
        }
    });
}

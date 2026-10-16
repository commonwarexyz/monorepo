//! End-to-end forward-history replay through real Simplex, Marshal, and Stateful actors.
//!
//! One validator runs the production stack: a Simplex [`simplex::Engine`], the Standard
//! [`Deferred`] Marshal adapter, the Marshal core actor with its P2P resolver, and the
//! [`StatefulActor`] over a real QMDB. The test plays the other three validators over the
//! simulated network. It sends valid notarizations so the real voter selects a chain
//! `B1..BD` above the finalized genesis without warming application state, then measures one
//! public input event: the leader's proposal and notarization of the candidate `C = B(D+1)`.
//!
//! Peers answer Marshal block requests through real resolver P2P engines over simulated links
//! with fixed latency. Out-of-order and tail scenarios hold one response at the producer.
//! Each run prints one machine-readable line prefixed by `E2E_FORWARD_HISTORY`.
//!
//! "Cold" means a cold in-memory application backlog above finality on a live node. No
//! scenario performs a persisted restart.

use super::{
    NoopQmdbResolver,
    common::{EPOCH_LENGTH, IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, archive_config},
    mocks::digested,
    single_db_app::{App, Block, SingleDatabaseSet, qmdb_config},
};
use crate::stateful::{
    Application, Config as StatefulConfig, Input, Proposed, Stateful as StatefulActor, SyncPlan,
    db::{DatabaseSet, Merkleized as _, SyncEngineConfig},
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_broadcast::{Broadcaster as _, buffered};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Heightable as _, History, Relay, Reporter, Viewable as _,
    marshal::{
        self,
        blocks::Blocks,
        core::Actor as MarshalActor,
        resolver::{handler::Key, p2p as marshal_resolver},
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        types::{Activity, Certificate, Context, Notarization, Notarize, Proposal, Vote},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digested, Digestible as _, Sha256, certificate::ConstantProvider, ed25519, sha256,
};
use commonware_p2p::{
    Manager as _, Receiver as _, Recipients, Sender as _,
    simulated::{self, Link, Network},
};
use commonware_parallel::Sequential;
use commonware_resolver::{Consumer, Delivery, p2p as resolver_p2p};
use commonware_runtime::{
    Clock as _, Quota, Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::archive::prunable;
use commonware_utils::{
    NZU64, NZUsize, channel::oneshot, non_empty, non_empty_range, ordered::Set, probability,
    sync::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, SystemTime},
};

type S = MockScheme<ed25519::PublicKey>;
type D = sha256::Digest;
type P = ed25519::PublicKey;
type Ctx = Context<D, P>;

const N: usize = 4;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FORWARD_HISTORY_E2E";
const VOTES: u64 = 0;
const CERTIFICATES: u64 = 1;
const SIMPLEX_RESOLVER: u64 = 2;
const BACKFILL: u64 = 3;
const BROADCAST: u64 = 4;

/// Upper bound on a producer-held response, so revisions that cannot satisfy a gate finish.
const HOLD_LIMIT: Duration = Duration::from_secs(3);

/// Which bodies are local and how peers order their responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Every selected body is buffered locally before the measured event.
    Local,
    /// Only the parent `BD` (and the candidate) are local; peers answer immediately.
    Cold,
    /// Odd heights and the parent are local; the remaining bodies are fetched.
    Mixed,
    /// As `Cold`, but the lowest missing body is held until a higher body was answered.
    OutOfOrder,
    /// As `Cold`, but the missing body at index `window` (or the last one) is held until the
    /// application executes a block, so only a forward prefix can execute before it arrives.
    Tail,
}

impl Kind {
    fn parse(value: &str) -> Self {
        match value {
            "local" => Self::Local,
            "cold" => Self::Cold,
            "mixed" => Self::Mixed,
            "ooo" => Self::OutOfOrder,
            "tail" => Self::Tail,
            other => panic!("unknown FH_SCENARIO {other}"),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cold => "cold",
            Self::Mixed => "mixed",
            Self::OutOfOrder => "ooo",
            Self::Tail => "tail",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    kind: Kind,
    seed: u64,
    depth: u64,
    window: usize,
    latency_ms: u64,
    forward_reports: bool,
    assert_pipeline: bool,
}

impl Scenario {
    const fn new(kind: Kind) -> Self {
        Self {
            kind,
            seed: 0,
            depth: 8,
            window: 3,
            latency_ms: 20,
            forward_reports: false,
            assert_pipeline: true,
        }
    }

    /// Applies optional FH_* environment overrides.
    fn with_env(mut self) -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        if let Some(kind) = var("FH_SCENARIO") {
            self.kind = Kind::parse(&kind);
        }
        if let Some(seed) = var("FH_SEED") {
            self.seed = seed.parse().expect("FH_SEED");
        }
        if let Some(depth) = var("FH_DEPTH") {
            self.depth = depth.parse().expect("FH_DEPTH");
        }
        if let Some(window) = var("FH_WINDOW") {
            self.window = window.parse().expect("FH_WINDOW");
        }
        if let Some(latency) = var("FH_LATENCY_MS") {
            self.latency_ms = latency.parse().expect("FH_LATENCY_MS");
        }
        if let Some(report) = var("FH_REPORT") {
            self.forward_reports = report == "forward";
        }
        if let Some(assert) = var("FH_ASSERT_PIPELINE") {
            self.assert_pipeline = assert != "0";
        }
        self
    }

    /// Heights of `B1..BD` whose bodies are buffered locally before the measured event.
    fn local_heights(&self) -> BTreeSet<u64> {
        (1..=self.depth)
            .filter(|&height| match self.kind {
                Kind::Local => true,
                Kind::Mixed => height == self.depth || height % 2 == 1,
                Kind::Cold | Kind::OutOfOrder | Kind::Tail => height == self.depth,
            })
            .collect()
    }
}

/// Application execution observed through the instrumented wrapper.
#[derive(Clone, Debug)]
struct Execution {
    kind: &'static str,
    height: u64,
    start: SystemTime,
    end: Option<SystemTime>,
    ok: Option<bool>,
}

/// One external block request observed by a peer's resolver producer.
#[derive(Clone, Debug)]
struct Request {
    at: SystemTime,
    peer: usize,
    height: u64,
    kind: &'static str,
}

#[derive(Default)]
struct Observations {
    t0: Option<SystemTime>,
    executions: Vec<Execution>,
    requests: Vec<Request>,
    responses: Vec<(SystemTime, u64)>,
    other_requests: usize,
    held: Option<(u64, oneshot::Sender<Bytes>, Bytes)>,
    hold_release: Option<(SystemTime, &'static str)>,
    stub_certified: u64,
    stub_verifies: usize,
    stub_certifies: usize,
    target_verifies: usize,
    target_certifies: usize,
    finalized_reports: usize,
    proposes: usize,
    inner_calls_before_t0: usize,
    target_verify_at: Option<SystemTime>,
    target_certify_at: Option<SystemTime>,
    certify_result: Option<(SystemTime, bool)>,
    finalize_vote_at: Option<SystemTime>,
}

type Shared = Arc<Mutex<Observations>>;

fn ns(from: SystemTime, to: SystemTime) -> u128 {
    to.duration_since(from).unwrap_or_default().as_nanos()
}

/// Wraps the single-database application and records every verify and apply.
#[derive(Clone)]
struct InstrumentedApp {
    inner: App,
    observations: Shared,
}

impl InstrumentedApp {
    fn begin(&self, context: &deterministic::Context, kind: &'static str, height: u64) -> usize {
        let mut observations = self.observations.lock();
        if observations.t0.is_none() {
            observations.inner_calls_before_t0 += 1;
        }
        observations.executions.push(Execution {
            kind,
            height,
            start: context.current(),
            end: None,
            ok: None,
        });
        observations.executions.len() - 1
    }

    fn end(&self, context: &deterministic::Context, index: usize, ok: bool) {
        let mut observations = self.observations.lock();
        let execution = &mut observations.executions[index];
        execution.end = Some(context.current());
        execution.ok = Some(ok);
    }
}

impl Application<deterministic::Context> for InstrumentedApp {
    type SigningScheme = S;
    type Context = Ctx;
    type Block = Block;
    type Databases = SingleDatabaseSet<deterministic::Context>;
    type Captured = ();
    type Provider = ();
    type Input = ();

    async fn genesis(&mut self) -> Self::Block {
        <App as Application<deterministic::Context>>::genesis(&mut self.inner).await
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        parent: Digested<Self::Block>,
        blocks: Blocks<Self::Block>,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        self.observations.lock().proposes += 1;
        let proposed = <App as Application<deterministic::Context>>::propose(
            &mut self.inner,
            context,
            parent,
            blocks,
            batches,
            input,
        )
        .await?;
        Some(Proposed {
            block: proposed.block,
            merkleized: proposed.merkleized,
        })
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: Digested<Self::Block>,
        parent: Digested<Self::Block>,
        blocks: Blocks<Self::Block>,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        let runtime = context.0.child("instrument");
        let index = self.begin(&runtime, "verify", block.height().get());
        let result = <App as Application<deterministic::Context>>::verify(
            &mut self.inner,
            context,
            block,
            parent,
            blocks,
            batches,
        )
        .await;
        self.end(&runtime, index, result.is_some());
        result
    }

    async fn apply(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        let runtime = context.0.child("instrument");
        let index = self.begin(&runtime, "apply", block.height.get());
        let result = <App as Application<deterministic::Context>>::apply(
            &mut self.inner,
            context,
            block,
            batches,
        )
        .await;
        let root_matches = result
            .as_ref()
            .is_some_and(|merkleized| merkleized.root() == block.state_root);
        self.end(&runtime, index, root_matches);
        result
    }

    async fn capture(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
    ) -> Self::Captured {
        <App as Application<deterministic::Context>>::capture(
            &mut self.inner,
            context,
            block,
            batches,
            readers,
        )
        .await
    }

    async fn finalized(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
    ) {
        <App as Application<deterministic::Context>>::finalized(
            &mut self.inner,
            context,
            block,
            captured,
            readers,
        )
        .await;
        self.observations.lock().finalized_reports += 1;
    }

    fn sync_targets(
        block: &Self::Block,
    ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
        <App as Application<deterministic::Context>>::sync_targets(block)
    }
}

/// Sits between the real Simplex engine and [`Deferred`].
///
/// Requests for the selected views `1..=D` are answered without reaching [`Deferred`], so no
/// independent verification or certification job prepares application state before the
/// measured event. Requests for the candidate view are forwarded unchanged with the voter's
/// history. Proposals are never produced.
#[derive(Clone)]
struct Gate<A> {
    context: Arc<deterministic::Context>,
    inner: A,
    target: View,
    forward_reports: bool,
    observations: Shared,
    proposals: Arc<Mutex<Vec<oneshot::Sender<D>>>>,
}

impl<A> Automaton for Gate<A>
where
    A: Automaton<Context = Ctx, Digest = D>,
{
    type Context = Ctx;
    type Digest = D;

    async fn propose(
        &mut self,
        _context: Self::Context,
        _ancestry: History<Self::Digest>,
    ) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        self.proposals.lock().push(sender);
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
        ancestry: History<Self::Digest>,
    ) -> oneshot::Receiver<bool> {
        if context.round.view() == self.target {
            {
                let mut observations = self.observations.lock();
                observations.target_verify_at = Some(self.context.current());
                observations.target_verifies += 1;
            }
            return self.inner.verify(context, payload, ancestry).await;
        }
        self.observations.lock().stub_verifies += 1;
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(true);
        receiver
    }
}

impl<A> CertifiableAutomaton for Gate<A>
where
    A: CertifiableAutomaton<Context = Ctx, Digest = D>,
{
    async fn certify(
        &mut self,
        round: Round,
        payload: Self::Digest,
        ancestry: History<Self::Digest>,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        if round.view() != self.target {
            {
                let mut observations = self.observations.lock();
                observations.stub_certified = observations.stub_certified.max(round.view().get());
                observations.stub_certifies += 1;
            }
            let _ = sender.send(true);
            return receiver;
        }
        {
            let mut observations = self.observations.lock();
            observations.target_certify_at = Some(self.context.current());
            observations.target_certifies += 1;
        }
        let inner = self.inner.certify(round, payload, ancestry).await;
        let observations = self.observations.clone();
        self.context
            .child("target_certify")
            .spawn(move |context| async move {
                if let Ok(result) = inner.await {
                    observations.lock().certify_result = Some((context.current(), result));
                    let _ = sender.send(result);
                }
            });
        receiver
    }
}

impl<A: Relay> Relay for Gate<A> {
    type Digest = A::Digest;
    type PublicKey = A::PublicKey;
    type Plan = A::Plan;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        self.inner.broadcast(payload, plan)
    }
}

impl<A> Reporter for Gate<A>
where
    A: Reporter<Activity = Activity<S, D>>,
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if !self.forward_reports && activity.view() < self.target {
            return Feedback::Ok;
        }
        self.inner.report(activity)
    }
}

/// Serves Marshal block requests on behalf of one scripted peer.
#[derive(Clone)]
struct ScriptedProducer {
    context: Arc<deterministic::Context>,
    peer: usize,
    kind: Kind,
    bodies: Arc<HashMap<D, (u64, Bytes)>>,
    notarized: Arc<HashMap<Round, (u64, Bytes)>>,
    missing: Arc<BTreeSet<u64>>,
    tail: Option<u64>,
    observations: Shared,
}

impl ScriptedProducer {
    fn respond(observations: &mut Observations, at: SystemTime, height: u64) {
        observations.responses.push((at, height));
    }

    fn release(observations: &mut Observations, at: SystemTime, reason: &'static str) {
        if let Some((height, sender, body)) = observations.held.take() {
            let _ = sender.send(body);
            Self::respond(observations, at, height);
            observations.hold_release = Some((at, reason));
        }
    }

    fn spawn_hold_limit(&self) {
        let observations = self.observations.clone();
        let kind = self.kind;
        let tail = self.tail;
        self.context.child("hold").spawn(move |context| async move {
            let deadline = context.current() + HOLD_LIMIT;
            loop {
                {
                    let mut guard = observations.lock();
                    if guard.held.is_none() {
                        return;
                    }
                    let now = context.current();
                    let prefix_applied = guard.executions.iter().any(|execution| {
                        tail.is_some_and(|tail| execution.height < tail) && execution.end.is_some()
                    });
                    if kind == Kind::Tail && prefix_applied {
                        Self::release(&mut guard, now, "prefix_applied");
                        return;
                    }
                    if now >= deadline {
                        Self::release(&mut guard, now, "hold_limit");
                        return;
                    }
                }
                context.sleep(Duration::from_millis(1)).await;
            }
        });
    }
}

impl resolver_p2p::Producer for ScriptedProducer {
    type Key = Key<D>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        let now = self.context.current();
        let mut observations = self.observations.lock();
        // Bodies by digest carry only the block. Notarized requests by round carry the
        // notarization followed by its block. Both share one availability and hold policy.
        let (kind, found) = match key {
            Key::Block(digest) => ("block", self.bodies.get(&digest).cloned()),
            Key::Notarized { round } => ("notarized", self.notarized.get(&round).cloned()),
            Key::Finalized { .. } => ("finalized", None),
        };
        let Some((height, body)) = found else {
            observations.other_requests += 1;
            return receiver;
        };
        observations.requests.push(Request {
            at: now,
            peer: self.peer,
            height,
            kind,
        });
        let hold = observations.held.is_none()
            && observations.hold_release.is_none()
            && match self.kind {
                Kind::OutOfOrder => self.missing.first() == Some(&height),
                Kind::Tail => self.tail == Some(height),
                _ => false,
            };
        if hold {
            observations.held = Some((height, sender, body));
            drop(observations);
            self.spawn_hold_limit();
            return receiver;
        }
        let _ = sender.send(body);
        Self::respond(&mut observations, now, height);
        if self.kind == Kind::OutOfOrder
            && observations
                .held
                .as_ref()
                .is_some_and(|(held, _, _)| *held < height)
        {
            Self::release(&mut observations, now, "higher_body_answered");
        }
        receiver
    }
}

/// Peers never fetch, so their resolver engines never deliver.
#[derive(Clone)]
struct NullConsumer;

impl Consumer for NullConsumer {
    type Key = Key<D>;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = bool;

    fn deliver(
        &mut self,
        _delivery: Delivery<Self::Key, Self::Subscriber>,
        _value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(false);
        receiver
    }
}

/// Default round-robin leader for an epoch-zero view with single-view terms.
fn leader(participants: &[P], view: u64) -> &P {
    &participants[(view as usize) % participants.len()]
}

/// Builds `B1..B(blocks)` on a private QMDB with contexts matching the real voter's rounds.
async fn build_chain(
    context: &deterministic::Context,
    participants: &[P],
    blocks: u64,
) -> (Block, Vec<Block>) {
    let initial_target =
        <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::initial_sync_targets();
    let genesis = Block::genesis(initial_target.root, initial_target.range);
    let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let databases = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::init(
        context.child("chain_builder"),
        qmdb_config("forward-history-chain-builder", page_cache),
        None,
    )
    .await;
    let mut batches = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<
        deterministic::Context,
    >>::new_batches(&databases)
    .await;
    let mut parent = genesis.clone();
    let mut chain = Vec::with_capacity(blocks as usize);

    // QMDB descendants retain uncommitted ancestry by weak reference after merkleization.
    let mut speculative = Vec::with_capacity(blocks as usize);
    for height in 1..=blocks {
        let height = Height::new(height);
        let merkleized = App::execute(height, batches).await;
        let bounds = merkleized.bounds();
        let block = Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height.get())),
                leader: leader(participants, height.get()).clone(),
                parent: (parent.context.round.view(), parent.digest()),
            },
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
        };
        speculative.push(merkleized);
        batches = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::fork_batches(
            speculative.last().expect("speculative batch missing"),
        );
        parent = block.clone();
        chain.push(block);
    }
    (genesis, chain)
}

fn proposal(block: &Block) -> Proposal<D> {
    Proposal::new(block.context.round, block.context.parent.0, block.digest())
}

fn notarization(schemes: &[S], signers: &[usize], block: &Block) -> Notarization<S, D> {
    let votes = signers
        .iter()
        .map(|&index| Notarize::sign(&schemes[index], proposal(block)).unwrap())
        .collect::<Vec<_>>();
    Notarization::from_notarizes(&schemes[signers[0]], non_empty![@&votes], &Sequential).unwrap()
}

fn json_list<T: std::fmt::Display>(values: impl IntoIterator<Item = T>) -> String {
    let values = values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

fn run(scenario: Scenario) {
    let config = deterministic::Config::new()
        .with_seed(scenario.seed)
        .with_timeout(Some(Duration::from_secs(600)));
    deterministic::Runner::new(config).start(|context| async move {
        let depth = scenario.depth;
        let target = View::new(depth + 1);
        let mut rng = context.child("fixture");
        let fixture = scheme_mocks::fixture(&mut rng, NAMESPACE, N as u32);
        let participants = fixture.participants.clone();
        let schemes = fixture.schemes.clone();

        // The measured node never leads the candidate view.
        let me = ((depth + 2) as usize) % N;
        let peers = (0..N).filter(|&index| index != me).collect::<Vec<_>>();
        let candidate_leader = (depth + 1) as usize % N;
        assert_ne!(candidate_leader, me);
        let (genesis, chain) = build_chain(&context, &participants, depth + 1).await;
        let candidate = chain.last().expect("candidate missing").clone();
        let selected = &chain[..depth as usize];
        let local = scenario.local_heights();
        let missing = (1..=depth)
            .filter(|height| !local.contains(height))
            .collect::<BTreeSet<_>>();
        let bodies = Arc::new(
            chain
                .iter()
                .map(|block| {
                    let body = Bytes::from(block.encode().to_vec());
                    (block.digest(), (block.height.get(), body))
                })
                .collect::<HashMap<D, (u64, Bytes)>>(),
        );
        let notarized = Arc::new(
            chain
                .iter()
                .map(|block| {
                    let mut response = notarization(&schemes, &peers[..3], block).encode().to_vec();
                    response.extend_from_slice(&block.encode());
                    (
                        block.context.round,
                        (block.height.get(), Bytes::from(response)),
                    )
                })
                .collect::<HashMap<Round, (u64, Bytes)>>(),
        );
        let missing_shared = Arc::new(missing.clone());
        let observations: Shared = Arc::new(Mutex::new(Observations::default()));

        // Simulated network with fixed-latency links between every pair.
        let (network, oracle) = Network::<_, P>::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(N),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();
        let mut manager = oracle.manager();
        manager.track(0, Set::from_iter_dedup(participants.iter().cloned()));
        let link = Link {
            latency: Duration::from_millis(scenario.latency_ms),
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        };
        for a in &participants {
            for b in &participants {
                if a != b {
                    oracle
                        .add_link(a.clone(), b.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }
        }

        // Scripted peers: vote and certificate senders, finalize-vote observers, and real
        // resolver P2P engines with scripted producers.
        let mut peer_votes = BTreeMap::new();
        let mut peer_certificates = BTreeMap::new();
        let mut peer_channels = Vec::new();
        let mut peer_resolvers = Vec::new();
        for &index in &peers {
            let control = oracle.control(participants[index].clone());
            let (vote_sender, mut vote_receiver) = control.register(VOTES, QUOTA).await.unwrap();
            let (certificate_sender, certificate_receiver) =
                control.register(CERTIFICATES, QUOTA).await.unwrap();
            let simplex_resolver = control.register(SIMPLEX_RESOLVER, QUOTA).await.unwrap();
            peer_channels.push((certificate_receiver, simplex_resolver));
            let backfill = control.register(BACKFILL, QUOTA).await.unwrap();
            let (engine, peer_mailbox) = resolver_p2p::Engine::new(
                context
                    .child("peer_resolver")
                    .with_attribute("index", index),
                resolver_p2p::Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(participants[index].clone()),
                    consumer: NullConsumer,
                    producer: ScriptedProducer {
                        context: Arc::new(context.child("producer").with_attribute("index", index)),
                        peer: index,
                        kind: scenario.kind,
                        bodies: bodies.clone(),
                        notarized: notarized.clone(),
                        missing: missing_shared.clone(),
                        tail: missing
                            .iter()
                            .nth(scenario.window.min(missing.len().saturating_sub(1)))
                            .copied(),
                        observations: observations.clone(),
                    },
                    mailbox_size: NZUsize!(1024),
                    me: Some(participants[index].clone()),
                    timeout: Duration::from_secs(10),
                    fetch_retry_timeout: Duration::from_millis(100),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            peer_resolvers.push((peer_mailbox, engine.start(backfill)));
            let me_key = participants[me].clone();
            let observer = observations.clone();
            context
                .child("peer_votes")
                .with_attribute("index", index)
                .spawn(move |context| async move {
                    while let Ok((sender, message)) = vote_receiver.recv().await {
                        if sender != me_key {
                            continue;
                        }
                        let Ok(vote) = Vote::<S, D>::decode(message) else {
                            continue;
                        };
                        if let Vote::Finalize(finalize) = vote
                            && finalize.proposal.round.view() == target
                        {
                            let mut guard = observer.lock();
                            if guard.finalize_vote_at.is_none() {
                                guard.finalize_vote_at = Some(context.current());
                            }
                        }
                    }
                });
            peer_votes.insert(index, vote_sender);
            peer_certificates.insert(index, certificate_sender);
        }

        // The candidate leader relays bodies through a real buffered broadcast engine.
        let leader_broadcast = oracle
            .control(participants[candidate_leader].clone())
            .register(BROADCAST, QUOTA)
            .await
            .unwrap();
        let (leader_engine, leader_buffer) = buffered::Engine::<_, P, Block, _, _>::new(
            context.child("leader_broadcast"),
            buffered::Config {
                public_key: participants[candidate_leader].clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: 1024,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
                strategy: Sequential,
            },
        );
        leader_engine.start(leader_broadcast);

        // Measured node: production wiring as in the single-database engine.
        let public_key = participants[me].clone();
        let control = oracle.control(public_key.clone());
        let vote_network = control.register(VOTES, QUOTA).await.unwrap();
        let certificate_network = control.register(CERTIFICATES, QUOTA).await.unwrap();
        let resolver_network = control.register(SIMPLEX_RESOLVER, QUOTA).await.unwrap();
        let backfill_network = control.register(BACKFILL, QUOTA).await.unwrap();
        let broadcast_network = control.register(BROADCAST, QUOTA).await.unwrap();
        let node = context.child("node");
        let prefix = "forward-history".to_string();
        let page_cache = CacheRef::from_pooler(&node, PAGE_SIZE, PAGE_CACHE_SIZE);
        let resolver = marshal_resolver::init(
            node.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(1024),
                timeout: Duration::from_secs(10),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill_network,
        );
        let (broadcast_engine, buffer) = buffered::Engine::new(
            node.child("broadcast"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: 1024,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
                strategy: Sequential,
            },
        );
        broadcast_engine.start(broadcast_network);
        let local_buffer = buffer.clone();
        let finalizations_by_height = prunable::Archive::init(
            node.child("finalizations_by_height"),
            archive_config(&prefix, "finalizations", page_cache.clone(), ()),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            node.child("finalized_blocks"),
            archive_config(&prefix, "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                node.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: ConstantProvider::new(schemes[me].clone()),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal::Start::Genesis(digested(genesis.clone())),
                    partition_prefix: prefix.clone(),
                    mailbox_size: NZUsize!(1024),
                    view_retention: ViewDelta::new(1024),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(scenario.window),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;
        let plan = SyncPlan::init(node.child("plan"), format!("{prefix}-stateful")).await;
        let (stateful, stateful_mailbox) = StatefulActor::new(
            node.child("stateful"),
            StatefulConfig {
                application: InstrumentedApp {
                    inner: App::new(genesis.clone()),
                    observations: observations.clone(),
                },
                db_config: qmdb_config(&format!("{prefix}-stateful"), page_cache.clone()),
                provider: (),
                marshal: (marshal.clone(), floor),
                mailbox_size: NZUsize!(1024),
                plan,
                resolvers: NoopQmdbResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: NZUsize!(8),
                    update_channel_size: NZUsize!(256),
                },
                prune_config: None,
                strategy: Sequential,
            },
        );
        let deferred = Deferred::new(
            node.child("deferred"),
            stateful_mailbox.clone(),
            marshal.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let _marshal_handle = marshal_actor.start(stateful_mailbox.clone(), buffer, resolver);
        let _stateful_handle = stateful.start();
        let _databases = stateful_mailbox.subscribe_databases().await;
        let gate = Gate {
            context: Arc::new(node.child("gate")),
            inner: deferred,
            target,
            forward_reports: scenario.forward_reports,
            observations: observations.clone(),
            proposals: Arc::new(Mutex::new(Vec::new())),
        };
        let engine = simplex::Engine::new(
            node.child("engine"),
            simplex::Config {
                scheme: schemes[me].clone(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(public_key.clone()),
                automaton: gate.clone(),
                relay: gate.clone(),
                reporter: gate,
                strategy: Sequential,
                partition: format!("{prefix}-simplex"),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(genesis.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(300),
                certification_timeout: Duration::from_secs(400),
                timeout_retry: Duration::from_secs(300),
                view_retention: ViewDelta::new(1024),
                skip: SkipPolicy::Disabled,
                fetch_timeout: Duration::from_secs(10),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        let _engine_handle = engine.start(vote_network, certificate_network, resolver_network);

        // Select B1..BD through the real voter with valid notarizations from three peers.
        let signers = &peers[..3];
        let sender = peers[0];
        for block in selected {
            let certificate = Certificate::Notarization(notarization(&schemes, signers, block));
            peer_certificates.get_mut(&sender).unwrap().send(
                Recipients::One(public_key.clone()),
                certificate.encode(),
                true,
            );
        }
        while observations.lock().stub_certified < depth {
            context.sleep(Duration::from_millis(1)).await;
        }

        // Seed local bodies through the network buffer, as a leader relay would: the parent BD,
        // the candidate, and scenario extras. Marshal and Stateful see no direct calls.
        let relayed = selected
            .iter()
            .filter(|block| local.contains(&block.height.get()))
            .chain(std::iter::once(&candidate))
            .collect::<Vec<_>>();
        for block in &relayed {
            let _ = leader_buffer.broadcast(
                Recipients::One(public_key.clone()),
                digested((*block).clone()),
            );
        }
        for block in &relayed {
            while local_buffer.get(block.digest()).await.is_none() {
                context.sleep(Duration::from_millis(1)).await;
            }
        }
        context.sleep(Duration::from_millis(500)).await;
        {
            let guard = observations.lock();
            assert!(
                guard.requests.is_empty(),
                "block requests before the measured event"
            );
            assert_eq!(
                guard.inner_calls_before_t0, 0,
                "application ran before the measured event"
            );
            assert!(guard.target_verify_at.is_none());
        }

        // Measured public input event: the leader's proposal and the candidate's notarization.
        let t0 = context.current();
        observations.lock().t0 = Some(t0);
        let leader_vote = Vote::Notarize(
            Notarize::sign(&schemes[candidate_leader], proposal(&candidate)).unwrap(),
        );
        peer_votes.get_mut(&candidate_leader).unwrap().send(
            Recipients::One(public_key.clone()),
            leader_vote.encode(),
            true,
        );
        let certificate = Certificate::Notarization(notarization(&schemes, signers, &candidate));
        peer_certificates.get_mut(&candidate_leader).unwrap().send(
            Recipients::One(public_key.clone()),
            certificate.encode(),
            true,
        );
        loop {
            {
                let guard = observations.lock();
                if guard.finalize_vote_at.is_some() && guard.certify_result.is_some() {
                    break;
                }
            }
            context.sleep(Duration::from_millis(1)).await;
        }
        drop(peer_channels);
        drop(peer_resolvers);

        // Scripted ancestors must never be finalized or processed.
        let processed_height = marshal
            .get_processed()
            .await
            .map_or(0, |processed| processed.height().get());

        // Metrics.
        let guard = observations.lock();
        let replay = guard
            .executions
            .iter()
            .filter(|execution| execution.height <= depth)
            .collect::<Vec<_>>();
        let apply_order = replay
            .iter()
            .map(|execution| execution.height)
            .collect::<Vec<_>>();
        let first_apply = replay.first().map(|execution| ns(t0, execution.start));
        let first_apply_done = replay
            .iter()
            .filter_map(|execution| execution.end)
            .min()
            .map(|end| ns(t0, end));
        let replay_done = replay
            .iter()
            .filter_map(|execution| execution.end)
            .max()
            .map(|end| ns(t0, end));
        let candidate_execution = guard
            .executions
            .iter()
            .find(|execution| execution.height == depth + 1)
            .expect("candidate was not verified");
        let correct_root = candidate_execution.ok == Some(true);
        let verify_done = candidate_execution.end.map(|end| ns(t0, end));
        let (certified_at, certified) = guard.certify_result.expect("certify result");
        let finalize_vote_at = guard.finalize_vote_at.expect("finalize vote");
        let completion = ns(t0, finalize_vote_at);
        let executions_before_completion = guard
            .executions
            .iter()
            .filter(|execution| execution.end.is_some_and(|end| end <= finalize_vote_at))
            .count();
        let requested = guard
            .requests
            .iter()
            .map(|request| request.height)
            .collect::<Vec<_>>();
        let request_times = guard.requests.iter().map(|request| ns(t0, request.at));
        let request_peers = guard.requests.iter().map(|request| request.peer);
        let distinct = requested.iter().copied().collect::<BTreeSet<_>>();

        // Requests and producer answers are timestamped at the serving peer. With fixed latency
        // and no jitter, each request left the node about one latency before it arrived; the
        // earliest a response can reach the node is one latency after the producer answered.
        // These transport intervals are estimates, not node-side dispatch or delivery times.
        let latency = Duration::from_millis(scenario.latency_ms);
        let mut answered = guard.responses.clone();
        let intervals = guard
            .requests
            .iter()
            .map(|request| {
                let end = answered
                    .iter()
                    .position(|(at, height)| *height == request.height && *at >= request.at)
                    .map(|index| answered.remove(index).0 + latency);
                (request.at - latency, end)
            })
            .collect::<Vec<_>>();
        let max_inflight = intervals
            .iter()
            .map(|(start, _)| {
                intervals
                    .iter()
                    .filter(|(s, e)| s <= start && e.is_none_or(|e| *start < e))
                    .count()
            })
            .max()
            .unwrap_or(0);
        let first_arrival = intervals.iter().filter_map(|(_, end)| *end).min();
        let inflight_before_first_arrival = first_arrival.map_or(intervals.len(), |arrival| {
            intervals
                .iter()
                .filter(|(start, _)| *start < arrival)
                .count()
        });
        let first_response = guard.responses.first().map(|(at, _)| ns(t0, *at));
        let last_response = guard.responses.last().map(|(at, _)| ns(t0, *at));
        let response_order = guard.responses.iter().map(|(_, height)| *height);
        let hold_release = guard.hold_release.map_or_else(
            || "null".to_string(),
            |(at, reason)| format!("{{\"at_ns\":{},\"reason\":\"{reason}\"}}", ns(t0, at)),
        );
        let opt = |value: Option<u128>| value.map_or_else(|| "null".to_string(), |v| v.to_string());
        let fields = [
            format!("\"scenario\":\"{}\"", scenario.kind.name()),
            format!("\"seed\":{}", scenario.seed),
            format!("\"depth\":{depth}"),
            format!("\"window\":{}", scenario.window),
            format!("\"latency_ms\":{}", scenario.latency_ms),
            format!(
                "\"reports\":\"{}\"",
                if scenario.forward_reports {
                    "forward"
                } else {
                    "gated"
                }
            ),
            format!(
                "\"t0_abs_ns\":{}",
                t0.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            format!("\"first_apply_ns\":{}", opt(first_apply)),
            format!("\"first_apply_done_ns\":{}", opt(first_apply_done)),
            format!("\"replay_done_ns\":{}", opt(replay_done)),
            format!("\"completion_ns\":{completion}"),
            format!("\"verify_done_ns\":{}", opt(verify_done)),
            format!("\"certify_done_ns\":{}", ns(t0, certified_at)),
            format!(
                "\"target_verify_ns\":{}",
                opt(guard.target_verify_at.map(|at| ns(t0, at)))
            ),
            format!(
                "\"target_certify_ns\":{}",
                opt(guard.target_certify_at.map(|at| ns(t0, at)))
            ),
            format!("\"external_requests\":{}", requested.len()),
            format!("\"distinct_requested_bodies\":{}", distinct.len()),
            format!("\"other_requests\":{}", guard.other_requests),
            format!("\"max_inflight\":{max_inflight}"),
            format!("\"max_inflight_estimated\":{max_inflight}"),
            "\"transport_timing\":\"estimated_from_peer_timestamps_and_fixed_latency\"".to_string(),
            "\"completion\":\"peer_observed_finalize_vote\"".to_string(),
            format!(
                "\"requests_before_earliest_possible_arrival\":{inflight_before_first_arrival}"
            ),
            format!(
                "\"earliest_possible_body_arrival_ns\":{}",
                opt(first_arrival.map(|at| ns(t0, at)))
            ),
            format!("\"first_response_ns\":{}", opt(first_response)),
            format!("\"last_response_ns\":{}", opt(last_response)),
            format!("\"hold_release\":{hold_release}"),
            format!("\"local_heights\":{}", json_list(local.iter())),
            format!("\"requested_heights\":{}", json_list(requested.iter())),
            format!("\"request_ns\":{}", json_list(request_times)),
            format!("\"request_peers\":{}", json_list(request_peers)),
            format!(
                "\"request_kinds\":{}",
                json_list(
                    guard
                        .requests
                        .iter()
                        .map(|request| format!("\"{}\"", request.kind))
                )
            ),
            format!("\"proposes\":{}", guard.proposes),
            format!("\"response_order\":{}", json_list(response_order)),
            format!("\"apply_order\":{}", json_list(apply_order.iter())),
            format!(
                "\"apply_start_ns\":{}",
                json_list(replay.iter().map(|execution| ns(t0, execution.start)))
            ),
            format!(
                "\"replay_kinds\":{}",
                json_list(
                    replay
                        .iter()
                        .map(|execution| format!("\"{}\"", execution.kind))
                )
            ),
            format!("\"stub_verifies\":{}", guard.stub_verifies),
            format!("\"stub_certifies\":{}", guard.stub_certifies),
            format!("\"target_verifies\":{}", guard.target_verifies),
            format!("\"target_certifies\":{}", guard.target_certifies),
            format!("\"executions\":{}", guard.executions.len()),
            format!("\"executions_before_completion\":{executions_before_completion}"),
            format!("\"finalized_reports\":{}", guard.finalized_reports),
            format!("\"processed_height\":{processed_height}"),
            format!("\"correct_root\":{correct_root}"),
            format!("\"certified\":{certified}"),
        ];
        println!("E2E_FORWARD_HISTORY {{{}}}", fields.join(","));

        // Revision-independent correctness.
        assert!(correct_root, "candidate QMDB root mismatch");
        assert_eq!(
            processed_height, 0,
            "scripted ancestors advanced the processed floor"
        );
        assert_eq!(
            guard.finalized_reports, 0,
            "finalized blocks reached the application"
        );
        assert_eq!(
            guard.proposes, 0,
            "the measured node must not build proposals"
        );
        assert_eq!(
            guard.other_requests, 0,
            "peers received unknown or unserved request keys"
        );
        assert_eq!(
            guard.target_verifies, 1,
            "candidate verification must reach Deferred once"
        );
        assert_eq!(
            guard.target_certifies, 1,
            "candidate certification must reach Deferred once"
        );
        assert_eq!(
            guard.executions.len(),
            depth as usize + 1,
            "application executed blocks other than one replay of B1..BD and the candidate"
        );
        assert_eq!(
            executions_before_completion,
            depth as usize + 1,
            "replay and candidate verification must finish before the finalize vote"
        );
        assert!(
            replay.iter().all(|execution| execution.ok == Some(true)),
            "replayed QMDB roots differ from the selected blocks"
        );
        assert!(certified, "candidate was not certified");
        assert!(distinct.is_disjoint(&local), "local bodies were requested");
        assert_eq!(
            distinct, missing,
            "requested bodies differ from missing bodies"
        );
        assert_eq!(
            apply_order,
            (1..=depth).collect::<Vec<_>>(),
            "replay must execute every selected block once in forward order"
        );

        // Forward-pipeline properties expected of the forward-history revision.
        // A single held response gates the causal scenarios, so a duplicate request for the held
        // height could bypass the hold. Require each missing body to be requested exactly once.
        if matches!(scenario.kind, Kind::OutOfOrder | Kind::Tail) {
            assert_eq!(
                requested.len(),
                distinct.len(),
                "duplicate requests would bypass the causal hold"
            );
        }

        if scenario.assert_pipeline {
            if missing.len() >= 2 && scenario.window >= 2 {
                assert!(
                    inflight_before_first_arrival >= 2,
                    "missing bodies were not requested concurrently"
                );
            }
            if scenario.kind == Kind::Tail {
                let (released, reason) = guard.hold_release.expect("tail body never released");
                assert!(
                    first_apply_done.is_some_and(|done| done <= ns(t0, released)),
                    "no prefix block finished executing before the held body was released"
                );
                assert_eq!(
                    reason, "prefix_applied",
                    "replay did not start before the last missing body arrived"
                );
            }
            if scenario.kind == Kind::OutOfOrder {
                let (_, reason) = guard.hold_release.expect("held body never released");
                assert_eq!(reason, "higher_body_answered");
            }
        }
    });
}

#[test]
fn forward_history_local() {
    run(Scenario::new(Kind::Local));
}

#[test]
fn forward_history_cold() {
    run(Scenario::new(Kind::Cold));
}

#[test]
fn forward_history_mixed() {
    run(Scenario::new(Kind::Mixed));
}

#[test]
fn forward_history_out_of_order() {
    run(Scenario::new(Kind::OutOfOrder));
}

#[test]
fn forward_history_tail() {
    run(Scenario::new(Kind::Tail));
}

#[test]
fn forward_history_cold_depth_32() {
    let mut scenario = Scenario::new(Kind::Cold);
    scenario.depth = 32;
    run(scenario);
}

/// Entry point for repeated measurement runs driven by FH_* variables.
#[test]
#[ignore]
fn forward_history_env() {
    run(Scenario::new(Kind::Cold).with_env());
}

//! End-to-end forward-history replay through real Simplex, Marshal, and Stateful actors.
//!
//! One validator runs the production stack: a Simplex [`simplex::Engine`], the Standard
//! [`Deferred`] Marshal adapter, the Marshal core actor with its P2P resolver, and the
//! [`StatefulActor`] over a real QMDB. The test plays the other three validators over the
//! simulated network. It sends valid notarizations so the real voter selects a chain
//! `B1..BD` above the finalized genesis without warming application state, then sends one
//! public input event: the leader's proposal and notarization of the candidate `C = B(D+1)`.
//!
//! Peers answer Marshal block requests through real resolver P2P engines over simulated links
//! with fixed latency. Out-of-order and tail scenarios hold one response at the producer. Sparse
//! scenarios send the voter only the parent's notarization, so the history it supplies is a
//! suffix and Marshal discovers the commitments below the parent from block bodies.
//!
//! "Cold" means a cold in-memory application backlog above finality on a live node. No
//! scenario performs a persisted restart.

use super::{
    NoopQmdbResolver, build_chain_with_leaders,
    common::{
        EPOCH_LENGTH, IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, TEST_QUOTA, archive_config,
    },
    mocks::digested,
    single_db_app::{App, Block, SingleDatabaseSet, qmdb_config},
};
use crate::stateful::{
    Application, Config as StatefulConfig, Finality, Input, Proposed, Stateful as StatefulActor,
    SyncPlan,
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
        blocks::{Ancestry, Blocks},
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
    types::{Epoch, FixedEpocher, Round, View, ViewDelta},
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
    Clock as _, Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::prunable;
use commonware_utils::{
    NZDuration, NZU64, NZUsize, channel::oneshot, non_empty, ordered::Set, probability, sync::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, SystemTime},
};

type S = MockScheme<ed25519::PublicKey>;
type D = sha256::Digest;
type P = ed25519::PublicKey;
type Ctx = Context<D, P>;

const N: usize = 4;
const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FORWARD_HISTORY_E2E";
const VOTES: u64 = 0;
const CERTIFICATES: u64 = 1;
const SIMPLEX_RESOLVER: u64 = 2;
const BACKFILL: u64 = 3;
const BROADCAST: u64 = 4;

/// Selected blocks `B1..BD` below the candidate.
const DEPTH: u64 = 8;

/// Marshal's repair window. It also bounds a range's pending bodies.
const WINDOW: usize = 3;

/// One-way latency of every simulated link.
const LATENCY: Duration = Duration::from_millis(20);

/// Upper bound on a producer-held response, so a run that cannot satisfy a gate still finishes.
const HOLD_LIMIT: Duration = Duration::from_secs(3);

/// Interval at which the test polls for a condition.
const POLL: Duration = Duration::from_millis(1);

/// Quiet period before the input event, in which any premature request or execution would show.
const SETTLE: Duration = Duration::from_millis(500);

/// Hang guard for a whole run.
const RUN_LIMIT: Duration = Duration::from_secs(600);

/// Timeout of one resolver fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Delay before a resolver retries a fetch.
const FETCH_RETRY: Duration = Duration::from_millis(100);

/// Simplex leader and retry timeout, long enough that no view times out during a run.
const VIEW_TIMEOUT: Duration = Duration::from_secs(300);

/// Simplex certification timeout, long enough that no certification times out during a run.
const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(400);

/// Which bodies are local and how peers order their responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Every selected body is buffered locally before the input event.
    Local,
    /// Only the parent `BD` and the candidate are local, and peers answer immediately.
    Cold,
    /// Odd heights and the parent are local, and the remaining bodies are fetched.
    Mixed,
    /// As `Cold`, but the lowest missing body is held until a higher body has been answered.
    OutOfOrder,
    /// As `Cold`, but the missing body at index [`WINDOW`] of the missing heights, or the last
    /// one, is held until the application executes a block below it, so only a forward prefix
    /// can execute before it arrives.
    Tail,
}

/// Body placement and notarization shape of one run.
#[derive(Clone, Copy, Debug)]
struct Scenario {
    /// Which bodies are local and how peers order their responses.
    kind: Kind,

    /// Whether the voter receives a notarization for the parent `BD` alone. Otherwise it
    /// receives one for each of `B1..BD`.
    sparse: bool,
}

impl Scenario {
    /// Returns the scenario with a notarization for each of `B1..BD`.
    const fn new(kind: Kind) -> Self {
        Self {
            kind,
            sparse: false,
        }
    }

    /// Returns the scenario with only the parent's notarization sent to the voter.
    const fn sparse(mut self) -> Self {
        self.sparse = true;
        self
    }

    /// Heights of `B1..BD` whose bodies are buffered locally before the input event.
    fn local_heights(&self) -> BTreeSet<u64> {
        (1..=DEPTH)
            .filter(|&height| match self.kind {
                Kind::Local => true,
                Kind::Mixed => height == DEPTH || height % 2 == 1,
                Kind::Cold | Kind::OutOfOrder | Kind::Tail => height == DEPTH,
            })
            .collect()
    }
}

/// Application execution observed through the instrumented wrapper.
#[derive(Clone, Debug)]
struct Execution {
    height: u64,
    end: Option<SystemTime>,
    ok: Option<bool>,
}

/// One external block request observed by a peer's resolver producer.
#[derive(Clone, Debug)]
struct Request {
    at: SystemTime,
    height: u64,
}

/// Everything a run observes at the application, the gate, and the scripted peers.
#[derive(Default)]
struct Observations {
    t0: Option<SystemTime>,
    executions: Vec<Execution>,
    requests: Vec<Request>,
    responses: Vec<(SystemTime, u64)>,
    other_requests: usize,
    held: Option<(u64, oneshot::Sender<Bytes>, Bytes)>,
    hold_release: Option<&'static str>,
    stub_certified: u64,
    target_verifies: usize,
    target_certifies: usize,
    finalized_reports: usize,
    inner_calls_before_t0: usize,
    certified: Option<bool>,
    finalize_vote_at: Option<SystemTime>,
}

type Shared = Arc<Mutex<Observations>>;

/// Values the assertions read, derived from the observations of one run.
struct Outcome<'a> {
    /// Executions of `B1..BD` in observed order.
    replay: Vec<&'a Execution>,
    /// Heights of `B1..BD` in execution order.
    apply_order: Vec<u64>,
    /// Whether the candidate's execution matched its state root.
    correct_root: bool,
    /// Executions that ended by the time a peer first received the node's finalize vote for the
    /// candidate.
    executions_before_completion: usize,
    /// Heights of every body request, in arrival order at the peers.
    requested: Vec<u64>,
    /// Distinct requested heights.
    distinct: BTreeSet<u64>,
    /// Requests estimated to have left the node before the first response reached it.
    inflight_before_first_arrival: usize,
}

impl<'a> Outcome<'a> {
    /// Derives the outcome of a finished run, panicking if the candidate was never executed or no
    /// peer observed the node's finalize vote for it.
    fn derive(observations: &'a Observations) -> Self {
        // Replay order, candidate result, and execution progress when a peer first received the
        // finalize vote.
        let replay = observations
            .executions
            .iter()
            .filter(|execution| execution.height <= DEPTH)
            .collect::<Vec<_>>();
        let apply_order = replay
            .iter()
            .map(|execution| execution.height)
            .collect::<Vec<_>>();
        let candidate_execution = observations
            .executions
            .iter()
            .find(|execution| execution.height == DEPTH + 1)
            .expect("the candidate must be executed");
        let correct_root = candidate_execution.ok == Some(true);
        let finalize_vote_at = observations
            .finalize_vote_at
            .expect("the node must vote to finalize the candidate");
        let executions_before_completion = observations
            .executions
            .iter()
            .filter(|execution| execution.end.is_some_and(|end| end <= finalize_vote_at))
            .count();

        // Every request in arrival order, and the distinct heights requested.
        let requested = observations
            .requests
            .iter()
            .map(|request| request.height)
            .collect::<Vec<_>>();
        let distinct = requested.iter().copied().collect::<BTreeSet<_>>();

        // Requests and producer answers are timestamped at the serving peer. With fixed latency
        // and no jitter, each request left the node about one latency before it arrived, and a
        // response reaches the node no earlier than one latency after the producer answered.
        // These transport intervals are estimates, not node-side dispatch or delivery times.
        let mut answered = observations.responses.clone();
        let intervals = observations
            .requests
            .iter()
            .map(|request| {
                let end = answered
                    .iter()
                    .position(|(at, height)| *height == request.height && *at >= request.at)
                    .map(|index| answered.remove(index).0 + LATENCY);
                (request.at - LATENCY, end)
            })
            .collect::<Vec<_>>();
        let first_arrival = intervals.iter().filter_map(|(_, end)| *end).min();
        let inflight_before_first_arrival = first_arrival.map_or(intervals.len(), |arrival| {
            intervals
                .iter()
                .filter(|(start, _)| *start < arrival)
                .count()
        });

        Self {
            replay,
            apply_order,
            correct_root,
            executions_before_completion,
            requested,
            distinct,
            inflight_before_first_arrival,
        }
    }
}

/// Wraps the single-database application and records every application execution.
#[derive(Clone)]
struct InstrumentedApp {
    inner: App,
    observations: Shared,
}

impl InstrumentedApp {
    /// Records the start of an execution at `height` and returns its index.
    fn begin(&self, height: u64) -> usize {
        let mut observations = self.observations.lock();
        if observations.t0.is_none() {
            observations.inner_calls_before_t0 += 1;
        }
        observations.executions.push(Execution {
            height,
            end: None,
            ok: None,
        });
        observations.executions.len() - 1
    }

    /// Records the end of execution `index` and whether its root matched the block.
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
        ancestry: Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let proposed = <App as Application<deterministic::Context>>::propose(
            &mut self.inner,
            context,
            ancestry,
            batches,
            input,
        )
        .await?;
        Some(Proposed {
            block: proposed.block,
            merkleized: proposed.merkleized,
        })
    }

    async fn process(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: Digested<Self::Block>,
        blocks: Blocks<Self::Block>,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        finality: Finality,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        let runtime = context.0.child("instrument");
        let index = self.begin(block.height().get());
        let expected_root = block.inner().state_root;
        let result = <App as Application<deterministic::Context>>::process(
            &mut self.inner,
            context,
            block,
            blocks,
            batches,
            finality,
        )
        .await;
        let root_matches = result
            .as_ref()
            .is_some_and(|merkleized| merkleized.root() == expected_root);
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
/// independent verification or certification job prepares application state before the input
/// event. Requests for the candidate view are forwarded unchanged with the voter's history.
/// Activity below the candidate view is not forwarded, and proposals are never produced.
#[derive(Clone)]
struct Gate<A> {
    context: Arc<deterministic::Context>,
    inner: A,
    target: View,
    observations: Shared,
    proposals: Arc<Mutex<Vec<oneshot::Sender<D>>>>,
}

impl<A> Automaton for Gate<A>
where
    A: Automaton<Context = Ctx, Digest = D>,
{
    type Context = Ctx;
    type Digest = D;

    fn propose(
        &mut self,
        _context: Self::Context,
        _history: History<Self::Digest>,
    ) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        self.proposals.lock().push(sender);
        receiver
    }

    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
        history: History<Self::Digest>,
    ) -> oneshot::Receiver<bool> {
        if context.round.view() == self.target {
            self.observations.lock().target_verifies += 1;
            return self.inner.verify(context, payload, history);
        }
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(true);
        receiver
    }
}

impl<A> CertifiableAutomaton for Gate<A>
where
    A: CertifiableAutomaton<Context = Ctx, Digest = D>,
{
    fn certify(
        &mut self,
        round: Round,
        payload: Self::Digest,
        history: History<Self::Digest>,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        if round.view() != self.target {
            {
                let mut observations = self.observations.lock();
                observations.stub_certified = observations.stub_certified.max(round.view().get());
            }
            let _ = sender.send(true);
            return receiver;
        }
        self.observations.lock().target_certifies += 1;
        let inner = self.inner.certify(round, payload, history);
        let observations = self.observations.clone();
        self.context
            .child("target_certify")
            .spawn(move |_| async move {
                if let Ok(result) = inner.await {
                    observations.lock().certified = Some(result);
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
        if activity.view() < self.target {
            return Feedback::Ok;
        }
        self.inner.report(activity)
    }
}

/// Serves Marshal block requests on behalf of one scripted peer.
#[derive(Clone)]
struct ScriptedProducer {
    context: Arc<deterministic::Context>,
    kind: Kind,
    bodies: Arc<HashMap<D, (u64, Bytes)>>,
    missing: Arc<BTreeSet<u64>>,
    tail: Option<u64>,
    observations: Shared,
}

impl ScriptedProducer {
    /// Records an answer for `height` at `at`.
    fn respond(observations: &mut Observations, at: SystemTime, height: u64) {
        observations.responses.push((at, height));
    }

    /// Answers the held request, if any, and records why it was released.
    fn release(observations: &mut Observations, at: SystemTime, reason: &'static str) {
        if let Some((height, sender, body)) = observations.held.take() {
            let _ = sender.send(body);
            Self::respond(observations, at, height);
            observations.hold_release = Some(reason);
        }
    }

    /// Releases the held request once a `Tail` scenario has executed a block below the held
    /// height, or once [`HOLD_LIMIT`] elapses.
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
                context.sleep(POLL).await;
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

        let found = match key {
            Key::Block(digest) => self.bodies.get(&digest).cloned(),
            Key::Notarized { .. } | Key::Finalized { .. } => None,
        };
        let Some((height, body)) = found else {
            observations.other_requests += 1;
            return receiver;
        };
        observations.requests.push(Request { at: now, height });

        // `OutOfOrder` holds the lowest missing body and `Tail` the body at its tail height,
        // each once per run.
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

        // Answer at once, and release an `OutOfOrder` hold once a higher body has been answered.
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

/// Returns the proposal that names `block`'s round, parent view, and digest.
fn proposal(block: &Block) -> Proposal<D> {
    Proposal::new(block.context.round, block.context.parent.0, block.digest())
}

/// Returns a notarization of `block` assembled from the votes of the validators at `signers`.
fn notarization(schemes: &[S], signers: &[usize], block: &Block) -> Notarization<S, D> {
    let votes = signers
        .iter()
        .map(|&index| Notarize::sign(&schemes[index], proposal(block)).unwrap())
        .collect::<Vec<_>>();
    Notarization::from_notarizes(&schemes[signers[0]], non_empty![@&votes], &Sequential).unwrap()
}

/// Runs `scenario` against one production node and checks that the candidate verifies on a
/// single forward replay of `B1..BD` that requests exactly the missing bodies.
fn run(scenario: Scenario) {
    deterministic::Runner::timed(RUN_LIMIT).start(|context| async move {
        // Four validators, with the candidate at the view after `B1..BD`.
        let depth = DEPTH;
        let target = View::new(depth + 1);
        let mut rng = context.child("fixture");
        let fixture = scheme_mocks::fixture(&mut rng, NAMESPACE, N as u32);
        let participants = fixture.participants.clone();
        let schemes = fixture.schemes.clone();

        // The node under test never leads the candidate view.
        let me = ((depth + 2) as usize) % N;
        let peers = (0..N).filter(|&index| index != me).collect::<Vec<_>>();
        let candidate_leader = (depth + 1) as usize % N;
        assert_ne!(candidate_leader, me);

        // The chain's contexts name the leaders the real voter elects for its rounds.
        let (genesis, chain) = build_chain_with_leaders(&context, depth + 1, |view| {
            leader(&participants, view).clone()
        })
        .await;
        let candidate = chain.last().expect("chain must not be empty").clone();
        let selected = &chain[..depth as usize];

        // Peers serve every body by digest. The scenario decides which selected bodies
        // are already local.
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
            latency: LATENCY,
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
            let (vote_sender, mut vote_receiver) =
                control.register(VOTES, TEST_QUOTA).await.unwrap();
            let (certificate_sender, certificate_receiver) =
                control.register(CERTIFICATES, TEST_QUOTA).await.unwrap();
            let simplex_resolver = control
                .register(SIMPLEX_RESOLVER, TEST_QUOTA)
                .await
                .unwrap();
            peer_channels.push((certificate_receiver, simplex_resolver));
            let backfill = control.register(BACKFILL, TEST_QUOTA).await.unwrap();
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
                        kind: scenario.kind,
                        bodies: bodies.clone(),
                        missing: missing_shared.clone(),
                        tail: missing
                            .iter()
                            .nth(WINDOW.min(missing.len().saturating_sub(1)))
                            .copied(),
                        observations: observations.clone(),
                    },
                    mailbox_size: NZUsize!(1024),
                    me: Some(participants[index].clone()),
                    fetch_timeout: NZDuration!(FETCH_TIMEOUT),
                    fetch_retry_delay: FETCH_RETRY,
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
            .register(BROADCAST, TEST_QUOTA)
            .await
            .unwrap();
        let (leader_engine, leader_buffer) = buffered::Engine::<_, P, Block, _, _, _>::new(
            context.child("leader_broadcast"),
            buffered::Config {
                public_key: participants[candidate_leader].clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: 1024,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
                blocker: oracle.control(participants[candidate_leader].clone()),
                strategy: Sequential,
            },
        );
        leader_engine.start(leader_broadcast);

        // Node under test: production wiring as in the single-database engine.
        let public_key = participants[me].clone();
        let control = oracle.control(public_key.clone());
        let vote_network = control.register(VOTES, TEST_QUOTA).await.unwrap();
        let certificate_network = control.register(CERTIFICATES, TEST_QUOTA).await.unwrap();
        let resolver_network = control
            .register(SIMPLEX_RESOLVER, TEST_QUOTA)
            .await
            .unwrap();
        let backfill_network = control.register(BACKFILL, TEST_QUOTA).await.unwrap();
        let broadcast_network = control.register(BROADCAST, TEST_QUOTA).await.unwrap();
        let node = context.child("node");
        let prefix = "forward-history".to_string();
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        let resolver = marshal_resolver::init(
            node.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(1024),
                fetch_timeout: NZDuration!(FETCH_TIMEOUT),
                fetch_retry_delay: FETCH_RETRY,
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
                blocker: control.clone(),
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
                    max_repair: NZUsize!(WINDOW),
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
                leader_timeout: VIEW_TIMEOUT,
                certification_timeout: CERTIFICATION_TIMEOUT,
                timeout_retry: VIEW_TIMEOUT,
                view_retention: ViewDelta::new(1024),
                skip: SkipPolicy::Disabled,
                fetch_timeout: NZDuration!(FETCH_TIMEOUT),
                fetch_retry_delay: FETCH_RETRY,
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        let _engine_handle = engine.start(vote_network, certificate_network, resolver_network);

        // Select B1..BD through the real voter with valid notarizations from three peers. A
        // sparse scenario sends only BD's, so every older link stays missing.
        let signers = &peers[..3];
        let sender = peers[0];
        let certified = if scenario.sparse {
            &selected[selected.len() - 1..]
        } else {
            selected
        };
        for block in certified {
            let certificate = Certificate::Notarization(notarization(&schemes, signers, block));
            peer_certificates.get_mut(&sender).unwrap().send(
                Recipients::One(public_key.clone()),
                certificate.encode(),
                true,
            );
        }
        while observations.lock().stub_certified < depth {
            context.sleep(POLL).await;
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
                context.sleep(POLL).await;
            }
        }
        context.sleep(SETTLE).await;

        // Nothing requests a body, runs the application, or verifies the candidate before the
        // input event.
        {
            let guard = observations.lock();
            assert!(
                guard.requests.is_empty(),
                "blocks must not be requested before the input event"
            );
            assert_eq!(
                guard.inner_calls_before_t0, 0,
                "the application must not run before the input event"
            );
            assert_eq!(guard.target_verifies, 0);
        }

        // Public input event: the leader's proposal and the candidate's notarization.
        observations.lock().t0 = Some(context.current());
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

        // Wait for the node's finalize vote and the candidate's certification.
        loop {
            {
                let guard = observations.lock();
                if guard.finalize_vote_at.is_some() && guard.certified.is_some() {
                    break;
                }
            }
            context.sleep(POLL).await;
        }
        drop(peer_channels);
        drop(peer_resolvers);

        // Scripted ancestors must never be finalized or processed.
        let processed_height = marshal
            .get_processed()
            .await
            .map_or(0, |processed| processed.height().get());

        // The candidate verifies and certifies once, on one forward replay of `B1..BD` that
        // requests exactly the missing bodies and finalizes nothing.
        let guard = observations.lock();
        let outcome = Outcome::derive(&guard);
        assert!(
            outcome.correct_root,
            "candidate QMDB root must match its block"
        );
        assert_eq!(
            processed_height, 0,
            "scripted ancestors must not advance the processed floor"
        );
        assert_eq!(
            guard.finalized_reports, 0,
            "finalized blocks must not reach the application"
        );
        assert_eq!(
            guard.other_requests, 0,
            "peers must receive only served request keys"
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
            "the application must execute only one replay of B1..BD and the candidate"
        );
        assert_eq!(
            outcome.executions_before_completion,
            depth as usize + 1,
            "replay and candidate verification must finish before the finalize vote"
        );
        assert!(
            outcome
                .replay
                .iter()
                .all(|execution| execution.ok == Some(true)),
            "replayed QMDB roots must match the selected blocks"
        );
        assert_eq!(guard.certified, Some(true), "the candidate must certify");
        assert!(
            outcome.distinct.is_disjoint(&local),
            "local bodies must not be requested"
        );
        assert_eq!(
            outcome.distinct, missing,
            "requested bodies must equal the missing bodies"
        );
        assert_eq!(
            outcome.apply_order,
            (1..=depth).collect::<Vec<_>>(),
            "replay must execute every selected block once in forward order"
        );

        // A single held response gates the causal scenarios, so a duplicate request for the held
        // height could bypass the hold. Require each missing body to be requested exactly once.
        if matches!(scenario.kind, Kind::OutOfOrder | Kind::Tail) {
            assert_eq!(
                outcome.requested.len(),
                outcome.distinct.len(),
                "each missing body must be requested once"
            );
        }

        // Bodies missing under a complete history are requested concurrently. Below a suffix,
        // each commitment is discovered from the body above it, so they are requested one at a
        // time.
        if missing.len() >= 2 && !scenario.sparse {
            assert!(
                outcome.inflight_before_first_arrival >= 2,
                "missing bodies must be requested concurrently"
            );
        }

        // The held body is released by the event its scenario waits for.
        if scenario.kind == Kind::Tail {
            let reason = guard.hold_release.expect("tail body must be released");
            assert_eq!(
                reason, "prefix_applied",
                "replay must start before the held body arrives"
            );
        }
        if scenario.kind == Kind::OutOfOrder {
            let reason = guard.hold_release.expect("held body must be released");
            assert_eq!(reason, "higher_body_answered");
        }
    });
}

#[test]
fn local() {
    run(Scenario::new(Kind::Local));
}

#[test]
fn cold() {
    run(Scenario::new(Kind::Cold));
}

#[test]
fn mixed() {
    run(Scenario::new(Kind::Mixed));
}

#[test]
fn out_of_order() {
    run(Scenario::new(Kind::OutOfOrder));
}

#[test]
fn tail() {
    run(Scenario::new(Kind::Tail));
}

#[test]
fn sparse_local() {
    run(Scenario::new(Kind::Local).sparse());
}

#[test]
fn sparse_cold() {
    run(Scenario::new(Kind::Cold).sparse());
}

//! A reusable deterministic Multimmit cluster over the simulated network.
//!
//! The harness launches complete production engines (ingress, verifier, voter, resolver, storage)
//! for one committee, each with its own marshal (custody, ordering, delivery), with per-node
//! crash/restart, link partitions, and finality and delivery assertions. It runs only under the
//! deterministic runtime; wall-clock schedules replay exactly per seed.

#[cfg(test)]
use crate::multimmit::storage::partitions;
use crate::{
    Reporter, Reporters,
    multimmit::{
        actors::voter,
        config::{LeaderSchedule, Tuning},
        engine::{CHECKPOINT_INTERVAL, Config as EngineConfig, Engine, Planes, Running},
        machine::{Generation, Inspection},
        marshal::OutputIndex,
        mocks::{
            Committee, MockApplication,
            facts::{FactLog, Facts},
            marshaled::{
                ClusterApplication, ClusterBroadcast, ClusterMarshal, Deliveries, Marshaled,
            },
        },
        types::{Activity, BlockRef, ChainId, Window},
    },
    types::{Participant, View, ViewDelta},
};
use commonware_actor::Feedback;
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::Variant, ed25519,
    ed25519::PrivateKey as Ed25519PrivateKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::simulated::{
    Config as NetworkConfig, Control, Link, Network, Oracle, Receiver as SimulatedReceiver,
    Sender as SimulatedSender,
};
#[cfg(test)]
use commonware_p2p::{LimitedSender, Recipients};
use commonware_parallel::Sequential;
#[cfg(test)]
use commonware_runtime::Storage as _;
#[cfg(test)]
use commonware_runtime::telemetry::metrics::count_running_tasks;
use commonware_runtime::{
    Clock as _, Quota, Spawner, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
};
use commonware_utils::{NZUsize, probability, sync::Mutex};
use rand_core::CryptoRng;
#[cfg(test)]
use std::time::SystemTime;
use std::{
    collections::HashMap,
    future::{self, Future},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{Arc, LazyLock},
    time::Duration,
};

/// Mixed into the cluster seed for extra, non-committee identities.
const EXTRA_IDENTITY_SEED_MASK: u64 = 0xdead_beef;

/// How often the wait helpers poll production and finality progress.
const PROGRESS_POLL: Duration = Duration::from_millis(100);

/// How often [`Cluster::wait_view`] polls view progress.
const VIEW_POLL: Duration = Duration::from_millis(10);

/// Simulated-network channel of the transaction-block data plane.
pub const DATA_CHANNEL: u64 = 0;

/// Simulated-network channel of the vote and proposal plane.
pub const CONSENSUS_CHANNEL: u64 = 1;

/// Simulated-network channel of the certificate plane.
pub const CERTIFICATE_CHANNEL: u64 = 2;

/// Simulated-network channel of the retrieval plane.
pub const RESOLVER_CHANNEL: u64 = 3;

/// Simulated-network channel of marshal's block-body broadcast.
pub const BODIES_CHANNEL: u64 = 4;

/// Simulated-network channel of marshal's backfill resolver.
pub const BACKFILL_CHANNEL: u64 = 5;

type MockEngineConfig<V> = EngineConfig<
    Sha256,
    ed25519::PublicKey,
    V,
    ClusterApplication<V>,
    ClusterBroadcast,
    Reporters<ClusterMarshal<V>, Reporters<Facts<V>, ClusterReporter<V>>>,
    Sequential,
    Sequential,
    Control<ed25519::PublicKey, deterministic::Context>,
>;

type ActivityCallback<V> = Box<dyn FnMut(Activity<V, Sha256Digest>) -> Feedback + Send + 'static>;

#[derive(Clone)]
struct ClusterReporter<V: Variant> {
    callback: Option<Arc<Mutex<ActivityCallback<V>>>>,
}

impl<V: Variant> ClusterReporter<V> {
    fn attached(callback: ActivityCallback<V>) -> Self {
        Self {
            callback: Some(Arc::new(Mutex::new(callback))),
        }
    }
}

impl<V: Variant> Default for ClusterReporter<V> {
    fn default() -> Self {
        Self { callback: None }
    }
}

impl<V: Variant> Reporter for ClusterReporter<V> {
    type Activity = Activity<V, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.callback
            .as_ref()
            .map_or(Feedback::Ok, |callback| callback.lock()(activity))
    }
}

/// Immutable cluster parameters.
#[derive(Clone, Debug)]
pub struct ClusterOptions {
    /// Committee size.
    pub n: u32,
    /// Deterministic key/epoch seed.
    pub seed: u64,
    /// Extra non-committee network identities.
    pub extras: u32,
    /// Explicit leader schedule; round-robin when absent.
    pub leaders: Option<LeaderSchedule>,
    /// Per-peer, per-plane message rate.
    ///
    /// A deployment rate-limits every plane. Multimmit exits a view as soon as its V-QC forms, so
    /// its message rate is set by the network rather than by a timer, and a quota sized for one
    /// view per second starves view exits while the producer chains keep running.
    pub quota: Quota,
    /// One-way link latency.
    pub latency: Duration,
    /// Uniform per-message link jitter.
    ///
    /// Jitter desynchronizes the replicas' view and ordering schedules, which is what surfaces
    /// interleavings a uniform-latency cluster can never produce.
    pub jitter: Duration,
    /// Retained views below the current one.
    pub view_retention: ViewDelta,
    /// Producer window: the cap and flow of each chain's unresolved heights.
    pub window: Window,
}

impl Default for ClusterOptions {
    /// A six-node committee over unlimited, low-latency, lossless links.
    fn default() -> Self {
        Self {
            n: 6,
            seed: 0,
            extras: 0,
            leaders: None,
            quota: QUOTA,
            latency: DEFAULT_LATENCY,
            jitter: Duration::ZERO,
            // Deterministic scenarios run hundreds of views, so keep the retained window small
            // enough that retirement is exercised without holding every view.
            view_retention: ViewDelta::new(16),
            window: Window::new(4).expect("default window is valid"),
        }
    }
}

impl ClusterOptions {
    /// Creates a cluster configuration with the supplied key seed and committee size.
    pub fn new(seed: u64, n: u32) -> Self {
        Self {
            n,
            seed,
            ..Self::default()
        }
    }
}

/// One network plane whose sends a test can block per recipient.
#[derive(Clone, Copy, Debug)]
pub enum Plane {
    /// The transaction-block data plane.
    Data,
    /// The vote and proposal plane.
    Consensus,
    /// The certificate plane.
    Certificates,
    /// Marshal's block-body broadcast.
    Bodies,
}

/// Per-node state that tests inspect or steer.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    /// Task label prefix of the running engine.
    task_prefix: Option<String>,
    /// Blocked recipients per [`Plane`].
    blocked: [Arc<Mutex<Vec<ed25519::PublicKey>>>; 4],
}

/// One engine slot: its application, running engine, observed finality, reported facts, and
/// delivered outputs.
struct Node<V: Variant> {
    app: MockApplication,
    engine: Option<RunningEngine<V>>,
    finality: FinalityHistory,
    facts: Arc<Mutex<FactLog>>,
    deliveries: Deliveries,
    generation: usize,
    #[cfg(test)]
    hooks: TestHooks,
}

impl<V: Variant> Node<V> {
    #[allow(
        clippy::missing_const_for_fn,
        reason = "test builds initialize hooks, which is not const"
    )]
    fn new(app: MockApplication) -> Self {
        Self {
            app,
            engine: None,
            finality: FinalityHistory::new(),
            facts: Arc::default(),
            deliveries: Deliveries::default(),
            generation: 0,
            #[cfg(test)]
            hooks: TestHooks::default(),
        }
    }
}

/// Which slot an engine occupies and where its activity goes.
pub struct LaunchSpec<V: Variant> {
    slot: usize,
    reporter: ClusterReporter<V>,
}

impl<V: Variant> LaunchSpec<V> {
    /// Launches `slot`, labelled by slot and generation, with activity discarded.
    pub fn new(slot: usize) -> Self {
        Self {
            slot,
            reporter: ClusterReporter::default(),
        }
    }

    /// Sends the engine's best-effort activity to `reporter`.
    pub fn reporter<S>(mut self, mut reporter: S) -> Self
    where
        S: Reporter<Activity = Activity<V, Sha256Digest>>,
    {
        self.reporter =
            ClusterReporter::attached(Box::new(move |activity| reporter.report(activity)));
        self
    }
}

/// How [`Cluster::launch_racing`] ended.
#[derive(Debug)]
pub enum Launch<T> {
    /// The engine opened and started.
    Started,
    /// The interrupt resolved first; the open was abandoned and nothing started.
    Interrupted(T),
}

/// The sender a cluster registers for one of its own planes; tests can block its recipients.
#[cfg(test)]
type OwnSender = BlockingSender<SimulatedSender<ed25519::PublicKey, deterministic::Context>>;
#[cfg(not(test))]
type OwnSender = SimulatedSender<ed25519::PublicKey, deterministic::Context>;

/// The planes a cluster registers for an engine it launches over its own identity.
type OwnPlanes = Planes<OwnSender, SimulatedReceiver<ed25519::PublicKey>>;

/// One deterministic cluster of complete Multimmit engines.
pub struct Cluster<V: Variant> {
    options: ClusterOptions,
    producers: Vec<Participant>,
    context: deterministic::Context,
    oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
    identities: Vec<ed25519::PublicKey>,
    nodes: Vec<Node<V>>,
    checkpoint_interval: NonZeroU64,
    production_policy: ProductionPolicy,
}

struct RunningEngine<V: Variant> {
    engine: Running<Sha256Digest>,
    flusher: voter::Flusher,
    marshal: Option<Marshaled<V>>,
}

impl<V: Variant> RunningEngine<V> {
    fn abort(&mut self) {
        self.engine.abort();
        if let Some(marshal) = &mut self.marshal {
            marshal.abort();
        }
    }

    /// Waits for every aborted task and asserts that marshal had not failed before the abort.
    async fn join(self) {
        // The engine was aborted first, so its root task reports the abort.
        let _ = self.engine.join().await;
        if let Some(marshal) = self.marshal
            && let Err(error) = marshal.join().await
        {
            panic!("marshal failed before the engine stopped: {error:?}");
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct BlockingSender<S> {
    inner: S,
    me: ed25519::PublicKey,
    identities: Vec<ed25519::PublicKey>,
    blocked: Arc<Mutex<Vec<ed25519::PublicKey>>>,
}

#[cfg(test)]
impl<S> LimitedSender for BlockingSender<S>
where
    S: LimitedSender<PublicKey = ed25519::PublicKey>,
{
    type PublicKey = ed25519::PublicKey;
    type Checked<'a>
        = S::Checked<'a>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let blocked = self.blocked.lock().clone();
        if blocked.is_empty() {
            return self.inner.check(recipients);
        }

        let allowed = |peer: &ed25519::PublicKey| !blocked.contains(peer);
        let recipients = match recipients {
            Recipients::All => Recipients::Some(
                self.identities
                    .iter()
                    .filter(|peer| *peer != &self.me && allowed(peer))
                    .cloned()
                    .collect(),
            ),
            Recipients::Some(peers) => {
                Recipients::Some(peers.into_iter().filter(allowed).collect())
            }
            Recipients::One(peer) if allowed(&peer) => Recipients::One(peer),
            Recipients::One(_) => Recipients::Some(Vec::new()),
        };
        self.inner.check(recipients)
    }
}

#[derive(Clone)]
struct FinalityHistory {
    generation: Generation,
    last_resolved: View,
}

impl FinalityHistory {
    const fn new() -> Self {
        Self {
            generation: Generation::new(0),
            last_resolved: View::zero(),
        }
    }

    fn observe(&mut self, node: usize, inspection: &Inspection<Sha256Digest>) {
        // Inspection includes staged journal events. An unclean restart may discard that
        // unsynced suffix, but progress remains monotonic within each process generation.
        let restarted = inspection.generation() > self.generation;
        assert!(
            inspection.generation() >= self.generation,
            "engine {node} generation regressed"
        );
        assert!(
            restarted || inspection.last_resolved() >= self.last_resolved,
            "engine {node} resolved view regressed from {} to {}",
            self.last_resolved,
            inspection.last_resolved(),
        );
        self.generation = inspection.generation();
        self.last_resolved = inspection.last_resolved();
    }
}

#[derive(Clone, Copy)]
enum ProductionPolicy {
    Paused,
    Continuous,
    Every { interval: usize, polls: usize },
}

impl<V: Variant> Cluster<V> {
    /// Builds the committee, simulated network, and fully connected links.
    pub async fn new(context: &deterministic::Context, options: ClusterOptions) -> Self {
        let producers: Vec<_> = (0..options.n).map(Participant::new).collect();
        let committee = Self::committee(&options, &producers);
        let mut identities = committee.identities.clone();
        for extra in 0..options.extras {
            identities.push(
                Ed25519PrivateKey::from_seed(
                    options.seed ^ EXTRA_IDENTITY_SEED_MASK ^ u64::from(extra),
                )
                .public_key(),
            );
        }
        let oracle = start_network(context, identities.clone(), 4 * 1024 * 1024).await;

        let mut cluster = Self {
            options,
            producers,
            context: context.child("cluster"),
            oracle,
            identities,
            nodes: Vec::new(),
            checkpoint_interval: CHECKPOINT_INTERVAL,
            production_policy: ProductionPolicy::Paused,
        };
        cluster.heal().await;
        cluster
    }

    fn committee(options: &ClusterOptions, producers: &[Participant]) -> Committee<V> {
        let mut committee = Committee::builder(options.seed, options.n)
            .producers(producers.to_vec())
            .window(options.window);
        if let Some(leaders) = &options.leaders {
            committee = committee.leaders(leaders.clone());
        }
        committee.build()
    }

    /// Returns every identity in committee order, followed by any extras.
    pub fn identities(&self) -> Vec<ed25519::PublicKey> {
        self.identities.clone()
    }

    /// Returns whether any engine has started.
    #[cfg(test)]
    fn started(&self) -> bool {
        self.nodes.iter().any(|node| node.generation > 0)
    }

    /// Sets the journal events between machine checkpoints before any engine starts.
    #[cfg(test)]
    pub fn set_checkpoint_interval(&mut self, checkpoint_interval: NonZeroU64) {
        assert!(
            !self.started(),
            "checkpoint interval must be set before any engine starts"
        );
        self.checkpoint_interval = checkpoint_interval;
    }

    /// Starts one committee engine without waiting for readiness.
    pub async fn start_one(&mut self, index: usize) {
        self.launch(LaunchSpec::new(index)).await;
    }

    /// Adds default slots until `index` exists.
    fn ensure_slot(&mut self, index: usize) {
        while self.nodes.len() <= index {
            self.reserve_slot("");
        }
    }

    /// Waits for every listed engine to become ready.
    pub async fn await_ready(&mut self, nodes: &[usize]) {
        for &index in nodes {
            let ready = self.nodes[index]
                .engine
                .as_mut()
                .expect("engine launched")
                .engine
                .ready()
                .await;
            assert!(ready.is_ok(), "engine {index} becomes ready");
        }
    }

    /// Returns every committee slot, in participant order.
    pub fn all_nodes(&self) -> Vec<usize> {
        (0..self.options.n as usize).collect()
    }

    /// Returns every producer chain, in chain order.
    pub fn all_chains(&self) -> Vec<u32> {
        let chains = u32::try_from(self.producers.len()).expect("chain count fits in u32");
        (0..chains).collect()
    }

    /// Returns the identity for `index` (committee first, then extras).
    pub fn identity(&self, index: usize) -> ed25519::PublicKey {
        self.identities[index].clone()
    }

    /// Rebuilds the deterministic committee fixture for artifact crafting.
    pub fn fixture(&self) -> Committee<V> {
        Self::committee(&self.options, &self.producers)
    }

    /// Returns one node's shared application handle.
    pub fn app(&self, index: usize) -> &MockApplication {
        &self.nodes[index].app
    }

    /// Registers a raw plane endpoint for `index`'s identity, which tests split between the two
    /// halves of an equivocating participant.
    pub async fn tap(
        &self,
        index: usize,
        channel: u64,
    ) -> (
        SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        SimulatedReceiver<ed25519::PublicKey>,
    ) {
        self.oracle
            .control(self.identities[index].clone())
            .register(channel, self.options.quota)
            .await
            .unwrap()
    }

    /// Returns the tuning every engine in this cluster runs with.
    pub const fn tuning(&self) -> Tuning {
        Tuning {
            view_retention: self.options.view_retention,
            timer_ceiling: Duration::from_secs(5),
            ..Tuning::new()
        }
    }

    /// Starts every committee engine fresh.
    pub async fn start_all(&mut self) {
        let nodes = (0..self.options.n as usize).collect::<Vec<_>>();
        for &index in &nodes {
            self.start_one(index).await;
        }
        self.await_ready(&nodes).await;
    }

    /// Launches (or relaunches) the engine in `spec`'s slot over that slot's own four planes.
    ///
    /// Re-registration replaces the previous instance's mailboxes, so a restarted node keeps
    /// receiving on the same four planes its peers already target.
    pub async fn launch(&mut self, spec: LaunchSpec<V>) {
        let launch = self.launch_racing(spec, future::pending::<()>()).await;
        assert!(matches!(launch, Launch::Started));
    }

    /// Launches like [`Self::launch`], unless `interrupt` resolves while the engine is still
    /// opening: then the open is dropped mid-recovery and nothing starts.
    pub async fn launch_racing<T>(
        &mut self,
        spec: LaunchSpec<V>,
        interrupt: impl Future<Output = T>,
    ) -> Launch<T> {
        self.ensure_slot(spec.slot);
        let planes = self.own_planes(spec.slot).await;
        let signer = spec.slot;
        self.launch_over_racing(spec, signer, planes, true, interrupt)
            .await
    }

    /// Registers `slot`'s four planes, wrapping the sends tests can block.
    async fn own_planes(&self, slot: usize) -> OwnPlanes {
        let control = self.oracle.control(self.identities[slot].clone());
        let quota = self.options.quota;
        let (data, data_receiver) = control.register(DATA_CHANNEL, quota).await.unwrap();
        let (consensus, consensus_receiver) =
            control.register(CONSENSUS_CHANNEL, quota).await.unwrap();
        let (certificates, certificates_receiver) =
            control.register(CERTIFICATE_CHANNEL, quota).await.unwrap();
        let (resolver, resolver_receiver) =
            control.register(RESOLVER_CHANNEL, quota).await.unwrap();
        Planes {
            data: (
                self.own_sender(slot, data, Some(Plane::Data)),
                data_receiver,
            ),
            consensus: (
                self.own_sender(slot, consensus, Some(Plane::Consensus)),
                consensus_receiver,
            ),
            certificates: (
                self.own_sender(slot, certificates, Some(Plane::Certificates)),
                certificates_receiver,
            ),
            resolver: (self.own_sender(slot, resolver, None), resolver_receiver),
        }
    }

    /// Registers `slot`'s marshal planes (body broadcast, then backfill), wrapping the body
    /// sends tests can block.
    async fn marshal_planes(
        &self,
        slot: usize,
    ) -> (
        (OwnSender, SimulatedReceiver<ed25519::PublicKey>),
        (OwnSender, SimulatedReceiver<ed25519::PublicKey>),
    ) {
        let control = self.oracle.control(self.identities[slot].clone());
        let quota = self.options.quota;
        let (bodies, bodies_receiver) = control.register(BODIES_CHANNEL, quota).await.unwrap();
        let (backfill, backfill_receiver) =
            control.register(BACKFILL_CHANNEL, quota).await.unwrap();
        (
            (
                self.own_sender(slot, bodies, Some(Plane::Bodies)),
                bodies_receiver,
            ),
            (self.own_sender(slot, backfill, None), backfill_receiver),
        )
    }

    /// Wraps one of `slot`'s plane senders so tests can block its recipients on `plane`.
    ///
    /// The resolver plane passes `None`: tests never block it.
    #[cfg(test)]
    fn own_sender(
        &self,
        slot: usize,
        sender: SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        plane: Option<Plane>,
    ) -> OwnSender {
        BlockingSender {
            inner: sender,
            me: self.identities[slot].clone(),
            identities: self.identities.clone(),
            blocked: plane.map_or_else(Arc::default, |plane| {
                Arc::clone(&self.nodes[slot].hooks.blocked[plane as usize])
            }),
        }
    }

    #[cfg(not(test))]
    const fn own_sender(
        &self,
        _slot: usize,
        sender: SimulatedSender<ed25519::PublicKey, deterministic::Context>,
        _plane: Option<Plane>,
    ) -> OwnSender {
        sender
    }

    /// Launches the engine in `spec`'s slot with `signer`'s key material over caller-supplied
    /// plane transports, without a marshal.
    ///
    /// The slot names the storage and application, so two engines signing as one participant
    /// keep entirely separate durable state.
    pub async fn launch_over<S, R>(
        &mut self,
        spec: LaunchSpec<V>,
        signer: usize,
        planes: Planes<S, R>,
    ) where
        S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let launch = self
            .launch_over_racing(spec, signer, planes, false, future::pending::<()>())
            .await;
        assert!(matches!(launch, Launch::Started));
    }

    async fn launch_over_racing<S, R, T>(
        &mut self,
        spec: LaunchSpec<V>,
        signer: usize,
        planes: Planes<S, R>,
        marshaled: bool,
        interrupt: impl Future<Output = T>,
    ) -> Launch<T>
    where
        S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let LaunchSpec { slot, reporter } = spec;
        self.ensure_slot(slot);
        let committee = Self::committee(&self.options, &self.producers);
        // Engines signing as one participant share its network identity, so peers attribute
        // them to a single committee weight.
        let me = self.identities[signer].clone();
        let node = &mut self.nodes[slot];
        let generation = node.generation;
        node.generation += 1;
        let label = engine_label(slot, generation);

        let application = node.app.clone();
        let deliveries = node.deliveries.clone();
        let facts = Facts::new(Arc::clone(&node.facts));
        let engine_context = self.context.child(label);
        let marshal_partition = format!("{}_marshal", self.partition_prefix(slot));
        #[cfg(test)]
        {
            self.nodes[slot].hooks.task_prefix = Some(engine_context.name().label);
        }
        let marshal = if marshaled {
            let chain = self
                .producers
                .iter()
                .position(|producer| usize::from(*producer) == signer)
                .map(|chain| ChainId::new(u32::try_from(chain).expect("chain fits in u32")));
            let (bodies, backfill) = self.marshal_planes(slot).await;
            Some(
                Marshaled::start(
                    engine_context.child("delivery"),
                    &committee,
                    &self.oracle,
                    me.clone(),
                    chain,
                    marshal_partition,
                    bodies,
                    backfill,
                    deliveries,
                )
                .await,
            )
        } else {
            None
        };
        let (automaton, relay, marshal_reporter) = match &marshal {
            Some(marshal) => (
                ClusterApplication::marshaled(
                    application,
                    engine_context.child("application"),
                    marshal.mailbox.clone(),
                ),
                marshal.relay.clone(),
                Some(marshal.mailbox.clone()),
            ),
            None => (
                ClusterApplication::detached(application),
                ClusterBroadcast::default(),
                None,
            ),
        };
        let config = EngineConfig {
            scheme: committee.signers[signer].clone(),
            genesis: committee.config.genesis().clone(),
            tuning: self.tuning(),
            automaton,
            relay,
            reporter: Reporters::from((marshal_reporter, Reporters::from((facts, reporter)))),
            strategy: Sequential,
            critical_strategy: Sequential,
            blocker: self.oracle.control(me),
            partition_prefix: self.partition_prefix(slot),
            page_cache: CacheRef::from_pooler(&self.context, paged::page_size(4_096), NZUsize!(8)),
            mailbox_size: NonZeroUsize::new(128).unwrap(),
        };
        match self
            .start_engine(engine_context, config, planes, interrupt)
            .await
        {
            Ok(mut running) => {
                running.marshal = marshal;
                self.nodes[slot].engine = Some(running);
                Launch::Started
            }
            Err(interrupted) => {
                if let Some(mut marshal) = marshal {
                    marshal.abort();
                    let _ = marshal.join().await;
                }
                Launch::Interrupted(interrupted)
            }
        }
    }

    /// Opens and starts one engine, unless `interrupt` resolves first.
    async fn start_engine<E, S, R, T>(
        &self,
        context: E,
        config: MockEngineConfig<V>,
        planes: Planes<S, R>,
        interrupt: impl Future<Output = T>,
    ) -> Result<RunningEngine<V>, T>
    where
        E: commonware_runtime::Clock
            + CryptoRng
            + Spawner
            + commonware_runtime::Storage
            + commonware_runtime::Metrics
            + commonware_runtime::BufferPooler,
        S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let engine = select! {
            engine = Box::pin(Engine::open_with(context, config, self.checkpoint_interval)) => {
                engine.expect("engine opens")
            },
            interrupted = interrupt => return Err(interrupted),
        };
        let flusher = engine.flusher();
        Ok(RunningEngine {
            engine: engine.start(planes),
            flusher,
            marshal: None,
        })
    }

    /// Reserves one extra slot for an engine a campaign launches itself and returns its index.
    ///
    /// The slot owns separate durable state, application instance, and scheduling. `salt` makes
    /// the application build a different body for the same chain height, so two slots signing as
    /// one producer equivocate.
    pub fn reserve_slot(&mut self, salt: &'static str) -> usize {
        let application = MockApplication::builder().salt(salt).build();
        Self::apply_production_policy(&application, self.production_policy);
        self.nodes.push(Node::new(application));
        self.nodes.len() - 1
    }

    fn apply_production_policy(application: &MockApplication, production_policy: ProductionPolicy) {
        match production_policy {
            ProductionPolicy::Paused => application.pause_building(),
            ProductionPolicy::Continuous => application.produce_continuously(),
            ProductionPolicy::Every { .. } => {
                application.pause_building();
                application.permit_builds(1);
            }
        }
    }

    fn apply_production_policy_to_all(&self) {
        for node in &self.nodes {
            Self::apply_production_policy(&node.app, self.production_policy);
        }
    }

    /// Crashes one engine uncleanly, leaving its durable partitions intact.
    pub async fn crash(&mut self, index: usize) {
        self.observe_running_finality().await;
        let mut engine = self.nodes[index].engine.take().expect("engine is running");

        #[cfg(test)]
        let task_prefix = self.nodes[index]
            .hooks
            .task_prefix
            .take()
            .expect("running engine has a task prefix");
        #[cfg(test)]
        assert!(
            count_running_tasks(&self.context, &task_prefix) > 0,
            "engine {index} has no running tasks under {task_prefix} before abort"
        );

        engine.abort();
        engine.join().await;

        #[cfg(test)]
        {
            self.context.sleep(Duration::from_millis(1)).await;
            let remaining = count_running_tasks(&self.context, &task_prefix);
            assert_eq!(
                remaining, 0,
                "engine {index} left {remaining} tasks under {task_prefix} after join"
            );
        }
    }

    /// Restarts a crashed engine over its durable partitions.
    pub async fn restart(&mut self, index: usize) {
        assert!(
            self.nodes[index].engine.is_none(),
            "crash before restarting"
        );
        self.launch(LaunchSpec::new(index)).await;
        self.await_ready(&[index]).await;
        self.observe_running_finality().await;
    }

    /// Applies full connectivity between every pair of identities.
    pub async fn heal(&mut self) {
        self.observe_running_finality().await;
        link_all_with(
            &self.oracle,
            &self.identities,
            self.options.latency,
            self.options.jitter,
        )
        .await;
        self.observe_running_finality().await;
    }

    /// Replaces the directed link from `from` to `to`.
    pub async fn set_link(&self, from: usize, to: usize, link: Link) {
        self.replace_link(
            self.identities[from].clone(),
            self.identities[to].clone(),
            link,
        )
        .await;
    }

    /// Drops `plane` sends from one engine to one identity.
    #[cfg(test)]
    pub fn block(&self, plane: Plane, from: usize, to: usize) {
        let recipient = self.identities[to].clone();
        let mut blocked = self.nodes[from].hooks.blocked[plane as usize].lock();
        if !blocked.contains(&recipient) {
            blocked.push(recipient);
        }
    }

    /// Restores `plane` sends from one engine to one identity.
    #[cfg(test)]
    pub fn unblock(&self, plane: Plane, from: usize, to: usize) {
        let recipient = &self.identities[to];
        self.nodes[from].hooks.blocked[plane as usize]
            .lock()
            .retain(|blocked| blocked != recipient);
    }

    async fn replace_link(&self, from: ed25519::PublicKey, to: ed25519::PublicKey, link: Link) {
        let _ = self.oracle.remove_link(from.clone(), to.clone()).await;
        self.oracle
            .add_link(from, to, link)
            .await
            .expect("network conditions are valid");
    }

    /// Severs every link between the two identity groups.
    pub async fn partition(&mut self, left: &[usize], right: &[usize]) {
        self.observe_running_finality().await;
        for &from in left {
            for &to in right {
                let from = self.identities[from].clone();
                let to = self.identities[to].clone();
                let _ = self.oracle.remove_link(from.clone(), to.clone()).await;
                let _ = self.oracle.remove_link(to, from).await;
                self.observe_running_finality().await;
            }
        }
        self.observe_running_finality().await;
    }

    /// Allows every current and future application to build continuously.
    pub fn produce(&mut self) {
        self.production_policy = ProductionPolicy::Continuous;
        self.apply_production_policy_to_all();
    }

    /// Allows every application to build one block on every `polls`-th refresh.
    ///
    /// Large topologies use a slower rate: every producer building on every poll is a firehose
    /// for a single-threaded simulation, and those tests are about topology rather than
    /// throughput.
    pub fn produce_every(&mut self, polls: usize) {
        self.production_policy = ProductionPolicy::Every {
            interval: polls.max(1),
            polls: 0,
        };
        self.refresh();
    }

    /// Prevents every current and future application from building.
    pub fn stop_producing(&mut self) {
        self.production_policy = ProductionPolicy::Paused;
        self.apply_production_policy_to_all();
    }

    /// Allows every application except the listed producers to build continuously.
    pub fn produce_except(&mut self, paused: &[usize]) {
        self.production_policy = ProductionPolicy::Continuous;
        self.apply_production_policy_to_all();
        for &index in paused {
            self.nodes[index].app.pause_building();
        }
    }

    /// Advances interval production by one poll.
    pub fn refresh(&mut self) {
        let ProductionPolicy::Every { interval, polls } = &mut self.production_policy else {
            return;
        };
        let permit = polls.is_multiple_of(*interval);
        *polls += 1;
        if permit {
            for node in &self.nodes {
                node.app.permit_builds(1);
            }
        }
    }

    /// Returns the storage partition prefix of `slot`'s engine.
    fn partition_prefix(&self, slot: usize) -> String {
        format!("cluster_{}_{slot}", self.options.seed)
    }

    /// Reads one running node's machine projection.
    pub async fn inspect(&self, index: usize) -> Option<Inspection<Sha256Digest>> {
        match &self.nodes[index].engine {
            Some(engine) => engine.engine.inspector().inspect().await,
            None => None,
        }
    }

    /// Demands durability for every journal append a running engine has admitted.
    ///
    /// The persistence actor syncs a non-urgent (reconstructible) barrier only once a later
    /// demand arrives, so an engine with nothing left to do can hold one pending indefinitely.
    /// Requests collapse into one and never take journal command capacity. Returns `false` when
    /// the engine is not running or its persistence actor stopped.
    pub fn flush(&self, index: usize) -> bool {
        self.nodes[index]
            .engine
            .as_ref()
            .is_some_and(|engine| engine.flusher.flush().is_ok())
    }

    /// Returns the durable safety-journal sections retained for one engine.
    #[cfg(test)]
    pub async fn journal_sections(&self, index: usize) -> Vec<u64> {
        let partition = partitions(&self.partition_prefix(index)).journal;
        let mut sections = self
            .context
            .scan(&partition)
            .await
            .unwrap_or_else(|error| panic!("scan engine {index} journal: {error}"))
            .into_iter()
            .map(|name| {
                let name: [u8; size_of::<u64>()] = name
                    .try_into()
                    .unwrap_or_else(|name: Vec<u8>| panic!("invalid journal blob name: {name:?}"));
                u64::from_be_bytes(name)
            })
            .collect::<Vec<_>>();
        sections.sort_unstable();
        sections
    }

    /// Returns every peer pair recorded by the simulated network's real blocker.
    pub async fn blocked_peers(&self) -> Vec<(ed25519::PublicKey, ed25519::PublicKey)> {
        self.oracle
            .blocked()
            .await
            .expect("simulated network is live")
    }

    /// Records monotonic finality progress for the listed nodes.
    pub async fn observe_finality(&mut self, nodes: &[usize]) {
        for &index in nodes {
            let inspection = self
                .inspect(index)
                .await
                .unwrap_or_else(|| panic!("engine {index} failed"));
            self.nodes[index].finality.observe(index, &inspection);
        }
    }

    async fn observe_running_finality(&mut self) {
        let nodes = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.engine.as_ref().map(|_| index))
            .collect::<Vec<_>>();
        self.observe_finality(&nodes).await;
    }

    /// Polls the listed nodes every `poll`, granting interval-production credits and observing
    /// finality after each round, until `done` holds for all of them.
    ///
    /// Returns whether `done` held within `timeout / poll` rounds. The budget counts polls, so
    /// the time spent inspecting the nodes is not charged against `timeout`.
    ///
    /// # Panics
    ///
    /// Panics when a listed engine is not running.
    pub async fn wait_until(
        &mut self,
        nodes: &[usize],
        timeout: Duration,
        poll: Duration,
        mut done: impl FnMut(&Inspection<Sha256Digest>) -> bool,
    ) -> bool {
        for _ in 0..polls(timeout, poll) {
            self.refresh();
            self.context.sleep(poll).await;
            let mut reached = true;
            for &index in nodes {
                let inspection = self
                    .inspect(index)
                    .await
                    .unwrap_or_else(|| panic!("engine {index} failed"));
                if !done(&inspection) {
                    reached = false;
                    break;
                }
            }
            self.observe_finality(nodes).await;
            if reached {
                return true;
            }
        }
        false
    }

    /// Waits until every listed node finalizes `height` on every listed chain.
    pub async fn wait_finalized(
        &mut self,
        nodes: &[usize],
        chains: &[u32],
        height: u64,
        timeout: Duration,
    ) {
        let reached = self
            .wait_until(nodes, timeout, PROGRESS_POLL, |inspection| {
                chains.iter().all(|&chain| {
                    inspection
                        .chain_progress()
                        .get(chain as usize)
                        .unwrap_or_else(|| panic!("engine does not track chain {chain}"))
                        .finalized()
                        .get()
                        >= height
                })
            })
            .await;
        assert!(
            reached,
            "nodes {nodes:?} did not finalize height {height} on every chain in {chains:?} in time"
        );
    }

    /// Waits until every committee engine finalizes `height` on every chain.
    pub async fn wait_finalized_all(&mut self, height: u64, timeout: Duration) {
        let nodes = self.all_nodes();
        let chains = self.all_chains();
        self.wait_finalized(&nodes, &chains, height, timeout).await;
    }

    /// Waits until every listed node reaches `view`.
    pub async fn wait_view(&mut self, nodes: &[usize], view: View, timeout: Duration) {
        let reached = self
            .wait_until(nodes, timeout, VIEW_POLL, |inspection| {
                inspection.view() >= view
            })
            .await;
        assert!(reached, "nodes {nodes:?} did not reach view {view} in time");
    }

    /// Returns the outputs `index`'s marshal delivered, across every restart.
    pub fn deliveries(&self, index: usize) -> Deliveries {
        self.nodes[index].deliveries.clone()
    }

    /// Returns the agreement facts `index`'s consensus reported, across every restart.
    pub fn facts(&self, index: usize) -> FactLog {
        self.nodes[index].facts.lock().clone()
    }

    /// Asserts that every view two listed nodes both resolved has one tips-history commitment.
    pub fn assert_resolutions_agree(&self, nodes: &[usize]) {
        let mut canonical: HashMap<View, (usize, Sha256Digest)> = HashMap::new();
        for &node in nodes {
            for (view, (commitment, _)) in &self.nodes[node].facts.lock().resolved {
                let (first, expected) = *canonical.entry(*view).or_insert((node, *commitment));
                assert_eq!(
                    expected, *commitment,
                    "nodes {first} and {node} resolved view {view} differently"
                );
            }
        }
    }

    /// Returns the marshal of `index`'s running engine, when it runs one.
    fn marshal(&self, index: usize) -> Option<ClusterMarshal<V>> {
        let engine = self.nodes[index].engine.as_ref()?;
        engine
            .marshal
            .as_ref()
            .map(|marshal| marshal.mailbox.clone())
    }

    /// Waits until every listed node's marshal delivered output `index`, granting
    /// interval-production credits and observing finality on the way.
    pub async fn wait_delivered(&mut self, nodes: &[usize], index: u64, timeout: Duration) {
        let target = OutputIndex::new(index);
        for _ in 0..polls(timeout, PROGRESS_POLL) {
            self.refresh();
            self.context.sleep(PROGRESS_POLL).await;
            self.observe_finality(nodes).await;
            if nodes
                .iter()
                .all(|&node| self.nodes[node].deliveries.last() >= Some(target))
            {
                return;
            }
        }
        let mut reached = Vec::new();
        for &node in nodes {
            let inspection = self.inspect(node).await;
            let progress = match self.marshal(node) {
                Some(marshal) => marshal.progress().await.map_err(|_| ()),
                None => Err(()),
            };
            // A stopped marshal answers nothing; stop the slot to read why.
            let failure = if progress.is_err() {
                self.stop_failed(node).await
            } else {
                None
            };
            reached.push(format!(
                "node {node}: delivered {:?}, view {:?}, resolved {:?}, committed {:?}, marshal failure {:?}",
                self.nodes[node].deliveries.last().map(OutputIndex::get),
                inspection.as_ref().map(|inspection| inspection.view().get()),
                inspection.as_ref().map(|inspection| inspection.last_resolved().get()),
                progress.ok().map(|progress| progress.committed.get()),
                failure,
            ));
        }
        panic!(
            "nodes {nodes:?} did not deliver output {index} in time:\n{}",
            reached.join("\n")
        );
    }

    /// Stops `index`'s engine and returns its marshal's failure, if marshal failed.
    pub(crate) async fn stop_failed(&mut self, index: usize) -> Option<String> {
        let mut engine = self.nodes[index].engine.take()?;
        engine.abort();
        let _ = engine.engine.join().await;
        let error = match engine.marshal {
            Some(marshal) => marshal.join().await.err(),
            None => None,
        };
        error.map(|error| format!("{error:?}"))
    }

    /// Asserts that the listed nodes delivered one ordered stream: each node's outputs are
    /// contiguous from its first, each chain's blocks appear in height order without gaps (from
    /// height one when the node delivered from genesis), and every index two nodes both delivered
    /// names the same block.
    ///
    /// Returns the longest delivered stream.
    pub fn assert_deliveries_agree(&self, nodes: &[usize]) -> Vec<BlockRef<Sha256Digest>> {
        let mut canonical: HashMap<OutputIndex, (usize, BlockRef<Sha256Digest>)> = HashMap::new();
        let mut longest = Vec::new();
        for &node in nodes {
            let outputs = self.nodes[node].deliveries.outputs();
            for window in outputs.windows(2) {
                assert_eq!(
                    window[0].0.get() + 1,
                    window[1].0.get(),
                    "node {node} skipped outputs after {:?}",
                    window[0].0
                );
            }
            let from_genesis = outputs.first().is_some_and(|(index, _)| index.get() == 1);
            let mut heights = HashMap::new();
            for (index, block) in &outputs {
                let height = block.height().get();
                if let Some(previous) = heights.insert(block.chain(), height) {
                    assert_eq!(
                        previous + 1,
                        height,
                        "node {node} delivered {block:?} at {index:?} out of chain order"
                    );
                } else if from_genesis {
                    assert_eq!(
                        height, 1,
                        "node {node} skipped the start of a chain at {index:?}"
                    );
                }
            }
            for (index, block) in &outputs {
                let (first, expected) = *canonical.entry(*index).or_insert((node, *block));
                assert_eq!(
                    expected, *block,
                    "nodes {first} and {node} delivered different blocks at {index:?}"
                );
            }
            if outputs.len() > longest.len() {
                longest = outputs.into_iter().map(|(_, block)| block).collect();
            }
        }
        longest
    }
}

/// Returns the static label for the engine launched in `slot` at `generation`.
///
/// Labels must be static and distinct so every engine's tasks and metrics stay distinguishable
/// across slots and restarts. Each label is allocated once per process and kept reachable, so
/// repeated clusters (such as fuzz iterations) reuse it rather than leaking a new one.
fn engine_label(slot: usize, generation: usize) -> &'static str {
    static LABELS: LazyLock<Mutex<HashMap<(usize, usize), &'static str>>> =
        LazyLock::new(Default::default);
    LABELS
        .lock()
        .entry((slot, generation))
        .or_insert_with(|| Box::leak(format!("n{slot}g{generation}").into_boxed_str()))
}

/// Returns how many polls of `poll` fit in `budget`, counting a partial poll.
const fn polls(budget: Duration, poll: Duration) -> u128 {
    budget.as_nanos().div_ceil(poll.as_nanos())
}

/// An effectively unlimited per-channel rate quota for test networks.
pub const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Starts a simulated network over `identities` and returns its oracle.
pub async fn start_network(
    context: &deterministic::Context,
    identities: Vec<ed25519::PublicKey>,
    max_size: u32,
) -> Oracle<ed25519::PublicKey, deterministic::Context> {
    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        NetworkConfig {
            max_size,
            max_peers_per_set: NZUsize!(identities.len()),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        identities,
    )
    .await;
    network.start();
    oracle
}

/// The one-way link latency clusters use unless a scenario picks its own.
pub const DEFAULT_LATENCY: Duration = Duration::from_millis(2);

/// Fully connects every pair of identities with a low-latency lossless link.
pub async fn link_all(
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    identities: &[ed25519::PublicKey],
) {
    link_all_with(oracle, identities, DEFAULT_LATENCY, Duration::ZERO).await;
}

/// Fully connects every pair of identities with a lossless link of the given latency and jitter.
pub async fn link_all_with(
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    identities: &[ed25519::PublicKey],
    latency: Duration,
    jitter: Duration,
) {
    let link = Link {
        latency,
        jitter,
        success_rate: probability!(1.0),
    };
    for from in identities {
        for to in identities {
            if from == to {
                continue;
            }
            let _ = oracle
                .add_link(from.clone(), to.clone(), link.clone())
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cluster, ClusterOptions, Plane, engine_label};
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_runtime::{Runner as _, deterministic};
    use std::time::Duration;

    #[test]
    fn engine_labels_are_interned_per_slot_and_generation() {
        let label = engine_label(3, 1);
        assert_eq!(label, "n3g1");
        assert!(std::ptr::eq(label, engine_label(3, 1)));
        assert_ne!(label, engine_label(1, 3));
    }

    #[test]
    fn reserved_slots_own_every_per_node_control() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut cluster = Cluster::<MinPk>::new(&context, ClusterOptions::new(79, 6)).await;
            let reserved = cluster.reserve_slot("reserved");
            cluster.ensure_slot(reserved + 1);
            assert_eq!(cluster.nodes.len(), reserved + 2);
            for slot in [reserved, reserved + 1] {
                for plane in [
                    Plane::Data,
                    Plane::Consensus,
                    Plane::Certificates,
                    Plane::Bodies,
                ] {
                    cluster.block(plane, slot, 2);
                    cluster.unblock(plane, slot, 2);
                }
            }
        });
    }
}

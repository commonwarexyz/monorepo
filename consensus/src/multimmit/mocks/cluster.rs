//! A reusable deterministic Multimmit cluster over the simulated network.
//!
//! The harness launches complete production engines (ingress, verifier, voter, resolver, storage)
//! for one committee, with per-node crash/restart, link partitions, and finality assertions. It
//! runs only under the deterministic runtime; wall-clock schedules replay exactly per seed.

#[cfg(test)]
use crate::multimmit::storage::partitions;
use crate::{
    Reporter,
    multimmit::{
        actors::{resolver, voter},
        config::{LeaderSchedule, Tuning},
        engine::{Config as EngineConfig, Engine, Overrides, Planes, Running},
        machine::{Generation, Inspection},
        mocks::{Committee, MockApplication},
        types::{Activity, PathLimits, ViewProof},
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
    Clock as _, Handle, Quota, Spawner, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, release_pending_syncs},
};
use commonware_utils::{NZUsize, probability, sync::Mutex};
use rand_core::CryptoRng;
use std::{
    future::{self, Future},
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
#[cfg(test)]
use std::{num::NonZeroU64, time::SystemTime};

/// Mixed into the cluster seed for extra identities, keeping them apart from committee keys,
/// which derive from `seed ^ (index + 1)`.
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

/// Simulated-network channel of the view-proof resolver plane.
pub const RESOLVER_CHANNEL: u64 = 3;

type MockEngineConfig<V> = EngineConfig<
    Sha256,
    ed25519::PublicKey,
    V,
    MockApplication,
    MockApplication,
    ClusterReporter<V>,
    Sequential,
    Sequential,
    ClusterBlocker,
>;

type ActivityCallback<V> = Box<dyn FnMut(Activity<V, Sha256Digest>) -> Feedback + Send + 'static>;
type BlockCallback = Box<dyn FnMut(ed25519::PublicKey, ed25519::PublicKey) + Send + 'static>;

#[derive(Clone)]
struct ClusterBlocker {
    inner: Control<ed25519::PublicKey, deterministic::Context>,
    me: ed25519::PublicKey,
    callback: Option<Arc<Mutex<BlockCallback>>>,
}

impl commonware_p2p::Blocker for ClusterBlocker {
    type PublicKey = ed25519::PublicKey;

    #[allow(
        clippy::disallowed_methods,
        reason = "the test wrapper must preserve the inner blocker's feedback"
    )]
    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        if let Some(callback) = &self.callback {
            callback.lock()(self.me.clone(), peer.clone());
        }
        commonware_p2p::Blocker::block(&mut self.inner, peer)
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        commonware_p2p::Blocker::blocked(&mut self.inner)
    }
}

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
    /// Empty-build retry interval.
    pub production: Duration,
    /// Retained views below the current one.
    pub view_retention: ViewDelta,
    /// Proposal pipeline depth and vote extension bound.
    pub limits: PathLimits,
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
            production: Duration::from_millis(100),
            // Deterministic scenarios run hundreds of views, so keep the retained window small
            // enough that retirement is exercised without holding every view.
            view_retention: ViewDelta::new(16),
            limits: PathLimits::new(2, 1).expect("default limits are valid"),
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

    /// Returns a link with this cluster's latency and jitter that delivers with `success_rate`.
    fn link(&self, success_rate: f64) -> Link {
        Link {
            latency: self.latency,
            jitter: self.jitter,
            success_rate: success_rate.try_into().expect("valid delivery probability"),
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
}

/// Per-node state that tests inspect or steer.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    /// Task label prefix of the running engine.
    task_prefix: Option<String>,
    /// Blocked recipients per [`Plane`].
    blocked: [Arc<Mutex<Vec<ed25519::PublicKey>>>; 3],
}

/// One engine slot: its application, running engine, and observed finality.
struct Node<V: Variant> {
    app: MockApplication,
    engine: Option<RunningEngine<V>>,
    finality: FinalityHistory,
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
            generation: 0,
            #[cfg(test)]
            hooks: TestHooks::default(),
        }
    }
}

/// Which slot an engine occupies, whose keys it signs with, and where its activity goes.
pub struct LaunchSpec<V: Variant> {
    slot: usize,
    signer: usize,
    label: Option<&'static str>,
    reporter: ClusterReporter<V>,
}

impl<V: Variant> LaunchSpec<V> {
    /// Launches `slot` with its own participant's keys, labelled by slot and generation, with
    /// activity discarded.
    pub fn new(slot: usize) -> Self {
        Self {
            slot,
            signer: slot,
            label: None,
            reporter: ClusterReporter::default(),
        }
    }

    /// Signs with `signer`'s key material, which a twin half sets to another participant.
    pub const fn signer(mut self, signer: usize) -> Self {
        self.signer = signer;
        self
    }

    /// Labels the engine's metrics and traces with `label`.
    pub const fn label(mut self, label: &'static str) -> Self {
        self.label = Some(label);
        self
    }

    /// Sends the engine's best-effort activity to `reporter`.
    pub fn reporter<S>(mut self, mut reporter: S) -> Self
    where
        S: Reporter<Activity = Activity<V, Sha256Digest>> + Send + 'static,
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
    block_callback: Option<Arc<Mutex<BlockCallback>>>,
    overrides: Overrides,
    production_policy: ProductionPolicy,
    storage_sync_interval: Option<Duration>,
}

struct RunningEngine<V: Variant> {
    engine: Running<Sha256Digest>,
    proofs: resolver::Server<V, Sha256Digest>,
    flusher: voter::Flusher,
    storage_sync_task: Option<Handle<()>>,
}

impl<V: Variant> RunningEngine<V> {
    fn abort(&self) {
        self.engine.abort();
        if let Some(task) = &self.storage_sync_task {
            task.abort();
        }
    }

    async fn join(self) {
        // The engine was aborted first, so its root task reports the abort.
        let _ = self.engine.join().await;
        if let Some(task) = self.storage_sync_task {
            task.abort();
            let _ = task.await;
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
    finality_floor: View,
}

impl FinalityHistory {
    const fn new() -> Self {
        Self {
            generation: Generation::new(0),
            finality_floor: View::zero(),
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
            restarted || inspection.finality_floor() >= self.finality_floor,
            "engine {node} finality floor regressed from {} to {}",
            self.finality_floor,
            inspection.finality_floor(),
        );
        self.generation = inspection.generation();
        self.finality_floor = inspection.finality_floor();
    }
}

#[derive(Clone, Copy)]
enum ProductionPolicy {
    Paused,
    Continuous,
    Once,
    Every { interval: usize, polls: usize },
}

impl<V: Variant> Cluster<V> {
    /// Builds the committee, simulated network, and fully connected links.
    pub async fn new(context: &deterministic::Context, options: ClusterOptions) -> Self {
        let producers = (0..options.n).map(Participant::new).collect();
        Self::new_with_producers(context, options, producers).await
    }

    /// Builds a cluster whose producer chains belong to `producers` in chain order.
    pub async fn new_with_producers(
        context: &deterministic::Context,
        options: ClusterOptions,
        producers: Vec<Participant>,
    ) -> Self {
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
            block_callback: None,
            overrides: Overrides::default(),
            production_policy: ProductionPolicy::Paused,
            storage_sync_interval: None,
        };
        cluster.heal().await;
        cluster
    }

    fn committee(options: &ClusterOptions, producers: &[Participant]) -> Committee<V> {
        let mut committee = Committee::builder(options.seed, options.n)
            .producers(producers.to_vec())
            .limits(options.limits);
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
    fn started(&self) -> bool {
        self.nodes.iter().any(|node| node.generation > 0)
    }

    /// Installs an observer invoked synchronously when an engine blocks a peer.
    #[cfg(any(test, feature = "mocks"))]
    pub fn set_block_callback(
        &mut self,
        callback: impl FnMut(ed25519::PublicKey, ed25519::PublicKey) + Send + 'static,
    ) {
        assert!(
            !self.started(),
            "the block observer must be installed before any engine starts"
        );
        self.block_callback = Some(Arc::new(Mutex::new(Box::new(callback))));
    }

    /// Selects real journal capacity demand for deterministic crash-cut tests.
    #[cfg(test)]
    pub(crate) fn set_journal_capacity(&mut self, capacity: NonZeroUsize) {
        assert!(self.nodes.iter().all(|node| node.engine.is_none()));
        self.overrides.journal_capacity = Some(capacity);
    }

    /// Sets the shared checkpoint cadence before any engine starts.
    #[cfg(test)]
    pub fn set_checkpoint_interval(&mut self, checkpoint_interval: NonZeroU64) {
        assert!(
            !self.started(),
            "checkpoint interval must be set before any engine starts"
        );
        self.overrides.checkpoint_interval = checkpoint_interval;
    }

    /// Delays started durability syncs by releasing them at a fixed interval.
    pub fn set_storage_sync_interval(&mut self, interval: Duration) {
        assert!(
            !interval.is_zero(),
            "storage sync interval must be non-zero"
        );
        assert!(
            !self.started(),
            "storage sync interval must be set before any engine starts"
        );
        self.storage_sync_interval = Some(interval);
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

    /// Returns the simulated-network oracle for custom link and bandwidth schedules.
    pub const fn oracle(&self) -> &Oracle<ed25519::PublicKey, deterministic::Context> {
        &self.oracle
    }

    /// Registers a raw plane endpoint for `index`.
    ///
    /// Tests use this to inject crafted traffic, and Twins campaigns use it to obtain the
    /// participant's single endpoint before splitting it between two halves.
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
            production_interval: self.options.production,
            view_retention: self.options.view_retention,
            ..Tuning::new(Duration::from_millis(500))
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
        self.launch_over_racing(spec, planes, interrupt).await
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

    /// Launches the engine in `spec`'s slot over caller-supplied plane transports.
    ///
    /// `spec`'s signer selects whose key material the engine uses, which a twin half sets to
    /// another participant. The slot names the storage and application, so two halves of one
    /// participant keep entirely separate durable state.
    pub async fn launch_over<S, R>(&mut self, spec: LaunchSpec<V>, planes: Planes<S, R>)
    where
        S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let launch = self
            .launch_over_racing(spec, planes, future::pending::<()>())
            .await;
        assert!(matches!(launch, Launch::Started));
    }

    async fn launch_over_racing<S, R, T>(
        &mut self,
        spec: LaunchSpec<V>,
        planes: Planes<S, R>,
        interrupt: impl Future<Output = T>,
    ) -> Launch<T>
    where
        S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let LaunchSpec {
            slot,
            signer,
            label,
            reporter,
        } = spec;
        self.ensure_slot(slot);
        let committee = Self::committee(&self.options, &self.producers);
        // Both halves of a twin share the signing participant's one network identity, which is
        // what makes honest nodes attribute them to a single committee weight.
        let me = self.identities[signer].clone();
        let node = &mut self.nodes[slot];
        let generation = node.generation;
        node.generation += 1;
        // Labels must be static; each launch leaks one short label so every engine's tasks and
        // metrics stay distinguishable across slots and restarts.
        let label =
            label.unwrap_or_else(|| Box::leak(format!("n{slot}g{generation}").into_boxed_str()));

        let application = node.app.clone();
        let engine_context = self.context.child(label);
        #[cfg(test)]
        {
            self.nodes[slot].hooks.task_prefix = Some(engine_context.name().label);
        }
        let config = EngineConfig {
            scheme: committee.signers[signer].clone(),
            genesis: committee.config.genesis().clone(),
            tuning: self.tuning(),
            automaton: application.clone(),
            relay: application,
            reporter,
            strategy: Sequential,
            critical_strategy: Sequential,
            blocker: ClusterBlocker {
                inner: self.oracle.control(me.clone()),
                me,
                callback: self.block_callback.clone(),
            },
            partition_prefix: self.partition_prefix(slot),
            page_cache: CacheRef::from_pooler(&self.context, paged::page_size(4_096), NZUsize!(8)),
            mailbox_size: NonZeroUsize::new(128).unwrap(),
        };
        let mut storage_sync_task: Option<Handle<()>> = None;
        let started = if let Some(interval) = self.storage_sync_interval {
            let pending_syncs = PendingSyncs::default();
            let releases = pending_syncs.clone();
            storage_sync_task = Some(engine_context.child("storage_syncs").spawn(
                move |context| async move {
                    loop {
                        context.sleep(interval).await;
                        release_pending_syncs(&releases);
                    }
                },
            ));
            let engine_context = DelayedSyncContext {
                inner: engine_context,
                pending: pending_syncs,
            };
            self.start_engine(engine_context, config, planes, interrupt)
                .await
        } else {
            self.start_engine(engine_context, config, planes, interrupt)
                .await
        };
        match started {
            Ok(mut running) => {
                running.storage_sync_task = storage_sync_task;
                self.nodes[slot].engine = Some(running);
                Launch::Started
            }
            Err(interrupted) => {
                if let Some(task) = storage_sync_task {
                    task.abort();
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
            engine = Box::pin(Engine::open_with(context, config, self.overrides)) => {
                engine.expect("engine opens")
            },
            interrupted = interrupt => return Err(interrupted),
        };
        let proofs = engine.proofs();
        let flusher = engine.flusher();
        Ok(RunningEngine {
            engine: engine.start(planes),
            proofs,
            flusher,
            storage_sync_task: None,
        })
    }

    /// Reserves one extra slot for an engine a campaign launches itself and returns its index.
    ///
    /// The slot owns separate durable state, application instance, and scheduling. `salt` makes
    /// the application build a different body for the same chain position, which forces a
    /// key-sharing twin to equivocate as a producer.
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
            ProductionPolicy::Once | ProductionPolicy::Every { .. } => {
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
        let engine = self.nodes[index].engine.take().expect("engine is running");

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

    /// Restores lossless links to and from one identity.
    pub async fn heal_node(&mut self, index: usize) {
        self.set_node_success_rate(index, 1.0).await;
    }

    /// Applies one delivery rate to every link to and from one identity.
    pub async fn set_node_success_rate(&mut self, index: usize, success_rate: f64) {
        self.observe_running_finality().await;
        let link = self.options.link(success_rate);
        let node = &self.identities[index];
        for peer in &self.identities {
            if peer == node {
                continue;
            }
            self.replace_link(node.clone(), peer.clone(), link.clone())
                .await;
            self.replace_link(peer.clone(), node.clone(), link.clone())
                .await;
        }
        self.observe_running_finality().await;
    }

    /// Applies one delivery rate to a single directed link.
    pub async fn set_directed_success_rate(&mut self, from: usize, to: usize, success_rate: f64) {
        self.set_link(from, to, self.options.link(success_rate))
            .await;
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

    /// Allows every current and future application to build one block.
    pub fn produce_once(&mut self) {
        self.production_policy = ProductionPolicy::Once;
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

    /// Applies the same delivery conditions to every directed link.
    pub async fn set_network_conditions(
        &mut self,
        latency: Duration,
        jitter: Duration,
        success_rate: f64,
    ) {
        self.observe_running_finality().await;
        let link = Link {
            latency,
            jitter,
            success_rate: success_rate.try_into().expect("valid delivery probability"),
        };
        let identities = self.identities.clone();
        for from in &identities {
            for to in &identities {
                if from == to {
                    continue;
                }
                self.replace_link(from.clone(), to.clone(), link.clone())
                    .await;
                self.observe_running_finality().await;
            }
        }
        self.observe_running_finality().await;
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

    /// Reads one checkpoint retained by a running engine's volatile resolver.
    pub async fn serve(&self, index: usize, view: View) -> Option<Arc<ViewProof<V, Sha256Digest>>> {
        let engine = self.nodes[index].engine.as_ref()?;
        engine.proofs.serve(view).await.ok().flatten()
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

    /// Returns the number of checkpoint blobs retained for one engine.
    #[cfg(test)]
    pub async fn checkpoint_blobs(&self, index: usize) -> usize {
        let partition = partitions(&self.partition_prefix(index)).checkpoints;
        self.context
            .scan(&partition)
            .await
            .unwrap_or_else(|error| panic!("scan engine {index} checkpoints: {error}"))
            .len()
    }

    /// Returns every peer pair recorded by the simulated network's real blocker.
    #[cfg(any(test, feature = "mocks"))]
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

    /// Waits until every listed node has durably produced at least `blocks` transaction blocks.
    ///
    /// Topology tests use this to stop synthetic work before waiting for consensus, keeping
    /// their message volume bounded without relying on a wall-clock delay.
    pub async fn wait_produced(&mut self, nodes: &[usize], blocks: u64, timeout: Duration) {
        let reached = self
            .wait_until(nodes, timeout, PROGRESS_POLL, |inspection| {
                inspection.produced_blocks() >= blocks
            })
            .await;
        assert!(
            reached,
            "nodes {nodes:?} did not produce {blocks} blocks in time"
        );
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

    /// Observes monotonic local finality every progress poll for `duration`, without granting
    /// interval-production credits.
    pub async fn observe_finality_progress(&mut self, nodes: &[usize], duration: Duration) {
        for _ in 0..polls(duration, PROGRESS_POLL) {
            self.context.sleep(PROGRESS_POLL).await;
            self.observe_finality(nodes).await;
        }
    }
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
    use super::{Cluster, ClusterOptions, Plane};
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_runtime::{Runner as _, deterministic};
    use std::time::Duration;

    #[test]
    fn reserved_slots_own_every_per_node_control() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut cluster = Cluster::<MinPk>::new(&context, ClusterOptions::new(79, 6)).await;
            let reserved = cluster.reserve_slot("reserved");
            cluster.ensure_slot(reserved + 1);
            assert_eq!(cluster.nodes.len(), reserved + 2);
            for slot in [reserved, reserved + 1] {
                for plane in [Plane::Data, Plane::Consensus, Plane::Certificates] {
                    cluster.block(plane, slot, 2);
                    cluster.unblock(plane, slot, 2);
                }
            }
        });
    }
}
